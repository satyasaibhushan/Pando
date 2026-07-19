use crate::model::{Lease, Overlay, SnapshotId};
use crate::snapshot::manifest_id;
use crate::snapshot::materialize_overlay;
use crate::store::ChunkStore;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcquireResult {
    Acquired(Lease),
    HeldBy(Lease),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityStatus {
    pub repo_id: String,
    pub lease: Option<Lease>,
    pub head: Option<SnapshotId>,
    pub last_snapshot_at_ms: Option<u64>,
    pub exposure_bytes: u64,
    #[serde(default)]
    pub forks: Vec<SnapshotId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityVerification {
    pub heads: usize,
    pub overlays: usize,
    pub chunks: usize,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreReport {
    pub snapshot: SnapshotId,
    pub files: usize,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GarbageCollectionReport {
    pub overlays: usize,
    pub chunks: usize,
    pub bytes: u64,
    pub applied: bool,
}

pub trait Authority {
    fn acquire(
        &mut self,
        repo_id: &str,
        trunk_id: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<AcquireResult>;
    fn release(&mut self, repo_id: &str, trunk_id: &str) -> Result<()>;
    fn put_chunk(&mut self, hash: &str, bytes: &[u8]) -> Result<()>;
    fn has_chunk(&self, hash: &str) -> Result<bool>;
    fn get_chunk(&self, hash: &str) -> Result<Vec<u8>>;
    fn publish(&mut self, overlay: &Overlay, trunk_id: &str, now_ms: u64) -> Result<()>;
    fn publish_fork(&mut self, overlay: &Overlay, trunk_id: &str, now_ms: u64) -> Result<()>;
    fn forks(&self, repo_id: &str) -> Result<Vec<SnapshotId>>;
    fn resolve_fork(&mut self, repo_id: &str, snapshot_id: &str) -> Result<()>;
    fn head(&self, repo_id: &str) -> Result<Option<SnapshotId>>;
    fn overlay(&self, snapshot_id: &str) -> Result<Overlay>;
    fn status(&self, repo_id: &str, now_ms: u64) -> Result<AuthorityStatus>;
}

#[derive(Clone, Debug)]
pub struct FileAuthority {
    root: PathBuf,
    chunks: ChunkStore,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct State {
    heads: BTreeMap<String, SnapshotId>,
    leases: BTreeMap<String, Lease>,
    generations: BTreeMap<String, u64>,
    #[serde(default)]
    forks: BTreeMap<String, Vec<SnapshotId>>,
}

impl FileAuthority {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("overlays"))?;
        let chunks = ChunkStore::new(root.join("chunks"))?;
        let authority = Self { root, chunks };
        if !authority.state_path().exists() {
            authority.save_state(&State::default())?;
        }
        Ok(authority)
    }

    pub fn open_existing(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        if !root.join("state.json").is_file() || !root.join("overlays").is_dir() {
            bail!("authority does not exist at {}", root.display());
        }
        let chunks = ChunkStore::open_existing(root.join("chunks"))?;
        Ok(Self { root, chunks })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn verify(&self) -> Result<AuthorityVerification> {
        let store = self.chunks.verify_all()?;
        let mut overlays = BTreeMap::new();
        for entry in fs::read_dir(self.root.join("overlays"))? {
            let entry = entry?;
            let path = entry.path();
            if path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with('.') && name.contains(".partial-"))
            {
                continue;
            }
            if !entry.file_type()?.is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                bail!("unexpected authority overlay entry {}", path.display());
            }
            let bytes = fs::read(&path)?;
            let overlay: Overlay = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse overlay {}", path.display()))?;
            let file_id = path
                .file_stem()
                .and_then(|value| value.to_str())
                .context("overlay file name is not valid UTF-8")?;
            if overlay.snapshot.id != file_id {
                bail!(
                    "overlay file {} contains snapshot {}",
                    path.display(),
                    overlay.snapshot.id
                );
            }
            let actual_id = manifest_id(&overlay.snapshot)?;
            if actual_id != overlay.snapshot.id {
                bail!(
                    "snapshot {} content hashes to {actual_id}",
                    overlay.snapshot.id
                );
            }
            verify_overlay_shape(&overlay)?;
            if overlays.insert(file_id.to_owned(), overlay).is_some() {
                bail!("duplicate overlay {file_id}");
            }
        }

        for (id, overlay) in &overlays {
            if let Some(parent) = &overlay.snapshot.parent
                && !overlays.contains_key(parent)
            {
                bail!("snapshot {id} references missing parent {parent}");
            }
            let mut ancestry = BTreeSet::new();
            let mut cursor = Some(id.as_str());
            while let Some(current) = cursor {
                if !ancestry.insert(current) {
                    bail!("snapshot ancestry cycle at {current}");
                }
                cursor = overlays
                    .get(current)
                    .and_then(|value| value.snapshot.parent.as_deref());
            }
        }

        let state = self.load_state()?;
        for (repo_id, head) in &state.heads {
            let overlay = overlays
                .get(head)
                .with_context(|| format!("repository {repo_id} references missing head {head}"))?;
            if overlay.snapshot.repo_id != *repo_id {
                bail!(
                    "repository {repo_id} head {head} belongs to {}",
                    overlay.snapshot.repo_id
                );
            }
        }

        let mut referenced = BTreeSet::new();
        for overlay in overlays.values() {
            for entry in overlay.snapshot.files.values() {
                if referenced.insert(&entry.chunk) {
                    let bytes = self.chunks.get(&entry.chunk)?;
                    if bytes.len() as u64 != entry.size {
                        bail!(
                            "chunk {} has {} bytes but manifest records {}",
                            entry.chunk,
                            bytes.len(),
                            entry.size
                        );
                    }
                }
            }
        }

        Ok(AuthorityVerification {
            heads: state.heads.len(),
            overlays: overlays.len(),
            chunks: store.chunks,
            bytes: store.bytes,
        })
    }

    pub fn restore(&self, snapshot_id: &str, destination: &Path) -> Result<RestoreReport> {
        let destination = if destination.is_absolute() {
            destination.to_owned()
        } else {
            std::env::current_dir()?.join(destination)
        };
        if destination.exists() {
            bail!(
                "restore destination already exists: {}",
                destination.display()
            );
        }
        let overlay = self.overlay(snapshot_id)?;
        let parent = destination
            .parent()
            .context("restore destination has no parent")?;
        fs::create_dir_all(parent)?;
        let name = destination
            .file_name()
            .context("restore destination has no file name")?
            .to_string_lossy();
        let staging = parent.join(format!(".{name}.pando-restore-{}", std::process::id()));
        if staging.exists() {
            bail!("restore staging path already exists: {}", staging.display());
        }
        fs::create_dir(&staging)?;
        let restored = Overlay {
            snapshot: overlay.snapshot.clone(),
            upserts: overlay.snapshot.files.clone(),
            deletes: Vec::new(),
        };
        materialize_overlay(&staging, &restored, &self.chunks).with_context(|| {
            format!(
                "restore failed; partial files remain at {}",
                staging.display()
            )
        })?;
        fs::rename(&staging, &destination)?;
        Ok(RestoreReport {
            snapshot: overlay.snapshot.id,
            files: overlay.snapshot.files.len(),
            bytes: overlay
                .snapshot
                .files
                .values()
                .map(|entry| entry.size)
                .sum(),
        })
    }

    pub fn garbage_collect(&self, apply: bool) -> Result<GarbageCollectionReport> {
        self.verify()
            .context("refuse to collect an invalid authority")?;
        let state = self.load_state()?;
        let mut overlays = BTreeMap::new();
        for entry in fs::read_dir(self.root.join("overlays"))? {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && entry.path().extension().and_then(|value| value.to_str()) == Some("json")
            {
                let overlay: Overlay = serde_json::from_slice(&fs::read(entry.path())?)?;
                overlays.insert(overlay.snapshot.id.clone(), overlay);
            }
        }

        let mut reachable = BTreeSet::new();
        let mut pending: Vec<_> = state
            .heads
            .values()
            .chain(state.forks.values().flatten())
            .cloned()
            .collect();
        while let Some(snapshot) = pending.pop() {
            if !reachable.insert(snapshot.clone()) {
                continue;
            }
            if let Some(parent) = overlays
                .get(&snapshot)
                .and_then(|overlay| overlay.snapshot.parent.clone())
            {
                pending.push(parent);
            }
        }

        let unreachable: Vec<_> = overlays
            .keys()
            .filter(|snapshot| !reachable.contains(*snapshot))
            .cloned()
            .collect();
        let retained_chunks: BTreeSet<_> = overlays
            .iter()
            .filter(|(snapshot, _)| reachable.contains(*snapshot))
            .flat_map(|(_, overlay)| {
                overlay
                    .snapshot
                    .files
                    .values()
                    .map(|entry| entry.chunk.clone())
            })
            .collect();
        let inventory = self.chunks.inventory()?;
        let unreferenced: Vec<_> = inventory
            .iter()
            .filter(|(hash, _)| !retained_chunks.contains(*hash))
            .map(|(hash, bytes)| (hash.clone(), *bytes))
            .collect();
        let bytes = unreferenced.iter().map(|(_, bytes)| bytes).sum();

        if apply {
            for snapshot in &unreachable {
                fs::remove_file(self.overlay_path(snapshot))?;
            }
            for (hash, _) in &unreferenced {
                self.chunks.remove(hash)?;
            }
            self.verify().context("verify authority after collection")?;
        }
        Ok(GarbageCollectionReport {
            overlays: unreachable.len(),
            chunks: unreferenced.len(),
            bytes,
            applied: apply,
        })
    }

    fn load_state(&self) -> Result<State> {
        let bytes = fs::read(self.state_path())?;
        serde_json::from_slice(&bytes).context("parse authority state")
    }

    fn save_state(&self, state: &State) -> Result<()> {
        atomic_json(&self.state_path(), state)
    }

    fn state_path(&self) -> PathBuf {
        self.root.join("state.json")
    }

    fn overlay_path(&self, id: &str) -> PathBuf {
        self.root.join("overlays").join(format!("{id}.json"))
    }
}

fn verify_overlay_shape(overlay: &Overlay) -> Result<()> {
    let symlinks: BTreeSet<_> = overlay
        .snapshot
        .files
        .iter()
        .filter(|(_, entry)| entry.kind == crate::model::FileKind::Symlink)
        .map(|(path, _)| Path::new(path))
        .collect();
    for path in overlay.snapshot.files.keys() {
        validate_snapshot_path(path)?;
        if Path::new(path)
            .ancestors()
            .skip(1)
            .any(|ancestor| symlinks.contains(ancestor))
        {
            bail!(
                "snapshot {} contains a path below a symlink: {path}",
                overlay.snapshot.id
            );
        }
    }
    for (path, entry) in &overlay.upserts {
        validate_snapshot_path(path)?;
        if overlay.snapshot.files.get(path) != Some(entry) {
            bail!("snapshot {} has invalid upsert {path}", overlay.snapshot.id);
        }
    }
    let mut deletes = BTreeSet::new();
    for path in &overlay.deletes {
        validate_snapshot_path(path)?;
        if !deletes.insert(path) {
            bail!("snapshot {} repeats delete {path}", overlay.snapshot.id);
        }
        if overlay.snapshot.files.contains_key(path) {
            bail!(
                "snapshot {} both contains and deletes {path}",
                overlay.snapshot.id
            );
        }
    }
    Ok(())
}

fn validate_snapshot_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
        || path.components().next() == Some(Component::Normal(".pando".as_ref()))
    {
        bail!("unsafe snapshot path {value:?}");
    }
    Ok(())
}

fn valid_object_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_overlay(overlay: &Overlay, chunks: &ChunkStore) -> Result<()> {
    if !valid_object_id(&overlay.snapshot.id) {
        bail!("invalid snapshot id {:?}", overlay.snapshot.id);
    }
    let actual_id = manifest_id(&overlay.snapshot)?;
    if actual_id != overlay.snapshot.id {
        bail!(
            "snapshot {} content hashes to {actual_id}",
            overlay.snapshot.id
        );
    }
    verify_overlay_shape(overlay)?;
    for entry in overlay.snapshot.files.values() {
        if !chunks.contains(&entry.chunk) {
            bail!("snapshot references missing chunk {}", entry.chunk);
        }
    }
    Ok(())
}

impl Authority for FileAuthority {
    fn acquire(
        &mut self,
        repo_id: &str,
        trunk_id: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<AcquireResult> {
        let mut state = self.load_state()?;
        if let Some(lease) = state.leases.get(repo_id)
            && lease.expires_at_ms > now_ms
            && lease.holder != trunk_id
        {
            return Ok(AcquireResult::HeldBy(lease.clone()));
        }
        let generation = match state.leases.get(repo_id) {
            Some(lease) if lease.holder == trunk_id => lease.generation,
            _ => {
                let next = state.generations.get(repo_id).copied().unwrap_or(0) + 1;
                state.generations.insert(repo_id.to_owned(), next);
                next
            }
        };
        let lease = Lease {
            repo_id: repo_id.to_owned(),
            holder: trunk_id.to_owned(),
            generation,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
        };
        state.leases.insert(repo_id.to_owned(), lease.clone());
        self.save_state(&state)?;
        Ok(AcquireResult::Acquired(lease))
    }

    fn release(&mut self, repo_id: &str, trunk_id: &str) -> Result<()> {
        let mut state = self.load_state()?;
        if state
            .leases
            .get(repo_id)
            .is_some_and(|lease| lease.holder == trunk_id)
        {
            state.leases.remove(repo_id);
            self.save_state(&state)?;
        }
        Ok(())
    }

    fn put_chunk(&mut self, hash: &str, bytes: &[u8]) -> Result<()> {
        self.chunks.put_verified(hash, bytes)
    }

    fn has_chunk(&self, hash: &str) -> Result<bool> {
        Ok(self.chunks.contains(hash))
    }

    fn get_chunk(&self, hash: &str) -> Result<Vec<u8>> {
        self.chunks.get(hash)
    }

    fn publish(&mut self, overlay: &Overlay, trunk_id: &str, now_ms: u64) -> Result<()> {
        validate_overlay(overlay, &self.chunks)?;
        let mut state = self.load_state()?;
        let lease = state
            .leases
            .get(&overlay.snapshot.repo_id)
            .context("cannot publish without a lease")?;
        if lease.holder != trunk_id || lease.expires_at_ms <= now_ms {
            bail!("write lease is not held by trunk {trunk_id}");
        }
        let current = state.heads.get(&overlay.snapshot.repo_id).cloned();
        if overlay.snapshot.parent != current {
            bail!(
                "diverged snapshot: authority head is {:?}, snapshot parent is {:?}",
                current,
                overlay.snapshot.parent
            );
        }
        atomic_json(&self.overlay_path(&overlay.snapshot.id), overlay)?;
        state.heads.insert(
            overlay.snapshot.repo_id.clone(),
            overlay.snapshot.id.clone(),
        );
        self.save_state(&state)?;
        Ok(())
    }

    fn publish_fork(&mut self, overlay: &Overlay, trunk_id: &str, now_ms: u64) -> Result<()> {
        let mut state = self.load_state()?;
        let lease = state
            .leases
            .get(&overlay.snapshot.repo_id)
            .context("cannot publish fork without a lease")?;
        if lease.holder != trunk_id || lease.expires_at_ms <= now_ms {
            bail!("write lease is not held by trunk {trunk_id}");
        }
        let parent = overlay
            .snapshot
            .parent
            .as_deref()
            .context("fork snapshot requires a parent")?;
        self.overlay(parent)?;
        validate_overlay(overlay, &self.chunks)?;
        atomic_json(&self.overlay_path(&overlay.snapshot.id), overlay)?;
        let forks = state
            .forks
            .entry(overlay.snapshot.repo_id.clone())
            .or_default();
        if !forks.contains(&overlay.snapshot.id) {
            forks.push(overlay.snapshot.id.clone());
        }
        self.save_state(&state)
    }

    fn forks(&self, repo_id: &str) -> Result<Vec<SnapshotId>> {
        Ok(self
            .load_state()?
            .forks
            .get(repo_id)
            .cloned()
            .unwrap_or_default())
    }

    fn resolve_fork(&mut self, repo_id: &str, snapshot_id: &str) -> Result<()> {
        let mut state = self.load_state()?;
        let forks = state.forks.entry(repo_id.to_owned()).or_default();
        let before = forks.len();
        forks.retain(|fork| fork != snapshot_id);
        if forks.len() == before {
            bail!("snapshot {snapshot_id} is not a pending fork for {repo_id}");
        }
        self.save_state(&state)
    }

    fn head(&self, repo_id: &str) -> Result<Option<SnapshotId>> {
        Ok(self.load_state()?.heads.get(repo_id).cloned())
    }

    fn overlay(&self, snapshot_id: &str) -> Result<Overlay> {
        if !valid_object_id(snapshot_id) {
            bail!("invalid snapshot id {snapshot_id:?}");
        }
        let bytes = fs::read(self.overlay_path(snapshot_id))
            .with_context(|| format!("read overlay {snapshot_id}"))?;
        let overlay: Overlay = serde_json::from_slice(&bytes).context("parse overlay")?;
        if overlay.snapshot.id != snapshot_id {
            bail!(
                "overlay {snapshot_id} contains snapshot {}",
                overlay.snapshot.id
            );
        }
        let actual_id = manifest_id(&overlay.snapshot)?;
        if actual_id != snapshot_id {
            bail!("snapshot {snapshot_id} content hashes to {actual_id}");
        }
        verify_overlay_shape(&overlay)?;
        Ok(overlay)
    }

    fn status(&self, repo_id: &str, now_ms: u64) -> Result<AuthorityStatus> {
        let state = self.load_state()?;
        let lease = state
            .leases
            .get(repo_id)
            .filter(|lease| lease.expires_at_ms > now_ms)
            .cloned();
        let head = state.heads.get(repo_id).cloned();
        let overlay = head.as_deref().map(|id| self.overlay(id)).transpose()?;
        Ok(AuthorityStatus {
            repo_id: repo_id.to_owned(),
            lease,
            head,
            last_snapshot_at_ms: overlay.as_ref().map(|value| value.snapshot.created_at_ms),
            exposure_bytes: overlay.as_ref().map(Overlay::bytes).unwrap_or(0),
            forks: state.forks.get(repo_id).cloned().unwrap_or_default(),
        })
    }
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.partial-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = fs::File::create(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}
