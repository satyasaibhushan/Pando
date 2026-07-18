use crate::model::{Lease, Overlay, SnapshotId};
use crate::store::ChunkStore;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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

    pub fn root(&self) -> &Path {
        &self.root
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
        for entry in overlay.snapshot.files.values() {
            if !self.chunks.contains(&entry.chunk) {
                bail!("snapshot references missing chunk {}", entry.chunk);
            }
        }
        atomic_json(&self.overlay_path(&overlay.snapshot.id), overlay)?;
        state.heads.insert(
            overlay.snapshot.repo_id.clone(),
            overlay.snapshot.id.clone(),
        );
        self.save_state(&state)?;
        Ok(())
    }

    fn head(&self, repo_id: &str) -> Result<Option<SnapshotId>> {
        Ok(self.load_state()?.heads.get(repo_id).cloned())
    }

    fn overlay(&self, snapshot_id: &str) -> Result<Overlay> {
        let bytes = fs::read(self.overlay_path(snapshot_id))
            .with_context(|| format!("read overlay {snapshot_id}"))?;
        serde_json::from_slice(&bytes).context("parse overlay")
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
