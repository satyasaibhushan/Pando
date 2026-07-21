use crate::authority::{AcquireResult, Authority, TRANSFER_BUDGET_BYTES};
use crate::classify::{ClassificationPolicy, Classifier};
use crate::clock::Clock;
use crate::model::SnapshotId;
use crate::snapshot::{
    capture, capture_with_policy, manifest_id, materialization_delta, materialize_overlay,
    overlay_against,
};
use crate::store::ChunkStore;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_LEASE_TTL_MS: u64 = 30_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushResult {
    Published {
        snapshot: SnapshotId,
        chunks_uploaded: usize,
        exposure_bytes: u64,
    },
    NoChanges {
        snapshot: SnapshotId,
    },
    LeaseHeld {
        holder: String,
        expires_at_ms: u64,
    },
    Diverged {
        local_head: Option<SnapshotId>,
        authority_head: Option<SnapshotId>,
    },
    Conflicted {
        local_head: SnapshotId,
        authority_head: SnapshotId,
        fork: SnapshotId,
        paths: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PullResult {
    Applied {
        snapshot: SnapshotId,
        chunks_downloaded: usize,
    },
    NoSnapshots,
    UpToDate {
        snapshot: SnapshotId,
    },
    Diverged {
        local_head: Option<SnapshotId>,
        authority_head: SnapshotId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileChoice {
    Authority,
    Fork,
    Manual,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileResult {
    pub resolved_fork: SnapshotId,
    pub head: SnapshotId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkConflict {
    pub path: String,
    pub authority_path: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Trunk {
    repo: PathBuf,
    repo_id: String,
    trunk_id: String,
    chunks: ChunkStore,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct LocalState {
    head: Option<SnapshotId>,
}

impl Trunk {
    pub fn open(
        repo: impl Into<PathBuf>,
        repo_id: impl Into<String>,
        trunk_id: impl Into<String>,
    ) -> Result<Self> {
        let repo = repo.into();
        fs::create_dir_all(&repo)?;
        let repo = repo.canonicalize()?;
        let repo_id = repo_id.into();
        let trunk_id = trunk_id.into();
        let identity = format!("{}\0{}\0{}", repo_id, trunk_id, repo.display());
        let key = blake3::hash(identity.as_bytes()).to_hex().to_string();
        let state_dir = default_data_root()?.join("trunks").join(key);
        Self::open_with_state(repo, repo_id, trunk_id, state_dir)
    }

    pub fn open_with_state(
        repo: impl Into<PathBuf>,
        repo_id: impl Into<String>,
        trunk_id: impl Into<String>,
        state_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        let repo = repo.into();
        fs::create_dir_all(&repo)?;
        let state_dir = state_dir.into();
        fs::create_dir_all(&state_dir)?;
        let chunks = ChunkStore::new(state_dir.join("chunks"))?;
        let trunk = Self {
            repo,
            repo_id: repo_id.into(),
            trunk_id: trunk_id.into(),
            chunks,
        };
        if !trunk.state_path().exists() {
            trunk.save_state(&LocalState::default())?;
        }
        Ok(trunk)
    }

    pub fn push<A: Authority + ?Sized, C: Clock>(
        &self,
        authority: &mut A,
        clock: &C,
    ) -> Result<PushResult> {
        let now_ms = clock.now_ms();
        match authority.acquire(&self.repo_id, &self.trunk_id, now_ms, DEFAULT_LEASE_TTL_MS)? {
            AcquireResult::HeldBy(lease) => {
                return Ok(PushResult::LeaseHeld {
                    holder: lease.holder,
                    expires_at_ms: lease.expires_at_ms,
                });
            }
            AcquireResult::Acquired(_) => {}
        }

        let result = (|| -> Result<PushResult> {
            let mut state = self.load_state()?;
            let authority_head = authority.head(&self.repo_id)?;
            if authority_head != state.head {
                let Some(authority_head) = authority_head else {
                    return Ok(PushResult::Diverged {
                        local_head: state.head,
                        authority_head: None,
                    });
                };
                // On first contact there is no base: merge against an empty
                // tree using the authority's classification policy. Otherwise
                // merge against our last-seen head using its policy.
                let base = state
                    .head
                    .as_deref()
                    .map(|head| authority.overlay(head))
                    .transpose()?;
                let remote = authority.overlay(&authority_head)?;
                let policy = base.as_ref().unwrap_or(&remote);
                let local = capture_with_policy(
                    &self.repo,
                    &self.repo_id,
                    &self.trunk_id,
                    Some(state.head.clone().unwrap_or_else(|| authority_head.clone())),
                    now_ms,
                    &self.chunks,
                    ClassificationPolicy {
                        version: policy.snapshot.classification_version,
                        patterns: policy.snapshot.ignore_patterns.clone(),
                    },
                )?;
                let empty = BTreeMap::new();
                let base_files = base
                    .as_ref()
                    .map(|base| &base.snapshot.files)
                    .unwrap_or(&empty);
                let (merged, conflicts) =
                    three_way_files(base_files, &local.files, &remote.snapshot.files);
                if !conflicts.is_empty() {
                    let fork_overlay = overlay_against(&self.repo, local, &self.chunks)?;
                    self.upload_missing_chunks(authority, &fork_overlay)?;
                    let fork = fork_overlay.snapshot.id.clone();
                    authority.publish_fork(&fork_overlay, &self.trunk_id, now_ms)?;
                    return Ok(PushResult::Conflicted {
                        local_head: state.head.unwrap_or_else(|| fork.clone()),
                        authority_head,
                        fork,
                        paths: conflicts,
                    });
                }
                let mut target = remote;
                target.snapshot.files = merged;
                let delta = materialization_delta(&self.repo, &target, &local.files)?;
                self.ensure_materialization_chunks(authority, &target, &delta)?;
                materialize_overlay(&self.repo, &delta, &self.chunks)?;
                self.ensure_git_history(&target)?;
                state.head = Some(authority_head);
                self.save_state(&state)?;
            }
            let manifest = capture(
                &self.repo,
                &self.repo_id,
                &self.trunk_id,
                state.head.clone(),
                now_ms,
                &self.chunks,
            )?;
            let previous = state
                .head
                .as_deref()
                .map(|head| authority.overlay(head))
                .transpose()?;
            if let Some(previous) = &previous
                && previous.snapshot.files == manifest.files
                && previous.snapshot.base_commit == manifest.base_commit
                && previous.snapshot.classification_version == manifest.classification_version
                && previous.snapshot.ignore_patterns == manifest.ignore_patterns
            {
                return Ok(PushResult::NoChanges {
                    snapshot: previous.snapshot.id.clone(),
                });
            }
            let overlay = overlay_against(&self.repo, manifest, &self.chunks)?;
            let uploaded = self.upload_missing_chunks(authority, &overlay)?;
            authority.publish(&overlay, &self.trunk_id, now_ms)?;
            let snapshot = overlay.snapshot.id.clone();
            let exposure_bytes = overlay.bytes();
            state.head = Some(snapshot.clone());
            self.save_state(&state)?;
            Ok(PushResult::Published {
                snapshot,
                chunks_uploaded: uploaded,
                exposure_bytes,
            })
        })();
        if result.is_err()
            || matches!(
                &result,
                Ok(PushResult::Diverged { .. } | PushResult::Conflicted { .. })
            )
        {
            let _ = authority.release(&self.repo_id, &self.trunk_id);
        }
        result
    }

    pub fn pull<A: Authority + ?Sized, C: Clock>(
        &self,
        authority: &A,
        clock: &C,
    ) -> Result<PullResult> {
        let mut state = self.load_state()?;
        let Some(authority_head) = authority.head(&self.repo_id)? else {
            return Ok(PullResult::NoSnapshots);
        };
        if state.head.as_ref() == Some(&authority_head) {
            return Ok(PullResult::UpToDate {
                snapshot: authority_head,
            });
        }
        let overlay = authority.overlay(&authority_head)?;
        let previous = state
            .head
            .as_deref()
            .map(|head| authority.overlay(head))
            .transpose()?;
        let current_policy = previous
            .as_ref()
            .map(|overlay| {
                (
                    overlay.snapshot.classification_version,
                    overlay.snapshot.ignore_patterns.clone(),
                )
            })
            .unwrap_or_else(|| {
                (
                    overlay.snapshot.classification_version,
                    overlay.snapshot.ignore_patterns.clone(),
                )
            });
        let current = capture_with_policy(
            &self.repo,
            &self.repo_id,
            &self.trunk_id,
            state.head.clone(),
            clock.now_ms(),
            &self.chunks,
            ClassificationPolicy {
                version: current_policy.0,
                patterns: current_policy.1,
            },
        )?;
        if let Some(previous) = previous {
            if current.files != previous.snapshot.files {
                return Ok(PullResult::Diverged {
                    local_head: state.head,
                    authority_head,
                });
            }
        } else {
            if current.files == overlay.snapshot.files {
                state.head = Some(authority_head.clone());
                self.save_state(&state)?;
                return Ok(PullResult::UpToDate {
                    snapshot: authority_head,
                });
            }
            if !self.initial_tree_is_clean(&overlay, &current.files)? {
                return Ok(PullResult::Diverged {
                    local_head: None,
                    authority_head,
                });
            }
        }

        let delta = materialization_delta(&self.repo, &overlay, &current.files)?;
        let downloaded = self.ensure_materialization_chunks(authority, &overlay, &delta)?;
        materialize_overlay(&self.repo, &delta, &self.chunks)?;
        self.ensure_git_history(&overlay)?;
        state.head = Some(authority_head.clone());
        self.save_state(&state)?;
        Ok(PullResult::Applied {
            snapshot: authority_head,
            chunks_downloaded: downloaded,
        })
    }

    pub fn release<A: Authority + ?Sized>(&self, authority: &mut A) -> Result<()> {
        authority.release(&self.repo_id, &self.trunk_id)
    }

    pub fn reconcile<A: Authority + ?Sized, C: Clock>(
        &self,
        authority: &mut A,
        clock: &C,
        fork_id: &str,
        choice: ReconcileChoice,
    ) -> Result<ReconcileResult> {
        if !authority
            .forks(&self.repo_id)?
            .iter()
            .any(|fork| fork == fork_id)
        {
            anyhow::bail!(
                "snapshot {fork_id} is not a pending fork for {}",
                self.repo_id
            );
        }
        let fork = authority.overlay(fork_id)?;
        let authority_head = authority
            .head(&self.repo_id)?
            .context("authority has no active head")?;
        let mut state = self.load_state()?;
        let current = capture_with_policy(
            &self.repo,
            &self.repo_id,
            &self.trunk_id,
            state.head.clone(),
            clock.now_ms(),
            &self.chunks,
            ClassificationPolicy {
                version: fork.snapshot.classification_version,
                patterns: fork.snapshot.ignore_patterns.clone(),
            },
        )?;
        if choice != ReconcileChoice::Manual && current.files != fork.snapshot.files {
            anyhow::bail!(
                "working tree changed after fork {}; use manual resolution to publish it",
                fork_id
            );
        }

        if choice == ReconcileChoice::Authority {
            let target = authority.overlay(&authority_head)?;
            self.materialize_from_authority(authority, &target, &current.files)?;
            state.head = Some(authority_head.clone());
            self.save_state(&state)?;
            authority.resolve_fork(&self.repo_id, fork_id)?;
            return Ok(ReconcileResult {
                resolved_fork: fork_id.into(),
                head: authority_head,
            });
        }

        match authority.acquire(
            &self.repo_id,
            &self.trunk_id,
            clock.now_ms(),
            DEFAULT_LEASE_TTL_MS,
        )? {
            AcquireResult::HeldBy(lease) => {
                anyhow::bail!("write lease is held by {}", lease.holder)
            }
            AcquireResult::Acquired(_) => {}
        }
        let result = (|| -> Result<ReconcileResult> {
            if authority.head(&self.repo_id)?.as_deref() != Some(&authority_head) {
                anyhow::bail!("authority head changed during reconciliation");
            }
            let mut manifest = if choice == ReconcileChoice::Fork {
                fork.snapshot.clone()
            } else {
                current.clone()
            };
            manifest.id.clear();
            manifest.trunk_id = self.trunk_id.clone();
            manifest.created_at_ms = clock.now_ms();
            manifest.parent = Some(authority_head);
            manifest.id = manifest_id(&manifest)?;
            let overlay = overlay_against(&self.repo, manifest, &self.chunks)?;
            for entry in overlay.upserts.values() {
                if !authority.has_chunk(&entry.chunk)? {
                    authority.put_chunk(&entry.chunk, &self.chunks.get(&entry.chunk)?)?;
                }
            }
            authority.publish(&overlay, &self.trunk_id, clock.now_ms())?;
            if choice == ReconcileChoice::Fork {
                self.materialize_from_authority(authority, &overlay, &current.files)?;
            }
            state.head = Some(overlay.snapshot.id.clone());
            self.save_state(&state)?;
            authority.resolve_fork(&self.repo_id, fork_id)?;
            Ok(ReconcileResult {
                resolved_fork: fork_id.into(),
                head: overlay.snapshot.id,
            })
        })();
        let _ = authority.release(&self.repo_id, &self.trunk_id);
        result
    }

    pub fn fork_conflicts<A: Authority + ?Sized>(
        &self,
        authority: &A,
        fork_id: &str,
    ) -> Result<Vec<ForkConflict>> {
        let fork = authority.overlay(fork_id)?;
        let head = authority
            .head(&self.repo_id)?
            .context("authority has no active head")?;
        let current = authority.overlay(&head)?;
        let base = self
            .load_state()?
            .head
            .map(|head| {
                authority
                    .overlay(&head)
                    .map(|overlay| overlay.snapshot.files)
            })
            .transpose()?
            .unwrap_or_default();
        let (_, conflicts) = three_way_files(&base, &fork.snapshot.files, &current.snapshot.files);
        Ok(conflicts
            .into_iter()
            .map(|path| ForkConflict {
                path,
                authority_path: None,
            })
            .collect())
    }

    pub fn reconcile_keep_both<A: Authority + ?Sized, C: Clock>(
        &self,
        authority: &mut A,
        clock: &C,
        fork_id: &str,
    ) -> Result<ReconcileResult> {
        if !authority
            .forks(&self.repo_id)?
            .iter()
            .any(|fork| fork == fork_id)
        {
            anyhow::bail!(
                "snapshot {fork_id} is not a pending fork for {}",
                self.repo_id
            );
        }
        let fork = authority.overlay(fork_id)?;
        let head = authority
            .head(&self.repo_id)?
            .context("authority has no active head")?;
        let current_head = authority.overlay(&head)?;
        let current = capture_with_policy(
            &self.repo,
            &self.repo_id,
            &self.trunk_id,
            self.load_state()?.head,
            clock.now_ms(),
            &self.chunks,
            ClassificationPolicy {
                version: fork.snapshot.classification_version,
                patterns: fork.snapshot.ignore_patterns.clone(),
            },
        )?;
        if current.files != fork.snapshot.files {
            anyhow::bail!(
                "working tree changed after fork {}; resolve it manually instead",
                fork_id
            );
        }

        let base = self
            .load_state()?
            .head
            .map(|head| {
                authority
                    .overlay(&head)
                    .map(|overlay| overlay.snapshot.files)
            })
            .transpose()?
            .unwrap_or_default();
        let (files, conflicts) =
            three_way_files(&base, &fork.snapshot.files, &current_head.snapshot.files);
        let mut merged = fork.snapshot.clone();
        merged.files = files;
        for path in conflicts {
            if let Some(entry) = fork.snapshot.files.get(&path) {
                merged.files.insert(path.clone(), entry.clone());
            }
            if let Some(entry) = current_head.snapshot.files.get(&path) {
                let copy = conflict_copy_path(&path, &merged.files);
                merged.files.insert(copy, entry.clone());
            }
        }
        merged.id.clear();
        merged.parent = Some(head);
        merged.created_at_ms = clock.now_ms();
        let target = crate::model::Overlay {
            snapshot: merged,
            upserts: current_head.snapshot.files,
            deletes: Vec::new(),
        };
        self.materialize_from_authority(authority, &target, &current.files)?;
        self.reconcile(authority, clock, fork_id, ReconcileChoice::Manual)
    }

    pub fn local_head(&self) -> Result<Option<SnapshotId>> {
        Ok(self.load_state()?.head)
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }
    pub fn trunk_id(&self) -> &str {
        &self.trunk_id
    }

    fn state_path(&self) -> PathBuf {
        self.chunks
            .root()
            .parent()
            .unwrap_or_else(|| self.chunks.root())
            .join("state.json")
    }

    fn load_state(&self) -> Result<LocalState> {
        let bytes = fs::read(self.state_path())?;
        serde_json::from_slice(&bytes).context("parse local Pando state")
    }

    fn save_state(&self, state: &LocalState) -> Result<()> {
        crate::fsutil::atomic_json(&self.state_path(), state, false)
    }

    fn initial_tree_is_clean(
        &self,
        overlay: &crate::model::Overlay,
        current_files: &std::collections::BTreeMap<String, crate::model::FileEntry>,
    ) -> Result<bool> {
        use std::collections::BTreeMap;
        let current_files: BTreeMap<_, _> = current_files
            .iter()
            .filter(|(path, _)| !path.starts_with(".git/"))
            .map(|(path, entry)| (path.clone(), entry.clone()))
            .collect();
        if current_files.is_empty() {
            return Ok(true);
        }
        let classifier = Classifier::from_policy(
            &self.repo,
            overlay.snapshot.classification_version,
            overlay.snapshot.ignore_patterns.clone(),
        )?;
        let mut baseline = match &overlay.snapshot.base_commit {
            Some(commit) => crate::git::baseline(&self.repo, commit, &self.chunks)?,
            None => BTreeMap::new(),
        };
        baseline.retain(|path, _| classifier.is_portable(Path::new(path), false));
        Ok(current_files == baseline)
    }

    fn materialize_from_authority<A: Authority + ?Sized>(
        &self,
        authority: &A,
        target: &crate::model::Overlay,
        current: &BTreeMap<String, crate::model::FileEntry>,
    ) -> Result<()> {
        let delta = materialization_delta(&self.repo, target, current)?;
        self.ensure_materialization_chunks(authority, target, &delta)?;
        materialize_overlay(&self.repo, &delta, &self.chunks)?;
        self.ensure_git_history(target)
    }

    /// Snapshots ship git history as a thin local-only pack; after
    /// materializing one, the remote-reachable objects must be fetched into
    /// the repository so its refs resolve.
    fn ensure_git_history(&self, target: &crate::model::Overlay) -> Result<()> {
        if let Some(commit) = target.snapshot.base_commit.as_deref()
            && crate::git::is_repository_root(&self.repo)
        {
            crate::git::ensure_commit(&self.repo, commit)?;
        }
        Ok(())
    }

    fn ensure_materialization_chunks<A: Authority + ?Sized>(
        &self,
        authority: &A,
        target: &crate::model::Overlay,
        delta: &crate::model::Overlay,
    ) -> Result<usize> {
        let mut downloaded = 0;
        if delta
            .upserts
            .values()
            .any(|entry| !self.chunks.contains(&entry.chunk))
            && target.snapshot.base_commit.is_some()
        {
            let baseline: Vec<String> = target
                .upserts
                .iter()
                .filter(|(path, entry)| {
                    (*path == ".git" || path.starts_with(".git/"))
                        && !self.chunks.contains(&entry.chunk)
                })
                .map(|(_, entry)| entry.chunk.clone())
                .collect();
            downloaded += self.download_chunks(authority, baseline)?;
            self.reconstruct_git_baseline(target)?;
        }
        let missing: Vec<String> = delta
            .upserts
            .values()
            .filter(|entry| !self.chunks.contains(&entry.chunk))
            .map(|entry| entry.chunk.clone())
            .collect();
        downloaded += self.download_chunks(authority, missing)?;
        Ok(downloaded)
    }

    fn download_chunks<A: Authority + ?Sized>(
        &self,
        authority: &A,
        mut hashes: Vec<String>,
    ) -> Result<usize> {
        hashes.sort();
        hashes.dedup();
        let mut downloaded = 0;
        authority.get_chunks(&hashes, &mut |hash, bytes| {
            self.chunks.put_verified(hash, &bytes)?;
            downloaded += 1;
            Ok(())
        })?;
        Ok(downloaded)
    }

    /// Upload the overlay's chunks the authority doesn't already have, in
    /// batched round trips. Returns how many chunks were sent.
    fn upload_missing_chunks<A: Authority + ?Sized>(
        &self,
        authority: &mut A,
        overlay: &crate::model::Overlay,
    ) -> Result<usize> {
        let mut hashes: Vec<String> = overlay
            .upserts
            .values()
            .map(|entry| entry.chunk.clone())
            .collect();
        hashes.sort();
        hashes.dedup();
        let missing = authority.missing_chunks(&hashes)?;
        let uploaded = missing.len();
        let mut batch = Vec::new();
        let mut batch_bytes = 0;
        for hash in missing {
            let bytes = self.chunks.get(&hash)?;
            if batch_bytes + bytes.len() > TRANSFER_BUDGET_BYTES && !batch.is_empty() {
                authority.put_chunks(std::mem::take(&mut batch))?;
                batch_bytes = 0;
            }
            batch_bytes += bytes.len();
            batch.push((hash, bytes));
        }
        if !batch.is_empty() {
            authority.put_chunks(batch)?;
        }
        Ok(uploaded)
    }

    fn reconstruct_git_baseline(&self, target: &crate::model::Overlay) -> Result<()> {
        let Some(commit) = target.snapshot.base_commit.as_deref() else {
            return Ok(());
        };
        let temporary = std::env::temp_dir().join(format!(
            "pando-baseline-{}-{}",
            std::process::id(),
            crate::model::short_id(&target.snapshot.id)
        ));
        if temporary.exists() {
            anyhow::bail!(
                "temporary baseline path already exists: {}",
                temporary.display()
            );
        }
        let result = (|| {
            let repo = temporary.join("repo");
            let git_upserts = target
                .upserts
                .iter()
                .filter(|(path, _)| *path == ".git" || path.starts_with(".git/"))
                .map(|(path, entry)| (path.clone(), entry.clone()))
                .collect();
            let git_overlay = crate::model::Overlay {
                snapshot: target.snapshot.clone(),
                upserts: git_upserts,
                deletes: Vec::new(),
            };
            materialize_overlay(&repo, &git_overlay, &self.chunks)?;
            // The thin pack omits remote-reachable objects on purpose; the
            // real repository next door already has them.
            crate::git::borrow_objects(&repo, &self.repo)?;
            crate::git::baseline(&repo, commit, &self.chunks)?;
            Result::<()>::Ok(())
        })();
        let _ = fs::remove_dir_all(&temporary);
        result
    }
}

fn conflict_copy_path(path: &str, files: &BTreeMap<String, crate::model::FileEntry>) -> String {
    let source = Path::new(path);
    let parent = source.parent().filter(|path| !path.as_os_str().is_empty());
    let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let mut number = 1;
    loop {
        let suffix = if number == 1 {
            ".pando-other".to_owned()
        } else {
            format!(".pando-other-{number}")
        };
        let candidate = parent
            .map(|parent| parent.join(format!("{name}{suffix}")))
            .unwrap_or_else(|| PathBuf::from(format!("{name}{suffix}")))
            .to_string_lossy()
            .replace('\\', "/");
        if !files.contains_key(&candidate) {
            return candidate;
        }
        number += 1;
    }
}

fn three_way_files(
    base: &BTreeMap<String, crate::model::FileEntry>,
    local: &BTreeMap<String, crate::model::FileEntry>,
    remote: &BTreeMap<String, crate::model::FileEntry>,
) -> (BTreeMap<String, crate::model::FileEntry>, Vec<String>) {
    let paths: BTreeSet<_> = base
        .keys()
        .chain(local.keys())
        .chain(remote.keys())
        .collect();
    let mut merged = BTreeMap::new();
    let mut conflicts = Vec::new();
    for path in paths {
        let base_entry = base.get(path);
        let local_entry = local.get(path);
        let remote_entry = remote.get(path);
        let selected = if local_entry == remote_entry {
            local_entry
        } else if local_entry == base_entry {
            remote_entry
        } else if remote_entry == base_entry {
            local_entry
        } else {
            conflicts.push(path.clone());
            continue;
        };
        if let Some(entry) = selected {
            merged.insert(path.clone(), entry.clone());
        }
    }
    (merged, conflicts)
}

pub(crate) fn default_data_root() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("PANDO_DATA_HOME") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    #[cfg(target_os = "macos")]
    return Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("Pando"));
    #[cfg(not(target_os = "macos"))]
    {
        if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
            Ok(PathBuf::from(path).join("pando"))
        } else {
            Ok(PathBuf::from(home).join(".local/share/pando"))
        }
    }
}
