use crate::authority::{AcquireResult, Authority};
use crate::classify::{ClassificationPolicy, Classifier};
use crate::clock::Clock;
use crate::model::SnapshotId;
use crate::snapshot::{
    capture, capture_with_policy, materialization_delta, materialize_overlay, overlay_against,
};
use crate::store::ChunkStore;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
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
                return Ok(PushResult::Diverged {
                    local_head: state.head,
                    authority_head,
                });
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
            let mut uploaded = 0;
            for entry in overlay.snapshot.files.values() {
                if !authority.has_chunk(&entry.chunk)? {
                    authority.put_chunk(&entry.chunk, &self.chunks.get(&entry.chunk)?)?;
                    uploaded += 1;
                }
            }
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
        if result.is_err() || matches!(&result, Ok(PushResult::Diverged { .. })) {
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
        let mut downloaded = 0;
        for entry in delta.upserts.values() {
            if !self.chunks.contains(&entry.chunk) {
                let bytes = authority.get_chunk(&entry.chunk)?;
                self.chunks.put_verified(&entry.chunk, &bytes)?;
                downloaded += 1;
            }
        }
        materialize_overlay(&self.repo, &delta, &self.chunks)?;
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
        let path = self.state_path();
        let temporary = path.with_extension(format!("partial-{}", std::process::id()));
        let mut file = fs::File::create(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(state)?)?;
        file.sync_all()?;
        fs::rename(temporary, path)?;
        Ok(())
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
