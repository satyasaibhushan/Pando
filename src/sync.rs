use crate::authority::{AcquireResult, Authority};
use crate::clock::Clock;
use crate::model::SnapshotId;
use crate::snapshot::{capture, materialize_overlay, overlay_against};
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
        let state_dir = repo.join(".pando");
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
            {
                return Ok(PushResult::NoChanges {
                    snapshot: previous.snapshot.id.clone(),
                });
            }
            let mut overlay = overlay_against(&self.repo, manifest, &self.chunks)?;
            if let Some(previous) = previous {
                for (path, entry) in &overlay.snapshot.files {
                    if previous.snapshot.files.get(path) != Some(entry) {
                        overlay.upserts.insert(path.clone(), entry.clone());
                    }
                }
                for path in previous.snapshot.files.keys() {
                    if !overlay.snapshot.files.contains_key(path) && !overlay.deletes.contains(path)
                    {
                        overlay.deletes.push(path.clone());
                    }
                }
            }
            let mut uploaded = 0;
            for entry in overlay.upserts.values() {
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
        if let Some(local_head) = &state.head {
            let previous = authority.overlay(local_head)?;
            let current = capture(
                &self.repo,
                &self.repo_id,
                &self.trunk_id,
                state.head.clone(),
                clock.now_ms(),
                &self.chunks,
            )?;
            if current.files != previous.snapshot.files {
                return Ok(PullResult::Diverged {
                    local_head: state.head,
                    authority_head,
                });
            }
        } else if !self.initial_tree_is_clean(&overlay)? {
            return Ok(PullResult::Diverged {
                local_head: None,
                authority_head,
            });
        }

        let mut downloaded = 0;
        for entry in overlay.upserts.values() {
            if !self.chunks.contains(&entry.chunk) {
                let bytes = authority.get_chunk(&entry.chunk)?;
                self.chunks.put_verified(&entry.chunk, &bytes)?;
                downloaded += 1;
            }
        }
        materialize_overlay(&self.repo, &overlay, &self.chunks)?;
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
        self.repo.join(".pando/state.json")
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

    fn initial_tree_is_clean(&self, overlay: &crate::model::Overlay) -> Result<bool> {
        use std::collections::BTreeMap;
        let current = capture(
            &self.repo,
            &self.repo_id,
            &self.trunk_id,
            None,
            0,
            &self.chunks,
        )?;
        let current_files: BTreeMap<_, _> = current
            .files
            .into_iter()
            .filter(|(path, _)| !path.starts_with(".git/"))
            .collect();
        let baseline = match &overlay.snapshot.base_commit {
            Some(commit) => crate::git::baseline(&self.repo, commit, &self.chunks)?,
            None => BTreeMap::new(),
        };
        Ok(current_files == baseline)
    }
}
