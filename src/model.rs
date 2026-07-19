use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type ChunkHash = String;
pub type SnapshotId = String;

pub(crate) fn short_id(value: &str) -> &str {
    &value[..value.len().min(12)]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Regular,
    Symlink,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub chunk: ChunkHash,
    pub size: u64,
    pub kind: FileKind,
    pub executable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub id: SnapshotId,
    pub repo_id: String,
    pub trunk_id: String,
    pub created_at_ms: u64,
    pub parent: Option<SnapshotId>,
    pub base_commit: Option<String>,
    #[serde(default)]
    pub classification_version: u32,
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    pub files: BTreeMap<String, FileEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overlay {
    pub snapshot: Manifest,
    pub upserts: BTreeMap<String, FileEntry>,
    pub deletes: Vec<String>,
}

impl Overlay {
    pub fn bytes(&self) -> u64 {
        self.upserts.values().map(|entry| entry.size).sum()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub repo_id: String,
    pub holder: String,
    pub generation: u64,
    pub expires_at_ms: u64,
}
