use crate::model::ChunkHash;
use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct ChunkStore {
    root: PathBuf,
}

impl ChunkStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)
            .with_context(|| format!("create chunk store {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn put(&self, bytes: &[u8]) -> Result<ChunkHash> {
        let hash = blake3::hash(bytes).to_hex().to_string();
        self.put_verified(&hash, bytes)?;
        Ok(hash)
    }

    pub fn put_verified(&self, hash: &str, bytes: &[u8]) -> Result<()> {
        let actual = blake3::hash(bytes).to_hex().to_string();
        if actual != hash {
            bail!("chunk hash mismatch: expected {hash}, got {actual}");
        }
        let path = self.path(hash);
        if path.exists() {
            return Ok(());
        }
        let parent = path.parent().context("chunk path has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".{hash}.partial-{}", std::process::id()));
        let mut file = fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::rename(&temporary, &path) {
            Ok(()) => Ok(()),
            Err(_error) if path.exists() => {
                let _ = fs::remove_file(temporary);
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn get(&self, hash: &str) -> Result<Vec<u8>> {
        let bytes = fs::read(self.path(hash)).with_context(|| format!("read chunk {hash}"))?;
        let actual = blake3::hash(&bytes).to_hex().to_string();
        if actual != hash {
            bail!("corrupt chunk {hash}: content hashes to {actual}");
        }
        Ok(bytes)
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.path(hash).is_file()
    }

    fn path(&self, hash: &str) -> PathBuf {
        let (prefix, suffix) = hash.split_at(hash.len().min(2));
        self.root.join(prefix).join(suffix)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}
