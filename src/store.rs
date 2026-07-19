use crate::model::ChunkHash;
use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreVerification {
    pub chunks: usize,
    pub bytes: u64,
}

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

    pub(crate) fn open_existing(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        if !root.is_dir() {
            bail!("chunk store does not exist at {}", root.display());
        }
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
        if !valid_hex(hash.as_bytes(), 64) {
            bail!("invalid chunk hash {hash:?}");
        }
        let bytes = fs::read(self.path(hash)).with_context(|| format!("read chunk {hash}"))?;
        let actual = blake3::hash(&bytes).to_hex().to_string();
        if actual != hash {
            bail!("corrupt chunk {hash}: content hashes to {actual}");
        }
        Ok(bytes)
    }

    pub fn contains(&self, hash: &str) -> bool {
        valid_hex(hash.as_bytes(), 64) && self.path(hash).is_file()
    }

    pub fn verify_all(&self) -> Result<StoreVerification> {
        let mut chunks = 0;
        let mut bytes = 0;
        for entry in WalkDir::new(&self.root).min_depth(1) {
            let entry = entry?;
            let relative = entry.path().strip_prefix(&self.root)?;
            if entry.file_type().is_dir() {
                if entry.depth() != 1 || !valid_hex_component(entry.file_name(), 2) {
                    bail!(
                        "unexpected directory in chunk store: {}",
                        relative.display()
                    );
                }
                continue;
            }
            if entry.depth() == 2
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with('.') && name.contains(".partial-"))
            {
                continue;
            }
            if !entry.file_type().is_file() || entry.depth() != 2 {
                bail!("unexpected entry in chunk store: {}", relative.display());
            }
            let mut components = relative.components();
            let prefix = components
                .next()
                .and_then(|part| part.as_os_str().to_str())
                .context("invalid chunk prefix")?;
            let suffix = components
                .next()
                .and_then(|part| part.as_os_str().to_str())
                .context("invalid chunk suffix")?;
            if components.next().is_some()
                || !valid_hex(prefix.as_bytes(), 2)
                || !valid_hex(suffix.as_bytes(), 62)
            {
                bail!("unexpected chunk path: {}", relative.display());
            }
            let hash = format!("{prefix}{suffix}");
            let contents = self.get(&hash)?;
            chunks += 1;
            bytes += contents.len() as u64;
        }
        Ok(StoreVerification { chunks, bytes })
    }

    fn path(&self, hash: &str) -> PathBuf {
        let (prefix, suffix) = hash.split_at(2);
        self.root.join(prefix).join(suffix)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn valid_hex_component(value: &std::ffi::OsStr, length: usize) -> bool {
    value
        .to_str()
        .is_some_and(|value| valid_hex(value.as_bytes(), length))
}

fn valid_hex(value: &[u8], length: usize) -> bool {
    value.len() == length
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}
