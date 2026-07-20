use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Atomically replace `path` with `contents`. Secret files are created 0600.
pub(crate) fn atomic_write(path: &Path, contents: &[u8], secret: bool) -> Result<()> {
    let parent = path.parent().context("write target has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.partial-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

pub(crate) fn atomic_json(path: &Path, value: &impl serde::Serialize, secret: bool) -> Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(value)?, secret)
}
