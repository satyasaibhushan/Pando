use crate::git;
use crate::model::{FileEntry, FileKind, Manifest, Overlay};
use crate::store::ChunkStore;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

pub fn capture(
    repo: &Path,
    repo_id: &str,
    trunk_id: &str,
    parent: Option<String>,
    created_at_ms: u64,
    store: &ChunkStore,
) -> Result<Manifest> {
    let canonical_repo = repo
        .canonicalize()
        .with_context(|| format!("open repository {}", repo.display()))?;
    let mut files = BTreeMap::new();
    for item in WalkDir::new(&canonical_repo)
        .follow_links(false)
        .into_iter()
        .filter_entry(|item| item.depth() == 0 || item.file_name() != ".pando")
    {
        let item = item?;
        let relative = item.path().strip_prefix(&canonical_repo)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if relative.components().next() == Some(Component::Normal(".pando".as_ref())) {
            if item.file_type().is_dir() {
                continue;
            }
            continue;
        }
        if item.file_type().is_dir() {
            continue;
        }
        let path = slash_path(relative)?;
        let (bytes, kind) = if item.file_type().is_symlink() {
            let target = fs::read_link(item.path())?;
            (
                target.to_string_lossy().as_bytes().to_vec(),
                FileKind::Symlink,
            )
        } else if item.file_type().is_file() {
            (fs::read(item.path())?, FileKind::Regular)
        } else {
            continue;
        };
        let executable = is_executable(item.path())?;
        let chunk = store.put(&bytes)?;
        files.insert(
            path,
            FileEntry {
                chunk,
                size: bytes.len() as u64,
                kind,
                executable,
            },
        );
    }

    let base_commit = git::pushed_base(&canonical_repo).unwrap_or(None);
    let mut manifest = Manifest {
        id: String::new(),
        repo_id: repo_id.to_owned(),
        trunk_id: trunk_id.to_owned(),
        created_at_ms,
        parent,
        base_commit,
        files,
    };
    manifest.id = manifest_id(&manifest)?;
    Ok(manifest)
}

pub fn overlay_against(repo: &Path, manifest: Manifest, store: &ChunkStore) -> Result<Overlay> {
    let baseline = match &manifest.base_commit {
        Some(commit) => git::baseline(repo, commit, store)?,
        None => BTreeMap::new(),
    };
    let upserts = manifest
        .files
        .iter()
        .filter(|(path, entry)| path.starts_with(".git/") || baseline.get(*path) != Some(*entry))
        .map(|(path, entry)| (path.clone(), entry.clone()))
        .collect();
    let deletes = baseline
        .keys()
        .filter(|path| !manifest.files.contains_key(*path))
        .cloned()
        .collect();
    Ok(Overlay {
        snapshot: manifest,
        upserts,
        deletes,
    })
}

pub fn materialize_overlay(repo: &Path, overlay: &Overlay, store: &ChunkStore) -> Result<()> {
    fs::create_dir_all(repo)?;
    for path in &overlay.deletes {
        remove_path(&safe_join(repo, path)?)?;
    }
    for (path, entry) in &overlay.upserts {
        let destination = safe_join(repo, path)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        remove_path(&destination)?;
        let bytes = store.get(&entry.chunk)?;
        match entry.kind {
            FileKind::Regular => {
                fs::write(&destination, bytes)?;
                set_executable(&destination, entry.executable)?;
            }
            FileKind::Symlink => create_symlink(&destination, &bytes)?,
        }
    }

    let expected: BTreeSet<_> = overlay.snapshot.files.keys().cloned().collect();
    let mut existing = Vec::new();
    for item in WalkDir::new(repo)
        .min_depth(1)
        .contents_first(true)
        .follow_links(false)
        .into_iter()
        .filter_entry(|item| item.file_name() != ".pando")
    {
        let item = item?;
        let relative = item.path().strip_prefix(repo)?;
        if relative.components().next() == Some(Component::Normal(".pando".as_ref())) {
            continue;
        }
        if !item.file_type().is_dir() {
            existing.push((slash_path(relative)?, item.path().to_owned()));
        }
    }
    for (relative, path) in existing {
        if !expected.contains(&relative) {
            remove_path(&path)?;
        }
    }
    Ok(())
}

pub fn manifest_id(manifest: &Manifest) -> Result<String> {
    let mut canonical = manifest.clone();
    canonical.id.clear();
    Ok(blake3::hash(&serde_json::to_vec(&canonical)?)
        .to_hex()
        .to_string())
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("unsafe snapshot path {relative:?}");
    }
    Ok(root.join(path))
}

fn slash_path(path: &Path) -> Result<String> {
    let pieces: Result<Vec<_>, _> = path
        .components()
        .map(|part| match part {
            Component::Normal(value) => value.to_str().context("path is not valid UTF-8"),
            _ => bail!("unexpected path component"),
        })
        .collect();
    Ok(pieces?.join("/"))
}

fn remove_path(path: &Path) -> Result<()> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn is_executable(path: &Path) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::symlink_metadata(path)?.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> Result<bool> {
    Ok(false)
}

#[cfg(unix)]
fn set_executable(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    let mode = permissions.mode();
    permissions.set_mode(if executable {
        mode | 0o111
    } else {
        mode & !0o111
    });
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path, _executable: bool) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn create_symlink(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::symlink;
    let target = std::str::from_utf8(bytes)?;
    symlink(target, path)?;
    Ok(())
}

#[cfg(windows)]
fn create_symlink(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::windows::fs::symlink_file;
    let target = std::str::from_utf8(bytes)?;
    symlink_file(target, path)?;
    Ok(())
}
