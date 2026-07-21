use crate::classify::{ClassificationPolicy, Classifier};
use crate::git;
use crate::model::{FileEntry, FileKind, Manifest, Overlay};
use crate::store::ChunkStore;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::BTreeMap;
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
    previous: Option<&Manifest>,
) -> Result<Manifest> {
    let canonical_repo = repo
        .canonicalize()
        .with_context(|| format!("open repository {}", repo.display()))?;
    let classifier = Classifier::load(&canonical_repo)?;
    capture_with_classifier(
        &canonical_repo,
        repo_id,
        trunk_id,
        parent,
        created_at_ms,
        store,
        classifier,
        previous,
    )
}

pub(crate) fn capture_with_policy(
    repo: &Path,
    repo_id: &str,
    trunk_id: &str,
    parent: Option<String>,
    created_at_ms: u64,
    store: &ChunkStore,
    policy: ClassificationPolicy,
    previous: Option<&Manifest>,
) -> Result<Manifest> {
    let canonical_repo = repo
        .canonicalize()
        .with_context(|| format!("open repository {}", repo.display()))?;
    let classifier = Classifier::from_policy(&canonical_repo, policy.version, policy.patterns)?;
    capture_with_classifier(
        &canonical_repo,
        repo_id,
        trunk_id,
        parent,
        created_at_ms,
        store,
        classifier,
        previous,
    )
}

fn capture_with_classifier(
    canonical_repo: &Path,
    repo_id: &str,
    trunk_id: &str,
    parent: Option<String>,
    created_at_ms: u64,
    store: &ChunkStore,
    classifier: Classifier,
    previous: Option<&Manifest>,
) -> Result<Manifest> {
    // Git repositories travel with a thin object pack instead of the whole
    // object database: remote-reachable history stays behind, and receivers
    // fetch it from the repository's own remotes only when an operation
    // actually needs it.
    let git_root = git::is_repository_root(canonical_repo);
    let mut files = BTreeMap::new();
    for item in WalkDir::new(canonical_repo)
        .follow_links(false)
        .into_iter()
        .filter_entry(|item| {
            item.depth() == 0
                || item
                    .path()
                    .strip_prefix(canonical_repo)
                    .is_ok_and(|relative| {
                        !(git_root && relative.starts_with(".git/objects"))
                            && classifier.is_portable(relative, item.file_type().is_dir())
                    })
        })
    {
        let item = item?;
        let relative = item.path().strip_prefix(canonical_repo)?;
        if relative.as_os_str().is_empty() {
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

    let base_commit = if git_root {
        match previous.filter(|previous| git_inputs(&previous.files) == git_inputs(&files)) {
            Some(previous) => {
                files.extend(
                    previous
                        .files
                        .iter()
                        .filter(|(path, _)| path.starts_with(".git/objects/"))
                        .map(|(path, entry)| (path.clone(), entry.clone())),
                );
                previous.base_commit.clone()
            }
            None => {
                files.extend(git::local_pack_entries(canonical_repo, store)?);
                git::pushed_base(canonical_repo).unwrap_or(None)
            }
        }
    } else {
        None
    };
    let mut manifest = Manifest {
        id: String::new(),
        repo_id: repo_id.to_owned(),
        trunk_id: trunk_id.to_owned(),
        created_at_ms,
        parent,
        base_commit,
        classification_version: classifier.version(),
        ignore_patterns: classifier.patterns().to_vec(),
        files,
    };
    manifest.id = manifest_id(&manifest)?;
    Ok(manifest)
}

/// The thin pack and the pushed base are pure functions of the repository's
/// portable git state: every packed object is reachable from a ref, reflog
/// entry, or the index, and all of those live in portable `.git` files. When
/// none of them changed since the previous snapshot, its pack entries still
/// hold — sparing both the repack and the need to have remote-reachable
/// history present locally at all.
fn git_inputs(files: &BTreeMap<String, FileEntry>) -> BTreeMap<&String, &FileEntry> {
    files
        .iter()
        .filter(|(path, _)| path.starts_with(".git/") && !path.starts_with(".git/objects/"))
        .collect()
}

pub fn overlay_against(repo: &Path, manifest: Manifest, store: &ChunkStore) -> Result<Overlay> {
    let classifier = Classifier::from_policy(
        repo,
        manifest.classification_version,
        manifest.ignore_patterns.clone(),
    )?;
    let mut baseline = match &manifest.base_commit {
        Some(commit) => git::baseline(repo, commit, store)?,
        None => BTreeMap::new(),
    };
    baseline.retain(|path, _| classifier.is_portable(Path::new(path), false));
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

pub fn materialization_delta(
    repo: &Path,
    target: &Overlay,
    current: &BTreeMap<String, FileEntry>,
) -> Result<Overlay> {
    let classifier = Classifier::from_policy(
        repo,
        target.snapshot.classification_version,
        target.snapshot.ignore_patterns.clone(),
    )?;
    let upserts = target
        .snapshot
        .files
        .iter()
        .filter(|(path, entry)| current.get(*path) != Some(*entry))
        .map(|(path, entry)| (path.clone(), entry.clone()))
        .collect();
    let deletes = current
        .keys()
        .filter(|path| {
            !target.snapshot.files.contains_key(*path)
                && classifier.is_portable(Path::new(path.as_str()), false)
        })
        .cloned()
        .collect();
    Ok(Overlay {
        snapshot: target.snapshot.clone(),
        upserts,
        deletes,
    })
}

pub fn materialize_overlay(repo: &Path, overlay: &Overlay, store: &ChunkStore) -> Result<()> {
    validate_case_collisions(&overlay.snapshot.files)?;
    fs::create_dir_all(repo)?;
    for path in &overlay.deletes {
        let destination = checked_destination(repo, path)?;
        remove_path(&destination)?;
    }
    for (path, entry) in &overlay.upserts {
        let destination = checked_destination(repo, path)?;
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
    Ok(())
}

fn validate_case_collisions(files: &BTreeMap<String, FileEntry>) -> Result<()> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let mut folded = BTreeMap::<String, &str>::new();
        for path in files.keys() {
            let key = path.to_lowercase();
            if let Some(previous) = folded.insert(key, path)
                && previous != path
            {
                bail!(
                    "snapshot paths {previous:?} and {path:?} collide on this case-insensitive platform"
                );
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let _ = files;
    Ok(())
}

pub fn manifest_id(manifest: &Manifest) -> Result<String> {
    if manifest.classification_version == 0 && manifest.ignore_patterns.is_empty() {
        #[derive(Serialize)]
        struct LegacyManifest<'a> {
            id: &'static str,
            repo_id: &'a str,
            trunk_id: &'a str,
            created_at_ms: u64,
            parent: &'a Option<String>,
            base_commit: &'a Option<String>,
            files: &'a BTreeMap<String, FileEntry>,
        }
        let canonical = LegacyManifest {
            id: "",
            repo_id: &manifest.repo_id,
            trunk_id: &manifest.trunk_id,
            created_at_ms: manifest.created_at_ms,
            parent: &manifest.parent,
            base_commit: &manifest.base_commit,
            files: &manifest.files,
        };
        return Ok(blake3::hash(&serde_json::to_vec(&canonical)?)
            .to_hex()
            .to_string());
    }
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

fn checked_destination(root: &Path, relative: &str) -> Result<PathBuf> {
    let destination = safe_join(root, relative)?;
    let relative_path = Path::new(relative);
    let mut ancestor = root.to_owned();
    if let Some(parent) = relative_path.parent() {
        for component in parent.components() {
            if let Component::Normal(part) = component {
                ancestor.push(part);
                match fs::symlink_metadata(&ancestor) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        bail!(
                            "snapshot path {relative:?} traverses symlink {}",
                            ancestor.display()
                        );
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    Ok(destination)
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
