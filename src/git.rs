use crate::model::{FileEntry, FileKind};
use crate::store::ChunkStore;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteRefChange {
    pub reference: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub forced: bool,
    pub rescue_ref: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FetchReport {
    pub changes: Vec<RemoteRefChange>,
}

pub fn fetch_remotes(repo: &Path) -> Result<FetchReport> {
    if !is_repository_root(repo) {
        return Ok(FetchReport::default());
    }
    let before = remote_refs(repo)?;
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["fetch", "--all", "--prune", "--no-write-fetch-head"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .context("run git fetch --all --prune")?;
    if !output.status.success() {
        bail!(
            "git fetch failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let after = remote_refs(repo)?;
    let references: std::collections::BTreeSet<_> =
        before.keys().chain(after.keys()).cloned().collect();
    let mut changes = Vec::new();
    for reference in references {
        let old = before.get(&reference).cloned();
        let new = after.get(&reference).cloned();
        if old == new {
            continue;
        }
        let forced = match (&old, &new) {
            (Some(old), Some(new)) => {
                !git_succeeds(repo, &["merge-base", "--is-ancestor", old, new])
            }
            _ => false,
        };
        let rescue_ref = if forced {
            old.as_deref()
                .map(|commit| rescue_commit(repo, &reference, commit))
                .transpose()?
        } else {
            None
        };
        changes.push(RemoteRefChange {
            reference,
            before: old,
            after: new,
            forced,
            rescue_ref,
        });
    }
    Ok(FetchReport { changes })
}

fn rescue_commit(repo: &Path, remote_ref: &str, commit: &str) -> Result<String> {
    if !git_succeeds(repo, &["cat-file", "-e", &format!("{commit}^{{commit}}")]) {
        bail!("cannot rescue missing commit {commit} from {remote_ref}");
    }
    let reference_hash = blake3::hash(remote_ref.as_bytes()).to_hex();
    let rescue_ref = format!("refs/pando/rescue/{reference_hash}/{commit}");
    git(repo, &["update-ref", &rescue_ref, commit])
        .with_context(|| format!("preserve {commit} as {rescue_ref}"))?;
    Ok(rescue_ref)
}

fn remote_refs(repo: &Path) -> Result<BTreeMap<String, String>> {
    let output = git(
        repo,
        &[
            "for-each-ref",
            "--format=%(refname)%00%(objectname)",
            "refs/remotes/",
        ],
    )?;
    let mut refs = BTreeMap::new();
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let Some(separator) = line.iter().position(|byte| *byte == 0) else {
            bail!("unexpected remote ref record");
        };
        let reference = std::str::from_utf8(&line[..separator])?.to_owned();
        if reference.ends_with("/HEAD") {
            continue;
        }
        refs.insert(
            reference,
            std::str::from_utf8(&line[separator + 1..])?.to_owned(),
        );
    }
    Ok(refs)
}

pub fn pushed_base(repo: &Path) -> Result<Option<String>> {
    if !is_repository_root(repo) {
        return Ok(None);
    }
    let upstream = git(
        repo,
        &[
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ],
    );
    if let Ok(upstream) = upstream {
        let reference = String::from_utf8(upstream)?.trim().to_owned();
        if !reference.is_empty() {
            let sha = git(repo, &["rev-parse", &reference])?;
            return Ok(Some(String::from_utf8(sha)?.trim().to_owned()));
        }
    }

    let refs = match git(
        repo,
        &["for-each-ref", "--format=%(objectname)", "refs/remotes/"],
    ) {
        Ok(refs) => String::from_utf8(refs)?,
        Err(_) => return Ok(None),
    };
    let mut nearest = None;
    for candidate in refs.lines() {
        if candidate.is_empty()
            || !git_succeeds(repo, &["merge-base", "--is-ancestor", candidate, "HEAD"])
        {
            continue;
        }
        let range = format!("{candidate}..HEAD");
        let distance = git(repo, &["rev-list", "--count", &range])
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(u64::MAX);
        if nearest.as_ref().is_none_or(|(best, _)| distance < *best) {
            nearest = Some((distance, candidate.to_owned()));
        }
    }
    Ok(nearest.map(|(_, sha)| sha))
}

/// Bundle every object that is not already reachable from a remote-tracking
/// ref into a single pack, returned as manifest entries at their natural
/// `.git/objects/pack/` paths. Covers all local refs, stashes, reflog entries,
/// and the index; a repository with no remotes packs its full history.
pub fn local_pack_entries(repo: &Path, store: &ChunkStore) -> Result<BTreeMap<String, FileEntry>> {
    let staging = std::env::temp_dir().join(format!(
        "pando-pack-{}-{}",
        std::process::id(),
        &blake3::hash(repo.to_string_lossy().as_bytes())
            .to_hex()
            .to_string()[..12]
    ));
    std::fs::create_dir_all(&staging)?;
    let result = pack_local_objects(repo, &staging, store);
    let _ = std::fs::remove_dir_all(&staging);
    result
}

fn pack_local_objects(
    repo: &Path,
    staging: &Path,
    store: &ChunkStore,
) -> Result<BTreeMap<String, FileEntry>> {
    let objects = git(
        repo,
        &[
            "rev-list",
            "--objects",
            "--all",
            "--reflog",
            "--indexed-objects",
            "--not",
            "--remotes",
        ],
    )?;
    if objects.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(BTreeMap::new());
    }
    // Single-threaded packing keeps the pack bytes reproducible, so an
    // unchanged repository keeps producing the identical manifest.
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "pack.threads=1", "pack-objects", "--quiet"])
        .arg(staging.join("pack"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("run git pack-objects")?;
    child
        .stdin
        .take()
        .context("open git pack-objects stdin")?
        .write_all(&objects)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "git pack-objects failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut entries = BTreeMap::new();
    for item in std::fs::read_dir(staging)? {
        let item = item?;
        let name = item
            .file_name()
            .into_string()
            .ok()
            .context("unexpected pack file name")?;
        let bytes = std::fs::read(item.path())?;
        let chunk = store.put(&bytes)?;
        entries.insert(
            format!(".git/objects/pack/{name}"),
            FileEntry {
                chunk,
                size: bytes.len() as u64,
                kind: FileKind::Regular,
                executable: false,
            },
        );
    }
    Ok(entries)
}

/// Make `commit` available locally, fetching from the repository's remotes
/// when it is missing. History that a snapshot did not carry must be
/// reachable this way; anything else is a hard error, never silent loss.
pub fn ensure_commit(repo: &Path, commit: &str) -> Result<()> {
    if commit_present(repo, commit) {
        return Ok(());
    }
    // Never fetch directly into the repository here: a snapshot-materialized
    // repository has refs pointing at objects the thin pack deliberately
    // omits, which poisons the negotiation, and a direct fetch also writes
    // ref and reflog files the snapshot never carried, leaving the tree
    // spuriously diverged from its own head. The clean room only adds
    // objects, never touching a ref.
    let outcome = fetch_all_remote_objects(repo);
    if commit_present(repo, commit) {
        return Ok(());
    }
    outcome.with_context(|| format!("fetch history for missing commit {commit}"))?;
    bail!("commit {commit} is not available locally or from any git remote");
}

/// Fetch every branch and tag from each remote through a fresh ref-less
/// repository, then hand the objects over. The clean-room negotiation never
/// claims to own objects the repository cannot actually read.
fn fetch_all_remote_objects(repo: &Path) -> Result<()> {
    let remotes = String::from_utf8(git(repo, &["remote"])?)?;
    let staging = std::env::temp_dir().join(format!(
        "pando-fetch-{}-{}",
        std::process::id(),
        &blake3::hash(repo.to_string_lossy().as_bytes())
            .to_hex()
            .to_string()[..12]
    ));
    let result = (|| {
        let mut failure = None;
        for remote in remotes
            .lines()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            let attempt = (|| {
                let url = String::from_utf8(git(repo, &["remote", "get-url", remote])?)?
                    .trim()
                    .to_owned();
                let clean_room = staging.join(remote);
                std::fs::create_dir_all(&clean_room)?;
                git(&clean_room, &["init", "--quiet", "--bare"])?;
                let fetched = Command::new("git")
                    .arg("-C")
                    .arg(&clean_room)
                    .args([
                        "fetch",
                        "--quiet",
                        &url,
                        "+refs/heads/*:refs/heads/*",
                        "+refs/tags/*:refs/tags/*",
                    ])
                    .env("GIT_TERMINAL_PROMPT", "0")
                    .output()
                    .context("run git fetch")?;
                if !fetched.status.success() {
                    bail!(
                        "git fetch {remote} failed: {}",
                        String::from_utf8_lossy(&fetched.stderr).trim()
                    );
                }
                copy_objects(&clean_room.join("objects"), &repo.join(".git/objects"))
            })();
            if let Err(error) = attempt {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    })();
    let _ = std::fs::remove_dir_all(&staging);
    result
}

fn copy_objects(source: &Path, destination: &Path) -> Result<()> {
    for item in std::fs::read_dir(source)? {
        let item = item?;
        let target = destination.join(item.file_name());
        if item.file_type()?.is_dir() {
            std::fs::create_dir_all(&target)?;
            copy_objects(&item.path(), &target)?;
        } else if !target.exists() {
            std::fs::copy(item.path(), &target)?;
        }
    }
    Ok(())
}

/// Let `repo` resolve objects it does not hold from `source`'s object store,
/// via git's alternates mechanism.
pub fn borrow_objects(repo: &Path, source: &Path) -> Result<()> {
    let objects = source.join(".git/objects");
    if !objects.is_dir() {
        return Ok(());
    }
    let info = repo.join(".git/objects/info");
    std::fs::create_dir_all(&info)?;
    std::fs::write(info.join("alternates"), format!("{}\n", objects.display()))?;
    Ok(())
}

fn commit_present(repo: &Path, commit: &str) -> bool {
    git(repo, &["cat-file", "-e", &format!("{commit}^{{commit}}")]).is_ok()
}

pub fn baseline(
    repo: &Path,
    commit: &str,
    store: &ChunkStore,
) -> Result<BTreeMap<String, FileEntry>> {
    if !is_repository_root(repo) {
        bail!("{} is not a Git repository root", repo.display());
    }
    ensure_commit(repo, commit)?;
    let output = git(repo, &["ls-tree", "-rz", "--full-tree", commit])?;
    let mut files = BTreeMap::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            bail!("unexpected git ls-tree record");
        };
        let header = std::str::from_utf8(&record[..tab])?;
        let mut fields = header.split_whitespace();
        let mode = fields.next().context("missing git mode")?;
        let kind = fields.next().context("missing git object type")?;
        let object = fields.next().context("missing git object id")?;
        if kind != "blob" {
            continue;
        }
        let path = String::from_utf8(record[tab + 1..].to_vec())?;
        let bytes = git(repo, &["cat-file", "blob", object])?;
        let chunk = store.put(&bytes)?;
        files.insert(
            path,
            FileEntry {
                chunk,
                size: bytes.len() as u64,
                kind: if mode == "120000" {
                    FileKind::Symlink
                } else {
                    FileKind::Regular
                },
                executable: mode == "100755",
            },
        );
    }
    Ok(files)
}

pub(crate) fn is_repository_root(repo: &Path) -> bool {
    let Ok(top_level) = git(repo, &["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    let Ok(top_level) = String::from_utf8(top_level) else {
        return false;
    };
    let Ok(expected) = repo.canonicalize() else {
        return false;
    };
    Path::new(top_level.trim())
        .canonicalize()
        .is_ok_and(|actual| actual == expected)
}

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .with_context(|| format!("run git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn git_succeeds(repo: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .status()
        .is_ok_and(|status| status.success())
}
