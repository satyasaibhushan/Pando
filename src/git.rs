use crate::model::{FileEntry, FileKind};
use crate::store::ChunkStore;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

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

pub fn baseline(
    repo: &Path,
    commit: &str,
    store: &ChunkStore,
) -> Result<BTreeMap<String, FileEntry>> {
    if !is_repository_root(repo) {
        bail!("{} is not a Git repository root", repo.display());
    }
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

fn is_repository_root(repo: &Path) -> bool {
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
