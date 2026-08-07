use crate::authority::Authority;
use crate::model::Overlay;
use crate::snapshot::{manifest_id, materialize_overlay};
use crate::store::ChunkStore;
use crate::transport::TransportKey;
use anyhow::{Context, Result, bail};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const FORMAT_VERSION: u32 = 1;
const MAGIC: &[u8] = b"PANDO-ESCAPE-V1\0";
const PARTS_MAGIC: &[u8] = b"PANDO-ESCAPE-PARTS-V1\0";
const KEY_CONTEXT: &str = "pando escape bundle encryption v1";
const BUNDLE_PATH: &str = "snapshot.pando";
const MAX_BLOB_BYTES: usize = 90 * 1024 * 1024;
const MAX_PARTS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportReport {
    pub snapshot: String,
    pub reference: String,
    pub chunks: usize,
    pub bytes: usize,
    pub pushed: bool,
    pub reused: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscapeRestoreReport {
    pub snapshot: String,
    pub files: usize,
    pub bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Bundle {
    version: u32,
    overlay: Overlay,
    chunks: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PartsManifest {
    bytes: u64,
    digest: String,
    parts: u32,
}

pub fn reference(repo_id: &str, trunk_id: &str) -> String {
    let repo = blake3::hash(repo_id.as_bytes()).to_hex();
    let trunk = blake3::hash(trunk_id.as_bytes()).to_hex();
    format!("refs/pando/escape/{repo}/{trunk}")
}

pub fn export<A: Authority + ?Sized>(
    repo: &Path,
    repo_id: &str,
    authority: &A,
    key: &TransportKey,
    remote: Option<&str>,
) -> Result<ExportReport> {
    ensure_repository_root(repo)?;
    let snapshot = authority
        .head(repo_id)?
        .with_context(|| format!("repository {repo_id} has no authority snapshot"))?;
    let overlay = authority.overlay(&snapshot)?;
    if overlay.snapshot.repo_id != repo_id {
        bail!(
            "authority snapshot {} belongs to repository {}",
            overlay.snapshot.id,
            overlay.snapshot.repo_id
        );
    }
    let reference = reference(repo_id, &overlay.snapshot.trunk_id);
    let remote_url = remote.map(|remote| remote_url(repo, remote)).transpose()?;
    let temporary = remote_url
        .as_deref()
        .map(|url| TemporaryBareRepo::from_remote(url, &reference))
        .transpose()?;
    let object_repo = temporary
        .as_ref()
        .map_or(repo, |temporary| temporary.path());
    if ref_protects_snapshot(object_repo, &reference, &snapshot) {
        return Ok(ExportReport {
            snapshot,
            reference,
            chunks: 0,
            bytes: 0,
            pushed: remote.is_some(),
            reused: true,
        });
    }
    let mut chunks = BTreeMap::new();
    for entry in overlay.upserts.values() {
        if !chunks.contains_key(&entry.chunk) {
            chunks.insert(entry.chunk.clone(), authority.get_chunk(&entry.chunk)?);
        }
    }
    let bundle = Bundle {
        version: FORMAT_VERSION,
        overlay,
        chunks,
    };
    let plaintext = bincode::serde::encode_to_vec(&bundle, bincode::config::standard())?;
    let encrypted = encrypt(&plaintext, key)?;
    write_ref(object_repo, &reference, &snapshot, &encrypted)?;
    let pushed = if let Some(remote_url) = remote_url.as_deref() {
        push_ref(object_repo, remote_url, &reference)?;
        true
    } else {
        false
    };
    Ok(ExportReport {
        snapshot,
        reference,
        chunks: bundle.chunks.len(),
        bytes: encrypted.len(),
        pushed,
        reused: false,
    })
}

struct TemporaryBareRepo {
    path: PathBuf,
}

impl TemporaryBareRepo {
    fn from_remote(remote_url: &str, reference: &str) -> Result<Self> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random)
            .map_err(|error| anyhow::anyhow!("generate temporary path: {error}"))?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path =
            std::env::temp_dir().join(format!("pando-escape-{}-{suffix}.git", std::process::id()));
        let output = Command::new("git")
            .args(["init", "--bare"])
            .arg(&path)
            .output()
            .context("initialize temporary bare Git repository")?;
        if !output.status.success() {
            bail!(
                "initialize temporary bare Git repository: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let temporary = Self { path };
        fetch_existing_ref(temporary.path(), remote_url, reference)?;
        Ok(temporary)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryBareRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn remote_url(repo: &Path, remote: &str) -> Result<String> {
    let url = String::from_utf8(git(repo, &["remote", "get-url", remote])?)?;
    let url = url.trim();
    if url.is_empty() {
        bail!("Git remote {remote} has no URL");
    }
    Ok(url.to_owned())
}

fn fetch_existing_ref(repo: &Path, remote_url: &str, reference: &str) -> Result<()> {
    let listed = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["ls-remote", "--exit-code", remote_url, reference])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .with_context(|| format!("inspect escape ref at {remote_url}"))?;
    if listed.status.code() == Some(2) {
        return Ok(());
    }
    if !listed.status.success() {
        bail!(
            "inspect remote escape ref failed: {}",
            String::from_utf8_lossy(&listed.stderr).trim()
        );
    }
    let refspec = format!("{reference}:{reference}");
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["fetch", "--no-write-fetch-head", remote_url, &refspec])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .with_context(|| format!("fetch existing escape ref from {remote_url}"))?;
    if !output.status.success() {
        bail!(
            "fetch existing escape ref failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn ref_protects_snapshot(repo: &Path, reference: &str, snapshot: &str) -> bool {
    let expected = format!("Pando escape snapshot {snapshot}");
    git(repo, &["log", "-1", "--format=%B", reference])
        .ok()
        .and_then(|message| String::from_utf8(message).ok())
        .is_some_and(|message| message.trim() == expected)
        && git(
            repo,
            &["cat-file", "-e", &format!("{reference}:{BUNDLE_PATH}")],
        )
        .is_ok()
}

pub fn fetch_ref(repo: &Path, remote: &str, reference: &str) -> Result<()> {
    ensure_repository_root(repo)?;
    let refspec = format!("{reference}:{reference}");
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["fetch", "--no-write-fetch-head", remote, &refspec])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .with_context(|| format!("fetch escape ref {reference} from {remote}"))?;
    if !output.status.success() {
        bail!(
            "git fetch escape ref failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub fn restore(
    repo: &Path,
    reference: &str,
    key: &TransportKey,
    destination: &Path,
) -> Result<EscapeRestoreReport> {
    ensure_repository_root(repo)?;
    let encrypted = read_encrypted(repo, reference)?;
    let plaintext = decrypt(&encrypted, key)?;
    let (bundle, consumed): (Bundle, usize) =
        bincode::serde::decode_from_slice(&plaintext, bincode::config::standard())?;
    if consumed != plaintext.len() {
        bail!("escape bundle has trailing data");
    }
    validate_bundle(&bundle)?;
    restore_bundle(bundle, destination)
}

fn encrypt(plaintext: &[u8], key: &TransportKey) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new((&key.derive_key(KEY_CONTEXT)).into());
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|error| anyhow::anyhow!("generate nonce: {error}"))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: MAGIC,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt escape bundle"))?;
    let mut output = Vec::with_capacity(MAGIC.len() + nonce.len() + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn decrypt(encrypted: &[u8], key: &TransportKey) -> Result<Vec<u8>> {
    if !encrypted.starts_with(MAGIC) || encrypted.len() < MAGIC.len() + 24 + 16 {
        bail!("not a Pando escape bundle");
    }
    let (nonce, ciphertext) = encrypted[MAGIC.len()..].split_at(24);
    let cipher = XChaCha20Poly1305::new((&key.derive_key(KEY_CONTEXT)).into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: MAGIC,
            },
        )
        .map_err(|_| anyhow::anyhow!("escape bundle authentication failed"))
}

fn validate_bundle(bundle: &Bundle) -> Result<()> {
    if bundle.version != FORMAT_VERSION {
        bail!("unsupported escape bundle version {}", bundle.version);
    }
    let actual_id = manifest_id(&bundle.overlay.snapshot)?;
    if actual_id != bundle.overlay.snapshot.id {
        bail!(
            "escape snapshot {} content hashes to {actual_id}",
            bundle.overlay.snapshot.id
        );
    }
    let required: BTreeSet<_> = bundle
        .overlay
        .upserts
        .values()
        .map(|entry| entry.chunk.as_str())
        .collect();
    for hash in required {
        let bytes = bundle
            .chunks
            .get(hash)
            .with_context(|| format!("escape bundle is missing chunk {hash}"))?;
        if blake3::hash(bytes).to_hex().as_str() != hash {
            bail!("escape bundle chunk {hash} failed verification");
        }
    }
    Ok(())
}

fn restore_bundle(bundle: Bundle, destination: &Path) -> Result<EscapeRestoreReport> {
    let destination = absolute(destination)?;
    if destination.exists() {
        bail!(
            "restore destination already exists: {}",
            destination.display()
        );
    }
    let parent = destination
        .parent()
        .context("restore destination has no parent")?;
    fs::create_dir_all(parent)?;
    let name = destination
        .file_name()
        .context("restore destination has no file name")?
        .to_string_lossy();
    let temporary = parent.join(format!(
        ".{name}.pando-escape-partial-{}",
        std::process::id()
    ));
    let chunk_root = parent.join(format!(
        ".{name}.pando-chunks-partial-{}",
        std::process::id()
    ));
    if temporary.exists() || chunk_root.exists() {
        bail!("temporary escape restore path already exists");
    }
    let result = (|| {
        let store = ChunkStore::new(&chunk_root)?;
        for (hash, bytes) in &bundle.chunks {
            store.put_verified(hash, bytes)?;
        }
        let mut overlay = bundle.overlay.clone();
        if let Some(commit) = overlay.snapshot.base_commit.as_deref() {
            let git_overlay = Overlay {
                snapshot: overlay.snapshot.clone(),
                upserts: overlay
                    .upserts
                    .iter()
                    .filter(|(path, _)| *path == ".git" || path.starts_with(".git/"))
                    .map(|(path, entry)| (path.clone(), entry.clone()))
                    .collect(),
                deletes: Vec::new(),
            };
            materialize_overlay(&temporary, &git_overlay, &store)?;
            crate::git::baseline(&temporary, commit, &store)?;
        }
        overlay.upserts = overlay.snapshot.files.clone();
        overlay.deletes.clear();
        materialize_overlay(&temporary, &overlay, &store)?;
        fs::rename(&temporary, &destination)?;
        Ok(EscapeRestoreReport {
            snapshot: overlay.snapshot.id,
            files: overlay.snapshot.files.len(),
            bytes: overlay
                .snapshot
                .files
                .values()
                .map(|entry| entry.size)
                .sum(),
        })
    })();
    let _ = fs::remove_dir_all(&chunk_root);
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn read_encrypted(repo: &Path, reference: &str) -> Result<Vec<u8>> {
    let manifest = git(repo, &["show", &format!("{reference}:{BUNDLE_PATH}")])?;
    if manifest.starts_with(MAGIC) {
        return Ok(manifest);
    }
    if !manifest.starts_with(PARTS_MAGIC) {
        bail!("not a Pando escape bundle");
    }
    let encoded = &manifest[PARTS_MAGIC.len()..];
    let (parts, consumed): (PartsManifest, usize) =
        bincode::serde::decode_from_slice(encoded, bincode::config::standard())?;
    if consumed != encoded.len() {
        bail!("escape parts manifest has trailing data");
    }
    let part_count = usize::try_from(parts.parts)?;
    if part_count == 0 || part_count > MAX_PARTS {
        bail!("escape parts manifest has invalid part count {part_count}");
    }
    let expected_bytes = usize::try_from(parts.bytes)?;
    let mut encrypted = Vec::new();
    for index in 0..part_count {
        let part = git(
            repo,
            &["show", &format!("{reference}:{}", part_path(index))],
        )?;
        if encrypted.len().saturating_add(part.len()) > expected_bytes {
            bail!("escape parts exceed their declared size");
        }
        encrypted.extend_from_slice(&part);
    }
    if encrypted.len() != expected_bytes {
        bail!(
            "escape parts contain {} bytes, expected {expected_bytes}",
            encrypted.len()
        );
    }
    if blake3::hash(&encrypted).to_hex().as_str() != parts.digest {
        bail!("escape parts failed verification");
    }
    Ok(encrypted)
}

fn write_ref(repo: &Path, reference: &str, snapshot: &str, encrypted: &[u8]) -> Result<()> {
    write_ref_with_max_blob_bytes(repo, reference, snapshot, encrypted, MAX_BLOB_BYTES)
}

fn write_ref_with_max_blob_bytes(
    repo: &Path,
    reference: &str,
    snapshot: &str,
    encrypted: &[u8],
    max_blob_bytes: usize,
) -> Result<()> {
    if max_blob_bytes == 0 {
        bail!("escape blob size must be greater than zero");
    }
    let mut tree_entries = Vec::new();
    if encrypted.len() <= max_blob_bytes {
        tree_entries.push((BUNDLE_PATH.to_owned(), write_blob(repo, encrypted)?));
    } else {
        let part_count = encrypted.len().div_ceil(max_blob_bytes);
        if part_count > MAX_PARTS {
            bail!("escape bundle requires too many parts ({part_count})");
        }
        let parts = PartsManifest {
            bytes: u64::try_from(encrypted.len())?,
            digest: blake3::hash(encrypted).to_hex().to_string(),
            parts: u32::try_from(part_count)?,
        };
        let mut manifest = PARTS_MAGIC.to_vec();
        manifest.extend(bincode::serde::encode_to_vec(
            &parts,
            bincode::config::standard(),
        )?);
        tree_entries.push((BUNDLE_PATH.to_owned(), write_blob(repo, &manifest)?));
        for (index, part) in encrypted.chunks(max_blob_bytes).enumerate() {
            tree_entries.push((part_path(index), write_blob(repo, part)?));
        }
    }
    let tree_input = tree_entries
        .iter()
        .map(|(path, blob)| format!("100644 blob {blob}\t{path}\n"))
        .collect::<String>();
    let tree = String::from_utf8(git_with_input(
        repo,
        &["mktree"],
        tree_input.as_bytes(),
        &[],
    )?)?;
    let parent = git(repo, &["rev-parse", "--verify", reference])
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|value| value.trim().to_owned());
    let mut arguments = vec!["commit-tree", tree.trim()];
    if let Some(parent) = &parent {
        arguments.extend(["-p", parent]);
    }
    let message = format!("Pando escape snapshot {snapshot}\n");
    let commit = String::from_utf8(git_with_input(
        repo,
        &arguments,
        message.as_bytes(),
        &[
            ("GIT_AUTHOR_NAME", "Pando Escape"),
            ("GIT_AUTHOR_EMAIL", "pando@localhost"),
            ("GIT_COMMITTER_NAME", "Pando Escape"),
            ("GIT_COMMITTER_EMAIL", "pando@localhost"),
        ],
    )?)?;
    git(repo, &["update-ref", reference, commit.trim()])?;
    Ok(())
}

fn write_blob(repo: &Path, bytes: &[u8]) -> Result<String> {
    let blob = String::from_utf8(git_with_input(
        repo,
        &["hash-object", "-w", "--stdin"],
        bytes,
        &[],
    )?)?;
    Ok(blob.trim().to_owned())
}

fn part_path(index: usize) -> String {
    format!("{BUNDLE_PATH}.part{index:04}")
}

fn push_ref(repo: &Path, remote: &str, reference: &str) -> Result<()> {
    let refspec = format!("{reference}:{reference}");
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["push", remote, &refspec])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .with_context(|| format!("push escape ref to {remote}"))?;
    if !output.status.success() {
        bail!(
            "git push escape ref failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn ensure_repository_root(repo: &Path) -> Result<()> {
    let top = String::from_utf8(git(repo, &["rev-parse", "--show-toplevel"])?)?;
    if repo.canonicalize()? != Path::new(top.trim()).canonicalize()? {
        bail!("{} is not a Git repository root", repo.display());
    }
    Ok(())
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
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

fn git_with_input(
    repo: &Path,
    args: &[&str],
    input: &[u8],
    environment: &[(&str, &str)],
) -> Result<Vec<u8>> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in environment {
        command.env(name, value);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("run git {}", args.join(" ")))?;
    child
        .stdin
        .take()
        .context("git stdin unavailable")?
        .write_all(input)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FileEntry, FileKind, Manifest};

    #[test]
    fn escape_refs_keep_small_bundles_in_the_legacy_single_blob_format() {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "-b", "main"]).unwrap();
        let encrypted = [MAGIC, b"small encrypted payload"].concat();

        write_ref_with_max_blob_bytes(
            root.path(),
            "refs/pando/test",
            "snapshot",
            &encrypted,
            encrypted.len(),
        )
        .unwrap();

        assert_eq!(
            read_encrypted(root.path(), "refs/pando/test").unwrap(),
            encrypted
        );
        let paths = String::from_utf8(
            git(root.path(), &["ls-tree", "--name-only", "refs/pando/test"]).unwrap(),
        )
        .unwrap();
        assert_eq!(paths, "snapshot.pando\n");
    }

    #[test]
    fn escape_refs_split_large_bundles_into_verified_parts() {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "-b", "main"]).unwrap();
        let contents = b"a payload larger than one test part";
        let chunk = blake3::hash(contents).to_hex().to_string();
        let entry = FileEntry {
            chunk: chunk.clone(),
            size: contents.len() as u64,
            kind: FileKind::Regular,
            executable: false,
        };
        let files = BTreeMap::from([("unfinished.txt".to_owned(), entry)]);
        let mut manifest = Manifest {
            id: String::new(),
            repo_id: "repo".to_owned(),
            trunk_id: "macbook".to_owned(),
            created_at_ms: 1,
            parent: None,
            base_commit: None,
            classification_version: 1,
            ignore_patterns: Vec::new(),
            files: files.clone(),
        };
        manifest.id = manifest_id(&manifest).unwrap();
        let bundle = Bundle {
            version: FORMAT_VERSION,
            overlay: Overlay {
                snapshot: manifest,
                upserts: files,
                deletes: Vec::new(),
            },
            chunks: BTreeMap::from([(chunk, contents.to_vec())]),
        };
        let plaintext =
            bincode::serde::encode_to_vec(&bundle, bincode::config::standard()).unwrap();
        let key = TransportKey::from_bytes([7; 32]);
        let encrypted = encrypt(&plaintext, &key).unwrap();

        write_ref_with_max_blob_bytes(root.path(), "refs/pando/test", "snapshot", &encrypted, 8)
            .unwrap();

        assert_eq!(
            read_encrypted(root.path(), "refs/pando/test").unwrap(),
            encrypted
        );
        let destination = root.path().join("restored");
        restore(root.path(), "refs/pando/test", &key, &destination).unwrap();
        assert_eq!(
            fs::read(destination.join("unfinished.txt")).unwrap(),
            contents
        );
        let paths = String::from_utf8(
            git(root.path(), &["ls-tree", "--name-only", "refs/pando/test"]).unwrap(),
        )
        .unwrap();
        let part_paths = paths
            .lines()
            .filter(|path| path.contains(".part"))
            .collect::<Vec<_>>();
        assert!(part_paths.len() > 1);
        for path in part_paths {
            let size = String::from_utf8(
                git(
                    root.path(),
                    &["cat-file", "-s", &format!("refs/pando/test:{path}")],
                )
                .unwrap(),
            )
            .unwrap();
            assert!(size.trim().parse::<usize>().unwrap() <= 8);
        }
    }
}
