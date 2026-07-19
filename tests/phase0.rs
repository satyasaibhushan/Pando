use pando::Clock;
use pando::authority::{AcquireResult, Authority, FileAuthority};
use pando::clock::{SystemClock, VirtualClock};
use pando::model::{FileEntry, FileKind, Manifest, Overlay};
use pando::snapshot::manifest_id;
use pando::sync::{PullResult, PushResult, Trunk};
use pando::transport::{RemoteAuthority, TransportKey};
use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

struct Harness {
    _root: TempDir,
    authority_path: PathBuf,
    state_path: PathBuf,
    first_path: PathBuf,
    second_path: PathBuf,
    clock: VirtualClock,
}

impl Harness {
    fn plain() -> Self {
        let root = tempfile::tempdir().unwrap();
        let authority_path = root.path().join("authority");
        let state_path = root.path().join("trunks");
        let first_path = root.path().join("first");
        let second_path = root.path().join("second");
        fs::create_dir_all(&first_path).unwrap();
        fs::create_dir_all(&second_path).unwrap();
        Self {
            _root: root,
            authority_path,
            state_path,
            first_path,
            second_path,
            clock: VirtualClock::at(1_000),
        }
    }

    fn authority(&self) -> FileAuthority {
        FileAuthority::open(&self.authority_path).unwrap()
    }

    fn first(&self) -> Trunk {
        Trunk::open_with_state(
            &self.first_path,
            "repo",
            "macbook",
            self.state_path.join("macbook"),
        )
        .unwrap()
    }

    fn second(&self) -> Trunk {
        Trunk::open_with_state(
            &self.second_path,
            "repo",
            "linuxbox",
            self.state_path.join("linuxbox"),
        )
        .unwrap()
    }
}

#[test]
fn dirty_tree_moves_between_two_trunks() {
    let harness = Harness::plain();
    fs::write(harness.first_path.join("work.txt"), "half-written\n").unwrap();
    fs::write(harness.first_path.join("untracked.txt"), "new\n").unwrap();
    let mut authority = harness.authority();
    let first = harness.first();
    let second = harness.second();

    assert!(matches!(
        first.push(&mut authority, &harness.clock).unwrap(),
        PushResult::Published { .. }
    ));
    first.release(&mut authority).unwrap();
    assert!(matches!(
        second.pull(&authority, &harness.clock).unwrap(),
        PullResult::Applied { .. }
    ));

    assert_eq!(
        fs::read_to_string(harness.second_path.join("work.txt")).unwrap(),
        "half-written\n"
    );
    assert_eq!(
        fs::read_to_string(harness.second_path.join("untracked.txt")).unwrap(),
        "new\n"
    );
}

#[test]
fn authority_integrity_audit_verifies_history_and_detects_chunk_corruption() {
    let harness = Harness::plain();
    fs::write(harness.first_path.join("work.txt"), "integrity\n").unwrap();
    let mut authority = harness.authority();
    let first = harness.first();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    harness.clock.advance(1_000);
    fs::write(harness.first_path.join("work.txt"), "changed!!\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();

    let report = authority.verify().unwrap();
    assert_eq!(report.heads, 1);
    assert_eq!(report.overlays, 2);
    assert_eq!(report.chunks, 2);
    assert_eq!(report.bytes, 20);

    let head = authority.head("repo").unwrap().unwrap();
    let overlay = authority.overlay(&head).unwrap();
    let hash = &overlay.snapshot.files["work.txt"].chunk;
    fs::write(
        authority
            .root()
            .join("chunks")
            .join(&hash[..2])
            .join(&hash[2..]),
        "corrupt",
    )
    .unwrap();

    let error = authority.verify().unwrap_err().to_string();
    assert!(error.contains("corrupt chunk"), "{error}");
}

#[test]
fn authority_integrity_audit_detects_tampered_snapshot_metadata() {
    let harness = Harness::plain();
    fs::write(harness.first_path.join("work.txt"), "integrity\n").unwrap();
    let mut authority = harness.authority();
    let first = harness.first();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    let head = authority.head("repo").unwrap().unwrap();
    let mut overlay = authority.overlay(&head).unwrap();
    overlay.snapshot.created_at_ms += 1;
    fs::write(
        authority
            .root()
            .join("overlays")
            .join(format!("{head}.json")),
        serde_json::to_vec_pretty(&overlay).unwrap(),
    )
    .unwrap();

    let error = authority.verify().unwrap_err().to_string();
    assert!(error.contains("content hashes to"), "{error}");
}

#[test]
fn read_only_authority_open_does_not_create_a_missing_store() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");

    assert!(FileAuthority::open_existing(&missing).is_err());
    assert!(!missing.exists());
}

#[test]
fn any_snapshot_restores_to_a_new_directory_without_overwriting() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let first = harness.first();
    fs::write(harness.first_path.join("work.txt"), "first\n").unwrap();
    let first_snapshot = match first.push(&mut authority, &harness.clock).unwrap() {
        PushResult::Published { snapshot, .. } => snapshot,
        result => panic!("unexpected push result: {result:?}"),
    };
    first.release(&mut authority).unwrap();
    harness.clock.advance(1_000);
    fs::write(harness.first_path.join("work.txt"), "second\n").unwrap();
    let second_snapshot = match first.push(&mut authority, &harness.clock).unwrap() {
        PushResult::Published { snapshot, .. } => snapshot,
        result => panic!("unexpected push result: {result:?}"),
    };
    first.release(&mut authority).unwrap();

    let first_destination = harness._root.path().join("restore-first");
    let second_destination = harness._root.path().join("restore-second");
    let first_report = authority
        .restore(&first_snapshot, &first_destination)
        .unwrap();
    authority
        .restore(&second_snapshot, &second_destination)
        .unwrap();

    assert_eq!(first_report.files, 1);
    assert_eq!(
        fs::read_to_string(first_destination.join("work.txt")).unwrap(),
        "first\n"
    );
    assert_eq!(
        fs::read_to_string(second_destination.join("work.txt")).unwrap(),
        "second\n"
    );
    let error = authority
        .restore(&second_snapshot, &first_destination)
        .unwrap_err()
        .to_string();
    assert!(error.contains("already exists"), "{error}");
    assert_eq!(
        fs::read_to_string(first_destination.join("work.txt")).unwrap(),
        "first\n"
    );
}

#[test]
fn verify_and_restore_cli_exercise_an_authority_snapshot() {
    let harness = Harness::plain();
    fs::write(harness.first_path.join("work.txt"), "cli restore\n").unwrap();
    let mut authority = harness.authority();
    let first = harness.first();
    let snapshot = match first.push(&mut authority, &harness.clock).unwrap() {
        PushResult::Published { snapshot, .. } => snapshot,
        result => panic!("unexpected push result: {result:?}"),
    };
    first.release(&mut authority).unwrap();

    let verify = Command::new(env!("CARGO_BIN_EXE_pando"))
        .args(["verify", "--data", harness.authority_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(verify.status.success(), "{:?}", verify.stderr);
    assert!(String::from_utf8_lossy(&verify.stdout).contains("verified 1 heads, 1 snapshots"));

    let destination = harness._root.path().join("cli-restore");
    let restore = Command::new(env!("CARGO_BIN_EXE_pando"))
        .args([
            "restore",
            "--data",
            harness.authority_path.to_str().unwrap(),
            "--snapshot",
            &snapshot,
            "--destination",
            destination.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(restore.status.success(), "{:?}", restore.stderr);
    assert_eq!(
        fs::read_to_string(destination.join("work.txt")).unwrap(),
        "cli restore\n"
    );
}

#[test]
fn authority_rejects_reserved_snapshot_paths() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let bytes = b"malicious";
    let chunk = blake3::hash(bytes).to_hex().to_string();
    authority.put_chunk(&chunk, bytes).unwrap();
    authority
        .acquire("repo", "macbook", harness.clock.now_ms(), 30_000)
        .unwrap();
    let mut files = BTreeMap::new();
    files.insert(
        ".pando/state".to_owned(),
        FileEntry {
            chunk,
            size: bytes.len() as u64,
            kind: FileKind::Regular,
            executable: false,
        },
    );
    let mut manifest = Manifest {
        id: String::new(),
        repo_id: "repo".into(),
        trunk_id: "macbook".into(),
        created_at_ms: harness.clock.now_ms(),
        parent: None,
        base_commit: None,
        classification_version: 1,
        ignore_patterns: Vec::new(),
        files: files.clone(),
    };
    manifest.id = manifest_id(&manifest).unwrap();
    let overlay = Overlay {
        snapshot: manifest,
        upserts: files,
        deletes: Vec::new(),
    };

    let error = authority
        .publish(&overlay, "macbook", harness.clock.now_ms())
        .unwrap_err()
        .to_string();
    assert!(error.contains("unsafe snapshot path"), "{error}");
}

#[cfg(unix)]
#[test]
fn materialization_refuses_to_traverse_existing_symlink_ancestors() {
    use pando::snapshot::materialize_overlay;
    use pando::store::ChunkStore;
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    let outside = root.path().join("outside");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&outside).unwrap();
    symlink(&outside, repo.join("link")).unwrap();
    let store = ChunkStore::new(root.path().join("chunks")).unwrap();
    let chunk = store.put(b"escape").unwrap();
    let entry = FileEntry {
        chunk,
        size: 6,
        kind: FileKind::Regular,
        executable: false,
    };
    let mut files = BTreeMap::new();
    files.insert("link/escaped.txt".to_owned(), entry.clone());
    let overlay = Overlay {
        snapshot: Manifest {
            id: "snapshot".into(),
            repo_id: "repo".into(),
            trunk_id: "macbook".into(),
            created_at_ms: 1,
            parent: None,
            base_commit: None,
            classification_version: 1,
            ignore_patterns: Vec::new(),
            files,
        },
        upserts: BTreeMap::from([("link/escaped.txt".to_owned(), entry)]),
        deletes: Vec::new(),
    };

    let error = materialize_overlay(&repo, &overlay, &store)
        .unwrap_err()
        .to_string();
    assert!(error.contains("traverses symlink"), "{error}");
    assert!(!outside.join("escaped.txt").exists());
}

#[test]
fn nested_non_repo_does_not_borrow_its_parent_git_baseline() {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "-b", "main"]);
    git(root.path(), &["config", "user.email", "pando@example.test"]);
    git(root.path(), &["config", "user.name", "Pando Test"]);
    fs::write(root.path().join("parent-only.txt"), "parent\n").unwrap();
    git(root.path(), &["add", "parent-only.txt"]);
    git(root.path(), &["commit", "-m", "parent base"]);
    let parent_head = git_output(root.path(), &["rev-parse", "HEAD"]);
    git(
        root.path(),
        &["update-ref", "refs/remotes/origin/main", &parent_head],
    );

    let demo = root.path().join(".pando-demo");
    let first_path = demo.join("macbook");
    let second_path = demo.join("linuxbox");
    fs::create_dir_all(&first_path).unwrap();
    fs::create_dir_all(&second_path).unwrap();
    fs::write(first_path.join("mid-edit.txt"), "this followed me\n").unwrap();
    let mut authority = FileAuthority::open(demo.join("authority")).unwrap();
    let clock = VirtualClock::at(1_000);
    let first = Trunk::open_with_state(
        &first_path,
        "demo",
        "macbook",
        demo.join("trunk-state/macbook"),
    )
    .unwrap();
    let second = Trunk::open_with_state(
        &second_path,
        "demo",
        "linuxbox",
        demo.join("trunk-state/linuxbox"),
    )
    .unwrap();

    first.push(&mut authority, &clock).unwrap();
    first.release(&mut authority).unwrap();
    let result = second.pull(&authority, &clock).unwrap();

    assert!(matches!(result, PullResult::Applied { .. }));
    assert_eq!(
        fs::read_to_string(second_path.join("mid-edit.txt")).unwrap(),
        "this followed me\n"
    );
}

#[test]
fn active_lease_refuses_a_second_writer() {
    let harness = Harness::plain();
    fs::write(harness.first_path.join("work.txt"), "first\n").unwrap();
    fs::write(harness.second_path.join("work.txt"), "second\n").unwrap();
    let mut authority = harness.authority();

    harness
        .first()
        .push(&mut authority, &harness.clock)
        .unwrap();
    let result = harness
        .second()
        .push(&mut authority, &harness.clock)
        .unwrap();
    assert!(matches!(result, PushResult::LeaseHeld { holder, .. } if holder == "macbook"));
}

#[test]
fn trunk_bookkeeping_survives_stashing_all_untracked_files() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    let state = root.path().join("trunk-state");
    let authority_path = root.path().join("authority");
    git(root.path(), &["init", "-b", "main", repo.to_str().unwrap()]);
    git(&repo, &["config", "user.email", "pando@example.test"]);
    git(&repo, &["config", "user.name", "Pando Test"]);
    fs::write(repo.join("tracked.txt"), "base\n").unwrap();
    git(&repo, &["add", "tracked.txt"]);
    git(&repo, &["commit", "-m", "base"]);

    let clock = VirtualClock::at(1_000);
    let trunk = Trunk::open_with_state(&repo, "repo", "macbook", &state).unwrap();
    let mut authority = FileAuthority::open(&authority_path).unwrap();
    fs::write(repo.join("untracked.txt"), "stash me\n").unwrap();
    trunk.push(&mut authority, &clock).unwrap();
    trunk.release(&mut authority).unwrap();
    git(&repo, &["stash", "push", "-u", "-m", "portable"]);

    assert!(state.join("state.json").is_file());
    assert!(state.join("chunks").is_dir());
    assert!(!repo.join(".pando").exists());
    assert!(trunk.local_head().unwrap().is_some());
    clock.advance(1_000);
    assert!(matches!(
        trunk.push(&mut authority, &clock).unwrap(),
        PushResult::Published { .. }
    ));
}

#[test]
fn expired_lease_still_refuses_a_stale_parent() {
    let harness = Harness::plain();
    fs::write(harness.first_path.join("work.txt"), "first\n").unwrap();
    let mut authority = harness.authority();
    harness
        .first()
        .push(&mut authority, &harness.clock)
        .unwrap();
    harness.clock.advance(31_000);
    fs::write(harness.second_path.join("work.txt"), "offline second\n").unwrap();

    let result = harness
        .second()
        .push(&mut authority, &harness.clock)
        .unwrap();
    assert!(matches!(
        result,
        PushResult::Diverged {
            local_head: None,
            authority_head: Some(_)
        }
    ));
    assert!(matches!(
        authority
            .acquire("repo", "macbook", harness.clock.now_ms(), 10)
            .unwrap(),
        AcquireResult::Acquired(_)
    ));
}

#[test]
fn stale_non_overlapping_edits_three_way_merge_and_publish() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let first = harness.first();
    let second = harness.second();
    fs::write(harness.first_path.join("left.txt"), "base\n").unwrap();
    fs::write(harness.first_path.join("right.txt"), "base\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();

    harness.clock.advance(1_000);
    fs::write(harness.first_path.join("left.txt"), "first\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    fs::write(harness.second_path.join("right.txt"), "second\n").unwrap();

    let result = second.push(&mut authority, &harness.clock).unwrap();
    assert!(matches!(result, PushResult::Published { .. }));
    assert_eq!(
        fs::read_to_string(harness.second_path.join("left.txt")).unwrap(),
        "first\n"
    );
    assert_eq!(
        fs::read_to_string(harness.second_path.join("right.txt")).unwrap(),
        "second\n"
    );
}

#[test]
fn stale_overlapping_edits_report_paths_without_overwriting_local_work() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let first = harness.first();
    let second = harness.second();
    fs::write(harness.first_path.join("shared.txt"), "base\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();

    harness.clock.advance(1_000);
    fs::write(harness.first_path.join("shared.txt"), "first\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    fs::write(harness.second_path.join("shared.txt"), "second\n").unwrap();

    let result = second.push(&mut authority, &harness.clock).unwrap();
    let fork = match result {
        PushResult::Conflicted { paths, fork, .. } => {
            assert_eq!(paths, ["shared.txt"]);
            fork
        }
        result => panic!("unexpected push result: {result:?}"),
    };
    assert_eq!(
        authority.forks("repo").unwrap().as_slice(),
        std::slice::from_ref(&fork)
    );
    let fork_overlay = authority.overlay(&fork).unwrap();
    let fork_chunk = &fork_overlay.snapshot.files["shared.txt"].chunk;
    assert_eq!(authority.get_chunk(fork_chunk).unwrap(), b"second\n");
    assert_eq!(
        fs::read_to_string(harness.second_path.join("shared.txt")).unwrap(),
        "second\n"
    );
}

#[test]
fn dirty_pull_is_refused_instead_of_overwritten() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let first = harness.first();
    let second = harness.second();
    fs::write(harness.first_path.join("work.txt"), "one\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();

    harness.clock.advance(1_000);
    fs::write(harness.first_path.join("work.txt"), "two\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    fs::write(harness.second_path.join("work.txt"), "local offline edit\n").unwrap();

    let result = second.pull(&authority, &harness.clock).unwrap();
    assert!(matches!(result, PullResult::Diverged { .. }));
    assert_eq!(
        fs::read_to_string(harness.second_path.join("work.txt")).unwrap(),
        "local offline edit\n"
    );
}

#[test]
fn first_pull_refuses_a_nonempty_untracked_tree() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    fs::write(harness.first_path.join("source.txt"), "source\n").unwrap();
    harness
        .first()
        .push(&mut authority, &harness.clock)
        .unwrap();
    fs::write(harness.second_path.join("local.txt"), "do not erase\n").unwrap();

    let result = harness.second().pull(&authority, &harness.clock).unwrap();
    assert!(matches!(
        result,
        PullResult::Diverged {
            local_head: None,
            ..
        }
    ));
    assert_eq!(
        fs::read_to_string(harness.second_path.join("local.txt")).unwrap(),
        "do not erase\n"
    );
}

#[test]
fn matching_tree_adopts_the_authority_head_after_state_relocation() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    fs::write(harness.first_path.join("source.txt"), "source\n").unwrap();
    let first = harness.first();
    let second = harness.second();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();

    let relocated = Trunk::open_with_state(
        &harness.second_path,
        "repo",
        "linuxbox",
        harness.state_path.join("linuxbox-relocated"),
    )
    .unwrap();
    let result = relocated.pull(&authority, &harness.clock).unwrap();

    assert!(matches!(result, PullResult::UpToDate { .. }));
    assert_eq!(
        relocated.local_head().unwrap(),
        authority.head("repo").unwrap()
    );
}

#[test]
fn reverting_a_file_to_its_base_is_transferred() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let first = harness.first();
    let second = harness.second();
    fs::write(harness.first_path.join("work.txt"), "changed\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();
    assert_eq!(
        fs::read_to_string(harness.second_path.join("work.txt")).unwrap(),
        "changed\n"
    );

    harness.clock.advance(1_000);
    fs::write(harness.first_path.join("work.txt"), "reverted\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();
    assert_eq!(
        fs::read_to_string(harness.second_path.join("work.txt")).unwrap(),
        "reverted\n"
    );
}

#[test]
fn receiver_two_snapshots_behind_sees_a_revert_to_the_git_base() {
    let root = tempfile::tempdir().unwrap();
    let remote = root.path().join("remote.git");
    let source = root.path().join("source");
    let target = root.path().join("target");
    git(root.path(), &["init", "--bare", remote.to_str().unwrap()]);
    git(&remote, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    git(
        root.path(),
        &["init", "-b", "main", source.to_str().unwrap()],
    );
    git(&source, &["config", "user.email", "pando@example.test"]);
    git(&source, &["config", "user.name", "Pando Test"]);
    fs::write(source.join("work.txt"), "base\n").unwrap();
    git(&source, &["add", "work.txt"]);
    git(&source, &["commit", "-m", "base"]);
    git(
        &source,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git(&source, &["push", "-u", "origin", "main"]);
    git(
        root.path(),
        &["clone", remote.to_str().unwrap(), target.to_str().unwrap()],
    );

    let mut authority = FileAuthority::open(root.path().join("authority")).unwrap();
    let clock = VirtualClock::at(1_000);
    let first = Trunk::open_with_state(
        &source,
        "repo",
        "macbook",
        root.path().join("trunks/macbook"),
    )
    .unwrap();
    let second = Trunk::open_with_state(
        &target,
        "repo",
        "linuxbox",
        root.path().join("trunks/linuxbox"),
    )
    .unwrap();

    fs::write(source.join("work.txt"), "dirty x\n").unwrap();
    first.push(&mut authority, &clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &clock).unwrap();

    clock.advance(1_000);
    fs::write(source.join("work.txt"), "base\n").unwrap();
    first.push(&mut authority, &clock).unwrap();
    first.release(&mut authority).unwrap();
    clock.advance(1_000);
    fs::write(source.join("later.txt"), "newer snapshot\n").unwrap();
    first.push(&mut authority, &clock).unwrap();
    first.release(&mut authority).unwrap();

    second.pull(&authority, &clock).unwrap();
    assert_eq!(
        fs::read_to_string(target.join("work.txt")).unwrap(),
        "base\n"
    );
    assert_eq!(
        fs::read_to_string(target.join("later.txt")).unwrap(),
        "newer snapshot\n"
    );
}

#[test]
fn one_shot_cli_push_releases_its_lease() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    let authority_path = root.path().join("authority");
    fs::create_dir_all(&repo).unwrap();
    fs::write(repo.join("work.txt"), "work\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pando"))
        .env("PANDO_DATA_HOME", root.path().join("client-state"))
        .args([
            "push",
            "--repo",
            repo.to_str().unwrap(),
            "--repo-id",
            "repo",
            "--trunk-id",
            "one-shot",
            "--authority",
            authority_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut authority = FileAuthority::open(authority_path).unwrap();
    assert!(matches!(
        authority
            .acquire("repo", "other-trunk", SystemClock.now_ms(), 1_000)
            .unwrap(),
        AcquireResult::Acquired(_)
    ));
}

#[test]
fn deletions_propagate_and_unchanged_trees_do_not_make_snapshots() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let first = harness.first();
    let second = harness.second();
    fs::write(harness.first_path.join("keep.txt"), "keep\n").unwrap();
    fs::write(harness.first_path.join("delete.txt"), "delete\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();

    assert!(matches!(
        first.push(&mut authority, &harness.clock).unwrap(),
        PushResult::NoChanges { .. }
    ));
    first.release(&mut authority).unwrap();
    fs::remove_file(harness.first_path.join("delete.txt")).unwrap();
    harness.clock.advance(1_000);
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();

    assert!(!harness.second_path.join("delete.txt").exists());
    assert_eq!(
        fs::read_to_string(harness.second_path.join("keep.txt")).unwrap(),
        "keep\n"
    );
}

#[cfg(unix)]
#[test]
fn executable_bits_and_symlinks_follow_the_user() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let script = harness.first_path.join("run.sh");
    fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();
    symlink("run.sh", harness.first_path.join("current")).unwrap();

    let first = harness.first();
    let second = harness.second();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();

    assert_ne!(
        fs::metadata(harness.second_path.join("run.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
    assert_eq!(
        fs::read_link(harness.second_path.join("current")).unwrap(),
        PathBuf::from("run.sh")
    );
}

#[test]
fn only_the_root_pando_directory_is_reserved() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    fs::create_dir_all(harness.first_path.join(".pando")).unwrap();
    fs::write(
        harness.first_path.join(".pando/local-state.txt"),
        "must stay local\n",
    )
    .unwrap();
    fs::create_dir_all(harness.first_path.join("docs/.pando")).unwrap();
    fs::write(
        harness.first_path.join("docs/.pando/source.txt"),
        "legitimate nested source\n",
    )
    .unwrap();

    let first = harness.first();
    let second = harness.second();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();

    assert!(!harness.second_path.join(".pando/local-state.txt").exists());
    assert_eq!(
        fs::read_to_string(harness.second_path.join("docs/.pando/source.txt")).unwrap(),
        "legitimate nested source\n"
    );
}

#[test]
fn derived_and_local_only_paths_never_enter_a_snapshot() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    fs::write(harness.first_path.join("source.rs"), "fn main() {}\n").unwrap();
    fs::write(harness.first_path.join(".gitignore"), ".env\n").unwrap();
    fs::write(harness.first_path.join(".env"), "TOKEN=portable\n").unwrap();
    for path in [
        "target/debug/app",
        "node_modules/pkg/index.js",
        ".venv/bin/python",
        "pkg/__pycache__/module.pyc",
        ".next/cache/data",
    ] {
        let path = harness.first_path.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "derived\n").unwrap();
    }
    fs::write(harness.first_path.join(".DS_Store"), "local\n").unwrap();

    harness
        .first()
        .push(&mut authority, &harness.clock)
        .unwrap();
    let head = authority.head("repo").unwrap().unwrap();
    let snapshot = authority.overlay(&head).unwrap().snapshot;

    assert!(snapshot.files.contains_key("source.rs"));
    assert!(snapshot.files.contains_key(".env"));
    for path in [
        "target/debug/app",
        "node_modules/pkg/index.js",
        ".venv/bin/python",
        "pkg/__pycache__/module.pyc",
        ".next/cache/data",
        ".DS_Store",
    ] {
        assert!(!snapshot.files.contains_key(path), "captured {path}");
    }
}

#[test]
fn ignored_local_state_survives_initial_pull() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    fs::write(harness.first_path.join("source.txt"), "portable\n").unwrap();
    for path in ["target/local.bin", "node_modules/local/index.js"] {
        let path = harness.second_path.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "keep local\n").unwrap();
    }
    fs::write(harness.second_path.join(".DS_Store"), "keep local\n").unwrap();
    #[cfg(unix)]
    let _socket =
        std::os::unix::net::UnixListener::bind(harness.second_path.join("local-service.sock"))
            .unwrap();

    let first = harness.first();
    let second = harness.second();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    assert!(matches!(
        second.pull(&authority, &harness.clock).unwrap(),
        PullResult::Applied { .. }
    ));

    assert_eq!(
        fs::read_to_string(harness.second_path.join("target/local.bin")).unwrap(),
        "keep local\n"
    );
    assert!(
        harness
            .second_path
            .join("node_modules/local/index.js")
            .is_file()
    );
    assert!(harness.second_path.join(".DS_Store").is_file());
    #[cfg(unix)]
    assert!(harness.second_path.join("local-service.sock").exists());
}

#[test]
fn pandoignore_can_add_ignores_and_override_builtins() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    fs::write(
        harness.first_path.join(".pandoignore"),
        "scratch/\n!/target/\n",
    )
    .unwrap();
    for (path, contents) in [
        ("scratch/drop.txt", "source scratch\n"),
        ("target/keep.txt", "explicitly portable\n"),
    ] {
        let path = harness.first_path.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    fs::create_dir_all(harness.second_path.join("scratch")).unwrap();
    fs::write(
        harness.second_path.join("scratch/local.txt"),
        "receiver scratch\n",
    )
    .unwrap();

    let first = harness.first();
    let second = harness.second();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();
    let head = authority.head("repo").unwrap().unwrap();
    let snapshot = authority.overlay(&head).unwrap().snapshot;

    assert!(snapshot.files.contains_key(".pandoignore"));
    assert!(snapshot.files.contains_key("target/keep.txt"));
    assert!(!snapshot.files.contains_key("scratch/drop.txt"));
    assert_eq!(
        fs::read_to_string(harness.second_path.join("target/keep.txt")).unwrap(),
        "explicitly portable\n"
    );
    assert_eq!(
        fs::read_to_string(harness.second_path.join("scratch/local.txt")).unwrap(),
        "receiver scratch\n"
    );
}

#[test]
fn newly_ignored_paths_are_preserved_on_receivers() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let first = harness.first();
    let second = harness.second();
    fs::create_dir_all(harness.first_path.join("scratch")).unwrap();
    fs::write(
        harness.first_path.join("scratch/state.txt"),
        "local state\n",
    )
    .unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();

    harness.clock.advance(1_000);
    fs::write(harness.first_path.join(".pandoignore"), "scratch/\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();

    assert_eq!(
        fs::read_to_string(harness.second_path.join("scratch/state.txt")).unwrap(),
        "local state\n"
    );
}

#[test]
fn phase0_snapshots_migrate_without_deleting_derived_state() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    fs::create_dir_all(harness.first_path.join("target")).unwrap();
    fs::write(harness.first_path.join("source.txt"), "portable\n").unwrap();
    fs::write(
        harness.first_path.join("target/cache.bin"),
        "legacy synced cache\n",
    )
    .unwrap();
    let source = b"portable\n";
    let cache = b"legacy synced cache\n";
    let source_hash = blake3::hash(source).to_hex().to_string();
    let cache_hash = blake3::hash(cache).to_hex().to_string();
    authority.put_chunk(&source_hash, source).unwrap();
    authority.put_chunk(&cache_hash, cache).unwrap();
    let files = BTreeMap::from([
        (
            "source.txt".into(),
            FileEntry {
                chunk: source_hash,
                size: source.len() as u64,
                kind: FileKind::Regular,
                executable: false,
            },
        ),
        (
            "target/cache.bin".into(),
            FileEntry {
                chunk: cache_hash,
                size: cache.len() as u64,
                kind: FileKind::Regular,
                executable: false,
            },
        ),
    ]);
    let mut manifest = Manifest {
        id: String::new(),
        repo_id: "repo".into(),
        trunk_id: "legacy".into(),
        created_at_ms: harness.clock.now_ms(),
        parent: None,
        base_commit: None,
        classification_version: 0,
        ignore_patterns: Vec::new(),
        files: files.clone(),
    };
    manifest.id = manifest_id(&manifest).unwrap();
    let overlay = Overlay {
        snapshot: manifest,
        upserts: files,
        deletes: Vec::new(),
    };
    authority
        .acquire("repo", "legacy", harness.clock.now_ms(), 1_000)
        .unwrap();
    authority
        .publish(&overlay, "legacy", harness.clock.now_ms())
        .unwrap();
    authority.release("repo", "legacy").unwrap();

    let first = harness.first();
    let second = harness.second();
    first.pull(&authority, &harness.clock).unwrap();
    second.pull(&authority, &harness.clock).unwrap();
    harness.clock.advance(1_000);
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();

    assert_eq!(
        fs::read_to_string(harness.second_path.join("target/cache.bin")).unwrap(),
        "legacy synced cache\n"
    );
}

#[test]
fn interrupted_upload_never_advances_the_head() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let bytes = b"orphaned partial sync";
    let hash = blake3::hash(bytes).to_hex().to_string();
    authority.put_chunk(&hash, bytes).unwrap();
    drop(authority);

    let restarted = harness.authority();
    assert_eq!(restarted.head("repo").unwrap(), None);
    assert!(restarted.has_chunk(&hash).unwrap());
}

#[test]
fn authority_lease_generation_increases_on_takeover() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let first = authority
        .acquire("repo", "macbook", harness.clock.now_ms(), 10)
        .unwrap();
    harness.clock.advance(11);
    let second = authority
        .acquire("repo", "linuxbox", harness.clock.now_ms(), 10)
        .unwrap();
    assert!(matches!((first, second), (
        AcquireResult::Acquired(first),
        AcquireResult::Acquired(second)
    ) if second.generation > first.generation));
}

#[test]
fn tcp_authority_transports_a_snapshot() {
    let harness = Harness::plain();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let authority = harness.authority();
    let key = TransportKey::from_bytes([7; 32]);
    let server_key = key.clone();
    std::thread::spawn(move || {
        pando::transport::serve_listener(listener, authority, server_key).unwrap()
    });
    let mut remote = RemoteAuthority::new(address.to_string(), key);
    fs::write(harness.first_path.join("network.txt"), "over tcp\n").unwrap();

    let first = harness.first();
    let second = harness.second();
    first.push(&mut remote, &harness.clock).unwrap();
    first.release(&mut remote).unwrap();
    second.pull(&remote, &harness.clock).unwrap();

    assert_eq!(
        fs::read_to_string(harness.second_path.join("network.txt")).unwrap(),
        "over tcp\n"
    );
}

#[test]
fn tcp_authority_rejects_a_client_with_the_wrong_key() {
    let harness = Harness::plain();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let authority = harness.authority();
    std::thread::spawn(move || {
        pando::transport::serve_listener(listener, authority, TransportKey::from_bytes([1; 32]))
            .unwrap()
    });
    let remote = RemoteAuthority::new(address.to_string(), TransportKey::from_bytes([2; 32]));

    let error = remote.head("repo").unwrap_err();
    assert!(
        format!("{error:#}").contains("secure authority handshake"),
        "{error:#}"
    );
}

#[test]
fn git_branch_stash_index_and_dirty_files_follow_the_user() {
    let root = tempfile::tempdir().unwrap();
    let remote = root.path().join("remote.git");
    let macbook = root.path().join("macbook");
    let linuxbox = root.path().join("linuxbox");
    git(root.path(), &["init", "--bare", remote.to_str().unwrap()]);
    git(&remote, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    git(
        root.path(),
        &["init", "-b", "main", macbook.to_str().unwrap()],
    );
    git(&macbook, &["config", "user.email", "pando@example.test"]);
    git(&macbook, &["config", "user.name", "Pando Test"]);
    fs::write(macbook.join("tracked.txt"), "base\n").unwrap();
    git(&macbook, &["add", "tracked.txt"]);
    git(&macbook, &["commit", "-m", "base"]);
    git(
        &macbook,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git(&macbook, &["push", "-u", "origin", "main"]);
    git(
        root.path(),
        &[
            "clone",
            remote.to_str().unwrap(),
            linuxbox.to_str().unwrap(),
        ],
    );
    git(&macbook, &["switch", "-c", "feature"]);
    fs::write(macbook.join("stashed.txt"), "stash me\n").unwrap();
    git(&macbook, &["stash", "push", "-u", "-m", "portable stash"]);
    fs::write(macbook.join("tracked.txt"), "dirty working tree\n").unwrap();
    fs::write(macbook.join("untracked.txt"), "also follows\n").unwrap();

    let mut authority = FileAuthority::open(root.path().join("authority")).unwrap();
    let clock = VirtualClock::at(42_000);
    let first = Trunk::open_with_state(
        &macbook,
        "git-repo",
        "macbook",
        root.path().join("trunks/macbook"),
    )
    .unwrap();
    let second = Trunk::open_with_state(
        &linuxbox,
        "git-repo",
        "linuxbox",
        root.path().join("trunks/linuxbox"),
    )
    .unwrap();
    first.push(&mut authority, &clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &clock).unwrap();

    assert_eq!(
        fs::read_to_string(linuxbox.join("tracked.txt")).unwrap(),
        "dirty working tree\n"
    );
    assert_eq!(
        fs::read_to_string(linuxbox.join("untracked.txt")).unwrap(),
        "also follows\n"
    );
    assert_eq!(
        git_output(&linuxbox, &["branch", "--show-current"]),
        "feature"
    );
    assert!(git_output(&linuxbox, &["stash", "list"]).contains("portable stash"));
}

fn git(cwd: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_output(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
