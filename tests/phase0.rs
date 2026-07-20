use pando::Clock;
use pando::authority::{AcquireResult, Authority, FileAuthority};
use pando::clock::{SystemClock, VirtualClock};
use pando::model::{FileEntry, FileKind, Manifest, Overlay};
use pando::snapshot::manifest_id;
use pando::store::ChunkStore;
use pando::sync::{PullResult, PushResult, Trunk};
use pando::transport::{RemoteAuthority, TransportKey};
use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
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

fn create_overlapping_fork(harness: &Harness, authority: &mut FileAuthority) -> (Trunk, String) {
    let first = harness.first();
    let second = harness.second();
    fs::write(harness.first_path.join("shared.txt"), "base\n").unwrap();
    first.push(authority, &harness.clock).unwrap();
    first.release(authority).unwrap();
    second.pull(authority, &harness.clock).unwrap();
    harness.clock.advance(1_000);
    fs::write(harness.first_path.join("shared.txt"), "authority\n").unwrap();
    first.push(authority, &harness.clock).unwrap();
    first.release(authority).unwrap();
    fs::write(harness.second_path.join("shared.txt"), "fork\n").unwrap();
    let fork = match second.push(authority, &harness.clock).unwrap() {
        PushResult::Conflicted { fork, .. } => fork,
        result => panic!("unexpected push result: {result:?}"),
    };
    (second, fork)
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
fn first_join_unions_disjoint_existing_folders_on_both_devices() {
    let harness = Harness::plain();
    fs::create_dir_all(harness.first_path.join("host-only")).unwrap();
    fs::write(harness.first_path.join("host-only/work.txt"), "host\n").unwrap();
    fs::create_dir_all(harness.second_path.join("client-only")).unwrap();
    fs::write(
        harness.second_path.join("client-only/notes.txt"),
        "client\n",
    )
    .unwrap();
    let mut authority = harness.authority();
    let first = harness.first();
    let second = harness.second();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();

    let joined = second.push(&mut authority, &harness.clock).unwrap();
    assert!(matches!(joined, PushResult::Published { .. }));
    second.release(&mut authority).unwrap();
    first.pull(&authority, &harness.clock).unwrap();

    for root in [&harness.first_path, &harness.second_path] {
        assert_eq!(
            fs::read_to_string(root.join("host-only/work.txt")).unwrap(),
            "host\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("client-only/notes.txt")).unwrap(),
            "client\n"
        );
    }
}

#[test]
fn first_join_preserves_same_path_conflicts_as_a_pending_fork() {
    let harness = Harness::plain();
    fs::write(harness.first_path.join("same.txt"), "host\n").unwrap();
    fs::write(harness.second_path.join("same.txt"), "client\n").unwrap();
    let mut authority = harness.authority();
    let first = harness.first();
    let second = harness.second();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();

    let conflict = second.push(&mut authority, &harness.clock).unwrap();
    let fork = match conflict {
        PushResult::Conflicted { fork, paths, .. } => {
            assert_eq!(paths, ["same.txt"]);
            fork
        }
        result => panic!("unexpected join result: {result:?}"),
    };
    assert_eq!(authority.forks("repo").unwrap(), [fork]);
    assert_eq!(
        fs::read_to_string(harness.second_path.join("same.txt")).unwrap(),
        "client\n"
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
fn expired_lease_preserves_a_stale_first_join_as_a_fork() {
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
        PushResult::Conflicted { paths, .. } if paths == ["work.txt"]
    ));
    assert_eq!(
        fs::read_to_string(harness.second_path.join("work.txt")).unwrap(),
        "offline second\n"
    );
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
fn reconciliation_can_keep_the_authority_tree() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let (second, fork) = create_overlapping_fork(&harness, &mut authority);

    second
        .reconcile(
            &mut authority,
            &harness.clock,
            &fork,
            pando::sync::ReconcileChoice::Authority,
        )
        .unwrap();

    assert_eq!(
        fs::read_to_string(harness.second_path.join("shared.txt")).unwrap(),
        "authority\n"
    );
    assert!(authority.forks("repo").unwrap().is_empty());
}

#[test]
fn reconciliation_can_promote_the_fork_tree() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let (second, fork) = create_overlapping_fork(&harness, &mut authority);

    let result = second
        .reconcile(
            &mut authority,
            &harness.clock,
            &fork,
            pando::sync::ReconcileChoice::Fork,
        )
        .unwrap();

    assert_eq!(authority.head("repo").unwrap(), Some(result.head));
    assert_eq!(
        fs::read_to_string(harness.second_path.join("shared.txt")).unwrap(),
        "fork\n"
    );
    assert!(authority.forks("repo").unwrap().is_empty());
}

#[test]
fn reconciliation_can_publish_a_manually_edited_tree() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let (second, fork) = create_overlapping_fork(&harness, &mut authority);
    fs::write(harness.second_path.join("shared.txt"), "manual merge\n").unwrap();

    second
        .reconcile(
            &mut authority,
            &harness.clock,
            &fork,
            pando::sync::ReconcileChoice::Manual,
        )
        .unwrap();

    let head = authority.head("repo").unwrap().unwrap();
    let overlay = authority.overlay(&head).unwrap();
    let chunk = &overlay.snapshot.files["shared.txt"].chunk;
    assert_eq!(authority.get_chunk(chunk).unwrap(), b"manual merge\n");
    assert!(authority.forks("repo").unwrap().is_empty());
}

#[test]
fn reconciliation_can_keep_both_versions_as_separate_files() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let (second, fork) = create_overlapping_fork(&harness, &mut authority);

    let conflicts = second.fork_conflicts(&authority, &fork).unwrap();
    assert_eq!(
        conflicts
            .iter()
            .map(|conflict| conflict.path.as_str())
            .collect::<Vec<_>>(),
        ["shared.txt"]
    );
    second
        .reconcile_keep_both(&mut authority, &harness.clock, &fork)
        .unwrap();

    assert_eq!(
        fs::read_to_string(harness.second_path.join("shared.txt")).unwrap(),
        "fork\n"
    );
    assert_eq!(
        fs::read_to_string(harness.second_path.join("shared.txt.pando-other")).unwrap(),
        "authority\n"
    );
    assert!(authority.forks("repo").unwrap().is_empty());
}

#[test]
fn keep_both_still_auto_merges_non_overlapping_files() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let first = harness.first();
    let second = harness.second();
    fs::write(harness.first_path.join("shared.txt"), "base\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    second.pull(&authority, &harness.clock).unwrap();

    harness.clock.advance(1_000);
    fs::write(harness.first_path.join("shared.txt"), "authority\n").unwrap();
    fs::write(harness.first_path.join("authority-only.txt"), "remote\n").unwrap();
    first.push(&mut authority, &harness.clock).unwrap();
    first.release(&mut authority).unwrap();
    fs::write(harness.second_path.join("shared.txt"), "fork\n").unwrap();
    fs::write(harness.second_path.join("local-only.txt"), "local\n").unwrap();
    let fork = match second.push(&mut authority, &harness.clock).unwrap() {
        PushResult::Conflicted { fork, .. } => fork,
        result => panic!("unexpected push result: {result:?}"),
    };

    assert_eq!(
        second
            .fork_conflicts(&authority, &fork)
            .unwrap()
            .into_iter()
            .map(|conflict| conflict.path)
            .collect::<Vec<_>>(),
        ["shared.txt"]
    );
    second
        .reconcile_keep_both(&mut authority, &harness.clock, &fork)
        .unwrap();

    assert_eq!(
        fs::read_to_string(harness.second_path.join("authority-only.txt")).unwrap(),
        "remote\n"
    );
    assert_eq!(
        fs::read_to_string(harness.second_path.join("local-only.txt")).unwrap(),
        "local\n"
    );
    assert!(
        !harness
            .second_path
            .join("authority-only.txt.pando-other")
            .exists()
    );
}

#[test]
fn reconciliation_refuses_to_overwrite_edits_made_after_the_fork() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let (second, fork) = create_overlapping_fork(&harness, &mut authority);
    fs::write(harness.second_path.join("shared.txt"), "newer edit\n").unwrap();

    let error = second
        .reconcile(
            &mut authority,
            &harness.clock,
            &fork,
            pando::sync::ReconcileChoice::Authority,
        )
        .unwrap_err()
        .to_string();

    assert!(error.contains("working tree changed after fork"), "{error}");
    assert_eq!(
        fs::read_to_string(harness.second_path.join("shared.txt")).unwrap(),
        "newer edit\n"
    );
    assert_eq!(authority.forks("repo").unwrap(), [fork]);
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

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn pando(data_home: &Path, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_pando"))
        .env("PANDO_DATA_HOME", data_home)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "pando {args:?} failed:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn cli_onboarding_flows_from_up_to_a_joined_folder() {
    let root = tempfile::tempdir().unwrap();
    let host_home = root.path().join("host-state");
    let guest_home = root.path().join("guest-state");
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let address = format!("127.0.0.1:{port}");

    // First device creates the network, then runs the authority.
    pando(
        &host_home,
        &[
            "up",
            "--no-services",
            "--name",
            "macbook",
            "--bind",
            &address,
        ],
    );
    let _serve = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_pando"))
            .env("PANDO_DATA_HOME", &host_home)
            .args(["serve", "--bind", &address])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    for attempt in 0.. {
        match std::net::TcpStream::connect(&address) {
            Ok(_) => break,
            Err(_) if attempt < 50 => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => panic!("authority never came up: {error}"),
        }
    }

    // Host shares a folder with real content.
    let folder = root.path().join("code");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("work.txt"), "over the wire\n").unwrap();
    pando(
        &host_home,
        &["share", folder.to_str().unwrap(), "--no-services"],
    );

    // Host mints an invite; second device enrolls with the printed code.
    let invite = pando(&host_home, &["invite"]);
    let code = invite
        .split_whitespace()
        .skip_while(|word| *word != "--code")
        .nth(1)
        .expect("invite output contains a code");
    pando(
        &guest_home,
        &[
            "up",
            "--no-services",
            "--name",
            "linuxbox",
            "--to",
            &address,
            "--code",
            code,
        ],
    );
    assert!(pando(&guest_home, &["devices"]).contains("macbook"));

    // Guest joins the shared folder and gets the files.
    let landing = root.path().join("guest-code");
    pando(
        &guest_home,
        &["join", "code", landing.to_str().unwrap(), "--no-services"],
    );
    assert_eq!(
        fs::read_to_string(landing.join("work.txt")).unwrap(),
        "over the wire\n"
    );

    // A one-shot sync releases its lease so other devices can push next.
    pando(&guest_home, &["sync"]);
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(guest_home.join("device.json")).unwrap()).unwrap();
    let workspace_id = config["shares"][0]["workspaces"][0]["id"].as_str().unwrap();
    let mut authority = FileAuthority::open(host_home.join("authority")).unwrap();
    assert!(matches!(
        authority
            .acquire(workspace_id, "probe", SystemClock.now_ms(), 1_000)
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

const TCP_DEVICE_ID: &str = "aabbccdd00112233aabbccdd00112233";

fn tcp_registry(directory: &Path, device_key: &TransportKey) -> pando::registry::Registry {
    pando::registry::Registry::create(
        directory,
        &pando::registry::random_hex(16).unwrap(),
        "127.0.0.1:7337",
        &TransportKey::from_bytes([9; 32]),
        TCP_DEVICE_ID,
        "macbook",
        device_key,
        1_000,
    )
    .unwrap()
}

#[test]
fn tcp_authority_transports_a_snapshot() {
    let harness = Harness::plain();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let authority = harness.authority();
    let key = TransportKey::from_bytes([7; 32]);
    let registry = tcp_registry(harness._root.path(), &key);
    std::thread::spawn(move || {
        pando::transport::serve_listener(listener, authority, registry).unwrap()
    });
    let mut remote = RemoteAuthority::new(address.to_string(), TCP_DEVICE_ID, key);
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
fn tcp_authority_moves_an_over_budget_chunk_in_parts() {
    let harness = Harness::plain();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let authority = harness.authority();
    let key = TransportKey::from_bytes([7; 32]);
    let registry = tcp_registry(harness._root.path(), &key);
    std::thread::spawn(move || {
        pando::transport::serve_listener(listener, authority, registry).unwrap()
    });
    let mut remote = RemoteAuthority::new(address.to_string(), TCP_DEVICE_ID, key);

    // One chunk over the transfer budget (moved in parts) plus small ones
    // (moved in a batch).
    let big: Vec<u8> = (0..pando::authority::TRANSFER_BUDGET_BYTES + 4096)
        .map(|index| (index % 251) as u8)
        .collect();
    fs::write(harness.first_path.join("big.bin"), &big).unwrap();
    fs::write(harness.first_path.join("small.txt"), "batched\n").unwrap();

    let first = harness.first();
    let second = harness.second();
    first.push(&mut remote, &harness.clock).unwrap();
    first.release(&mut remote).unwrap();
    second.pull(&remote, &harness.clock).unwrap();

    assert_eq!(fs::read(harness.second_path.join("big.bin")).unwrap(), big);
    assert_eq!(
        fs::read_to_string(harness.second_path.join("small.txt")).unwrap(),
        "batched\n"
    );
}

#[test]
fn tcp_authority_rejects_a_client_with_the_wrong_key() {
    let harness = Harness::plain();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let authority = harness.authority();
    let registry = tcp_registry(harness._root.path(), &TransportKey::from_bytes([1; 32]));
    std::thread::spawn(move || {
        pando::transport::serve_listener(listener, authority, registry).unwrap()
    });
    let remote = RemoteAuthority::new(
        address.to_string(),
        TCP_DEVICE_ID,
        TransportKey::from_bytes([2; 32]),
    );

    let error = remote.head("repo").unwrap_err();
    assert!(
        format!("{error:#}").contains("secure authority handshake"),
        "{error:#}"
    );
}

#[test]
fn enrollment_code_admits_a_new_device_and_revocation_expels_it() {
    let harness = Harness::plain();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let authority = harness.authority();
    let host_key = TransportKey::from_bytes([7; 32]);
    let registry = tcp_registry(harness._root.path(), &host_key);
    std::thread::spawn(move || {
        pando::transport::serve_listener(listener, authority, registry).unwrap()
    });
    let host = RemoteAuthority::new(address.clone(), TCP_DEVICE_ID, host_key);

    // The host mints a code; a new device enrolls with it once.
    let invite = host.invite().unwrap();
    let grant = pando::transport::enroll(&address, &invite.code, "linuxbox").unwrap();
    assert_ne!(grant.device_id, TCP_DEVICE_ID);
    assert!(pando::transport::enroll(&address, &invite.code, "impostor").is_err());

    // The minted credentials work for normal RPCs.
    let joined = RemoteAuthority::new(
        address.clone(),
        grant.device_id.clone(),
        TransportKey::from_hex(&grant.device_key).unwrap(),
    );
    assert_eq!(joined.devices().unwrap().len(), 2);

    // A wrong code never yields credentials.
    let second = host.invite().unwrap();
    assert!(pando::transport::enroll(&address, "wrong-code99", "sneak").is_err());
    assert_ne!(second.code, invite.code);

    // Revocation deletes the device's key; its next call is refused.
    host.revoke_device(&grant.device_id).unwrap();
    assert!(joined.devices().is_err());
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

#[test]
fn git_history_travels_as_a_thin_pack_and_refetches_from_the_remote() {
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
    fs::write(macbook.join("pushed.txt"), "pushed\n").unwrap();
    git(&macbook, &["add", "pushed.txt"]);
    git(&macbook, &["commit", "-m", "pushed history"]);
    git(
        &macbook,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git(&macbook, &["push", "-u", "origin", "main"]);
    fs::write(macbook.join("local.txt"), "local only\n").unwrap();
    git(&macbook, &["add", "local.txt"]);
    git(&macbook, &["commit", "-m", "local only commit"]);
    let local_commit = git_output(&macbook, &["rev-parse", "HEAD"]);

    let mut authority = FileAuthority::open(root.path().join("authority")).unwrap();
    let clock = VirtualClock::at(42_000);
    let first = Trunk::open_with_state(
        &macbook,
        "git-repo",
        "macbook",
        root.path().join("trunks/macbook"),
    )
    .unwrap();
    first.push(&mut authority, &clock).unwrap();
    clock.advance(1_000);
    let repeat = first.push(&mut authority, &clock).unwrap();
    assert!(
        matches!(repeat, PushResult::NoChanges { .. }),
        "an unchanged repository must repack deterministically: {repeat:?}"
    );
    first.release(&mut authority).unwrap();

    let head = authority.head("git-repo").unwrap().unwrap();
    let overlay = authority.overlay(&head).unwrap();
    let object_paths: Vec<_> = overlay
        .snapshot
        .files
        .keys()
        .filter(|path| path.starts_with(".git/objects/"))
        .collect();
    assert!(!object_paths.is_empty());
    assert!(
        object_paths
            .iter()
            .all(|path| path.starts_with(".git/objects/pack/pack-")),
        "snapshot carries the object database instead of a thin pack: {object_paths:?}"
    );

    fs::create_dir_all(&linuxbox).unwrap();
    let second = Trunk::open_with_state(
        &linuxbox,
        "git-repo",
        "linuxbox",
        root.path().join("trunks/linuxbox"),
    )
    .unwrap();
    second.pull(&authority, &clock).unwrap();
    assert_eq!(git_output(&linuxbox, &["rev-parse", "HEAD"]), local_commit);
    assert!(git_output(&linuxbox, &["log", "--format=%s"]).contains("pushed history"));
    assert_eq!(
        fs::read_to_string(linuxbox.join("pushed.txt")).unwrap(),
        "pushed\n"
    );

    fs::remove_dir_all(&remote).unwrap();
    let edgebox = root.path().join("edgebox");
    fs::create_dir_all(&edgebox).unwrap();
    let third = Trunk::open_with_state(
        &edgebox,
        "git-repo",
        "edgebox",
        root.path().join("trunks/edgebox"),
    )
    .unwrap();
    let error = format!("{:#}", third.pull(&authority, &clock).unwrap_err());
    assert!(
        error.contains("fetch history for missing commit"),
        "expected a loud fetch failure, got: {error}"
    );
}

#[test]
fn fetch_reports_fast_forward_and_forced_remote_movement() {
    let root = tempfile::tempdir().unwrap();
    let remote = root.path().join("remote.git");
    let source = root.path().join("source");
    let clone = root.path().join("clone");
    git(root.path(), &["init", "--bare", remote.to_str().unwrap()]);
    git(&remote, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    git(
        root.path(),
        &["init", "-b", "main", source.to_str().unwrap()],
    );
    git(&source, &["config", "user.email", "pando@example.test"]);
    git(&source, &["config", "user.name", "Pando Test"]);
    fs::write(source.join("work.txt"), "one\n").unwrap();
    git(&source, &["add", "work.txt"]);
    git(&source, &["commit", "-m", "one"]);
    git(
        &source,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git(&source, &["push", "-u", "origin", "main"]);
    git(
        root.path(),
        &["clone", remote.to_str().unwrap(), clone.to_str().unwrap()],
    );

    fs::write(source.join("work.txt"), "two\n").unwrap();
    git(&source, &["commit", "-am", "two"]);
    git(&source, &["push", "origin", "main"]);
    let fast_forward = pando::git::fetch_remotes(&clone).unwrap();
    assert_eq!(fast_forward.changes.len(), 1);
    assert_eq!(
        fast_forward.changes[0].reference,
        "refs/remotes/origin/main"
    );
    assert!(!fast_forward.changes[0].forced);
    assert!(fast_forward.changes[0].rescue_ref.is_none());
    let endangered = fast_forward.changes[0].after.clone().unwrap();

    git(&source, &["reset", "--hard", "HEAD~1"]);
    fs::write(source.join("work.txt"), "alternate\n").unwrap();
    git(&source, &["commit", "-am", "alternate"]);
    git(&source, &["push", "--force", "origin", "main"]);
    let forced = pando::git::fetch_remotes(&clone).unwrap();
    assert_eq!(forced.changes.len(), 1);
    assert!(forced.changes[0].forced);
    assert_eq!(forced.changes[0].before.as_deref(), Some(&*endangered));
    let rescue_ref = forced.changes[0].rescue_ref.as_deref().unwrap();
    assert_eq!(git_output(&clone, &["rev-parse", rescue_ref]), endangered);

    git(&clone, &["reflog", "expire", "--expire=now", "--all"]);
    git(&clone, &["gc", "--prune=now"]);
    assert_eq!(git_output(&clone, &["rev-parse", rescue_ref]), endangered);
    git(
        &clone,
        &["cat-file", "-e", &format!("{endangered}^{{tree}}")],
    );
}

#[test]
fn encrypted_escape_ref_restores_without_the_authority() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().join("repo");
    let remote = root.path().join("remote.git");
    let authority_path = root.path().join("authority");
    let state = root.path().join("state");
    let recovery_repo = root.path().join("recovery");
    let restored = root.path().join("restored");
    git(root.path(), &["init", "-b", "main", repo.to_str().unwrap()]);
    git(root.path(), &["init", "--bare", remote.to_str().unwrap()]);
    git(
        &repo,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    fs::write(repo.join("unfinished.txt"), "secret working tree\n").unwrap();

    let mut authority = FileAuthority::open(&authority_path).unwrap();
    let trunk = Trunk::open_with_state(&repo, "escape-repo", "macbook", state).unwrap();
    trunk.push(&mut authority, &VirtualClock::at(42)).unwrap();
    trunk.release(&mut authority).unwrap();
    let key = TransportKey::from_bytes([7; 32]);
    let report =
        pando::escape::export(&repo, "escape-repo", &authority, &key, Some("origin")).unwrap();
    assert!(report.pushed);
    assert_eq!(
        git_output(&remote, &["rev-parse", &report.reference]).len(),
        40
    );
    let encrypted = Command::new("git")
        .arg("-C")
        .arg(&remote)
        .args(["show", &format!("{}:snapshot.pando", report.reference)])
        .output()
        .unwrap()
        .stdout;
    assert!(
        !encrypted
            .windows(b"secret working tree".len())
            .any(|window| window == b"secret working tree")
    );
    assert!(
        !Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["rev-parse", "--verify", &report.reference])
            .output()
            .unwrap()
            .status
            .success()
    );

    let remote_commit = git_output(&remote, &["rev-parse", &report.reference]);
    let reused =
        pando::escape::export(&repo, "escape-repo", &authority, &key, Some("origin")).unwrap();
    assert!(reused.reused);
    assert_eq!(
        git_output(&remote, &["rev-parse", &report.reference]),
        remote_commit
    );

    fs::remove_dir_all(&authority_path).unwrap();
    git(
        root.path(),
        &["init", "-b", "main", recovery_repo.to_str().unwrap()],
    );
    git(
        &recovery_repo,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    pando::escape::fetch_ref(&recovery_repo, "origin", &report.reference).unwrap();
    let restored_report =
        pando::escape::restore(&recovery_repo, &report.reference, &key, &restored).unwrap();
    assert_eq!(restored_report.snapshot, report.snapshot);
    assert_eq!(
        fs::read_to_string(restored.join("unfinished.txt")).unwrap(),
        "secret working tree\n"
    );
    let wrong_key = TransportKey::from_bytes([8; 32]);
    assert!(
        pando::escape::restore(
            &recovery_repo,
            &report.reference,
            &wrong_key,
            &root.path().join("wrong-key")
        )
        .unwrap_err()
        .to_string()
        .contains("authentication failed")
    );
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn materialization_refuses_case_colliding_snapshot_paths() {
    let root = tempfile::tempdir().unwrap();
    let store = ChunkStore::new(root.path().join("chunks")).unwrap();
    let lower = store.put(b"lower\n").unwrap();
    let upper = store.put(b"upper\n").unwrap();
    let files = BTreeMap::from([
        (
            "Readme".to_owned(),
            FileEntry {
                chunk: lower,
                size: 6,
                kind: FileKind::Regular,
                executable: false,
            },
        ),
        (
            "README".to_owned(),
            FileEntry {
                chunk: upper,
                size: 6,
                kind: FileKind::Regular,
                executable: false,
            },
        ),
    ]);
    let mut manifest = Manifest {
        id: String::new(),
        repo_id: "repo".into(),
        trunk_id: "linux".into(),
        created_at_ms: 1,
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
    let destination = root.path().join("destination");
    let error = pando::materialize_overlay(&destination, &overlay, &store).unwrap_err();
    assert!(error.to_string().contains("collide"));
    assert!(!destination.exists());
}

#[test]
fn authority_gc_reclaims_only_resolved_forks_and_orphan_chunks() {
    let harness = Harness::plain();
    let mut authority = harness.authority();
    let (_trunk, fork) = create_overlapping_fork(&harness, &mut authority);
    authority.resolve_fork("repo", &fork).unwrap();
    let head = authority.head("repo").unwrap().unwrap();

    let preview = authority.garbage_collect(false).unwrap();
    assert!(!preview.applied);
    assert_eq!(preview.overlays, 1);
    assert!(preview.chunks >= 1);
    assert!(authority.overlay(&fork).is_ok());

    let applied = authority.garbage_collect(true).unwrap();
    assert!(applied.applied);
    assert_eq!(applied.overlays, preview.overlays);
    assert_eq!(applied.chunks, preview.chunks);
    assert!(authority.overlay(&fork).is_err());
    assert!(authority.overlay(&head).is_ok());
    authority.verify().unwrap();
}

#[test]
fn pushed_base_chunks_compact_and_reconstruct_for_pull_restore_and_escape() {
    let root = tempfile::tempdir().unwrap();
    let remote = root.path().join("remote.git");
    let first_repo = root.path().join("first");
    let second_repo = root.path().join("second");
    let recovery_repo = root.path().join("recovery");
    let authority_path = root.path().join("authority");
    let state = root.path().join("state");
    git(root.path(), &["init", "--bare", remote.to_str().unwrap()]);
    git(
        root.path(),
        &["init", "-b", "main", first_repo.to_str().unwrap()],
    );
    git(&first_repo, &["config", "user.email", "pando@example.test"]);
    git(&first_repo, &["config", "user.name", "Pando Test"]);
    fs::write(first_repo.join("base.txt"), "absorbed by Git\n").unwrap();
    git(&first_repo, &["add", "base.txt"]);
    git(&first_repo, &["commit", "-m", "base"]);
    git(
        &first_repo,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git(&first_repo, &["push", "-u", "origin", "main"]);
    fs::write(first_repo.join("dirty.txt"), "only in Pando\n").unwrap();

    let mut authority = FileAuthority::open(&authority_path).unwrap();
    let first = Trunk::open_with_state(&first_repo, "compact-repo", "macbook", state.join("first"))
        .unwrap();
    first.push(&mut authority, &VirtualClock::at(100)).unwrap();
    first.release(&mut authority).unwrap();
    let head = authority.head("compact-repo").unwrap().unwrap();
    let overlay = authority.overlay(&head).unwrap();
    let base_chunk = &overlay.snapshot.files["base.txt"].chunk;
    assert!(!overlay.upserts.contains_key("base.txt"));
    assert!(overlay.upserts.contains_key("dirty.txt"));
    assert!(!authority.has_chunk(base_chunk).unwrap());
    authority
        .put_chunk(base_chunk, b"absorbed by Git\n")
        .unwrap();
    let compacted = authority.garbage_collect(true).unwrap();
    assert!(compacted.chunks >= 1);
    assert!(!authority.has_chunk(base_chunk).unwrap());
    authority.verify().unwrap();

    fs::create_dir(&second_repo).unwrap();
    let second =
        Trunk::open_with_state(&second_repo, "compact-repo", "second", state.join("second"))
            .unwrap();
    second.pull(&authority, &VirtualClock::at(200)).unwrap();
    assert_eq!(
        fs::read_to_string(second_repo.join("base.txt")).unwrap(),
        "absorbed by Git\n"
    );
    assert_eq!(
        fs::read_to_string(second_repo.join("dirty.txt")).unwrap(),
        "only in Pando\n"
    );

    let restored = root.path().join("restored");
    authority.restore(&head, &restored).unwrap();
    assert_eq!(
        fs::read_to_string(restored.join("base.txt")).unwrap(),
        "absorbed by Git\n"
    );

    let key = TransportKey::from_bytes([9; 32]);
    let escape = pando::escape::export(
        &first_repo,
        "compact-repo",
        &authority,
        &key,
        Some("origin"),
    )
    .unwrap();
    git(
        root.path(),
        &["init", "-b", "main", recovery_repo.to_str().unwrap()],
    );
    git(
        &recovery_repo,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    pando::escape::fetch_ref(&recovery_repo, "origin", &escape.reference).unwrap();
    let escaped = root.path().join("escaped");
    pando::escape::restore(&recovery_repo, &escape.reference, &key, &escaped).unwrap();
    assert_eq!(
        fs::read_to_string(escaped.join("base.txt")).unwrap(),
        "absorbed by Git\n"
    );
    assert_eq!(
        fs::read_to_string(escaped.join("dirty.txt")).unwrap(),
        "only in Pando\n"
    );
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
