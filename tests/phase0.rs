use pando::Clock;
use pando::authority::{AcquireResult, Authority, FileAuthority};
use pando::clock::VirtualClock;
use pando::sync::{PullResult, PushResult, Trunk};
use pando::transport::RemoteAuthority;
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
    std::thread::spawn(move || pando::transport::serve_listener(listener, authority).unwrap());
    let mut remote = RemoteAuthority::new(address.to_string());
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
