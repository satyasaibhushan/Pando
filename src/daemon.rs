use crate::authority::Authority;
use crate::classify::{Classifier, global_rules_path};
use crate::clock::SystemClock;
use crate::model::short_id;
use crate::rehydrate::Hydrator;
use crate::sync::{PullResult, PushResult, Trunk};
use anyhow::Result;
use notify::{Event, RecursiveMode, Watcher};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

pub struct WatchOptions {
    pub quiescence: Duration,
    pub idle_release: Duration,
    pub poll_interval: Duration,
    pub full_scan_interval: Duration,
    pub rehydrate: bool,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            quiescence: Duration::from_millis(750),
            idle_release: Duration::from_secs(3),
            poll_interval: Duration::from_secs(1),
            full_scan_interval: Duration::from_secs(60),
            rehydrate: false,
        }
    }
}

pub fn watch(trunk: Trunk, mut authority: Box<dyn Authority>, options: WatchOptions) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let signal = running.clone();
    ctrlc::set_handler(move || signal.store(false, Ordering::SeqCst))?;

    let (sender, receiver) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = sender.send(event);
    })?;
    watcher.watch(trunk.repo(), RecursiveMode::Recursive)?;
    let global_rules = global_rules_path()?;
    if let Some(parent) = global_rules.parent()
        && parent.is_dir()
    {
        watcher.watch(parent, RecursiveMode::NonRecursive)?;
    }

    let clock = SystemClock;
    let mut classifier = Classifier::load(trunk.repo())?;
    let mut hydrator = options
        .rehydrate
        .then(|| Hydrator::open(trunk.repo()))
        .transpose()?;
    report_pull(trunk.pull(authority.as_ref(), &clock), hydrator.as_mut());
    let mut dirty_at = None;
    let mut last_activity = None;
    let mut last_poll = Instant::now();
    let mut last_full_scan = Instant::now();
    let mut lease_released = true;

    while running.load(Ordering::SeqCst) {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(event)) => {
                let rules_changed =
                    classification_rules_changed(&event, trunk.repo(), &global_rules);
                if rules_changed {
                    match Classifier::load(trunk.repo()) {
                        Ok(updated) => classifier = updated,
                        Err(error) => eprintln!("classification reload failed: {error:#}"),
                    }
                }
                if rules_changed || relevant(&event, trunk.repo(), &classifier) {
                    if std::env::var_os("PANDO_DEBUG").is_some() {
                        eprintln!("watch event: {:?} {:?}", event.kind, event.paths);
                    }
                    let now = Instant::now();
                    dirty_at = Some(now);
                    last_activity = Some(now);
                }
            }
            Ok(Err(error)) => eprintln!("watch error: {error}"),
            _ => {}
        }

        let quiescent = dirty_at.is_some_and(|at| at.elapsed() >= options.quiescence);
        let integrity_scan =
            dirty_at.is_none() && last_full_scan.elapsed() >= options.full_scan_interval;
        if quiescent || integrity_scan {
            if integrity_scan {
                last_activity = Some(Instant::now());
            }
            match trunk.push(authority.as_mut(), &clock) {
                Ok(result) => {
                    lease_released = matches!(
                        result,
                        PushResult::LeaseHeld { .. }
                            | PushResult::Diverged { .. }
                            | PushResult::Conflicted { .. }
                    );
                    println!("{}", describe_push(&result));
                    if matches!(result, PushResult::NoChanges { .. }) {
                        if let Err(error) = trunk.release(authority.as_mut()) {
                            eprintln!("lease release failed: {error:#}");
                        } else {
                            lease_released = true;
                        }
                    }
                }
                Err(error) => eprintln!("snapshot failed: {error:#}"),
            }
            dirty_at = None;
            last_full_scan = Instant::now();
        }

        if !lease_released && last_activity.is_some_and(|at| at.elapsed() >= options.idle_release) {
            if let Err(error) = trunk.release(authority.as_mut()) {
                eprintln!("lease release failed: {error:#}");
            } else {
                lease_released = true;
            }
        }

        if dirty_at.is_none() && last_poll.elapsed() >= options.poll_interval {
            report_pull(trunk.pull(authority.as_ref(), &clock), hydrator.as_mut());
            last_poll = Instant::now();
        }
    }
    trunk.release(authority.as_mut())?;
    Ok(())
}

pub fn describe_push(result: &PushResult) -> String {
    match result {
        PushResult::Published {
            snapshot,
            chunks_uploaded,
            exposure_bytes,
        } => format!(
            "published {} ({} chunks, {} exposure bytes)",
            short_id(snapshot),
            chunks_uploaded,
            exposure_bytes
        ),
        PushResult::NoChanges { snapshot } => format!("no changes ({})", short_id(snapshot)),
        PushResult::LeaseHeld {
            holder,
            expires_at_ms,
        } => format!("write refused: lease held by {holder} until {expires_at_ms}"),
        PushResult::Diverged {
            local_head,
            authority_head,
        } => format!(
            "write refused: local head {local_head:?} diverged from authority {authority_head:?}"
        ),
        PushResult::Conflicted {
            local_head,
            authority_head,
            fork,
            paths,
        } => format!(
            "reconcile required: fork {} preserves local {}; authority {}; both changed {}",
            short_id(fork),
            short_id(local_head),
            short_id(authority_head),
            paths.join(", ")
        ),
    }
}

pub fn describe_pull(result: &PullResult) -> String {
    match result {
        PullResult::Applied {
            snapshot,
            chunks_downloaded,
        } => format!(
            "applied {} ({} chunks)",
            short_id(snapshot),
            chunks_downloaded
        ),
        PullResult::NoSnapshots => "authority has no snapshots".into(),
        PullResult::UpToDate { snapshot } => format!("up to date ({})", short_id(snapshot)),
        PullResult::Diverged {
            local_head,
            authority_head,
        } => format!(
            "pull refused: dirty local head {local_head:?}, authority {}",
            short_id(authority_head)
        ),
    }
}

fn report_pull(result: Result<PullResult>, hydrator: Option<&mut Hydrator>) {
    match result {
        Ok(result @ PullResult::Applied { .. }) => {
            println!("{}", describe_pull(&result));
            if let Some(hydrator) = hydrator {
                match hydrator.run_changed(false) {
                    Ok(summary) => println!("{summary}"),
                    Err(error) => eprintln!("rehydration failed: {error:#}"),
                }
            }
        }
        Ok(result @ PullResult::Diverged { .. }) => println!("{}", describe_pull(&result)),
        Ok(_) => {}
        Err(error) => eprintln!("pull failed: {error:#}"),
    }
}

fn relevant(event: &Event, repo: &std::path::Path, classifier: &Classifier) -> bool {
    event.paths.iter().any(|path| {
        let Ok(relative) = path.strip_prefix(repo) else {
            return false;
        };
        classifier.is_portable(relative, path.is_dir())
    })
}

fn classification_rules_changed(
    event: &Event,
    repo: &std::path::Path,
    global_rules: &std::path::Path,
) -> bool {
    event.paths.iter().any(|path| {
        path == global_rules
            || path.strip_prefix(repo).ok() == Some(std::path::Path::new(".pandoignore"))
    })
}
