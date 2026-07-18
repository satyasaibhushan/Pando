use crate::authority::Authority;
use crate::clock::SystemClock;
use crate::sync::{PullResult, PushResult, Trunk};
use anyhow::Result;
use notify::{Event, RecursiveMode, Watcher};
use std::path::Component;
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
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            quiescence: Duration::from_millis(750),
            idle_release: Duration::from_secs(3),
            poll_interval: Duration::from_secs(1),
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

    let clock = SystemClock;
    report_pull(trunk.pull(authority.as_ref(), &clock));
    let mut dirty_at = None;
    let mut last_activity = None;
    let mut last_poll = Instant::now();
    let mut lease_released = true;

    while running.load(Ordering::SeqCst) {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(event)) if relevant(&event) => {
                if std::env::var_os("PANDO_DEBUG").is_some() {
                    eprintln!("watch event: {:?} {:?}", event.kind, event.paths);
                }
                let now = Instant::now();
                dirty_at = Some(now);
                last_activity = Some(now);
            }
            Ok(Err(error)) => eprintln!("watch error: {error}"),
            _ => {}
        }

        if dirty_at.is_some_and(|at| at.elapsed() >= options.quiescence) {
            match trunk.push(authority.as_mut(), &clock) {
                Ok(result) => {
                    lease_released = matches!(
                        result,
                        PushResult::LeaseHeld { .. } | PushResult::Diverged { .. }
                    );
                    println!("{}", describe_push(&result));
                }
                Err(error) => eprintln!("snapshot failed: {error:#}"),
            }
            dirty_at = None;
        }

        if !lease_released && last_activity.is_some_and(|at| at.elapsed() >= options.idle_release) {
            if let Err(error) = trunk.release(authority.as_mut()) {
                eprintln!("lease release failed: {error:#}");
            } else {
                lease_released = true;
            }
        }

        if dirty_at.is_none() && last_poll.elapsed() >= options.poll_interval {
            report_pull(trunk.pull(authority.as_ref(), &clock));
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
            short(snapshot),
            chunks_uploaded,
            exposure_bytes
        ),
        PushResult::NoChanges { snapshot } => format!("no changes ({})", short(snapshot)),
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
    }
}

pub fn describe_pull(result: &PullResult) -> String {
    match result {
        PullResult::Applied {
            snapshot,
            chunks_downloaded,
        } => format!("applied {} ({} chunks)", short(snapshot), chunks_downloaded),
        PullResult::NoSnapshots => "authority has no snapshots".into(),
        PullResult::UpToDate { snapshot } => format!("up to date ({})", short(snapshot)),
        PullResult::Diverged {
            local_head,
            authority_head,
        } => format!(
            "pull refused: dirty local head {local_head:?}, authority {}",
            short(authority_head)
        ),
    }
}

fn report_pull(result: Result<PullResult>) {
    match result {
        Ok(result @ (PullResult::Applied { .. } | PullResult::Diverged { .. })) => {
            println!("{}", describe_pull(&result))
        }
        Ok(_) => {}
        Err(error) => eprintln!("pull failed: {error:#}"),
    }
}

fn relevant(event: &Event) -> bool {
    event.paths.iter().any(|path| {
        !path
            .components()
            .any(|part| part == Component::Normal(".pando".as_ref()))
    })
}

fn short(value: &str) -> &str {
    &value[..value.len().min(12)]
}
