use crate::authority::Authority;
use crate::classify::{Classifier, global_rules_path};
use crate::clock::SystemClock;
use crate::config::DeviceConfig;
use crate::model::short_id;
use crate::rehydrate::Hydrator;
use crate::sync::{PullResult, PushResult, Trunk};
use crate::transport::{RemoteAuthority, TransportKey};
use anyhow::{Context, Result};
use notify::{Event, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};

const DEVICE_SYNC_WORKERS: usize = 2;
const DEVICE_POLL_INTERVAL: Duration = Duration::from_secs(60);
const DEVICE_FULL_SCAN_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const DEVICE_RETRY_INTERVAL: Duration = Duration::from_secs(30);

pub struct WatchOptions {
    pub quiescence: Duration,
    pub idle_release: Duration,
    pub poll_interval: Duration,
    pub full_scan_interval: Duration,
    pub fetch_interval: Duration,
    pub escape_interval: Duration,
    pub escape_key: Option<TransportKey>,
    pub escape_remote: Option<String>,
    pub rehydrate: bool,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            quiescence: Duration::from_millis(750),
            idle_release: Duration::from_secs(3),
            poll_interval: Duration::from_secs(30),
            full_scan_interval: Duration::from_secs(15 * 60),
            fetch_interval: Duration::from_secs(10 * 60),
            escape_interval: Duration::ZERO,
            escape_key: None,
            escape_remote: None,
            rehydrate: false,
        }
    }
}

pub fn watch(trunk: Trunk, authority: Box<dyn Authority>, options: WatchOptions) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let signal = running.clone();
    ctrlc::set_handler(move || signal.store(false, Ordering::SeqCst))?;
    watch_until(trunk, authority, options, running)
}

pub fn watch_until(
    trunk: Trunk,
    mut authority: Box<dyn Authority>,
    options: WatchOptions,
    running: Arc<AtomicBool>,
) -> Result<()> {
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
    let hydrator = options
        .rehydrate
        .then(|| Hydrator::open(trunk.repo()))
        .transpose()?;
    let mut async_hydrator = hydrator.map(AsyncHydrator::new);
    let mut initial_sync_succeeded = false;
    if running.load(Ordering::SeqCst) {
        match trunk.pull(authority.as_ref(), &clock) {
            Ok(result) => {
                let should_push = matches!(
                    result,
                    PullResult::NoSnapshots | PullResult::UpToDate { .. }
                );
                if report_pull(Ok(result))
                    && let Some(hydrator) = async_hydrator.as_mut()
                {
                    hydrator.trigger();
                }
                if should_push {
                    match push_and_release(&trunk, authority.as_mut(), &clock) {
                        Ok(()) => initial_sync_succeeded = true,
                        Err(error) => eprintln!("initial snapshot failed: {error:#}"),
                    }
                } else {
                    initial_sync_succeeded = true;
                }
            }
            Err(error) => eprintln!("initial pull failed: {error:#}"),
        }
    }
    let mut dirty_at = None;
    let mut last_activity = None;
    let mut last_poll = Instant::now();
    let now = Instant::now();
    let mut last_full_scan = if initial_sync_succeeded {
        now
    } else {
        now.checked_sub(options.full_scan_interval).unwrap_or(now)
    };
    let mut last_fetch = Instant::now();
    let mut last_escape = Instant::now();
    let fetch_running = Arc::new(AtomicBool::new(false));
    let (fetch_sender, fetch_receiver) = mpsc::channel::<Result<crate::git::FetchReport>>();
    let mut lease_released = true;

    while running.load(Ordering::SeqCst) {
        if let Some(hydrator) = async_hydrator.as_mut() {
            hydrator.poll();
        }
        if let Ok(report) = fetch_receiver.try_recv() {
            fetch_running.store(false, Ordering::SeqCst);
            match report {
                Ok(report) => {
                    for change in report.changes {
                        let movement = if change.forced {
                            "non-fast-forward"
                        } else if change.after.is_none() {
                            "deleted"
                        } else {
                            "updated"
                        };
                        println!("remote {} {movement}", change.reference);
                        if let Some(rescue_ref) = change.rescue_ref {
                            println!("rescued previous Git base as {rescue_ref}");
                        }
                    }
                }
                Err(error) => eprintln!("git fetch failed: {error:#}"),
            }
        }
        if dirty_at.is_none()
            && !options.fetch_interval.is_zero()
            && last_fetch.elapsed() >= options.fetch_interval
            && fetch_running
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            let repo = trunk.repo().to_owned();
            let sender = fetch_sender.clone();
            std::thread::spawn(move || {
                let _ = sender.send(crate::git::fetch_remotes(&repo));
            });
            last_fetch = Instant::now();
        }
        if dirty_at.is_none()
            && !options.escape_interval.is_zero()
            && last_escape.elapsed() >= options.escape_interval
        {
            if let Some(key) = options.escape_key.as_ref() {
                match crate::escape::export(
                    trunk.repo(),
                    trunk.repo_id(),
                    authority.as_ref(),
                    key,
                    options.escape_remote.as_deref(),
                ) {
                    Ok(report) if report.reused => {
                        println!("escape ref already protects {}", short_id(&report.snapshot));
                    }
                    Ok(report) => println!(
                        "escape ref {} protects {} ({} encrypted bytes)",
                        report.reference,
                        short_id(&report.snapshot),
                        report.bytes
                    ),
                    Err(error) => eprintln!("escape export failed: {error:#}"),
                }
            }
            last_escape = Instant::now();
        }
        let event_wait = if dirty_at.is_some() {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(1)
        };
        match receiver.recv_timeout(event_wait) {
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
            if report_pull(trunk.pull(authority.as_ref(), &clock))
                && let Some(hydrator) = async_hydrator.as_mut()
            {
                hydrator.trigger();
            }
            last_poll = Instant::now();
        }
    }
    trunk.release(authority.as_mut())?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum DeviceJobKind {
    Initial,
    Push,
    Pull,
    FullScan,
}

#[derive(Clone, Copy, Debug)]
struct DeviceJob {
    workspace: usize,
    kind: DeviceJobKind,
}

#[derive(Debug)]
struct DeviceJobResult {
    workspace: usize,
    kind: DeviceJobKind,
    result: Result<()>,
}

#[derive(Clone, Debug)]
struct DeviceWorkspace {
    label: String,
    path: PathBuf,
    id: String,
}

struct DeviceSchedule {
    classifier: Classifier,
    dirty_at: Option<Instant>,
    initial_due: Option<Instant>,
    retry: Option<(Instant, DeviceJobKind)>,
    queued: bool,
    next_poll: Instant,
    next_full_scan: Instant,
}

/// Supervise every joined repository with one filesystem watcher and a fixed
/// worker pool. The process and thread count stay constant as folders grow.
pub fn watch_device(config: DeviceConfig, rehydrate: bool, running: Arc<AtomicBool>) -> Result<()> {
    let workspaces = Arc::new(
        config
            .shares
            .iter()
            .flat_map(|share| {
                share.workspaces.iter().map(|workspace| DeviceWorkspace {
                    label: format!("{}/{}", share.name, workspace.name),
                    path: config.workspace_path(share, workspace),
                    id: workspace.id.clone(),
                })
            })
            .collect::<Vec<_>>(),
    );
    println!(
        "Pando daemon managing {} workspace(s) with one watcher and {DEVICE_SYNC_WORKERS} sync workers",
        workspaces.len()
    );
    if workspaces.is_empty() {
        while running.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(1));
        }
        return Ok(());
    }

    let global_rules = global_rules_path()?;
    let (event_sender, event_receiver) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = event_sender.send(event);
    })?;
    for workspace in workspaces.iter() {
        watcher
            .watch(&workspace.path, RecursiveMode::Recursive)
            .with_context(|| format!("watch {}", workspace.path.display()))?;
    }
    if let Some(parent) = global_rules.parent()
        && parent.is_dir()
    {
        watcher.watch(parent, RecursiveMode::NonRecursive)?;
    }

    let now = Instant::now();
    let mut schedules = workspaces
        .iter()
        .enumerate()
        .map(|(index, workspace)| {
            Ok(DeviceSchedule {
                classifier: Classifier::load(&workspace.path)?,
                dirty_at: None,
                initial_due: Some(now + Duration::from_millis(index as u64 * 100)),
                retry: None,
                queued: false,
                next_poll: now
                    + DEVICE_POLL_INTERVAL
                    + spread(DEVICE_POLL_INTERVAL, index, workspaces.len()),
                next_full_scan: now
                    + DEVICE_FULL_SCAN_INTERVAL
                    + spread(DEVICE_FULL_SCAN_INTERVAL, index, workspaces.len()),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let (job_sender, job_receiver) = mpsc::channel::<DeviceJob>();
    let job_receiver = Arc::new(Mutex::new(job_receiver));
    let (result_sender, result_receiver) = mpsc::channel::<DeviceJobResult>();
    let device_key = config.device_key()?;
    let network_key = config.network_key().ok();
    for index in 0..DEVICE_SYNC_WORKERS {
        let receiver = job_receiver.clone();
        let sender = result_sender.clone();
        let workspaces = workspaces.clone();
        let authority = RemoteAuthority::new(
            config.authority.clone(),
            config.device_id.clone(),
            device_key.clone(),
        );
        let device_id = config.device_id.clone();
        let network_key = network_key.clone();
        thread::Builder::new()
            .name(format!("pando-sync-{index}"))
            .spawn(move || {
                loop {
                    let job = {
                        let receiver = receiver.lock().unwrap_or_else(|error| error.into_inner());
                        receiver.recv()
                    };
                    let Ok(job) = job else {
                        break;
                    };
                    let result = run_device_job(
                        &workspaces[job.workspace],
                        job.kind,
                        &device_id,
                        &authority,
                        network_key.as_ref(),
                        rehydrate,
                    );
                    if sender
                        .send(DeviceJobResult {
                            workspace: job.workspace,
                            kind: job.kind,
                            result,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })?;
    }
    drop(result_sender);

    while running.load(Ordering::SeqCst) {
        match event_receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(Ok(event)) => {
                record_device_event(&event, &workspaces, &mut schedules, &global_rules)
            }
            Ok(Err(error)) => eprintln!("watch error: {error}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("filesystem watcher stopped")
            }
        }
        while let Ok(event) = event_receiver.try_recv() {
            match event {
                Ok(event) => {
                    record_device_event(&event, &workspaces, &mut schedules, &global_rules)
                }
                Err(error) => eprintln!("watch error: {error}"),
            }
        }
        while let Ok(completed) = result_receiver.try_recv() {
            schedules[completed.workspace].queued = false;
            if let Err(error) = completed.result {
                schedules[completed.workspace].retry =
                    Some((Instant::now() + DEVICE_RETRY_INTERVAL, completed.kind));
                eprintln!(
                    "{} {:?} failed: {error:#}",
                    workspaces[completed.workspace].label, completed.kind
                );
            }
        }

        let now = Instant::now();
        for (index, schedule) in schedules.iter_mut().enumerate() {
            if schedule.queued {
                continue;
            }
            let kind = if let Some(due) = schedule.initial_due {
                if now >= due {
                    schedule.initial_due = None;
                    Some(DeviceJobKind::Initial)
                } else {
                    None
                }
            } else if let Some((due, kind)) = schedule.retry {
                if now >= due {
                    schedule.retry = None;
                    Some(kind)
                } else {
                    None
                }
            } else if schedule
                .dirty_at
                .is_some_and(|dirty| dirty.elapsed() >= Duration::from_millis(750))
            {
                schedule.dirty_at = None;
                Some(DeviceJobKind::Push)
            } else if now >= schedule.next_full_scan {
                schedule.next_full_scan = now + DEVICE_FULL_SCAN_INTERVAL;
                Some(DeviceJobKind::FullScan)
            } else if now >= schedule.next_poll {
                schedule.next_poll = now + DEVICE_POLL_INTERVAL;
                Some(DeviceJobKind::Pull)
            } else {
                None
            };
            if let Some(kind) = kind {
                schedule.queued = true;
                job_sender.send(DeviceJob {
                    workspace: index,
                    kind,
                })?;
            }
        }
    }
    Ok(())
}

fn record_device_event(
    event: &Event,
    workspaces: &[DeviceWorkspace],
    schedules: &mut [DeviceSchedule],
    global_rules: &std::path::Path,
) {
    for (index, workspace) in workspaces.iter().enumerate() {
        let rules_changed = classification_rules_changed(event, &workspace.path, global_rules);
        if rules_changed {
            match Classifier::load(&workspace.path) {
                Ok(classifier) => schedules[index].classifier = classifier,
                Err(error) => eprintln!(
                    "{} classification reload failed: {error:#}",
                    workspace.label
                ),
            }
        }
        if rules_changed || relevant(event, &workspace.path, &schedules[index].classifier) {
            schedules[index].dirty_at = Some(Instant::now());
        }
    }
}

fn run_device_job(
    workspace: &DeviceWorkspace,
    kind: DeviceJobKind,
    device_id: &str,
    authority: &RemoteAuthority,
    network_key: Option<&TransportKey>,
    rehydrate: bool,
) -> Result<()> {
    let clock = SystemClock;
    match kind {
        DeviceJobKind::Initial => {
            let trunk = Trunk::open(&workspace.path, &workspace.id, device_id)?;
            let pull = trunk.pull(authority, &clock)?;
            let should_push = initial_should_push(&pull);
            if matches!(
                pull,
                PullResult::Applied { .. } | PullResult::Diverged { .. }
            ) {
                println!("{}: {}", workspace.label, describe_pull(&pull));
                if rehydrate && matches!(pull, PullResult::Applied { .. }) {
                    println!(
                        "{}: {}",
                        workspace.label,
                        Hydrator::open(&workspace.path)?.run_changed(false)?
                    );
                }
            }
            if should_push {
                publish_device_workspace(workspace, &trunk, authority, network_key, &clock)?;
            }
            Ok(())
        }
        DeviceJobKind::Push | DeviceJobKind::FullScan => {
            let trunk = Trunk::open(&workspace.path, &workspace.id, device_id)?;
            publish_device_workspace(workspace, &trunk, authority, network_key, &clock)
        }
        DeviceJobKind::Pull => {
            let trunk = Trunk::open(&workspace.path, &workspace.id, device_id)?;
            let result = trunk.pull(authority, &clock)?;
            if matches!(
                result,
                PullResult::Applied { .. } | PullResult::Diverged { .. }
            ) {
                println!("{}: {}", workspace.label, describe_pull(&result));
            }
            if rehydrate && matches!(result, PullResult::Applied { .. }) {
                println!(
                    "{}: {}",
                    workspace.label,
                    Hydrator::open(&workspace.path)?.run_changed(false)?
                );
            }
            Ok(())
        }
    }
}

fn publish_device_workspace(
    workspace: &DeviceWorkspace,
    trunk: &Trunk,
    authority: &RemoteAuthority,
    network_key: Option<&TransportKey>,
    clock: &SystemClock,
) -> Result<()> {
    let mut authority = authority.clone();
    if !authority.forks(&workspace.id)?.is_empty() {
        return Ok(());
    }
    let result = trunk.push(&mut authority, clock)?;
    let published = matches!(result, PushResult::Published { .. });
    if !matches!(result, PushResult::NoChanges { .. }) {
        println!("{}: {}", workspace.label, describe_push(&result));
    }
    if matches!(result, PushResult::LeaseHeld { .. }) {
        anyhow::bail!("write postponed while another device holds the lease");
    }
    if !matches!(
        result,
        PushResult::LeaseHeld { .. } | PushResult::Diverged { .. } | PushResult::Conflicted { .. }
    ) {
        trunk.release(&mut authority)?;
    }
    if published && let Some(key) = network_key {
        match crate::escape::export(
            &workspace.path,
            &workspace.id,
            &authority,
            key,
            Some("origin"),
        ) {
            Ok(report) if !report.reused => println!(
                "{}: escape ref protects {}",
                workspace.label,
                short_id(&report.snapshot)
            ),
            Ok(_) => {}
            Err(error) => eprintln!("{} escape export failed: {error:#}", workspace.label),
        }
    }
    Ok(())
}

fn spread(interval: Duration, index: usize, total: usize) -> Duration {
    interval.mul_f64(index as f64 / total.max(1) as f64)
}

fn initial_should_push(result: &PullResult) -> bool {
    !matches!(result, PullResult::Applied { .. })
}

fn push_and_release(
    trunk: &Trunk,
    authority: &mut dyn Authority,
    clock: &SystemClock,
) -> Result<()> {
    let result = trunk.push(authority, clock)?;
    println!("{}", describe_push(&result));
    if !matches!(
        result,
        PushResult::LeaseHeld { .. } | PushResult::Diverged { .. } | PushResult::Conflicted { .. }
    ) {
        trunk.release(authority)?;
    }
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

struct AsyncHydrator {
    hydrator: Option<Hydrator>,
    pending: bool,
    sender: mpsc::Sender<(Hydrator, Result<crate::rehydrate::HydrationSummary>)>,
    receiver: mpsc::Receiver<(Hydrator, Result<crate::rehydrate::HydrationSummary>)>,
}

impl AsyncHydrator {
    fn new(hydrator: Hydrator) -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            hydrator: Some(hydrator),
            pending: false,
            sender,
            receiver,
        }
    }

    fn trigger(&mut self) {
        let Some(mut hydrator) = self.hydrator.take() else {
            self.pending = true;
            return;
        };
        let sender = self.sender.clone();
        std::thread::spawn(move || {
            let result = hydrator.run_changed(false);
            let _ = sender.send((hydrator, result));
        });
    }

    fn poll(&mut self) {
        let Ok((hydrator, result)) = self.receiver.try_recv() else {
            return;
        };
        match result {
            Ok(summary) => println!("{summary}"),
            Err(error) => eprintln!("rehydration failed: {error:#}"),
        }
        self.hydrator = Some(hydrator);
        if std::mem::take(&mut self.pending) {
            self.trigger();
        }
    }
}

fn report_pull(result: Result<PullResult>) -> bool {
    match result {
        Ok(result @ PullResult::Applied { .. }) => {
            println!("{}", describe_pull(&result));
            true
        }
        Ok(result @ PullResult::Diverged { .. }) => {
            println!("{}", describe_pull(&result));
            false
        }
        Ok(_) => false,
        Err(error) => {
            eprintln!("pull failed: {error:#}");
            false
        }
    }
}

fn relevant(event: &Event, repo: &std::path::Path, classifier: &Classifier) -> bool {
    event.paths.iter().any(|path| {
        let Ok(relative) = path.strip_prefix(repo) else {
            return false;
        };
        !is_git_object_churn(relative) && classifier.is_portable(relative, path.is_dir())
    })
}

fn is_git_object_churn(path: &std::path::Path) -> bool {
    let mut components = path.components();
    components
        .next()
        .is_some_and(|part| part.as_os_str() == ".git")
        && components
            .next()
            .is_some_and(|part| part.as_os_str() == "objects")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_defaults_scale_to_many_workspaces() {
        let options = WatchOptions::default();
        assert!(options.poll_interval >= Duration::from_secs(30));
        assert!(options.full_scan_interval >= Duration::from_secs(10 * 60));
        assert!(options.fetch_interval >= Duration::from_secs(10 * 60));
    }

    #[test]
    fn git_object_database_changes_do_not_retrigger_sync() {
        assert!(is_git_object_churn(std::path::Path::new(
            ".git/objects/pack/pack-a.pack"
        )));
        assert!(is_git_object_churn(std::path::Path::new(
            ".git/objects/pando-pack-123/pack-a.idx"
        )));
        assert!(!is_git_object_churn(std::path::Path::new(
            ".git/refs/heads/main"
        )));
        assert!(!is_git_object_churn(std::path::Path::new("src/main.rs")));
    }

    #[test]
    fn periodic_work_is_spread_across_its_interval() {
        let interval = Duration::from_secs(60);
        assert_eq!(spread(interval, 0, 100), Duration::ZERO);
        assert_eq!(spread(interval, 50, 100), Duration::from_secs(30));
        assert!(DEVICE_FULL_SCAN_INTERVAL >= Duration::from_secs(6 * 60 * 60));
        assert!(DEVICE_RETRY_INTERVAL >= Duration::from_secs(30));
    }

    #[test]
    fn initial_divergence_continues_into_safe_merge_push() {
        let result = PullResult::Diverged {
            local_head: None,
            authority_head: "authority-head".into(),
        };
        assert!(initial_should_push(&result));
    }
}
