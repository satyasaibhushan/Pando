use crate::authority::Authority;
use crate::classify::{Classifier, global_rules_path};
use crate::clock::SystemClock;
use crate::config::{DeviceConfig, ShareConfig, WorkspaceConfig};
use crate::model::short_id;
use crate::registry::ShareRecord;
use crate::rehydrate::Hydrator;
use crate::sync::{PullResult, PushResult, Trunk};
use crate::transport::{RemoteAuthority, TransportKey};
use anyhow::{Context, Result};
use notify::{Event, RecursiveMode, Watcher};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::{Duration, Instant};

const DEVICE_SYNC_WORKERS: usize = 2;
const DEVICE_POLL_INTERVAL: Duration = Duration::from_secs(60);
const DEVICE_STARTUP_SCAN_WINDOW: Duration = Duration::from_secs(10 * 60);
const DEVICE_FULL_SCAN_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const DEVICE_RETRY_INTERVAL: Duration = Duration::from_secs(30);
const DEVICE_SHARE_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const DEVICE_DISCOVERY_QUIESCENCE: Duration = Duration::from_secs(2);

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

enum DeviceJob {
    Sync {
        index: usize,
        workspace: Arc<DeviceWorkspace>,
        kind: DeviceJobKind,
    },
    Refresh {
        shares: Vec<ShareConfig>,
    },
}

enum DeviceJobResult {
    Sync {
        index: usize,
        kind: DeviceJobKind,
        result: Result<DeviceJobOutcome>,
    },
    Refresh(Result<Vec<ShareAddition>>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeviceJobOutcome {
    Complete,
    DeferredStartupScan,
}

#[derive(Clone, Debug)]
struct DeviceWorkspace {
    label: String,
    path: PathBuf,
    id: String,
}

impl DeviceWorkspace {
    fn new(config: &DeviceConfig, share: &ShareConfig, workspace: &WorkspaceConfig) -> Self {
        Self {
            label: format!("{}/{}", share.name, workspace.name),
            path: config.workspace_path(share, workspace),
            id: workspace.id.clone(),
        }
    }
}

/// Workspaces a share gained since the daemon last looked: repositories that
/// appeared under a folder this device hosts, or workspaces the host added to
/// a folder this device joined.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareAddition {
    pub share: String,
    pub workspaces: Vec<WorkspaceConfig>,
}

struct RefreshPlan {
    additions: Vec<ShareAddition>,
    upserts: Vec<ShareRecord>,
}

fn plan_share_refresh(
    network_id: &str,
    device_name: &str,
    shares: &[ShareConfig],
    records: &[ShareRecord],
    discover: impl Fn(&Path) -> Result<Vec<PathBuf>>,
) -> Result<RefreshPlan> {
    let mut plan = RefreshPlan {
        additions: Vec::new(),
        upserts: Vec::new(),
    };
    for share in shares {
        let Some(record) = records.iter().find(|record| record.name == share.name) else {
            continue;
        };
        // A folder that is itself the repository has nothing beneath it to add.
        if share
            .workspaces
            .iter()
            .any(|workspace| workspace.relative_path == Path::new("."))
        {
            continue;
        }
        let hosted_here = record.host == device_name;
        let candidates = if hosted_here {
            discover(&share.path)?
                .into_iter()
                .filter(|relative| relative.as_path() != Path::new("."))
                .map(|relative| {
                    crate::config::workspace(network_id, &share.name, &share.path, relative)
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            record.workspaces.clone()
        };
        let added = candidates
            .into_iter()
            .filter(|candidate| {
                !share
                    .workspaces
                    .iter()
                    .any(|existing| existing.id == candidate.id)
            })
            .collect::<Vec<_>>();
        if added.is_empty() {
            continue;
        }
        if hosted_here {
            let mut record = record.clone();
            record.workspaces = share.workspaces.iter().chain(&added).cloned().collect();
            plan.upserts.push(record);
        } else {
            for workspace in &added {
                crate::config::validate_workspace(workspace)?;
            }
        }
        plan.additions.push(ShareAddition {
            share: share.name.clone(),
            workspaces: added,
        });
    }
    Ok(plan)
}

fn refresh_shares(
    network_id: &str,
    device_name: &str,
    shares: &[ShareConfig],
    authority: &RemoteAuthority,
) -> Result<Vec<ShareAddition>> {
    let records = authority.shares()?;
    let plan = plan_share_refresh(
        network_id,
        device_name,
        shares,
        &records,
        crate::config::discover,
    )?;
    for record in plan.upserts {
        authority.upsert_share(record)?;
    }
    Ok(plan.additions)
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

impl DeviceSchedule {
    fn starting(
        workspace: &DeviceWorkspace,
        now: Instant,
        index: usize,
        total: usize,
    ) -> Result<Self> {
        Ok(Self {
            classifier: Classifier::load(&workspace.path)?,
            dirty_at: None,
            initial_due: Some(now + Duration::from_millis(index as u64 * 100)),
            retry: None,
            queued: false,
            next_poll: now + DEVICE_POLL_INTERVAL + spread(DEVICE_POLL_INTERVAL, index, total),
            next_full_scan: now
                + DEVICE_FULL_SCAN_INTERVAL
                + spread(DEVICE_FULL_SCAN_INTERVAL, index, total),
        })
    }
}

/// Supervise every joined repository with one filesystem watcher and a fixed
/// worker pool. The process and thread count stay constant as folders grow,
/// and repositories that appear later are picked up without a restart.
pub fn watch_device(
    mut config: DeviceConfig,
    rehydrate: bool,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let mut workspaces = config
        .shares
        .iter()
        .flat_map(|share| {
            share
                .workspaces
                .iter()
                .map(|workspace| Arc::new(DeviceWorkspace::new(&config, share, workspace)))
        })
        .collect::<Vec<_>>();
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
    // Watching each shared folder as a whole also shows repositories arriving
    // between the known workspaces.
    for share in &config.shares {
        watcher
            .watch(&share.path, RecursiveMode::Recursive)
            .with_context(|| format!("watch {}", share.path.display()))?;
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
        .map(|(index, workspace)| DeviceSchedule::starting(workspace, now, index, workspaces.len()))
        .collect::<Result<Vec<_>>>()?;

    let (job_sender, job_receiver) = mpsc::channel::<DeviceJob>();
    let job_receiver = Arc::new(Mutex::new(job_receiver));
    let (result_sender, result_receiver) = mpsc::channel::<DeviceJobResult>();
    let device_key = config.device_key()?;
    let network_key = config.network_key().ok();
    for index in 0..DEVICE_SYNC_WORKERS {
        let receiver = job_receiver.clone();
        let sender = result_sender.clone();
        let authority = RemoteAuthority::new(
            config.authority.clone(),
            config.device_id.clone(),
            device_key.clone(),
        );
        let device_id = config.device_id.clone();
        let network_id = config.network_id.clone();
        let device_name = config.device_name.clone();
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
                    let result =
                        match job {
                            DeviceJob::Sync {
                                index,
                                workspace,
                                kind,
                            } => DeviceJobResult::Sync {
                                index,
                                kind,
                                result: run_device_job(
                                    &workspace,
                                    kind,
                                    &device_id,
                                    &authority,
                                    network_key.as_ref(),
                                    rehydrate,
                                ),
                            },
                            DeviceJob::Refresh { shares } => DeviceJobResult::Refresh(
                                refresh_shares(&network_id, &device_name, &shares, &authority),
                            ),
                        };
                    if sender.send(result).is_err() {
                        break;
                    }
                }
            })?;
    }
    drop(result_sender);

    let mut next_refresh = Instant::now();
    let mut refresh_dirty_at: Option<Instant> = None;
    let mut refresh_queued = false;
    while running.load(Ordering::SeqCst) {
        match event_receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(Ok(event)) => record_device_event(
                &event,
                &config.shares,
                &workspaces,
                &mut schedules,
                &global_rules,
                &mut refresh_dirty_at,
            ),
            Ok(Err(error)) => eprintln!("watch error: {error}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("filesystem watcher stopped")
            }
        }
        while let Ok(event) = event_receiver.try_recv() {
            match event {
                Ok(event) => record_device_event(
                    &event,
                    &config.shares,
                    &workspaces,
                    &mut schedules,
                    &global_rules,
                    &mut refresh_dirty_at,
                ),
                Err(error) => eprintln!("watch error: {error}"),
            }
        }
        while let Ok(completed) = result_receiver.try_recv() {
            match completed {
                DeviceJobResult::Sync {
                    index,
                    kind,
                    result,
                } => {
                    schedules[index].queued = false;
                    match result {
                        Ok(DeviceJobOutcome::Complete) => {}
                        Ok(DeviceJobOutcome::DeferredStartupScan) => {
                            schedules[index].next_full_scan = Instant::now()
                                + spread(DEVICE_STARTUP_SCAN_WINDOW, index, workspaces.len());
                        }
                        Err(error) => {
                            schedules[index].retry =
                                Some((Instant::now() + DEVICE_RETRY_INTERVAL, kind));
                            eprintln!("{} {:?} failed: {error:#}", workspaces[index].label, kind);
                        }
                    }
                }
                DeviceJobResult::Refresh(result) => {
                    refresh_queued = false;
                    match result {
                        Ok(additions) => {
                            adopt_additions(&mut config, additions, &mut workspaces, &mut schedules)
                        }
                        Err(error) => {
                            next_refresh = Instant::now() + DEVICE_RETRY_INTERVAL;
                            eprintln!("share refresh failed: {error:#}");
                        }
                    }
                }
            }
        }

        let now = Instant::now();
        let discovery_due =
            refresh_dirty_at.is_some_and(|dirty| dirty.elapsed() >= DEVICE_DISCOVERY_QUIESCENCE);
        if !refresh_queued && (now >= next_refresh || discovery_due) {
            refresh_dirty_at = None;
            refresh_queued = true;
            next_refresh = now + DEVICE_SHARE_REFRESH_INTERVAL;
            job_sender.send(DeviceJob::Refresh {
                shares: config.shares.clone(),
            })?;
        }
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
                job_sender.send(DeviceJob::Sync {
                    index,
                    workspace: workspaces[index].clone(),
                    kind,
                })?;
            }
        }
    }
    Ok(())
}

fn adopt_additions(
    config: &mut DeviceConfig,
    additions: Vec<ShareAddition>,
    workspaces: &mut Vec<Arc<DeviceWorkspace>>,
    schedules: &mut Vec<DeviceSchedule>,
) {
    let mut changed = false;
    for addition in additions {
        let Some(position) = config
            .shares
            .iter()
            .position(|share| share.name == addition.share)
        else {
            continue;
        };
        for workspace in addition.workspaces {
            if config.shares[position]
                .workspaces
                .iter()
                .any(|existing| existing.id == workspace.id)
            {
                continue;
            }
            let device_workspace =
                DeviceWorkspace::new(config, &config.shares[position], &workspace);
            let schedule = fs::create_dir_all(&device_workspace.path)
                .map_err(anyhow::Error::from)
                .and_then(|()| DeviceSchedule::starting(&device_workspace, Instant::now(), 0, 1));
            match schedule {
                Ok(schedule) => {
                    println!("{}: added", device_workspace.label);
                    schedules.push(schedule);
                    workspaces.push(Arc::new(device_workspace));
                    config.shares[position].workspaces.push(workspace);
                    changed = true;
                }
                Err(error) => eprintln!("{}: cannot add: {error:#}", device_workspace.label),
            }
        }
    }
    if changed && let Err(error) = crate::config::save(config) {
        eprintln!("device config save failed: {error:#}");
    }
}

fn record_device_event(
    event: &Event,
    shares: &[ShareConfig],
    workspaces: &[Arc<DeviceWorkspace>],
    schedules: &mut [DeviceSchedule],
    global_rules: &Path,
    refresh_dirty_at: &mut Option<Instant>,
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
    if event
        .paths
        .iter()
        .any(|path| between_workspaces(path, shares, workspaces))
    {
        *refresh_dirty_at = Some(Instant::now());
    }
}

/// A change beneath a shared folder that no workspace claims may be a new
/// repository.
fn between_workspaces(
    path: &Path,
    shares: &[ShareConfig],
    workspaces: &[Arc<DeviceWorkspace>],
) -> bool {
    shares.iter().any(|share| path.starts_with(&share.path))
        && !workspaces
            .iter()
            .any(|workspace| path.starts_with(&workspace.path))
}

fn run_device_job(
    workspace: &DeviceWorkspace,
    kind: DeviceJobKind,
    device_id: &str,
    authority: &RemoteAuthority,
    network_key: Option<&TransportKey>,
    rehydrate: bool,
) -> Result<DeviceJobOutcome> {
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
            Ok(if matches!(pull, PullResult::UpToDate { .. }) {
                DeviceJobOutcome::DeferredStartupScan
            } else {
                DeviceJobOutcome::Complete
            })
        }
        DeviceJobKind::Push | DeviceJobKind::FullScan => {
            let trunk = Trunk::open(&workspace.path, &workspace.id, device_id)?;
            publish_device_workspace(workspace, &trunk, authority, network_key, &clock)?;
            Ok(DeviceJobOutcome::Complete)
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
            Ok(DeviceJobOutcome::Complete)
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
    matches!(
        result,
        PullResult::NoSnapshots | PullResult::Diverged { .. }
    )
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
        assert!(DEVICE_STARTUP_SCAN_WINDOW >= Duration::from_secs(10 * 60));
        assert!(DEVICE_FULL_SCAN_INTERVAL >= Duration::from_secs(6 * 60 * 60));
        assert!(DEVICE_RETRY_INTERVAL >= Duration::from_secs(30));
    }

    const NETWORK: &str = "00112233445566770011223344556677";

    fn code_share(root: &Path, relatives: &[&str]) -> ShareConfig {
        ShareConfig {
            name: "code".into(),
            path: root.to_owned(),
            workspaces: relatives
                .iter()
                .map(|relative| {
                    crate::config::workspace(NETWORK, "code", root, relative.into()).unwrap()
                })
                .collect(),
        }
    }

    fn never_discover(_: &Path) -> Result<Vec<PathBuf>> {
        unreachable!("discovery must not run for this share")
    }

    #[test]
    fn hosted_folder_gains_repositories_that_appear_beneath_it() {
        let root = Path::new("/srv/Code");
        let share = code_share(root, &["apps/one"]);
        let record = ShareRecord {
            name: "code".into(),
            host: "macbook".into(),
            workspaces: share.workspaces.clone(),
        };
        let plan = plan_share_refresh(
            NETWORK,
            "macbook",
            std::slice::from_ref(&share),
            &[record],
            |_| Ok(vec!["apps/one".into(), "apps/two".into()]),
        )
        .unwrap();

        let two = crate::config::workspace(NETWORK, "code", root, "apps/two".into()).unwrap();
        assert_eq!(
            plan.additions,
            vec![ShareAddition {
                share: "code".into(),
                workspaces: vec![two.clone()],
            }]
        );
        assert_eq!(plan.upserts.len(), 1);
        assert_eq!(plan.upserts[0].host, "macbook");
        assert_eq!(
            plan.upserts[0].workspaces,
            vec![share.workspaces[0].clone(), two]
        );
    }

    #[test]
    fn joined_folder_adopts_workspaces_the_host_registered() {
        let root = Path::new("/srv/Code");
        let share = code_share(root, &["apps/one"]);
        let hosted = code_share(root, &["apps/one", "apps/two"]);
        let record = ShareRecord {
            name: "code".into(),
            host: "macbook".into(),
            workspaces: hosted.workspaces.clone(),
        };
        let plan =
            plan_share_refresh(NETWORK, "devbox", &[share], &[record], never_discover).unwrap();

        assert_eq!(
            plan.additions,
            vec![ShareAddition {
                share: "code".into(),
                workspaces: vec![hosted.workspaces[1].clone()],
            }]
        );
        assert!(plan.upserts.is_empty());
    }

    #[test]
    fn unchanged_single_repository_and_unregistered_folders_are_left_alone() {
        let root = Path::new("/srv/Code");
        let single = code_share(root, &["."]);
        let record = ShareRecord {
            name: "code".into(),
            host: "macbook".into(),
            workspaces: single.workspaces.clone(),
        };
        let plan =
            plan_share_refresh(NETWORK, "macbook", &[single], &[record], never_discover).unwrap();
        assert!(plan.additions.is_empty() && plan.upserts.is_empty());

        let unregistered = code_share(root, &["apps/one"]);
        let plan =
            plan_share_refresh(NETWORK, "macbook", &[unregistered], &[], never_discover).unwrap();
        assert!(plan.additions.is_empty() && plan.upserts.is_empty());
    }

    #[test]
    fn only_paths_outside_every_workspace_trigger_discovery() {
        let root = Path::new("/srv/Code");
        let share = code_share(root, &["apps/one"]);
        let config = DeviceConfig::new(
            NETWORK.into(),
            "88990011223344558899001122334455".into(),
            "macbook".into(),
            "127.0.0.1:7337".into(),
        );
        let workspaces = vec![Arc::new(DeviceWorkspace::new(
            &config,
            &share,
            &share.workspaces[0],
        ))];
        let shares = [share];
        assert!(between_workspaces(
            Path::new("/srv/Code/apps/two/.git"),
            &shares,
            &workspaces
        ));
        assert!(!between_workspaces(
            Path::new("/srv/Code/apps/one/src/main.rs"),
            &shares,
            &workspaces
        ));
        assert!(!between_workspaces(
            Path::new("/home/me/.config/pando/ignore"),
            &shares,
            &workspaces
        ));
    }

    #[test]
    fn initial_divergence_continues_into_safe_merge_push() {
        let result = PullResult::Diverged {
            local_head: None,
            authority_head: "authority-head".into(),
        };
        assert!(initial_should_push(&result));
        assert!(!initial_should_push(&PullResult::UpToDate {
            snapshot: "shared-head".into()
        }));
        assert!(initial_should_push(&PullResult::NoSnapshots));
    }
}
