use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use pando::authority::{Authority, FileAuthority};
use pando::classify::Classifier;
use pando::clock::{Clock, SystemClock};
use pando::config::{DeviceConfig, ShareConfig};
use pando::daemon::{WatchOptions, describe_pull, describe_push};
use pando::registry::Registry;
use pando::rehydrate::Hydrator;
use pando::sync::{ReconcileChoice, Trunk};
use pando::transport::{RemoteAuthority, TransportKey};
use std::fs;
use std::net::{IpAddr, UdpSocket};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(version, about = "Your working tree, on every device")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Bring this device onto a Pando network (creates one on first use)
    Up {
        /// Address of an existing network's authority, from `pando invite`
        #[arg(long, requires = "code")]
        to: Option<String>,
        /// One-time enrollment code, from `pando invite`
        #[arg(long, requires = "to")]
        code: Option<String>,
        /// Name for this device (defaults to the hostname)
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "0.0.0.0:7337", hide = true)]
        bind: String,
        /// Skip installing background services
        #[arg(long)]
        no_services: bool,
    },
    /// Print a one-time code that lets another device join
    Invite,
    /// Host a folder on the network so other devices can join it
    Share {
        folder: PathBuf,
        /// Name other devices use to join (defaults to the folder's name)
        #[arg(long)]
        name: Option<String>,
        /// Skip installing background services
        #[arg(long)]
        no_services: bool,
    },
    /// Bring a hosted folder onto this device
    Join {
        name: String,
        /// Where to put the folder (defaults to ~/Pando/<name>)
        path: Option<PathBuf>,
        /// Skip installing background services
        #[arg(long)]
        no_services: bool,
    },
    /// List the folders hosted on this network
    Folders,
    /// List the devices on this network
    Devices,
    /// Remove a device from the network
    Revoke { device: String },
    /// Show sync state for every joined folder
    Status,
    /// Push every joined folder now
    Sync,
    /// Open the dashboard
    Tui,
    #[command(hide = true)]
    Serve {
        #[arg(long, default_value = "0.0.0.0:7337")]
        bind: String,
        #[arg(long)]
        data: Option<PathBuf>,
    },
    #[command(hide = true)]
    Watch {
        workspace: String,
        #[arg(long)]
        rehydrate: bool,
    },
    #[command(hide = true)]
    Fetch {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
    #[command(hide = true)]
    Escape {
        #[command(subcommand)]
        command: EscapeCommand,
    },
    #[command(hide = true)]
    Reconcile {
        #[arg(default_value = ".")]
        folder: PathBuf,
        #[arg(long)]
        fork: Option<String>,
        #[arg(long, value_enum, requires = "fork")]
        choice: Option<CliReconcileChoice>,
    },
    #[command(hide = true)]
    Hydrate {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        force: bool,
    },
    #[command(hide = true)]
    Classify {
        path: PathBuf,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        directory: bool,
    },
    #[command(hide = true)]
    Verify {
        #[arg(long)]
        data: Option<PathBuf>,
    },
    #[command(hide = true)]
    Gc {
        #[arg(long)]
        data: Option<PathBuf>,
        #[arg(long)]
        apply: bool,
    },
    #[command(hide = true)]
    Restore {
        #[arg(long)]
        data: Option<PathBuf>,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        destination: PathBuf,
    },
    #[command(hide = true)]
    Demo {
        #[arg(long, default_value = ".pando-demo")]
        root: PathBuf,
    },
}

#[derive(Subcommand)]
enum EscapeCommand {
    Export {
        #[arg(default_value = ".")]
        folder: PathBuf,
        #[arg(long, default_value = "origin")]
        remote: String,
        #[arg(long)]
        local_only: bool,
    },
    Restore {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        workspace_id: String,
        #[arg(long)]
        device_id: String,
        #[arg(long, env = "PANDO_KEY")]
        key: PathBuf,
        #[arg(long)]
        destination: PathBuf,
        #[arg(long)]
        fetch_remote: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliReconcileChoice {
    Authority,
    Fork,
    Manual,
}

fn main() -> Result<()> {
    let Some(command) = Cli::parse().command else {
        return match pando::config::try_load()? {
            Some(config) => pando::tui::run(config),
            None => {
                println!("This device is not on a Pando network yet.");
                println!();
                println!("  pando up                          start a new network here");
                println!(
                    "  pando up --to <addr> --code <c>   join one (get both from `pando invite` on another device)"
                );
                Ok(())
            }
        };
    };
    match command {
        Command::Up {
            to,
            code,
            name,
            bind,
            no_services,
        } => up(to, code, name, &bind, no_services),
        Command::Invite => {
            let config = pando::config::load()?;
            let invite = remote(&config)?.invite()?;
            let minutes = invite
                .expires_at_ms
                .saturating_sub(SystemClock.now_ms())
                .div_ceil(60_000);
            println!("On the new device, run:");
            println!();
            println!("  pando up --to {} --code {}", invite.address, invite.code);
            println!();
            println!("The code works once and expires in {minutes} minutes.");
            Ok(())
        }
        Command::Share {
            folder,
            name,
            no_services,
        } => share(&folder, name, no_services),
        Command::Join {
            name,
            path,
            no_services,
        } => join(&name, path, no_services),
        Command::Folders => {
            let config = pando::config::load()?;
            let shares = remote(&config)?.shares()?;
            if shares.is_empty() {
                println!("no folders yet; host one with `pando share <folder>`");
            }
            for share in shares {
                let joined = match config.share(&share.name) {
                    Some(local) => format!("here at {}", local.path.display()),
                    None => format!("join with `pando join {}`", share.name),
                };
                println!(
                    "{}  hosted by {} · {} workspace(s) · {}",
                    share.name,
                    share.host,
                    share.workspaces.len(),
                    joined
                );
            }
            Ok(())
        }
        Command::Devices => {
            let config = pando::config::load()?;
            for device in remote(&config)?.devices()? {
                println!(
                    "{}  {}{}",
                    &device.id[..12.min(device.id.len())],
                    device.name,
                    if device.id == config.device_id {
                        "  (this device)"
                    } else {
                        ""
                    }
                );
            }
            Ok(())
        }
        Command::Revoke { device } => {
            let config = pando::config::load()?;
            let authority = remote(&config)?;
            let matches: Vec<_> = authority
                .devices()?
                .into_iter()
                .filter(|entry| entry.name == device || entry.id.starts_with(&device))
                .collect();
            let target = match matches.as_slice() {
                [target] => target.clone(),
                [] => bail!("no device named {device}; see `pando devices`"),
                _ => bail!("{device} matches more than one device; use the ID"),
            };
            authority.revoke_device(&target.id)?;
            println!("revoked {} ({})", target.name, &target.id[..12]);
            Ok(())
        }
        Command::Status => {
            let config = pando::config::load()?;
            let authority = remote(&config)?;
            println!(
                "network {} · device {}",
                &config.network_id[..12.min(config.network_id.len())],
                config.device_name
            );
            for share in &config.shares {
                for workspace in &share.workspaces {
                    let status = authority.status(&workspace.id, SystemClock.now_ms())?;
                    let state = if status.forks.is_empty() {
                        "in sync".to_owned()
                    } else {
                        format!("needs decision ({})", status.forks.len())
                    };
                    println!("{}/{}: {state}", share.name, workspace.name);
                }
            }
            Ok(())
        }
        Command::Sync => {
            let config = pando::config::load()?;
            let mut authority = remote(&config)?;
            push_shares(&config, &mut authority, None)
        }
        Command::Tui => pando::tui::run(pando::config::load()?),
        Command::Serve { bind, data } => {
            let data = match data {
                Some(data) => data,
                None => pando::config::authority_data_path()?,
            };
            let registry = Registry::open(&data)?;
            println!(
                "Pando authority for network {} listening on {bind}",
                &registry.network_id()?[..12]
            );
            pando::transport::serve(&bind, FileAuthority::open(&data)?, registry)
        }
        Command::Watch {
            workspace,
            rehydrate,
        } => {
            let config = pando::config::load()?;
            let (share, found) = config
                .workspace_by_id(&workspace)
                .with_context(|| format!("workspace {workspace} is not joined on this device"))?;
            let trunk = Trunk::open(
                config.workspace_path(share, found),
                &found.id,
                &config.device_id,
            )?;
            let escape_key = config.network_key().ok();
            if escape_key.is_none() {
                eprintln!("escape export disabled: network key is missing");
            }
            let authority = Box::new(remote(&config)?);
            pando::daemon::watch(
                trunk,
                authority,
                WatchOptions {
                    escape_interval: if escape_key.is_some() {
                        Duration::from_secs(600)
                    } else {
                        Duration::ZERO
                    },
                    escape_key,
                    escape_remote: Some("origin".into()),
                    rehydrate,
                    ..WatchOptions::default()
                },
            )
        }
        Command::Fetch { repo } => {
            let report = pando::git::fetch_remotes(&repo)?;
            if report.changes.is_empty() {
                println!("remote-tracking refs unchanged");
            }
            for change in report.changes {
                println!(
                    "{}: {}",
                    change.reference,
                    if change.forced {
                        "non-fast-forward"
                    } else if change.after.is_none() {
                        "deleted"
                    } else {
                        "updated"
                    }
                );
                if let Some(rescue_ref) = change.rescue_ref {
                    println!("  rescued previous Git base as {rescue_ref}");
                }
            }
            Ok(())
        }
        Command::Escape { command } => match command {
            EscapeCommand::Export {
                folder,
                remote: escape_remote,
                local_only,
            } => {
                let config = pando::config::load()?;
                let (share, workspace) = config
                    .find_workspace(&folder)
                    .with_context(|| format!("{} is not a joined folder", folder.display()))?;
                let authority = remote(&config)?;
                let report = pando::escape::export(
                    &config.workspace_path(share, workspace),
                    &workspace.id,
                    &authority,
                    &config.network_key()?,
                    (!local_only).then_some(escape_remote.as_str()),
                )?;
                println!(
                    "{} {} chunks ({} bytes) from {} in {}{}",
                    if report.reused { "reused" } else { "encrypted" },
                    report.chunks,
                    report.bytes,
                    report.snapshot,
                    report.reference,
                    if report.pushed { " and pushed it" } else { "" }
                );
                Ok(())
            }
            EscapeCommand::Restore {
                repo,
                workspace_id,
                device_id,
                key,
                destination,
                fetch_remote,
            } => {
                let key = TransportKey::load(key)?;
                let reference = pando::escape::reference(&workspace_id, &device_id);
                if let Some(remote) = fetch_remote {
                    pando::escape::fetch_ref(&repo, &remote, &reference)?;
                }
                let report = pando::escape::restore(&repo, &reference, &key, &destination)?;
                println!(
                    "restored {} files ({} bytes) from encrypted snapshot {} to {}",
                    report.files,
                    report.bytes,
                    report.snapshot,
                    destination.display()
                );
                Ok(())
            }
        },
        Command::Reconcile {
            folder,
            fork,
            choice,
        } => {
            let config = pando::config::load()?;
            let (share, workspace) = config
                .find_workspace(&folder)
                .with_context(|| format!("{} is not a joined folder", folder.display()))?;
            let mut authority = remote(&config)?;
            let Some(fork) = fork else {
                let forks = authority.forks(&workspace.id)?;
                if forks.is_empty() {
                    println!("no pending forks");
                }
                for fork in forks {
                    let overlay = authority.overlay(&fork)?;
                    println!(
                        "{} parent={} device={} created_at_ms={}",
                        fork,
                        overlay.snapshot.parent.as_deref().unwrap_or("none"),
                        overlay.snapshot.trunk_id,
                        overlay.snapshot.created_at_ms
                    );
                }
                return Ok(());
            };
            let choice = match choice.context("--choice is required with --fork")? {
                CliReconcileChoice::Authority => ReconcileChoice::Authority,
                CliReconcileChoice::Fork => ReconcileChoice::Fork,
                CliReconcileChoice::Manual => ReconcileChoice::Manual,
            };
            let trunk = Trunk::open(
                config.workspace_path(share, workspace),
                &workspace.id,
                &config.device_id,
            )?;
            let result = trunk.reconcile(&mut authority, &SystemClock, &fork, choice)?;
            println!(
                "resolved fork {} at head {}",
                result.resolved_fork, result.head
            );
            Ok(())
        }
        Command::Hydrate { repo, force } => {
            let summary = Hydrator::open(&repo)?.run_changed(force)?;
            println!("{summary}");
            Ok(())
        }
        Command::Classify {
            path,
            repo,
            directory,
        } => {
            let repo = repo
                .canonicalize()
                .with_context(|| format!("resolve repository {}", repo.display()))?;
            let relative = classification_path(&repo, &path)?;
            let classification = Classifier::load(&repo)?
                .explain(&relative, directory || repo.join(&relative).is_dir());
            println!(
                "{}: {}",
                relative.display(),
                if classification.portable {
                    "portable"
                } else {
                    "excluded"
                }
            );
            println!("reason: {}", classification.reason);
            Ok(())
        }
        Command::Verify { data } => {
            let report = FileAuthority::open_existing(&authority_data(data)?)?.verify()?;
            println!(
                "verified {} heads, {} snapshots, {} chunks ({} bytes)",
                report.heads, report.overlays, report.chunks, report.bytes
            );
            Ok(())
        }
        Command::Gc { data, apply } => {
            let report =
                FileAuthority::open_existing(&authority_data(data)?)?.garbage_collect(apply)?;
            println!(
                "{} {} unreachable snapshots and {} chunks ({} bytes)",
                if report.applied {
                    "collected"
                } else {
                    "would collect"
                },
                report.overlays,
                report.chunks,
                report.bytes
            );
            if !report.applied {
                println!("dry run only; pass --apply after stopping the authority service");
            }
            Ok(())
        }
        Command::Restore {
            data,
            snapshot,
            destination,
        } => {
            let report = FileAuthority::open_existing(&authority_data(data)?)?
                .restore(&snapshot, &destination)?;
            println!(
                "restored {} files ({} bytes) from {} to {}",
                report.files,
                report.bytes,
                report.snapshot,
                destination.display()
            );
            Ok(())
        }
        Command::Demo { root } => demo(&root),
    }
}

fn up(
    to: Option<String>,
    code: Option<String>,
    name: Option<String>,
    bind: &str,
    no_services: bool,
) -> Result<()> {
    if let Some(config) = pando::config::try_load()? {
        if to.is_some() {
            bail!(
                "this device is already on network {}; revoke it there first to move it",
                &config.network_id[..12]
            );
        }
        println!(
            "already on network {} as {}",
            &config.network_id[..12],
            config.device_name
        );
        ensure_services(&config, no_services)?;
        return Ok(());
    }
    let device_name = name.unwrap_or_else(default_device_name);
    pando::config::validate_name(&device_name, "device")?;

    let config = match (to, code) {
        (Some(to), Some(code)) => {
            let grant = pando::transport::enroll(&to, &code, &device_name)?;
            TransportKey::from_hex(&grant.device_key)?.store(pando::config::device_key_path()?)?;
            TransportKey::from_hex(&grant.network_key)?.store(pando::config::network_key_path()?)?;
            let config =
                DeviceConfig::new(grant.network_id, grant.device_id, device_name.clone(), to);
            pando::config::save(&config)?;
            println!(
                "joined network {} as {}",
                &config.network_id[..12],
                device_name
            );
            println!("next: `pando folders` to see what you can join");
            config
        }
        (None, None) => {
            let now = SystemClock.now_ms();
            let port = bind
                .rsplit_once(':')
                .map(|(_, port)| port)
                .unwrap_or("7337");
            let advertised = format!("{}:{port}", detect_ip());
            let network_key = TransportKey::random()?;
            let device_key = TransportKey::random()?;
            let network_id = pando::registry::random_hex(16)?;
            let device_id = pando::registry::random_hex(16)?;
            Registry::create(
                &pando::config::authority_data_path()?,
                &network_id,
                &advertised,
                &network_key,
                &device_id,
                &device_name,
                &device_key,
                now,
            )?;
            device_key.store(pando::config::device_key_path()?)?;
            network_key.store(pando::config::network_key_path()?)?;
            let config = DeviceConfig::new(
                network_id,
                device_id,
                device_name.clone(),
                format!("127.0.0.1:{port}"),
            );
            pando::config::save(&config)?;
            println!(
                "created network {} · this device is {} and hosts the authority at {advertised}",
                &config.network_id[..12],
                device_name
            );
            println!("next: `pando invite` to add a device, `pando share <folder>` to host code");
            config
        }
        _ => unreachable!("clap enforces --to and --code together"),
    };
    ensure_services(&config, no_services)
}

fn share(folder: &Path, name: Option<String>, no_services: bool) -> Result<()> {
    let mut config = pando::config::load()?;
    let root = pando::config::canonical_directory(folder)?;
    let name = match name {
        Some(name) => name,
        None => root
            .file_name()
            .and_then(|name| name.to_str())
            .context("folder has no usable name; pass --name")?
            .to_owned(),
    };
    pando::config::validate_name(&name, "share")?;
    let workspaces = pando::config::discover(&root)?
        .into_iter()
        .map(|relative| pando::config::workspace(&config.network_id, &name, &root, relative))
        .collect::<Result<Vec<_>>>()?;
    let mut authority = remote(&config)?;
    authority.upsert_share(pando::registry::ShareRecord {
        name: name.clone(),
        host: config.device_name.clone(),
        workspaces: workspaces.clone(),
    })?;
    config.upsert_share(ShareConfig {
        name: name.clone(),
        path: root,
        workspaces,
    });
    pando::config::save(&config)?;
    println!("hosting {name} · join it elsewhere with `pando join {name}`");
    push_shares(&config, &mut authority, Some(&name))?;
    ensure_services(&config, no_services)
}

fn join(name: &str, path: Option<PathBuf>, no_services: bool) -> Result<()> {
    let mut config = pando::config::load()?;
    let authority = remote(&config)?;
    let shares = authority.shares()?;
    let Some(share) = shares.iter().find(|share| share.name == name) else {
        let available = shares
            .iter()
            .map(|share| share.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "no folder named {name} on this network{}",
            if available.is_empty() {
                "; host one with `pando share <folder>`".to_owned()
            } else {
                format!("; available: {available}")
            }
        );
    };
    let path = match path {
        Some(path) => path,
        None => home_directory()?.join("Pando").join(name),
    };
    fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
    let path = path.canonicalize()?;
    let local = ShareConfig {
        name: share.name.clone(),
        path,
        workspaces: share.workspaces.clone(),
    };
    for workspace in &local.workspaces {
        let workspace_path = config.workspace_path(&local, workspace);
        fs::create_dir_all(&workspace_path)?;
        let trunk = Trunk::open(&workspace_path, &workspace.id, &config.device_id)?;
        println!("{}/{}: syncing", name, workspace.name);
        let started = Instant::now();
        let result = trunk.pull(&authority, &SystemClock)?;
        println!(
            "{}/{}: {} in {:.1}s",
            name,
            workspace.name,
            describe_pull(&result),
            started.elapsed().as_secs_f64()
        );
    }
    config.upsert_share(local);
    pando::config::save(&config)?;
    ensure_services(&config, no_services)
}

fn push_shares(
    config: &DeviceConfig,
    authority: &mut dyn Authority,
    only: Option<&str>,
) -> Result<()> {
    let mut failures = 0;
    for share in &config.shares {
        if only.is_some_and(|name| name != share.name) {
            continue;
        }
        for workspace in &share.workspaces {
            let path = config.workspace_path(share, workspace);
            println!("{}/{}: syncing", share.name, workspace.name);
            let started = Instant::now();
            let outcome = Trunk::open(&path, &workspace.id, &config.device_id).and_then(|trunk| {
                let result = trunk.push(authority, &SystemClock)?;
                trunk.release(authority)?;
                Ok(result)
            });
            let elapsed = started.elapsed().as_secs_f64();
            match outcome {
                Ok(result) => println!(
                    "{}/{}: {} in {:.1}s",
                    share.name,
                    workspace.name,
                    describe_push(&result),
                    elapsed
                ),
                Err(error) => {
                    failures += 1;
                    eprintln!(
                        "{}/{}: failed in {elapsed:.1}s: {error:#}",
                        share.name, workspace.name
                    );
                }
            }
        }
    }
    if failures > 0 {
        anyhow::bail!("{failures} workspace(s) failed to sync");
    }
    Ok(())
}

/// Install (or refresh) the background services this device needs: the
/// authority when it hosts one, and a watcher per joined workspace.
fn ensure_services(config: &DeviceConfig, no_services: bool) -> Result<()> {
    if no_services {
        return Ok(());
    }
    let binary = std::env::current_exe()?.canonicalize()?;
    let platform = match pando::service::ServicePlatform::native() {
        Ok(platform) => platform,
        Err(error) => {
            eprintln!(
                "services not installed: {error}; run `pando serve` and `pando watch` manually"
            );
            return Ok(());
        }
    };
    let mut kinds = Vec::new();
    if hosts_authority(config) {
        kinds.push(pando::service::ServiceKind::Authority);
    }
    for share in &config.shares {
        for workspace in &share.workspaces {
            kinds.push(pando::service::ServiceKind::Watch {
                workspace_id: workspace.id.clone(),
            });
        }
    }
    for kind in kinds {
        let report = pando::service::install(&kind, &binary, platform, None, true)?;
        println!("service {} running", report.service_name);
    }
    Ok(())
}

fn hosts_authority(config: &DeviceConfig) -> bool {
    config.authority.starts_with("127.0.0.1:") || config.authority.starts_with("localhost:")
}

fn remote(config: &DeviceConfig) -> Result<RemoteAuthority> {
    Ok(RemoteAuthority::new(
        config.authority.clone(),
        config.device_id.clone(),
        config.device_key()?,
    ))
}

/// Best local IP to advertise, discovered by routing (no packets sent).
/// A Tailscale-style CGNAT address wins because it is stable across networks.
fn detect_ip() -> String {
    let probe = |target: &str| -> Option<IpAddr> {
        let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect(target).ok()?;
        Some(socket.local_addr().ok()?.ip())
    };
    if let Some(ip) = probe("100.100.100.100:53")
        && is_cgnat(ip)
    {
        return ip.to_string();
    }
    probe("8.8.8.8:53")
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "127.0.0.1".into())
}

fn is_cgnat(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
}

fn authority_data(data: Option<PathBuf>) -> Result<PathBuf> {
    match data {
        Some(data) => Ok(data),
        None => pando::config::authority_data_path(),
    }
}

fn home_directory() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

fn default_device_name() -> String {
    std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "device".into())
}

fn classification_path(repo: &Path, path: &Path) -> Result<PathBuf> {
    let relative = if path.is_absolute() {
        path.strip_prefix(repo).with_context(|| {
            format!(
                "{} is outside repository {}",
                path.display(),
                repo.display()
            )
        })?
    } else {
        path
    };
    if relative.as_os_str().is_empty()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("classification path must be a path inside the repository");
    }
    Ok(relative.to_owned())
}

fn demo(root: &Path) -> Result<()> {
    let authority_path = root.join("authority");
    let first_path = root.join("macbook");
    let second_path = root.join("linuxbox");
    fs::create_dir_all(&first_path)?;
    fs::create_dir_all(&second_path)?;
    fs::write(first_path.join("mid-edit.txt"), "this followed me\n")?;
    let mut authority = FileAuthority::open(authority_path)?;
    let first = Trunk::open_with_state(
        &first_path,
        "demo",
        "macbook",
        root.join("trunk-state/macbook"),
    )?;
    let second = Trunk::open_with_state(
        &second_path,
        "demo",
        "linuxbox",
        root.join("trunk-state/linuxbox"),
    )?;
    println!(
        "macbook: {}",
        describe_push(&first.push(&mut authority, &SystemClock)?)
    );
    first.release(&mut authority)?;
    println!(
        "linuxbox: {}",
        describe_pull(&second.pull(&authority, &SystemClock)?)
    );
    let rendered = fs::read_to_string(second_path.join("mid-edit.txt"))
        .context("demo did not materialize the dirty file")?;
    println!("rendered: {rendered:?}");
    Ok(())
}
