use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use pando::authority::{Authority, FileAuthority};
use pando::classify::Classifier;
use pando::clock::SystemClock;
use pando::daemon::{WatchOptions, describe_pull, describe_push};
use pando::rehydrate::Hydrator;
use pando::sync::{ReconcileChoice, Trunk};
use pando::transport::{RemoteAuthority, TransportKey};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    Serve {
        #[arg(long, default_value = "0.0.0.0:7337")]
        bind: String,
        #[arg(long, default_value = ".pando-authority")]
        data: PathBuf,
        #[arg(long, env = "PANDO_KEY")]
        key: PathBuf,
    },
    Push(TrunkArgs),
    Pull(TrunkArgs),
    Fetch {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
    Reconcile {
        #[command(flatten)]
        trunk: TrunkArgs,
        #[arg(long)]
        fork: Option<String>,
        #[arg(long, value_enum, requires = "fork")]
        choice: Option<CliReconcileChoice>,
    },
    Hydrate {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        force: bool,
    },
    Classify {
        path: PathBuf,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        directory: bool,
    },
    Verify {
        #[arg(long, default_value = ".pando-authority")]
        data: PathBuf,
    },
    Restore {
        #[arg(long, default_value = ".pando-authority")]
        data: PathBuf,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        destination: PathBuf,
    },
    Watch {
        #[command(flatten)]
        trunk: TrunkArgs,
        #[arg(long, default_value_t = 750)]
        quiescence_ms: u64,
        #[arg(long, default_value_t = 3_000)]
        idle_ms: u64,
        #[arg(long, default_value_t = 60)]
        full_scan_secs: u64,
        #[arg(long, default_value_t = 30)]
        fetch_secs: u64,
        #[arg(long)]
        rehydrate: bool,
    },
    Status {
        #[arg(long)]
        repo_id: String,
        #[arg(long)]
        authority: String,
        #[arg(long, env = "PANDO_KEY")]
        key: Option<PathBuf>,
    },
    Tui {
        #[arg(long)]
        repo_id: String,
        #[arg(long)]
        authority: String,
        #[arg(long, env = "PANDO_KEY")]
        key: Option<PathBuf>,
    },
    Demo {
        #[arg(long, default_value = ".pando-demo")]
        root: PathBuf,
    },
}

#[derive(clap::Args)]
struct TrunkArgs {
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[arg(long)]
    repo_id: String,
    #[arg(long)]
    trunk_id: String,
    #[arg(long)]
    authority: String,
    #[arg(long, env = "PANDO_KEY")]
    key: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum CliReconcileChoice {
    Authority,
    Fork,
    Manual,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { output } => {
            let key = TransportKey::generate(&output)?;
            println!(
                "created transport key {} (fingerprint {})",
                output.display(),
                key.fingerprint()
            );
            Ok(())
        }
        Command::Serve { bind, data, key } => {
            let key = TransportKey::load(key)?;
            println!(
                "Pando authority listening securely on {bind}; data at {}; key {}",
                data.display(),
                key.fingerprint()
            );
            pando::transport::serve(&bind, FileAuthority::open(data)?, key)
        }
        Command::Push(args) => {
            let trunk = open_trunk(&args)?;
            let mut authority = authority(&args.authority, args.key.as_deref())?;
            let result = trunk.push(authority.as_mut(), &SystemClock)?;
            trunk.release(authority.as_mut())?;
            println!("{}", describe_push(&result));
            Ok(())
        }
        Command::Pull(args) => {
            let trunk = open_trunk(&args)?;
            let authority = authority(&args.authority, args.key.as_deref())?;
            println!(
                "{}",
                describe_pull(&trunk.pull(authority.as_ref(), &SystemClock)?)
            );
            Ok(())
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
        Command::Reconcile {
            trunk,
            fork,
            choice,
        } => {
            let mut authority = authority(&trunk.authority, trunk.key.as_deref())?;
            let Some(fork) = fork else {
                let forks = authority.forks(&trunk.repo_id)?;
                if forks.is_empty() {
                    println!("no pending forks");
                }
                for fork in forks {
                    let overlay = authority.overlay(&fork)?;
                    println!(
                        "{} parent={} trunk={} created_at_ms={}",
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
            let result =
                open_trunk(&trunk)?.reconcile(authority.as_mut(), &SystemClock, &fork, choice)?;
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
            let report = FileAuthority::open_existing(&data)?.verify()?;
            println!(
                "verified {} heads, {} snapshots, {} chunks ({} bytes)",
                report.heads, report.overlays, report.chunks, report.bytes
            );
            Ok(())
        }
        Command::Restore {
            data,
            snapshot,
            destination,
        } => {
            let report = FileAuthority::open_existing(&data)?.restore(&snapshot, &destination)?;
            println!(
                "restored {} files ({} bytes) from {} to {}",
                report.files,
                report.bytes,
                report.snapshot,
                destination.display()
            );
            Ok(())
        }
        Command::Watch {
            trunk,
            quiescence_ms,
            idle_ms,
            full_scan_secs,
            fetch_secs,
            rehydrate,
        } => {
            let authority = authority(&trunk.authority, trunk.key.as_deref())?;
            let trunk = open_trunk(&trunk)?;
            pando::daemon::watch(
                trunk,
                authority,
                WatchOptions {
                    quiescence: Duration::from_millis(quiescence_ms),
                    idle_release: Duration::from_millis(idle_ms),
                    full_scan_interval: Duration::from_secs(full_scan_secs),
                    fetch_interval: Duration::from_secs(fetch_secs),
                    rehydrate,
                    ..WatchOptions::default()
                },
            )
        }
        Command::Status {
            repo_id,
            authority: endpoint,
            key,
        } => {
            let authority = authority(&endpoint, key.as_deref())?;
            let status = authority.status(&repo_id, pando::Clock::now_ms(&SystemClock))?;
            println!("repo: {}", status.repo_id);
            println!(
                "lease: {}",
                status
                    .lease
                    .map(|lease| lease.holder)
                    .unwrap_or_else(|| "free".into())
            );
            println!("head: {}", status.head.unwrap_or_else(|| "none".into()));
            println!("exposure: {} bytes", status.exposure_bytes);
            println!("forks: {}", status.forks.len());
            Ok(())
        }
        Command::Tui {
            repo_id,
            authority: endpoint,
            key,
        } => pando::tui::run(authority(&endpoint, key.as_deref())?, repo_id),
        Command::Demo { root } => demo(&root),
    }
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
        anyhow::bail!("classification path must be a path inside the repository");
    }
    Ok(relative.to_owned())
}

fn open_trunk(args: &TrunkArgs) -> Result<Trunk> {
    Trunk::open(&args.repo, &args.repo_id, &args.trunk_id)
}

fn authority(endpoint: &str, key: Option<&Path>) -> Result<Box<dyn Authority>> {
    if let Some(address) = endpoint.strip_prefix("tcp://") {
        let key_path = key.context("TCP authority requires --key or PANDO_KEY")?;
        Ok(Box::new(RemoteAuthority::new(
            address,
            TransportKey::load(key_path)?,
        )))
    } else {
        Ok(Box::new(FileAuthority::open(endpoint)?))
    }
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
