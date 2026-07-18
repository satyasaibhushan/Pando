use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pando::authority::{Authority, FileAuthority};
use pando::clock::SystemClock;
use pando::daemon::{WatchOptions, describe_pull, describe_push};
use pando::sync::Trunk;
use pando::transport::RemoteAuthority;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "0.0.0.0:7337")]
        bind: String,
        #[arg(long, default_value = ".pando-authority")]
        data: PathBuf,
    },
    Push(TrunkArgs),
    Pull(TrunkArgs),
    Watch {
        #[command(flatten)]
        trunk: TrunkArgs,
        #[arg(long, default_value_t = 750)]
        quiescence_ms: u64,
        #[arg(long, default_value_t = 3_000)]
        idle_ms: u64,
    },
    Status {
        #[arg(long)]
        repo_id: String,
        #[arg(long)]
        authority: String,
    },
    Tui {
        #[arg(long)]
        repo_id: String,
        #[arg(long)]
        authority: String,
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
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Serve { bind, data } => {
            println!(
                "Pando authority listening on {bind}; data at {}",
                data.display()
            );
            pando::transport::serve(&bind, FileAuthority::open(data)?)
        }
        Command::Push(args) => {
            let trunk = open_trunk(&args)?;
            let mut authority = authority(&args.authority)?;
            println!(
                "{}",
                describe_push(&trunk.push(authority.as_mut(), &SystemClock)?)
            );
            Ok(())
        }
        Command::Pull(args) => {
            let trunk = open_trunk(&args)?;
            let authority = authority(&args.authority)?;
            println!(
                "{}",
                describe_pull(&trunk.pull(authority.as_ref(), &SystemClock)?)
            );
            Ok(())
        }
        Command::Watch {
            trunk,
            quiescence_ms,
            idle_ms,
        } => {
            let authority = authority(&trunk.authority)?;
            let trunk = open_trunk(&trunk)?;
            pando::daemon::watch(
                trunk,
                authority,
                WatchOptions {
                    quiescence: Duration::from_millis(quiescence_ms),
                    idle_release: Duration::from_millis(idle_ms),
                    ..WatchOptions::default()
                },
            )
        }
        Command::Status {
            repo_id,
            authority: endpoint,
        } => {
            let authority = authority(&endpoint)?;
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
            Ok(())
        }
        Command::Tui {
            repo_id,
            authority: endpoint,
        } => pando::tui::run(authority(&endpoint)?, repo_id),
        Command::Demo { root } => demo(&root),
    }
}

fn open_trunk(args: &TrunkArgs) -> Result<Trunk> {
    Trunk::open(&args.repo, &args.repo_id, &args.trunk_id)
}

fn authority(endpoint: &str) -> Result<Box<dyn Authority>> {
    if let Some(address) = endpoint.strip_prefix("tcp://") {
        Ok(Box::new(RemoteAuthority::new(address)))
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
