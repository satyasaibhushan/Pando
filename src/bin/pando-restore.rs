use anyhow::Result;
use clap::Parser;
use pando::transport::TransportKey;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Restore an encrypted Pando snapshot from a Git escape ref"
)]
struct Args {
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[arg(long)]
    repo_id: String,
    #[arg(long)]
    trunk_id: String,
    #[arg(long, env = "PANDO_KEY")]
    key: PathBuf,
    #[arg(long)]
    destination: PathBuf,
    #[arg(long)]
    fetch_remote: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let key = TransportKey::load(args.key)?;
    let reference = pando::escape::reference(&args.repo_id, &args.trunk_id);
    if let Some(remote) = args.fetch_remote {
        pando::escape::fetch_ref(&args.repo, &remote, &reference)?;
    }
    let report = pando::escape::restore(&args.repo, &reference, &key, &args.destination)?;
    println!(
        "restored {} files ({} bytes) from encrypted snapshot {} to {}",
        report.files,
        report.bytes,
        report.snapshot,
        args.destination.display()
    );
    Ok(())
}
