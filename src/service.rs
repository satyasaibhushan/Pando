use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServicePlatform {
    Launchd,
    Systemd,
}

impl ServicePlatform {
    pub fn native() -> Result<Self> {
        if cfg!(target_os = "macos") {
            Ok(Self::Launchd)
        } else if cfg!(target_os = "linux") {
            Ok(Self::Systemd)
        } else {
            bail!("Pando service installation supports macOS and Linux")
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceSpec {
    pub binary: PathBuf,
    pub repo: PathBuf,
    pub repo_id: String,
    pub trunk_id: String,
    pub authority: String,
    pub key: PathBuf,
    pub quiescence_ms: u64,
    pub idle_ms: u64,
    pub full_scan_secs: u64,
    pub fetch_secs: u64,
    pub escape_secs: u64,
    pub escape_remote: String,
    pub rehydrate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallReport {
    pub path: PathBuf,
    pub service_name: String,
    pub activated: bool,
}

pub fn install(
    spec: &ServiceSpec,
    platform: ServicePlatform,
    output_directory: Option<&Path>,
    activate: bool,
) -> Result<InstallReport> {
    validate(spec)?;
    if activate && output_directory.is_some() {
        bail!("cannot activate a service written to a custom output directory");
    }
    let service_name = service_name(spec);
    let (directory, filename, contents) = match platform {
        ServicePlatform::Launchd => {
            let directory = output_directory
                .map(Path::to_owned)
                .unwrap_or(default_launchd_directory()?);
            let filename = format!("{service_name}.plist");
            (directory, filename, render_launchd(spec, &service_name))
        }
        ServicePlatform::Systemd => {
            let directory = output_directory
                .map(Path::to_owned)
                .unwrap_or(default_systemd_directory()?);
            let filename = format!("{service_name}.service");
            (directory, filename, render_systemd(spec))
        }
    };
    fs::create_dir_all(&directory)
        .with_context(|| format!("create service directory {}", directory.display()))?;
    let path = directory.join(filename);
    atomic_write(&path, contents.as_bytes())?;
    if activate {
        activate_service(platform, &service_name, &path)?;
    }
    Ok(InstallReport {
        path,
        service_name,
        activated: activate,
    })
}

fn validate(spec: &ServiceSpec) -> Result<()> {
    if !spec.binary.is_absolute() || !spec.binary.is_file() {
        bail!(
            "service binary must be an existing absolute path: {}",
            spec.binary.display()
        );
    }
    if !spec.repo.is_absolute() || !spec.repo.is_dir() {
        bail!(
            "service repository must be an existing absolute path: {}",
            spec.repo.display()
        );
    }
    if !spec.key.is_absolute() || !spec.key.is_file() {
        bail!(
            "service key must be an existing absolute path: {}",
            spec.key.display()
        );
    }
    if spec.repo_id.is_empty() || spec.trunk_id.is_empty() || spec.authority.is_empty() {
        bail!("service repository, trunk, and authority identifiers cannot be empty");
    }
    Ok(())
}

fn service_name(spec: &ServiceSpec) -> String {
    let identity = format!("{}\0{}", spec.repo_id, spec.trunk_id);
    format!(
        "io.pando.watch.{}",
        &blake3::hash(identity.as_bytes()).to_hex()[..12]
    )
}

fn arguments(spec: &ServiceSpec) -> Vec<String> {
    let mut arguments = vec![
        spec.binary.display().to_string(),
        "watch".into(),
        "--repo".into(),
        spec.repo.display().to_string(),
        "--repo-id".into(),
        spec.repo_id.clone(),
        "--trunk-id".into(),
        spec.trunk_id.clone(),
        "--authority".into(),
        spec.authority.clone(),
        "--key".into(),
        spec.key.display().to_string(),
        "--quiescence-ms".into(),
        spec.quiescence_ms.to_string(),
        "--idle-ms".into(),
        spec.idle_ms.to_string(),
        "--full-scan-secs".into(),
        spec.full_scan_secs.to_string(),
        "--fetch-secs".into(),
        spec.fetch_secs.to_string(),
        "--escape-secs".into(),
        spec.escape_secs.to_string(),
        "--escape-remote".into(),
        spec.escape_remote.clone(),
    ];
    if spec.rehydrate {
        arguments.push("--rehydrate".into());
    }
    arguments
}

fn render_launchd(spec: &ServiceSpec, label: &str) -> String {
    let arguments = arguments(spec)
        .iter()
        .map(|argument| format!("    <string>{}</string>\n", xml_escape(argument)))
        .collect::<String>();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
  <key>Label</key>\n  <string>{}</string>\n\
  <key>ProgramArguments</key>\n  <array>\n{}  </array>\n\
  <key>RunAtLoad</key>\n  <true/>\n\
  <key>KeepAlive</key>\n  <true/>\n\
  <key>ProcessType</key>\n  <string>Background</string>\n\
</dict>\n\
</plist>\n",
        xml_escape(label),
        arguments
    )
}

fn render_systemd(spec: &ServiceSpec) -> String {
    let command = arguments(spec)
        .iter()
        .map(|argument| systemd_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "[Unit]\nDescription=Pando working-tree continuity for {}\nAfter=network-online.target\nWants=network-online.target\n\n\
[Service]\nType=simple\nExecStart={command}\nRestart=on-failure\nRestartSec=3\n\n\
[Install]\nWantedBy=default.target\n",
        spec.repo_id.replace('\n', " ")
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn systemd_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    )
}

fn default_launchd_directory() -> Result<PathBuf> {
    Ok(home_directory()?.join("Library/LaunchAgents"))
}

fn default_systemd_directory() -> Result<PathBuf> {
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
        Ok(PathBuf::from(config).join("systemd/user"))
    } else {
        Ok(home_directory()?.join(".config/systemd/user"))
    }
}

fn home_directory() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("partial-{}", std::process::id()));
    let mut file = fs::File::create(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn activate_service(platform: ServicePlatform, service_name: &str, path: &Path) -> Result<()> {
    match platform {
        ServicePlatform::Launchd => {
            let domain = format!("gui/{}", user_id()?);
            let target = format!("{domain}/{service_name}");
            let _ = Command::new("launchctl")
                .args(["bootout", &target])
                .output();
            run(
                "launchctl",
                &["bootstrap", &domain, path.to_string_lossy().as_ref()],
            )?;
            run("launchctl", &["kickstart", "-k", &target])
        }
        ServicePlatform::Systemd => {
            run("systemctl", &["--user", "daemon-reload"])?;
            run(
                "systemctl",
                &[
                    "--user",
                    "enable",
                    "--now",
                    &format!("{service_name}.service"),
                ],
            )
        }
    }
}

fn user_id() -> Result<String> {
    let output = Command::new("id").arg("-u").output()?;
    if !output.status.success() {
        bail!("id -u failed");
    }
    let value = String::from_utf8(output.stdout)?;
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("id -u returned an invalid user ID");
    }
    Ok(value.to_owned())
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(root: &Path) -> ServiceSpec {
        let binary = root.join("pando");
        let repo = root.join("repo & work");
        let key = root.join("fabric.key");
        fs::write(&binary, "binary").unwrap();
        fs::create_dir(&repo).unwrap();
        fs::write(&key, "key").unwrap();
        ServiceSpec {
            binary,
            repo,
            repo_id: "project".into(),
            trunk_id: "macbook".into(),
            authority: "tcp://host:7337".into(),
            key,
            quiescence_ms: 750,
            idle_ms: 3_000,
            full_scan_secs: 60,
            fetch_secs: 30,
            escape_secs: 600,
            escape_remote: "origin".into(),
            rehydrate: true,
        }
    }

    #[test]
    fn installs_launchd_and_systemd_units_without_a_shell() {
        let root = tempfile::tempdir().unwrap();
        let spec = spec(root.path());
        let launchd_dir = root.path().join("launchd");
        let launchd = install(&spec, ServicePlatform::Launchd, Some(&launchd_dir), false).unwrap();
        let plist = fs::read_to_string(launchd.path).unwrap();
        assert!(plist.contains("<string>watch</string>"));
        assert!(plist.contains("repo &amp; work"));
        assert!(!plist.contains("sh -c"));

        let systemd_dir = root.path().join("systemd");
        let systemd = install(&spec, ServicePlatform::Systemd, Some(&systemd_dir), false).unwrap();
        let unit = fs::read_to_string(systemd.path).unwrap();
        assert!(unit.contains("ExecStart="));
        assert!(unit.contains("\"watch\""));
        assert!(!unit.contains("/bin/sh"));
    }
}
