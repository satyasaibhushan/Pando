use crate::fsutil::atomic_write;
use anyhow::{Context, Result, bail};
use std::fs;
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

/// Background entry points. New installations use one device daemon; the
/// authority and per-workspace variants remain for the hidden diagnostic
/// commands and for recognising installations created by older versions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceKind {
    Daemon,
    Authority,
    Watch { workspace_id: String },
}

impl ServiceKind {
    fn name(&self) -> String {
        match self {
            Self::Daemon => "io.pando.daemon".into(),
            Self::Authority => "io.pando.authority".into(),
            Self::Watch { workspace_id } => {
                format!(
                    "io.pando.watch.{}",
                    &workspace_id[..workspace_id.len().min(12)]
                )
            }
        }
    }

    fn arguments(&self, binary: &Path) -> Vec<String> {
        let binary = binary.display().to_string();
        match self {
            Self::Daemon => vec![binary, "daemon".into()],
            Self::Authority => vec![binary, "serve".into()],
            Self::Watch { workspace_id } => vec![binary, "watch".into(), workspace_id.clone()],
        }
    }
}

/// Stop and remove service files created by the old process-per-workspace
/// layout. This is intentionally narrow so unrelated launchd/systemd jobs can
/// never be touched by a Pando upgrade.
pub fn remove_obsolete(platform: ServicePlatform) -> Result<Vec<String>> {
    let directory = match platform {
        ServicePlatform::Launchd => default_launchd_directory()?,
        ServicePlatform::Systemd => default_systemd_directory()?,
    };
    if !directory.is_dir() {
        return Ok(Vec::new());
    }

    let mut removed = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        if !entry.file_type()?.is_file() || !is_obsolete_service_name(filename) {
            continue;
        }
        let service_name = filename
            .strip_suffix(".plist")
            .or_else(|| filename.strip_suffix(".service"))
            .expect("obsolete service names have a known suffix");
        deactivate_service(platform, service_name);
        fs::remove_file(entry.path())
            .with_context(|| format!("remove obsolete Pando service {filename}"))?;
        removed.push(service_name.to_owned());
    }
    if platform == ServicePlatform::Systemd && !removed.is_empty() {
        run("systemctl", &["--user", "daemon-reload"])?;
    }
    removed.sort();
    Ok(removed)
}

fn is_obsolete_service_name(filename: &str) -> bool {
    matches!(
        filename,
        "io.pando.authority.plist" | "io.pando.authority.service"
    ) || (filename.starts_with("io.pando.watch.")
        && (filename.ends_with(".plist") || filename.ends_with(".service")))
}

fn deactivate_service(platform: ServicePlatform, service_name: &str) {
    match platform {
        ServicePlatform::Launchd => {
            if let Ok(uid) = user_id() {
                let target = format!("gui/{uid}/{service_name}");
                let _ = Command::new("launchctl")
                    .args(["bootout", &target])
                    .output();
            }
        }
        ServicePlatform::Systemd => {
            let _ = Command::new("systemctl")
                .args([
                    "--user",
                    "disable",
                    "--now",
                    &format!("{service_name}.service"),
                ])
                .output();
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallReport {
    pub path: PathBuf,
    pub service_name: String,
    pub activated: bool,
}

pub fn install(
    kind: &ServiceKind,
    binary: &Path,
    platform: ServicePlatform,
    output_directory: Option<&Path>,
    activate: bool,
) -> Result<InstallReport> {
    if !binary.is_absolute() || !binary.is_file() {
        bail!(
            "service binary must be an existing absolute path: {}",
            binary.display()
        );
    }
    if activate && output_directory.is_some() {
        bail!("cannot activate a service written to a custom output directory");
    }
    let service_name = kind.name();
    let (directory, filename, contents) = match platform {
        ServicePlatform::Launchd => {
            let directory = output_directory
                .map(Path::to_owned)
                .unwrap_or(default_launchd_directory()?);
            let log_directory = output_directory
                .map(|directory| directory.join("logs"))
                .unwrap_or(default_launchd_log_directory()?);
            fs::create_dir_all(&log_directory)?;
            let filename = format!("{service_name}.plist");
            (
                directory,
                filename,
                render_launchd(kind, binary, &service_name, &log_directory),
            )
        }
        ServicePlatform::Systemd => {
            let directory = output_directory
                .map(Path::to_owned)
                .unwrap_or(default_systemd_directory()?);
            let filename = format!("{service_name}.service");
            (
                directory,
                filename,
                render_systemd(kind, binary, &service_name),
            )
        }
    };
    fs::create_dir_all(&directory)
        .with_context(|| format!("create service directory {}", directory.display()))?;
    let path = directory.join(filename);
    atomic_write(&path, contents.as_bytes(), false)?;
    if activate {
        activate_service(platform, &service_name, &path)?;
    }
    Ok(InstallReport {
        path,
        service_name,
        activated: activate,
    })
}

fn render_launchd(kind: &ServiceKind, binary: &Path, label: &str, log_directory: &Path) -> String {
    let arguments = kind
        .arguments(binary)
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
  <key>Nice</key>\n  <integer>10</integer>\n\
  <key>LowPriorityIO</key>\n  <true/>\n\
  <key>StandardOutPath</key>\n  <string>{}</string>\n\
  <key>StandardErrorPath</key>\n  <string>{}</string>\n\
</dict>\n\
</plist>\n",
        xml_escape(label),
        arguments,
        xml_escape(&log_directory.join("daemon.log").display().to_string()),
        xml_escape(&log_directory.join("daemon.error.log").display().to_string())
    )
}

fn render_systemd(kind: &ServiceKind, binary: &Path, name: &str) -> String {
    let command = kind
        .arguments(binary)
        .iter()
        .map(|argument| systemd_quote(argument))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "[Unit]\nDescription=Pando {name}\nAfter=network-online.target\nWants=network-online.target\n\n\
[Service]\nType=simple\nExecStart={command}\nRestart=on-failure\nRestartSec=3\nNice=10\nCPUWeight=20\nCPUQuota=50%\nMemoryHigh=512M\nIOSchedulingClass=idle\n\n\
[Install]\nWantedBy=default.target\n"
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

fn default_launchd_log_directory() -> Result<PathBuf> {
    Ok(home_directory()?.join("Library/Logs/Pando"))
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

fn activate_service(platform: ServicePlatform, service_name: &str, path: &Path) -> Result<()> {
    match platform {
        ServicePlatform::Launchd => {
            let domain = format!("gui/{}", user_id()?);
            let target = format!("{domain}/{service_name}");
            let _ = Command::new("launchctl")
                .args(["bootout", &target])
                .output();
            run_with_retry(
                "launchctl",
                &["bootstrap", &domain, path.to_string_lossy().as_ref()],
                100,
            )
        }
        ServicePlatform::Systemd => {
            run("systemctl", &["--user", "daemon-reload"])?;
            let unit = format!("{service_name}.service");
            run("systemctl", &["--user", "enable", &unit])?;
            run("systemctl", &["--user", "restart", &unit])
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

fn run_with_retry(program: &str, args: &[&str], attempts: usize) -> Result<()> {
    let mut last_error = String::new();
    for attempt in 0..attempts.max(1) {
        let output = Command::new(program).args(args).output()?;
        if output.status.success() {
            return Ok(());
        }
        last_error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if attempt + 1 < attempts {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    bail!("{program} failed: {last_error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_single_device_daemon_without_a_shell() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("pando & tools");
        fs::write(&binary, "binary").unwrap();
        let kind = ServiceKind::Daemon;

        let launchd_dir = root.path().join("launchd");
        let launchd = install(
            &kind,
            &binary,
            ServicePlatform::Launchd,
            Some(&launchd_dir),
            false,
        )
        .unwrap();
        assert_eq!(launchd.service_name, "io.pando.daemon");
        let plist = fs::read_to_string(launchd.path).unwrap();
        assert!(plist.contains("<string>daemon</string>"));
        assert!(plist.contains("pando &amp; tools"));
        assert!(plist.contains("<key>Nice</key>"));
        assert!(plist.contains("<key>LowPriorityIO</key>"));
        assert!(plist.contains("<key>StandardOutPath</key>"));
        assert!(plist.contains("daemon.error.log"));
        assert!(!plist.contains("sh -c"));

        let systemd_dir = root.path().join("systemd");
        let systemd = install(
            &ServiceKind::Daemon,
            &binary,
            ServicePlatform::Systemd,
            Some(&systemd_dir),
            false,
        )
        .unwrap();
        assert_eq!(systemd.service_name, "io.pando.daemon");
        let unit = fs::read_to_string(systemd.path).unwrap();
        assert!(unit.contains("ExecStart="));
        assert!(unit.contains("\"daemon\""));
        assert!(unit.contains("Nice=10"));
        assert!(unit.contains("CPUWeight=20"));
        assert!(unit.contains("CPUQuota=50%"));
        assert!(unit.contains("MemoryHigh=512M"));
        assert!(unit.contains("IOSchedulingClass=idle"));
        assert!(!unit.contains("/bin/sh"));
    }

    #[test]
    fn recognises_only_superseded_service_names() {
        assert!(is_obsolete_service_name("io.pando.authority.plist"));
        assert!(is_obsolete_service_name(
            "io.pando.watch.aabbccddeeff.plist"
        ));
        assert!(is_obsolete_service_name("io.pando.authority.service"));
        assert!(is_obsolete_service_name(
            "io.pando.watch.aabbccddeeff.service"
        ));
        assert!(!is_obsolete_service_name("io.pando.daemon.plist"));
        assert!(!is_obsolete_service_name("io.pando.daemon.service"));
        assert!(!is_obsolete_service_name("unrelated.service"));
    }
}
