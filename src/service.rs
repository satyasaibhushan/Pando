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

/// The two background jobs Pando runs: the network authority, and one file
/// watcher per workspace. All configuration lives in the device config, so
/// units carry nothing but the subcommand.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceKind {
    Authority,
    Watch { workspace_id: String },
}

impl ServiceKind {
    fn name(&self) -> String {
        match self {
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
            Self::Authority => vec![binary, "serve".into()],
            Self::Watch { workspace_id } => vec![binary, "watch".into(), workspace_id.clone()],
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
            let filename = format!("{service_name}.plist");
            (
                directory,
                filename,
                render_launchd(kind, binary, &service_name),
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

fn render_launchd(kind: &ServiceKind, binary: &Path, label: &str) -> String {
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
</dict>\n\
</plist>\n",
        xml_escape(label),
        arguments
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
[Service]\nType=simple\nExecStart={command}\nRestart=on-failure\nRestartSec=3\n\n\
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

    #[test]
    fn installs_launchd_and_systemd_units_without_a_shell() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("pando & tools");
        fs::write(&binary, "binary").unwrap();
        let kind = ServiceKind::Watch {
            workspace_id: "aabbccddeeff00112233".into(),
        };

        let launchd_dir = root.path().join("launchd");
        let launchd = install(
            &kind,
            &binary,
            ServicePlatform::Launchd,
            Some(&launchd_dir),
            false,
        )
        .unwrap();
        assert_eq!(launchd.service_name, "io.pando.watch.aabbccddeeff");
        let plist = fs::read_to_string(launchd.path).unwrap();
        assert!(plist.contains("<string>watch</string>"));
        assert!(plist.contains("<string>aabbccddeeff00112233</string>"));
        assert!(plist.contains("pando &amp; tools"));
        assert!(!plist.contains("sh -c"));

        let systemd_dir = root.path().join("systemd");
        let systemd = install(
            &ServiceKind::Authority,
            &binary,
            ServicePlatform::Systemd,
            Some(&systemd_dir),
            false,
        )
        .unwrap();
        assert_eq!(systemd.service_name, "io.pando.authority");
        let unit = fs::read_to_string(systemd.path).unwrap();
        assert!(unit.contains("ExecStart="));
        assert!(unit.contains("\"serve\""));
        assert!(!unit.contains("/bin/sh"));
    }
}
