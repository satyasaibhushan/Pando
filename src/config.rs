use crate::transport::TransportKey;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

const CONFIG_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    pub id: String,
    pub name: String,
    pub relative_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub version: u32,
    pub network_id: String,
    pub device_id: String,
    pub device_name: String,
    pub root: PathBuf,
    pub authority: String,
    pub key_path: PathBuf,
    pub workspaces: Vec<WorkspaceConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Invitation {
    version: u32,
    network_id: String,
    authority: String,
    key: String,
    workspaces: Vec<WorkspaceConfig>,
}

impl DeviceConfig {
    pub fn workspace_path(&self, workspace: &WorkspaceConfig) -> PathBuf {
        if workspace.relative_path == Path::new(".") {
            self.root.clone()
        } else {
            self.root.join(&workspace.relative_path)
        }
    }
}

pub fn create_host(
    root: &Path,
    device_name: &str,
    authority: &str,
    key_path: &Path,
    invitation_path: &Path,
) -> Result<DeviceConfig> {
    create_host_in(
        root,
        device_name,
        authority,
        key_path,
        invitation_path,
        &crate::sync::default_data_root()?,
    )
}

fn create_host_in(
    root: &Path,
    device_name: &str,
    authority: &str,
    key_path: &Path,
    invitation_path: &Path,
    data_root: &Path,
) -> Result<DeviceConfig> {
    validate_name(device_name, "device")?;
    if authority.is_empty() {
        bail!("authority cannot be empty");
    }
    let root = canonical_directory(root)?;
    let key = TransportKey::load(key_path)?;
    let network_id = random_id(16)?;
    let device_id = random_id(16)?;
    let discovered = discover(&root)?;
    let workspaces = discovered
        .into_iter()
        .map(|relative_path| workspace(&network_id, &root, relative_path))
        .collect::<Result<Vec<_>>>()?;
    let managed_key = managed_key_path(data_root, &network_id);
    write_secret(
        &managed_key,
        format!("{}\n", key.encoded()).as_bytes(),
        false,
    )?;
    let config = DeviceConfig {
        version: CONFIG_VERSION,
        network_id: network_id.clone(),
        device_id,
        device_name: device_name.to_owned(),
        root,
        authority: authority.to_owned(),
        key_path: managed_key,
        workspaces: workspaces.clone(),
    };
    save_in(&config, data_root)?;
    let invitation = Invitation {
        version: CONFIG_VERSION,
        network_id,
        authority: authority.to_owned(),
        key: key.encoded(),
        workspaces,
    };
    write_secret(
        invitation_path,
        &serde_json::to_vec_pretty(&invitation)?,
        true,
    )?;
    Ok(config)
}

pub fn join(root: &Path, device_name: &str, invitation_path: &Path) -> Result<DeviceConfig> {
    join_in(
        root,
        device_name,
        invitation_path,
        &crate::sync::default_data_root()?,
    )
}

fn join_in(
    root: &Path,
    device_name: &str,
    invitation_path: &Path,
    data_root: &Path,
) -> Result<DeviceConfig> {
    validate_name(device_name, "device")?;
    fs::create_dir_all(root)?;
    let root = canonical_directory(root)?;
    let invitation: Invitation = serde_json::from_slice(
        &fs::read(invitation_path)
            .with_context(|| format!("read invitation {}", invitation_path.display()))?,
    )
    .context("parse Pando invitation")?;
    if invitation.version != CONFIG_VERSION {
        bail!("unsupported invitation version {}", invitation.version);
    }
    validate_id(&invitation.network_id, "network")?;
    if invitation.workspaces.is_empty() {
        bail!("invitation contains no workspaces");
    }
    for workspace in &invitation.workspaces {
        validate_workspace(workspace)?;
        let path = if workspace.relative_path == Path::new(".") {
            root.clone()
        } else {
            root.join(&workspace.relative_path)
        };
        fs::create_dir_all(path)?;
    }
    let managed_key = managed_key_path(data_root, &invitation.network_id);
    write_secret(
        &managed_key,
        format!("{}\n", invitation.key).as_bytes(),
        false,
    )?;
    TransportKey::load(&managed_key).context("invitation contains an invalid key")?;
    let config = DeviceConfig {
        version: CONFIG_VERSION,
        network_id: invitation.network_id,
        device_id: random_id(16)?,
        device_name: device_name.to_owned(),
        root,
        authority: invitation.authority,
        key_path: managed_key,
        workspaces: invitation.workspaces,
    };
    save_in(&config, data_root)?;
    Ok(config)
}

pub fn load(root: &Path) -> Result<DeviceConfig> {
    let root = canonical_directory(root)?;
    let path = config_path(&crate::sync::default_data_root()?, &root);
    let config: DeviceConfig = serde_json::from_slice(&fs::read(&path).with_context(|| {
        format!(
            "no Pando setup found for {}; run `pando setup host` or `pando setup join`",
            root.display()
        )
    })?)
    .with_context(|| format!("parse device configuration {}", path.display()))?;
    if config.version != CONFIG_VERSION || config.root != root {
        bail!("invalid device configuration {}", path.display());
    }
    TransportKey::load(&config.key_path)?;
    Ok(config)
}

pub fn discover(root: &Path) -> Result<Vec<PathBuf>> {
    let root = canonical_directory(root)?;
    if root.join(".git").exists() {
        return Ok(vec![PathBuf::from(".")]);
    }
    let mut repositories = Vec::new();
    for entry in WalkDir::new(&root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| discoverable(entry, &root))
    {
        let entry = entry?;
        if entry.depth() > 0 && entry.file_type().is_dir() && entry.path().join(".git").exists() {
            repositories.push(entry.path().strip_prefix(&root)?.to_owned());
        }
    }
    if repositories.is_empty() {
        repositories.push(PathBuf::from("."));
    }
    repositories.sort();
    repositories.dedup();
    Ok(repositories)
}

fn discoverable(entry: &DirEntry, root: &Path) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    if matches!(
        name.as_ref(),
        ".git" | ".pando" | "node_modules" | ".venv" | "target"
    ) {
        return false;
    }
    let parent_is_repo = entry
        .path()
        .parent()
        .is_some_and(|parent| parent != root && parent.join(".git").exists());
    !parent_is_repo
}

fn workspace(network_id: &str, root: &Path, relative_path: PathBuf) -> Result<WorkspaceConfig> {
    validate_relative(&relative_path)?;
    let path = if relative_path == Path::new(".") {
        root
    } else {
        &root.join(&relative_path)
    };
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("workspace")
        .to_owned();
    let identity = format!("{network_id}\0{}", relative_path.display());
    Ok(WorkspaceConfig {
        id: blake3::hash(identity.as_bytes()).to_hex().to_string(),
        name,
        relative_path,
    })
}

fn validate_workspace(workspace: &WorkspaceConfig) -> Result<()> {
    validate_id(&workspace.id, "workspace")?;
    validate_name(&workspace.name, "workspace")?;
    validate_relative(&workspace.relative_path)
}

fn validate_relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("workspace path must stay inside the selected folder");
    }
    Ok(())
}

fn validate_name(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.contains(['\n', '\r', '\0']) {
        bail!("{label} name is invalid");
    }
    Ok(())
}

fn validate_id(value: &str, label: &str) -> Result<()> {
    if value.len() != 32 && value.len() != 64 {
        bail!("invalid {label} ID");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("invalid {label} ID");
    }
    Ok(())
}

fn canonical_directory(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("open folder {}", path.display()))
}

fn save_in(config: &DeviceConfig, data_root: &Path) -> Result<()> {
    let path = config_path(data_root, &config.root);
    write_secret(&path, &serde_json::to_vec_pretty(config)?, false)
}

fn config_path(data_root: &Path, root: &Path) -> PathBuf {
    let key = blake3::hash(root.as_os_str().as_encoded_bytes()).to_hex();
    data_root.join("configurations").join(format!("{key}.json"))
}

fn managed_key_path(data_root: &Path, network_id: &str) -> PathBuf {
    data_root
        .join("networks")
        .join(network_id)
        .join("fabric.key")
}

fn random_id(bytes: usize) -> Result<String> {
    let mut random = vec![0_u8; bytes];
    getrandom::fill(&mut random).map_err(|error| anyhow::anyhow!("generate ID: {error}"))?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn write_secret(path: &Path, contents: &[u8], create_new: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("partial-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let target = if create_new { path } else { &temporary };
    let mut file = options
        .open(target)
        .with_context(|| format!("create {}", target.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    if !create_new {
        fs::rename(&temporary, path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_discovers_repositories_and_join_preserves_relative_paths() {
        let root = tempfile::tempdir().unwrap();
        let host = root.path().join("host");
        let client = root.path().join("client");
        fs::create_dir_all(host.join("apps/one/.git")).unwrap();
        fs::create_dir_all(host.join("services/two/.git")).unwrap();
        fs::create_dir_all(host.join("apps/one/nested/.git")).unwrap();
        fs::create_dir_all(host.join("node_modules/ignored/.git")).unwrap();
        let key = root.path().join("source.key");
        TransportKey::generate(&key).unwrap();
        let invitation = root.path().join("invite.json");

        let data = root.path().join("data");
        let host_config = create_host_in(
            &host,
            "devbox",
            "tcp://devbox:7337",
            &key,
            &invitation,
            &data,
        )
        .unwrap();
        assert_eq!(
            host_config
                .workspaces
                .iter()
                .map(|workspace| workspace.relative_path.clone())
                .collect::<Vec<_>>(),
            [PathBuf::from("apps/one"), PathBuf::from("services/two")]
        );

        let client_config = join_in(&client, "macbook", &invitation, &data).unwrap();
        assert_eq!(client_config.network_id, host_config.network_id);
        assert_eq!(client_config.workspaces, host_config.workspaces);
        assert!(client.join("apps/one").is_dir());
        assert!(client.join("services/two").is_dir());
        assert_ne!(client_config.device_id, host_config.device_id);
    }
}
