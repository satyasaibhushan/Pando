use crate::fsutil::atomic_json;
use crate::transport::TransportKey;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

const CONFIG_VERSION: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    pub id: String,
    pub name: String,
    pub relative_path: PathBuf,
}

/// A share this device has joined, mapped to a local folder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShareConfig {
    pub name: String,
    pub path: PathBuf,
    pub workspaces: Vec<WorkspaceConfig>,
}

/// This device's standing on its network. One config per device, stored in
/// the Pando data directory alongside the managed keys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub version: u32,
    pub network_id: String,
    pub device_id: String,
    pub device_name: String,
    /// Authority address as `host:port`.
    pub authority: String,
    pub shares: Vec<ShareConfig>,
}

impl DeviceConfig {
    pub fn new(
        network_id: String,
        device_id: String,
        device_name: String,
        authority: String,
    ) -> Self {
        Self {
            version: CONFIG_VERSION,
            network_id,
            device_id,
            device_name,
            authority,
            shares: Vec::new(),
        }
    }

    pub fn share(&self, name: &str) -> Option<&ShareConfig> {
        self.shares.iter().find(|share| share.name == name)
    }

    pub fn upsert_share(&mut self, share: ShareConfig) {
        match self.shares.iter_mut().find(|entry| entry.name == share.name) {
            Some(entry) => *entry = share,
            None => self.shares.push(share),
        }
    }

    pub fn workspace_path(&self, share: &ShareConfig, workspace: &WorkspaceConfig) -> PathBuf {
        if workspace.relative_path == Path::new(".") {
            share.path.clone()
        } else {
            share.path.join(&workspace.relative_path)
        }
    }

    /// Find the workspace containing `path`, if any share covers it.
    pub fn find_workspace(&self, path: &Path) -> Option<(&ShareConfig, &WorkspaceConfig)> {
        let path = path.canonicalize().ok()?;
        self.shares
            .iter()
            .flat_map(|share| {
                share
                    .workspaces
                    .iter()
                    .map(move |workspace| (share, workspace))
            })
            .filter(|(share, workspace)| path.starts_with(self.workspace_path(share, workspace)))
            .max_by_key(|(share, workspace)| {
                self.workspace_path(share, workspace).components().count()
            })
    }

    pub fn workspace_by_id(&self, id: &str) -> Option<(&ShareConfig, &WorkspaceConfig)> {
        self.shares.iter().find_map(|share| {
            share
                .workspaces
                .iter()
                .find(|workspace| workspace.id == id)
                .map(|workspace| (share, workspace))
        })
    }

    pub fn device_key(&self) -> Result<TransportKey> {
        TransportKey::load(device_key_path()?)
    }

    pub fn network_key(&self) -> Result<TransportKey> {
        TransportKey::load(network_key_path()?)
    }
}

pub fn config_path() -> Result<PathBuf> {
    Ok(crate::sync::default_data_root()?.join("device.json"))
}

pub fn device_key_path() -> Result<PathBuf> {
    Ok(crate::sync::default_data_root()?.join("keys/device.key"))
}

pub fn network_key_path() -> Result<PathBuf> {
    Ok(crate::sync::default_data_root()?.join("keys/network.key"))
}

/// Where this device's own authority keeps its data, when it hosts one.
pub fn authority_data_path() -> Result<PathBuf> {
    Ok(crate::sync::default_data_root()?.join("authority"))
}

pub fn load() -> Result<DeviceConfig> {
    try_load()?.context("this device is not on a Pando network yet; run `pando up`")
}

pub fn try_load() -> Result<Option<DeviceConfig>> {
    let path = config_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("read device config {}", path.display()));
        }
    };
    let config: DeviceConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse device config {}", path.display()))?;
    if config.version != CONFIG_VERSION {
        bail!("unsupported device config version {}", config.version);
    }
    validate_id(&config.network_id, "network")?;
    validate_id(&config.device_id, "device")?;
    validate_name(&config.device_name, "device")?;
    for share in &config.shares {
        validate_name(&share.name, "share")?;
        for workspace in &share.workspaces {
            validate_workspace(workspace)?;
        }
    }
    Ok(Some(config))
}

pub fn save(config: &DeviceConfig) -> Result<()> {
    atomic_json(&config_path()?, config, true)
}

/// Find the Git repositories beneath `root`, one workspace each. A folder
/// that is itself a repository becomes a single workspace at ".".
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

pub fn workspace(
    network_id: &str,
    share_name: &str,
    root: &Path,
    relative_path: PathBuf,
) -> Result<WorkspaceConfig> {
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
    let identity = format!("{network_id}\0{share_name}\0{}", relative_path.display());
    Ok(WorkspaceConfig {
        id: blake3::hash(identity.as_bytes()).to_hex().to_string(),
        name,
        relative_path,
    })
}

pub fn validate_workspace(workspace: &WorkspaceConfig) -> Result<()> {
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
        bail!("workspace path must stay inside the shared folder");
    }
    Ok(())
}

pub fn validate_name(value: &str, label: &str) -> Result<()> {
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

pub fn canonical_directory(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("open folder {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn discovery_finds_top_level_repositories_only() {
        let root = tempfile::tempdir().unwrap();
        let host = root.path().join("host");
        fs::create_dir_all(host.join("apps/one/.git")).unwrap();
        fs::create_dir_all(host.join("services/two/.git")).unwrap();
        fs::create_dir_all(host.join("apps/one/nested/.git")).unwrap();
        fs::create_dir_all(host.join("node_modules/ignored/.git")).unwrap();

        assert_eq!(
            discover(&host).unwrap(),
            [PathBuf::from("apps/one"), PathBuf::from("services/two")]
        );
    }

    #[test]
    fn workspace_ids_are_scoped_to_network_and_share() {
        let root = tempfile::tempdir().unwrap();
        let network = "0011223344556677001122334455667700112233445566770011223344556677";
        let personal = workspace(network, "personal", root.path(), PathBuf::from("blog")).unwrap();
        let work = workspace(network, "work", root.path(), PathBuf::from("blog")).unwrap();

        assert_eq!(personal.name, "blog");
        assert_ne!(personal.id, work.id);
    }

    #[test]
    fn find_workspace_prefers_the_deepest_match() {
        let root = tempfile::tempdir().unwrap();
        let share_path = root.path().canonicalize().unwrap();
        fs::create_dir_all(share_path.join("apps/one/src")).unwrap();
        let mut config = DeviceConfig::new(
            "00112233445566770011223344556677".into(),
            "88990011223344558899001122334455".into(),
            "devbox".into(),
            "127.0.0.1:7337".into(),
        );
        config.upsert_share(ShareConfig {
            name: "personal".into(),
            path: share_path.clone(),
            workspaces: vec![
                workspace(&config.network_id, "personal", &share_path, ".".into()).unwrap(),
                workspace(&config.network_id, "personal", &share_path, "apps/one".into()).unwrap(),
            ],
        });

        let (_, found) = config
            .find_workspace(&share_path.join("apps/one/src"))
            .unwrap();
        assert_eq!(found.relative_path, PathBuf::from("apps/one"));
        let (_, found) = config.find_workspace(&share_path).unwrap();
        assert_eq!(found.relative_path, PathBuf::from("."));
    }
}
