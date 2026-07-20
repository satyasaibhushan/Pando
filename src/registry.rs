use crate::config::WorkspaceConfig;
use crate::fsutil::atomic_json;
use crate::transport::TransportKey;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const CODE_TTL_MS: u64 = 15 * 60 * 1000;
const CODE_MAX_ATTEMPTS: u32 = 3;
/// Unambiguous lowercase alphabet for enrollment codes (no 0/o/1/l/i).
const CODE_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
const ENROLLMENT_PSK_CONTEXT: &str = "pando-enrollment-psk-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub name: String,
    key: String,
    pub enrolled_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub enrolled_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShareRecord {
    pub name: String,
    pub host: String,
    pub workspaces: Vec<WorkspaceConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnrollmentGrant {
    pub network_id: String,
    pub device_id: String,
    pub device_key: String,
    pub network_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingCode {
    psk: String,
    expires_at_ms: u64,
    attempts: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegistryState {
    network_id: String,
    network_key: String,
    advertised: String,
    devices: BTreeMap<String, DeviceRecord>,
    #[serde(default)]
    codes: BTreeMap<String, PendingCode>,
    #[serde(default)]
    shares: BTreeMap<String, ShareRecord>,
}

/// The authority's device, enrollment-code, and share catalog, stored next to
/// its snapshot data. Every mutation is written back atomically.
#[derive(Clone, Debug)]
pub struct Registry {
    path: PathBuf,
}

impl Registry {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        directory: &Path,
        network_id: &str,
        advertised: &str,
        network_key: &TransportKey,
        device_id: &str,
        device_name: &str,
        device_key: &TransportKey,
        now_ms: u64,
    ) -> Result<Self> {
        let registry = Self {
            path: directory.join("registry.json"),
        };
        if registry.path.exists() {
            bail!("a Pando network already exists at {}", directory.display());
        }
        registry.save(&RegistryState {
            network_id: network_id.to_owned(),
            network_key: network_key.encoded(),
            advertised: advertised.to_owned(),
            devices: BTreeMap::from([(
                device_id.to_owned(),
                DeviceRecord {
                    name: device_name.to_owned(),
                    key: device_key.encoded(),
                    enrolled_at_ms: now_ms,
                },
            )]),
            codes: BTreeMap::new(),
            shares: BTreeMap::new(),
        })?;
        Ok(registry)
    }

    pub fn open(directory: &Path) -> Result<Self> {
        let registry = Self {
            path: directory.join("registry.json"),
        };
        registry.load()?;
        Ok(registry)
    }

    pub fn network_id(&self) -> Result<String> {
        Ok(self.load()?.network_id)
    }

    pub fn advertised(&self) -> Result<String> {
        Ok(self.load()?.advertised)
    }

    pub fn device_key(&self, device_id: &str) -> Result<TransportKey> {
        let state = self.load()?;
        let record = state
            .devices
            .get(device_id)
            .with_context(|| format!("unknown device {device_id}"))?;
        TransportKey::from_hex(&record.key)
    }

    pub fn device_name(&self, device_id: &str) -> Result<String> {
        let state = self.load()?;
        Ok(state
            .devices
            .get(device_id)
            .with_context(|| format!("unknown device {device_id}"))?
            .name
            .clone())
    }

    pub fn devices(&self) -> Result<Vec<DeviceInfo>> {
        Ok(self
            .load()?
            .devices
            .into_iter()
            .map(|(id, record)| DeviceInfo {
                id,
                name: record.name,
                enrolled_at_ms: record.enrolled_at_ms,
            })
            .collect())
    }

    /// Delete a device's credentials; its next connection is refused.
    pub fn revoke_device(&self, device_id: &str) -> Result<String> {
        let mut state = self.load()?;
        let record = state
            .devices
            .remove(device_id)
            .with_context(|| format!("unknown device {device_id}"))?;
        self.save(&state)?;
        Ok(record.name)
    }

    /// Mint a fresh single-use enrollment code.
    pub fn new_code(&self, now_ms: u64) -> Result<(String, u64)> {
        let mut state = self.load()?;
        state.codes.retain(|_, code| code.expires_at_ms > now_ms);
        let code = generate_code()?;
        let expires_at_ms = now_ms + CODE_TTL_MS;
        state.codes.insert(
            code_id(&code),
            PendingCode {
                psk: hex(&enrollment_psk(&code)),
                expires_at_ms,
                attempts: 0,
            },
        );
        self.save(&state)?;
        Ok((code, expires_at_ms))
    }

    /// Look up the handshake secret for a pending code, counting the attempt.
    /// Codes disappear after expiry or too many failed handshakes.
    pub fn enrollment_psk(&self, code_id: &str, now_ms: u64) -> Result<TransportKey> {
        let mut state = self.load()?;
        let Some(code) = state.codes.get_mut(code_id) else {
            bail!("unknown or already-used enrollment code");
        };
        if code.expires_at_ms <= now_ms {
            state.codes.remove(code_id);
            self.save(&state)?;
            bail!("enrollment code expired");
        }
        code.attempts += 1;
        if code.attempts > CODE_MAX_ATTEMPTS {
            state.codes.remove(code_id);
            self.save(&state)?;
            bail!("enrollment code invalidated after too many attempts");
        }
        let psk = TransportKey::from_hex(&state.codes[code_id].psk)?;
        self.save(&state)?;
        Ok(psk)
    }

    /// Mint credentials for a newly enrolled device and burn the code.
    pub fn enroll_device(
        &self,
        code_id: &str,
        device_name: &str,
        now_ms: u64,
    ) -> Result<EnrollmentGrant> {
        let mut state = self.load()?;
        if state.codes.remove(code_id).is_none() {
            bail!("unknown or already-used enrollment code");
        }
        let device_id = random_hex(16)?;
        let device_key = TransportKey::random()?;
        state.devices.insert(
            device_id.clone(),
            DeviceRecord {
                name: device_name.to_owned(),
                key: device_key.encoded(),
                enrolled_at_ms: now_ms,
            },
        );
        let grant = EnrollmentGrant {
            network_id: state.network_id.clone(),
            device_id,
            device_key: device_key.encoded(),
            network_key: state.network_key.clone(),
        };
        self.save(&state)?;
        Ok(grant)
    }

    pub fn upsert_share(&self, share: ShareRecord) -> Result<()> {
        let mut state = self.load()?;
        state.shares.insert(share.name.clone(), share);
        self.save(&state)
    }

    pub fn shares(&self) -> Result<Vec<ShareRecord>> {
        Ok(self.load()?.shares.into_values().collect())
    }

    fn load(&self) -> Result<RegistryState> {
        let bytes = fs::read(&self.path)
            .with_context(|| format!("read network registry {}", self.path.display()))?;
        serde_json::from_slice(&bytes).context("parse network registry")
    }

    fn save(&self, state: &RegistryState) -> Result<()> {
        atomic_json(&self.path, state, true)
    }
}

/// Derive the enrollment handshake secret from a one-time code.
pub fn enrollment_psk(code: &str) -> [u8; 32] {
    blake3::derive_key(ENROLLMENT_PSK_CONTEXT, code.trim().as_bytes())
}

/// Public identifier for a code, safe to send before the handshake.
pub fn code_id(code: &str) -> String {
    blake3::hash(code.trim().as_bytes()).to_hex()[..16].to_owned()
}

fn generate_code() -> Result<String> {
    let mut random = [0_u8; 10];
    getrandom::fill(&mut random).map_err(|error| anyhow::anyhow!("generate code: {error}"))?;
    let characters: String = random
        .iter()
        .map(|byte| CODE_ALPHABET[(*byte as usize) % CODE_ALPHABET.len()] as char)
        .collect();
    Ok(format!("{}-{}", &characters[..5], &characters[5..]))
}

pub fn random_hex(bytes: usize) -> Result<String> {
    let mut random = vec![0_u8; bytes];
    getrandom::fill(&mut random).map_err(|error| anyhow::anyhow!("generate ID: {error}"))?;
    Ok(hex(&random))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(root: &Path) -> Registry {
        Registry::create(
            root,
            &random_hex(16).unwrap(),
            "192.0.2.1:7337",
            &TransportKey::random().unwrap(),
            "aabbccdd00112233aabbccdd00112233",
            "devbox",
            &TransportKey::random().unwrap(),
            1_000,
        )
        .unwrap()
    }

    #[test]
    fn codes_are_single_use_and_expire() {
        let root = tempfile::tempdir().unwrap();
        let registry = registry(root.path());
        let (code, expires) = registry.new_code(1_000).unwrap();
        assert_eq!(expires, 1_000 + CODE_TTL_MS);

        let id = code_id(&code);
        assert!(registry.enrollment_psk(&id, 2_000).is_ok());
        let grant = registry.enroll_device(&id, "macbook", 2_000).unwrap();
        assert_eq!(grant.device_key.len(), 64);
        assert!(registry.enrollment_psk(&id, 2_000).is_err());
        assert!(registry.enroll_device(&id, "macbook", 2_000).is_err());

        let (stale, _) = registry.new_code(1_000).unwrap();
        assert!(
            registry
                .enrollment_psk(&code_id(&stale), 1_000 + CODE_TTL_MS)
                .is_err()
        );
    }

    #[test]
    fn codes_stop_working_after_repeated_attempts() {
        let root = tempfile::tempdir().unwrap();
        let registry = registry(root.path());
        let (code, _) = registry.new_code(1_000).unwrap();
        let id = code_id(&code);
        for _ in 0..CODE_MAX_ATTEMPTS {
            assert!(registry.enrollment_psk(&id, 2_000).is_ok());
        }
        assert!(registry.enrollment_psk(&id, 2_000).is_err());
        assert!(registry.enroll_device(&id, "macbook", 2_000).is_err());
    }

    #[test]
    fn revoked_devices_lose_their_keys() {
        let root = tempfile::tempdir().unwrap();
        let registry = registry(root.path());
        let (code, _) = registry.new_code(1_000).unwrap();
        let id = code_id(&code);
        registry.enrollment_psk(&id, 2_000).unwrap();
        let grant = registry.enroll_device(&id, "macbook", 2_000).unwrap();

        assert!(registry.device_key(&grant.device_id).is_ok());
        assert_eq!(registry.revoke_device(&grant.device_id).unwrap(), "macbook");
        assert!(registry.device_key(&grant.device_id).is_err());
        assert_eq!(registry.devices().unwrap().len(), 1);
    }
}
