use crate::authority::{AcquireResult, Authority, AuthorityStatus, FileAuthority};
use crate::clock::{Clock, SystemClock};
use crate::model::{Overlay, SnapshotId};
use crate::registry::{DeviceInfo, EnrollmentGrant, Registry, ShareRecord};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use zeroize::Zeroize;

const MAX_MESSAGE_BYTES: usize = 512 * 1024 * 1024;
const MAX_NOISE_PLAINTEXT_BYTES: usize = 65_519;
const MAX_NOISE_CIPHERTEXT_BYTES: usize = 65_535;
const NOISE_PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const NOISE_PROLOGUE: &[u8] = b"pando-authority-rpc-v1";

#[derive(Clone)]
pub struct TransportKey([u8; 32]);

impl TransportKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)
                .with_context(|| format!("inspect transport key {}", path.display()))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                bail!(
                    "transport key {} is accessible by group or others; run chmod 600 {}",
                    path.display(),
                    path.display()
                );
            }
        }
        let encoded = fs::read_to_string(path)
            .with_context(|| format!("read transport key {}", path.display()))?;
        let encoded = encoded.trim();
        if encoded.len() != 64 || !encoded.is_ascii() {
            bail!("transport key must contain exactly 64 hexadecimal characters");
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
                .context("transport key contains non-hexadecimal characters")?;
        }
        Ok(Self(bytes))
    }

    pub fn from_hex(encoded: &str) -> Result<Self> {
        let encoded = encoded.trim();
        if encoded.len() != 64 || !encoded.is_ascii() {
            bail!("key must contain exactly 64 hexadecimal characters");
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
                .context("key contains non-hexadecimal characters")?;
        }
        Ok(Self(bytes))
    }

    pub fn random() -> Result<Self> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("generate key: {error}"))?;
        Ok(Self(bytes))
    }

    /// Persist this key at `path` (0600), refusing to overwrite an existing key.
    pub fn store(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("create key directory {}", parent.display()))?;
        }
        let encoded = self.hex();
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("create key {}", path.display()))?;
        writeln!(file, "{encoded}")?;
        file.sync_all()?;
        Ok(())
    }

    pub fn generate(path: impl AsRef<Path>) -> Result<Self> {
        let key = Self::random()?;
        key.store(path)?;
        Ok(key)
    }

    pub fn fingerprint(&self) -> String {
        blake3::hash(&self.0).to_hex()[..12].to_owned()
    }

    pub(crate) fn derive_key(&self, context: &str) -> [u8; 32] {
        blake3::derive_key(context, &self.0)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for &byte in &self.0 {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }

    pub(crate) fn encoded(&self) -> String {
        self.hex()
    }
}

impl Drop for TransportKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for TransportKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TransportKey")
            .field(&self.fingerprint())
            .finish()
    }
}

#[derive(Clone)]
pub struct RemoteAuthority {
    address: String,
    device_id: String,
    key: TransportKey,
}

impl fmt::Debug for RemoteAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteAuthority")
            .field("address", &self.address)
            .field("device_id", &self.device_id)
            .field("key_fingerprint", &self.key.fingerprint())
            .finish()
    }
}

/// Sent in the clear before the Noise handshake so the authority knows which
/// pre-shared key to expect: an enrolled device's key, or one derived from a
/// pending enrollment code.
#[derive(Debug, Serialize, Deserialize)]
enum Hello {
    Device { device_id: String },
    Enroll { code_id: String },
}

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Enroll {
        device_name: String,
    },
    NewCode,
    Devices,
    RevokeDevice {
        device_id: String,
    },
    UpsertShare {
        share: ShareRecord,
    },
    Shares,
    Acquire {
        repo_id: String,
        trunk_id: String,
        now_ms: u64,
        ttl_ms: u64,
    },
    Release {
        repo_id: String,
        trunk_id: String,
    },
    PutChunk {
        hash: String,
        bytes: Vec<u8>,
    },
    HasChunk {
        hash: String,
    },
    GetChunk {
        hash: String,
    },
    Publish {
        overlay: Overlay,
        trunk_id: String,
        now_ms: u64,
    },
    PublishFork {
        overlay: Overlay,
        trunk_id: String,
        now_ms: u64,
    },
    Forks {
        repo_id: String,
    },
    ResolveFork {
        repo_id: String,
        snapshot_id: String,
    },
    Head {
        repo_id: String,
    },
    Overlay {
        snapshot_id: String,
    },
    Status {
        repo_id: String,
        now_ms: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
enum Response {
    Ok,
    Enrolled(EnrollmentGrant),
    Code {
        code: String,
        address: String,
        expires_at_ms: u64,
    },
    Devices(Vec<DeviceInfo>),
    Shares(Vec<ShareRecord>),
    Acquire(AcquireResult),
    Bool(bool),
    Bytes(Vec<u8>),
    Head(Option<SnapshotId>),
    Overlay(Overlay),
    Forks(Vec<SnapshotId>),
    Status(AuthorityStatus),
    Error(String),
}

/// A freshly minted enrollment code plus where to point the new device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invite {
    pub code: String,
    pub address: String,
    pub expires_at_ms: u64,
}

impl RemoteAuthority {
    pub fn new(
        address: impl Into<String>,
        device_id: impl Into<String>,
        key: TransportKey,
    ) -> Self {
        Self {
            address: address.into(),
            device_id: device_id.into(),
            key,
        }
    }

    pub fn invite(&self) -> Result<Invite> {
        match self.rpc(Request::NewCode)? {
            Response::Code {
                code,
                address,
                expires_at_ms,
            } => Ok(Invite {
                code,
                address,
                expires_at_ms,
            }),
            _ => bail!("unexpected invite response"),
        }
    }

    pub fn devices(&self) -> Result<Vec<DeviceInfo>> {
        match self.rpc(Request::Devices)? {
            Response::Devices(devices) => Ok(devices),
            _ => bail!("unexpected devices response"),
        }
    }

    pub fn revoke_device(&self, device_id: &str) -> Result<()> {
        expect_ok(self.rpc(Request::RevokeDevice {
            device_id: device_id.into(),
        })?)
    }

    pub fn upsert_share(&self, share: ShareRecord) -> Result<()> {
        expect_ok(self.rpc(Request::UpsertShare { share })?)
    }

    pub fn shares(&self) -> Result<Vec<ShareRecord>> {
        match self.rpc(Request::Shares)? {
            Response::Shares(shares) => Ok(shares),
            _ => bail!("unexpected shares response"),
        }
    }

    fn rpc(&self, request: Request) -> Result<Response> {
        let mut stream = open_stream(&self.address)?;
        write_handshake_frame(&mut stream, &encode_hello(&Hello::Device {
            device_id: self.device_id.clone(),
        })?)?;
        let mut session =
            initiator_handshake(&mut stream, &self.key).context("secure authority handshake")?;
        write_secure_message(&mut stream, &mut session, &request)?;
        let response: Response = read_secure_message(&mut stream, &mut session)?;
        match response {
            Response::Error(message) => bail!(message),
            other => Ok(other),
        }
    }
}

/// Join a network: authenticate with a one-time enrollment code and receive
/// this device's minted credentials.
pub fn enroll(address: &str, code: &str, device_name: &str) -> Result<EnrollmentGrant> {
    let psk = TransportKey::from_bytes(crate::registry::enrollment_psk(code));
    let mut stream = open_stream(address)?;
    write_handshake_frame(&mut stream, &encode_hello(&Hello::Enroll {
        code_id: crate::registry::code_id(code),
    })?)?;
    let mut session = initiator_handshake(&mut stream, &psk)
        .context("enrollment refused; check the code and address")?;
    write_secure_message(&mut stream, &mut session, &Request::Enroll {
        device_name: device_name.to_owned(),
    })?;
    match read_secure_message(&mut stream, &mut session)? {
        Response::Enrolled(grant) => Ok(grant),
        Response::Error(message) => bail!(message),
        _ => bail!("unexpected enrollment response"),
    }
}

fn open_stream(address: &str) -> Result<TcpStream> {
    let addresses = address
        .to_socket_addrs()
        .with_context(|| format!("resolve authority {address}"))?;
    let stream = connect_any(addresses, std::time::Duration::from_secs(5))
        .with_context(|| format!("connect to authority {address}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    Ok(stream)
}

fn encode_hello(hello: &Hello) -> Result<Vec<u8>> {
    Ok(bincode::serde::encode_to_vec(
        hello,
        bincode::config::standard(),
    )?)
}

fn connect_any(
    addresses: impl Iterator<Item = SocketAddr>,
    timeout: std::time::Duration,
) -> std::io::Result<TcpStream> {
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "no authority addresses")
    }))
}

impl Authority for RemoteAuthority {
    fn acquire(
        &mut self,
        repo_id: &str,
        trunk_id: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<AcquireResult> {
        match self.rpc(Request::Acquire {
            repo_id: repo_id.into(),
            trunk_id: trunk_id.into(),
            now_ms,
            ttl_ms,
        })? {
            Response::Acquire(result) => Ok(result),
            _ => bail!("unexpected acquire response"),
        }
    }

    fn release(&mut self, repo_id: &str, trunk_id: &str) -> Result<()> {
        expect_ok(self.rpc(Request::Release {
            repo_id: repo_id.into(),
            trunk_id: trunk_id.into(),
        })?)
    }

    fn put_chunk(&mut self, hash: &str, bytes: &[u8]) -> Result<()> {
        expect_ok(self.rpc(Request::PutChunk {
            hash: hash.into(),
            bytes: bytes.to_vec(),
        })?)
    }

    fn has_chunk(&self, hash: &str) -> Result<bool> {
        match self.rpc(Request::HasChunk { hash: hash.into() })? {
            Response::Bool(value) => Ok(value),
            _ => bail!("unexpected has-chunk response"),
        }
    }

    fn get_chunk(&self, hash: &str) -> Result<Vec<u8>> {
        match self.rpc(Request::GetChunk { hash: hash.into() })? {
            Response::Bytes(bytes) => Ok(bytes),
            _ => bail!("unexpected get-chunk response"),
        }
    }

    fn publish(&mut self, overlay: &Overlay, trunk_id: &str, now_ms: u64) -> Result<()> {
        expect_ok(self.rpc(Request::Publish {
            overlay: overlay.clone(),
            trunk_id: trunk_id.into(),
            now_ms,
        })?)
    }

    fn publish_fork(&mut self, overlay: &Overlay, trunk_id: &str, now_ms: u64) -> Result<()> {
        expect_ok(self.rpc(Request::PublishFork {
            overlay: overlay.clone(),
            trunk_id: trunk_id.into(),
            now_ms,
        })?)
    }

    fn forks(&self, repo_id: &str) -> Result<Vec<SnapshotId>> {
        match self.rpc(Request::Forks {
            repo_id: repo_id.into(),
        })? {
            Response::Forks(forks) => Ok(forks),
            _ => bail!("unexpected forks response"),
        }
    }

    fn resolve_fork(&mut self, repo_id: &str, snapshot_id: &str) -> Result<()> {
        expect_ok(self.rpc(Request::ResolveFork {
            repo_id: repo_id.into(),
            snapshot_id: snapshot_id.into(),
        })?)
    }

    fn head(&self, repo_id: &str) -> Result<Option<SnapshotId>> {
        match self.rpc(Request::Head {
            repo_id: repo_id.into(),
        })? {
            Response::Head(head) => Ok(head),
            _ => bail!("unexpected head response"),
        }
    }

    fn overlay(&self, snapshot_id: &str) -> Result<Overlay> {
        match self.rpc(Request::Overlay {
            snapshot_id: snapshot_id.into(),
        })? {
            Response::Overlay(overlay) => Ok(overlay),
            _ => bail!("unexpected overlay response"),
        }
    }

    fn status(&self, repo_id: &str, now_ms: u64) -> Result<AuthorityStatus> {
        match self.rpc(Request::Status {
            repo_id: repo_id.into(),
            now_ms,
        })? {
            Response::Status(status) => Ok(status),
            _ => bail!("unexpected status response"),
        }
    }
}

pub fn serve(address: &str, authority: FileAuthority, registry: Registry) -> Result<()> {
    let listener =
        TcpListener::bind(address).with_context(|| format!("bind authority to {address}"))?;
    serve_listener(listener, authority, registry)
}

pub fn serve_listener(
    listener: TcpListener,
    authority: FileAuthority,
    registry: Registry,
) -> Result<()> {
    let authority = Arc::new(Mutex::new(authority));
    let registry = Arc::new(Mutex::new(registry));
    for stream in listener.incoming() {
        let authority = authority.clone();
        let registry = registry.clone();
        let stream = stream?;
        thread::spawn(move || {
            if let Err(error) = handle_connection(stream, &authority, &registry)
                && std::env::var_os("PANDO_DEBUG").is_some()
            {
                eprintln!("authority connection failed: {error:#}");
            }
        });
    }
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    authority: &Arc<Mutex<FileAuthority>>,
    registry: &Arc<Mutex<Registry>>,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let hello = read_handshake_frame(&mut stream)?;
    let (hello, bytes_read): (Hello, usize) =
        bincode::serde::decode_from_slice(&hello, bincode::config::standard())
            .context("decode client hello")?;
    if bytes_read != hello_length(&hello)? {
        bail!("client hello contains trailing bytes");
    }
    let now_ms = SystemClock.now_ms();
    match hello {
        Hello::Device { device_id } => {
            let key = lock(registry)?.device_key(&device_id)?;
            let mut session =
                responder_handshake(&mut stream, &key).context("secure client handshake")?;
            let request: Request = read_secure_message(&mut stream, &mut session)?;
            let response = dispatch(request, &device_id, authority, registry, now_ms);
            write_secure_message(&mut stream, &mut session, &response)
        }
        Hello::Enroll { code_id } => {
            let psk = lock(registry)?.enrollment_psk(&code_id, now_ms)?;
            let mut session =
                responder_handshake(&mut stream, &psk).context("enrollment handshake")?;
            let request: Request = read_secure_message(&mut stream, &mut session)?;
            let response = match request {
                Request::Enroll { device_name } => lock(registry)
                    .and_then(|registry| registry.enroll_device(&code_id, &device_name, now_ms))
                    .map(Response::Enrolled)
                    .unwrap_or_else(|error| Response::Error(format!("{error:#}"))),
                _ => Response::Error("this connection may only enroll".into()),
            };
            write_secure_message(&mut stream, &mut session, &response)
        }
    }
}

fn hello_length(hello: &Hello) -> Result<usize> {
    Ok(bincode::serde::encode_to_vec(hello, bincode::config::standard())?.len())
}

fn lock<'a, T>(value: &'a Arc<Mutex<T>>) -> Result<std::sync::MutexGuard<'a, T>> {
    value
        .lock()
        .map_err(|_| anyhow::anyhow!("authority lock poisoned"))
}

fn dispatch(
    request: Request,
    caller: &str,
    authority: &Arc<Mutex<FileAuthority>>,
    registry: &Arc<Mutex<Registry>>,
    now_ms: u64,
) -> Response {
    let result = (|| -> Result<Response> {
        match request {
            Request::Enroll { .. } => {
                bail!("enrollment requires a one-time code, not device credentials")
            }
            Request::NewCode => {
                let registry = lock(registry)?;
                let (code, expires_at_ms) = registry.new_code(now_ms)?;
                return Ok(Response::Code {
                    code,
                    address: registry.advertised()?,
                    expires_at_ms,
                });
            }
            Request::Devices => return Ok(Response::Devices(lock(registry)?.devices()?)),
            Request::RevokeDevice { device_id } => {
                if device_id == caller {
                    bail!("a device cannot revoke itself");
                }
                lock(registry)?.revoke_device(&device_id)?;
                return Ok(Response::Ok);
            }
            Request::UpsertShare { share } => {
                lock(registry)?.upsert_share(share)?;
                return Ok(Response::Ok);
            }
            Request::Shares => return Ok(Response::Shares(lock(registry)?.shares()?)),
            _ => {}
        }
        let mut authority = lock(authority)?;
        Ok(match request {
            Request::Acquire {
                repo_id,
                trunk_id,
                now_ms,
                ttl_ms,
            } => Response::Acquire(authority.acquire(&repo_id, &trunk_id, now_ms, ttl_ms)?),
            Request::Release { repo_id, trunk_id } => {
                authority.release(&repo_id, &trunk_id)?;
                Response::Ok
            }
            Request::PutChunk { hash, bytes } => {
                authority.put_chunk(&hash, &bytes)?;
                Response::Ok
            }
            Request::HasChunk { hash } => Response::Bool(authority.has_chunk(&hash)?),
            Request::GetChunk { hash } => Response::Bytes(authority.get_chunk(&hash)?),
            Request::Publish {
                overlay,
                trunk_id,
                now_ms,
            } => {
                authority.publish(&overlay, &trunk_id, now_ms)?;
                Response::Ok
            }
            Request::PublishFork {
                overlay,
                trunk_id,
                now_ms,
            } => {
                authority.publish_fork(&overlay, &trunk_id, now_ms)?;
                Response::Ok
            }
            Request::Forks { repo_id } => Response::Forks(authority.forks(&repo_id)?),
            Request::ResolveFork {
                repo_id,
                snapshot_id,
            } => {
                authority.resolve_fork(&repo_id, &snapshot_id)?;
                Response::Ok
            }
            Request::Head { repo_id } => Response::Head(authority.head(&repo_id)?),
            Request::Overlay { snapshot_id } => Response::Overlay(authority.overlay(&snapshot_id)?),
            Request::Status { repo_id, now_ms } => {
                Response::Status(authority.status(&repo_id, now_ms)?)
            }
            _ => bail!("request was already handled"),
        })
    })();
    result.unwrap_or_else(|error| Response::Error(format!("{error:#}")))
}

fn expect_ok(response: Response) -> Result<()> {
    match response {
        Response::Ok => Ok(()),
        _ => bail!("unexpected authority response"),
    }
}

fn write_secure_message<W: Write>(
    stream: &mut W,
    session: &mut snow::TransportState,
    value: &impl Serialize,
) -> Result<()> {
    let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard())?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        bail!("authority message exceeds {} bytes", MAX_MESSAGE_BYTES);
    }
    write_noise_record(stream, session, &(bytes.len() as u64).to_be_bytes())?;
    for chunk in bytes.chunks(MAX_NOISE_PLAINTEXT_BYTES) {
        write_noise_record(stream, session, chunk)?;
    }
    stream.flush()?;
    Ok(())
}

fn read_secure_message<R: Read, T: DeserializeOwned>(
    stream: &mut R,
    session: &mut snow::TransportState,
) -> Result<T> {
    let header = read_noise_record(stream, session)?;
    let header: [u8; 8] = header
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid encrypted message header"))?;
    let length = usize::try_from(u64::from_be_bytes(header))
        .context("authority message length does not fit this platform")?;
    if length > MAX_MESSAGE_BYTES {
        bail!("authority message claims {length} bytes");
    }
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        let chunk = read_noise_record(stream, session)?;
        if bytes.len() + chunk.len() > length {
            bail!("encrypted authority message exceeds declared length");
        }
        bytes.extend_from_slice(&chunk);
    }
    let (value, bytes_read) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
            .context("decode authority message")?;
    if bytes_read != bytes.len() {
        bail!("authority message contains trailing bytes");
    }
    Ok(value)
}

fn initiator_handshake(stream: &mut TcpStream, key: &TransportKey) -> Result<snow::TransportState> {
    let mut handshake = snow::Builder::new(NOISE_PATTERN.parse()?)
        .psk(0, key.as_bytes())?
        .prologue(NOISE_PROLOGUE)?
        .build_initiator()?;
    let mut message = [0; MAX_NOISE_CIPHERTEXT_BYTES];
    let length = handshake.write_message(&[], &mut message)?;
    write_handshake_frame(stream, &message[..length])?;
    let response = read_handshake_frame(stream)?;
    let mut payload = [0; MAX_NOISE_CIPHERTEXT_BYTES];
    handshake.read_message(&response, &mut payload)?;
    handshake.into_transport_mode().map_err(anyhow::Error::from)
}

fn responder_handshake(stream: &mut TcpStream, key: &TransportKey) -> Result<snow::TransportState> {
    let mut handshake = snow::Builder::new(NOISE_PATTERN.parse()?)
        .psk(0, key.as_bytes())?
        .prologue(NOISE_PROLOGUE)?
        .build_responder()?;
    let request = read_handshake_frame(stream)?;
    let mut payload = [0; MAX_NOISE_CIPHERTEXT_BYTES];
    handshake.read_message(&request, &mut payload)?;
    let mut message = [0; MAX_NOISE_CIPHERTEXT_BYTES];
    let length = handshake.write_message(&[], &mut message)?;
    write_handshake_frame(stream, &message[..length])?;
    handshake.into_transport_mode().map_err(anyhow::Error::from)
}

fn write_handshake_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    let length = u16::try_from(bytes.len()).context("Noise handshake message is too large")?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

fn read_handshake_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0; 2];
    stream.read_exact(&mut header)?;
    let length = u16::from_be_bytes(header) as usize;
    if length == 0 {
        bail!("empty Noise handshake message");
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_noise_record<W: Write>(
    stream: &mut W,
    session: &mut snow::TransportState,
    plaintext: &[u8],
) -> Result<()> {
    if plaintext.len() > MAX_NOISE_PLAINTEXT_BYTES {
        bail!("Noise plaintext record is too large");
    }
    let mut ciphertext = vec![0; plaintext.len() + 16];
    let length = session.write_message(plaintext, &mut ciphertext)?;
    let length = u16::try_from(length).context("Noise ciphertext record is too large")?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&ciphertext[..length as usize])?;
    Ok(())
}

fn read_noise_record<R: Read>(
    stream: &mut R,
    session: &mut snow::TransportState,
) -> Result<Vec<u8>> {
    let mut header = [0; 2];
    stream.read_exact(&mut header)?;
    let length = u16::from_be_bytes(header) as usize;
    if !(16..=MAX_NOISE_CIPHERTEXT_BYTES).contains(&length) {
        bail!("invalid Noise ciphertext record length {length}");
    }
    let mut ciphertext = vec![0; length];
    stream.read_exact(&mut ciphertext)?;
    let mut plaintext = vec![0; length];
    let length = session.read_message(&ciphertext, &mut plaintext)?;
    plaintext.truncate(length);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_NOISE_CIPHERTEXT_BYTES, NOISE_PATTERN, NOISE_PROLOGUE, Request, TransportKey,
        connect_any, handle_connection, read_secure_message, write_secure_message,
    };
    use crate::authority::FileAuthority;
    use crate::registry::{Registry, random_hex};
    use std::io::{Cursor, ErrorKind, Read, Write};
    use std::net::{Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[test]
    fn connection_falls_back_to_the_next_resolved_address() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let reachable = listener.local_addr().unwrap();
        let unreachable = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), reachable.port());

        let stream = connect_any(
            [unreachable, reachable].into_iter(),
            Duration::from_millis(100),
        );

        assert!(stream.is_ok());
    }

    #[test]
    fn secure_frames_hide_plaintext_and_round_trip() {
        let (mut initiator, mut responder) = transport_pair(&TransportKey::from_bytes([9; 32]));
        let marker = b"top secret working tree bytes";
        let secret = marker.repeat(10_000);
        let mut wire = Vec::new();

        write_secure_message(&mut wire, &mut initiator, &secret).unwrap();

        assert!(!wire.windows(marker.len()).any(|window| window == marker));
        let decoded: Vec<u8> = read_secure_message(&mut Cursor::new(wire), &mut responder).unwrap();
        assert_eq!(decoded, secret);
    }

    #[test]
    fn tampered_secure_frame_is_rejected() {
        let (mut initiator, mut responder) = transport_pair(&TransportKey::from_bytes([5; 32]));
        let mut wire = Vec::new();
        write_secure_message(
            &mut wire,
            &mut initiator,
            &Request::Head {
                repo_id: "private-repo".into(),
            },
        )
        .unwrap();
        *wire.last_mut().unwrap() ^= 1;

        let result: anyhow::Result<Request> =
            read_secure_message(&mut Cursor::new(wire), &mut responder);
        assert!(result.is_err());
    }

    #[test]
    fn legacy_plaintext_client_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let authority = Arc::new(Mutex::new(
            FileAuthority::open(root.path().join("authority")).unwrap(),
        ));
        let registry = Arc::new(Mutex::new(
            Registry::create(
                root.path(),
                &random_hex(16).unwrap(),
                "192.0.2.1:7337",
                &TransportKey::from_bytes([7; 32]),
                "aabbccdd00112233aabbccdd00112233",
                "devbox",
                &TransportKey::from_bytes([3; 32]),
                1_000,
            )
            .unwrap(),
        ));
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream, &authority, &registry).unwrap_err()
        });
        let request = bincode::serde::encode_to_vec(
            Request::Head {
                repo_id: "repo".into(),
            },
            bincode::config::standard(),
        )
        .unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(&(request.len() as u64).to_be_bytes())
            .unwrap();
        client.write_all(&request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        if let Err(error) = client.read_to_end(&mut response) {
            assert_eq!(error.kind(), ErrorKind::ConnectionReset);
        }

        assert!(response.is_empty());
        assert!(format!("{:#}", server.join().unwrap()).contains("empty Noise handshake message"));
    }

    #[test]
    fn generated_keys_are_loadable_and_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("fabric.key");

        let generated = TransportKey::generate(&path).unwrap();
        let loaded = TransportKey::load(&path).unwrap();

        assert_eq!(generated.fingerprint(), loaded.fingerprint());
        assert!(TransportKey::generate(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(TransportKey::load(&path).is_err());
        }
    }

    fn transport_pair(key: &TransportKey) -> (snow::TransportState, snow::TransportState) {
        let mut initiator = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
            .psk(0, key.as_bytes())
            .unwrap()
            .prologue(NOISE_PROLOGUE)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut responder = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
            .psk(0, key.as_bytes())
            .unwrap()
            .prologue(NOISE_PROLOGUE)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut first = [0; MAX_NOISE_CIPHERTEXT_BYTES];
        let mut second = [0; MAX_NOISE_CIPHERTEXT_BYTES];
        let mut payload = [0; MAX_NOISE_CIPHERTEXT_BYTES];
        let first_len = initiator.write_message(&[], &mut first).unwrap();
        responder
            .read_message(&first[..first_len], &mut payload)
            .unwrap();
        let second_len = responder.write_message(&[], &mut second).unwrap();
        initiator
            .read_message(&second[..second_len], &mut payload)
            .unwrap();
        (
            initiator.into_transport_mode().unwrap(),
            responder.into_transport_mode().unwrap(),
        )
    }
}
