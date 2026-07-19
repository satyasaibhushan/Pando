use crate::authority::{AcquireResult, Authority, AuthorityStatus, FileAuthority};
use crate::model::{Overlay, SnapshotId};
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

    pub fn generate(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .with_context(|| format!("create key directory {}", parent.display()))?;
        }
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("generate key: {error}"))?;
        let key = Self(bytes);
        let encoded = key.hex();
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("create transport key {}", path.display()))?;
        writeln!(file, "{encoded}")?;
        file.sync_all()?;
        Ok(key)
    }

    pub fn fingerprint(&self) -> String {
        blake3::hash(&self.0).to_hex()[..12].to_owned()
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
    key: TransportKey,
}

impl fmt::Debug for RemoteAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteAuthority")
            .field("address", &self.address)
            .field("key_fingerprint", &self.key.fingerprint())
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum Request {
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
    Acquire(AcquireResult),
    Bool(bool),
    Bytes(Vec<u8>),
    Head(Option<SnapshotId>),
    Overlay(Overlay),
    Forks(Vec<SnapshotId>),
    Status(AuthorityStatus),
    Error(String),
}

impl RemoteAuthority {
    pub fn new(address: impl Into<String>, key: TransportKey) -> Self {
        Self {
            address: address.into(),
            key,
        }
    }

    fn rpc(&self, request: Request) -> Result<Response> {
        let addresses = self
            .address
            .to_socket_addrs()
            .with_context(|| format!("resolve authority {}", self.address))?;
        let mut stream = connect_any(addresses, std::time::Duration::from_secs(5))
            .with_context(|| format!("connect to authority {}", self.address))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
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

pub fn serve(address: &str, authority: FileAuthority, key: TransportKey) -> Result<()> {
    let listener =
        TcpListener::bind(address).with_context(|| format!("bind authority to {address}"))?;
    serve_listener(listener, authority, key)
}

pub fn serve_listener(
    listener: TcpListener,
    authority: FileAuthority,
    key: TransportKey,
) -> Result<()> {
    let authority = Arc::new(Mutex::new(authority));
    for stream in listener.incoming() {
        let authority = authority.clone();
        let stream = stream?;
        let key = key.clone();
        thread::spawn(move || {
            if let Err(error) = handle_connection(stream, &authority, &key)
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
    key: &TransportKey,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut session = responder_handshake(&mut stream, key).context("secure client handshake")?;
    let request: Request = read_secure_message(&mut stream, &mut session)?;
    let response = dispatch(request, authority);
    write_secure_message(&mut stream, &mut session, &response)
}

fn dispatch(request: Request, authority: &Arc<Mutex<FileAuthority>>) -> Response {
    let result = (|| -> Result<Response> {
        let mut authority = authority
            .lock()
            .map_err(|_| anyhow::anyhow!("authority lock poisoned"))?;
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
            Request::Head { repo_id } => Response::Head(authority.head(&repo_id)?),
            Request::Overlay { snapshot_id } => Response::Overlay(authority.overlay(&snapshot_id)?),
            Request::Status { repo_id, now_ms } => {
                Response::Status(authority.status(&repo_id, now_ms)?)
            }
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
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream, &authority, &TransportKey::from_bytes([3; 32])).unwrap_err()
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
