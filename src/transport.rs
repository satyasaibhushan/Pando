use crate::authority::{AcquireResult, Authority, AuthorityStatus, FileAuthority};
use crate::model::{Overlay, SnapshotId};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;

const MAX_MESSAGE_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct RemoteAuthority {
    address: String,
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
    Status(AuthorityStatus),
    Error(String),
}

impl RemoteAuthority {
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
        }
    }

    fn rpc(&self, request: Request) -> Result<Response> {
        let addresses = self
            .address
            .to_socket_addrs()
            .with_context(|| format!("resolve authority {}", self.address))?;
        let mut stream = connect_any(addresses, std::time::Duration::from_secs(5))
            .with_context(|| format!("connect to authority {}", self.address))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
        write_message(&mut stream, &request)?;
        let response: Response = read_message(&mut stream)?;
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

pub fn serve(address: &str, authority: FileAuthority) -> Result<()> {
    let listener =
        TcpListener::bind(address).with_context(|| format!("bind authority to {address}"))?;
    serve_listener(listener, authority)
}

pub fn serve_listener(listener: TcpListener, authority: FileAuthority) -> Result<()> {
    let authority = Arc::new(Mutex::new(authority));
    for stream in listener.incoming() {
        let authority = authority.clone();
        let mut stream = stream?;
        thread::spawn(move || {
            let response = match read_message::<Request>(&mut stream) {
                Ok(request) => dispatch(request, &authority),
                Err(error) => Response::Error(error.to_string()),
            };
            let _ = write_message(&mut stream, &response);
        });
    }
    Ok(())
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

fn write_message(stream: &mut TcpStream, value: &impl Serialize) -> Result<()> {
    let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard())?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        bail!("authority message exceeds {} bytes", MAX_MESSAGE_BYTES);
    }
    stream.write_all(&(bytes.len() as u64).to_be_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn read_message<T: DeserializeOwned>(stream: &mut TcpStream) -> Result<T> {
    let mut header = [0; 8];
    stream.read_exact(&mut header)?;
    let length = u64::from_be_bytes(header) as usize;
    if length > MAX_MESSAGE_BYTES {
        bail!("authority message claims {length} bytes");
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    let (value, _bytes_read) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
            .context("decode authority message")?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::connect_any;
    use std::net::{Ipv6Addr, SocketAddr, TcpListener};
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
}
