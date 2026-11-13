#![forbid(unsafe_code)]
//! Frozen-world wire transport over host Unix sockets or guest AF_VSOCK.
use crate::{
    files,
    http::{Upstream, UpstreamError, UpstreamResponse, MAX_HTTP_BODY_BYTES},
    sys,
};
use hermetic_common::wire::{
    Method, RequestFrame, ResponseFrame, WireError, MAX_REQUEST_FRAME_SIZE,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read, Write},
    os::unix::{ffi::OsStrExt, fs::FileTypeExt, net::UnixStream},
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
    time::Instant,
};

/// Dedicated WorldServer port; 5000 remains execd, 5002 reserved for gateway.
pub const WORLD_PORT: u32 = 5001;
pub const HOST_CID: u32 = 2;
/// First request id on a connection; ids then increase by one per request.
pub const FIRST_REQUEST_ID: u64 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireRequest {
    pub method: String,
    pub authority: String,
    pub path: String,
    pub range: Option<(u64, u64)>,
}
impl WireRequest {
    fn clone_frame(&self, request_id: u64) -> Result<RequestFrame, UpstreamError> {
        Self {
            method: self.method.clone(),
            authority: self.authority.clone(),
            path: self.path.clone(),
            range: self.range,
        }
        .frame(request_id)
    }
    fn frame(self, request_id: u64) -> Result<RequestFrame, UpstreamError> {
        let method = match self.method.as_str() {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            _ => return Err(bad_request()),
        };
        let frame = RequestFrame {
            method,
            request_id,
            authority: self.authority,
            path_and_query: self.path,
            range: self.range,
        };
        frame.encode().map_err(|_| bad_request())?;
        Ok(frame)
    }
}
fn bad_request() -> UpstreamError {
    UpstreamError::BadRequest("invalid_descriptor".into())
}
fn backend() -> UpstreamError {
    UpstreamError::Backend("invalid_response".into())
}
fn io_error(error: io::Error) -> UpstreamError {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        UpstreamError::Timeout
    } else {
        UpstreamError::Io("transport_failed".into())
    }
}
fn wire_error(error: WireError) -> UpstreamError {
    if let WireError::Io(e) = error {
        io_error(e)
    } else {
        backend()
    }
}

#[derive(Clone, Debug)]
enum Endpoint {
    Unix(PathBuf),
    Vsock,
}

/// The single WorldServer connection. A sandboxed WorldServer accepts exactly one
/// connection per run and then serves its frames in order, so requests are
/// serialized on one stream with increasing request ids. A stream left in an
/// unknown state (error, undrained body) is dropped, never reused.
#[derive(Debug, Default)]
struct Slot {
    stream: Option<UnixStream>,
    busy: bool,
    next_id: u64,
}
#[derive(Debug, Default)]
struct Shared {
    slot: Mutex<Slot>,
    idle: Condvar,
}

/// No network resolver or Internet socket is used by this upstream.
#[derive(Clone, Debug)]
pub struct VsockUpstream {
    endpoint: Endpoint,
    shared: Arc<Shared>,
}
impl VsockUpstream {
    pub fn guest() -> Self {
        Self {
            endpoint: Endpoint::Vsock,
            shared: Arc::default(),
        }
    }
    /// Host/test mode: connect directly to WorldServer's `--socket` endpoint.
    pub fn unix(path: impl AsRef<Path>) -> Self {
        Self {
            endpoint: Endpoint::Unix(path.as_ref().to_owned()),
            shared: Arc::default(),
        }
    }
    fn connect(&self, deadline: Instant) -> io::Result<UnixStream> {
        match &self.endpoint {
            Endpoint::Vsock => sys::vsock(WORLD_PORT, deadline),
            Endpoint::Unix(path) => {
                let pinned = files::pin(path)?;
                if !pinned.metadata()?.file_type().is_socket() {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                sys::unix(files::fd_path(&pinned).as_os_str().as_bytes(), deadline)
            }
        }
    }
    /// Wait (bounded by `deadline`) for exclusive use of the connection.
    fn lease(&self, deadline: Instant) -> Result<Lease, UpstreamError> {
        let mut slot = self
            .shared
            .slot
            .lock()
            .map_err(|_| UpstreamError::Io("transport_failed".into()))?;
        while slot.busy {
            let wait = deadline
                .checked_duration_since(Instant::now())
                .ok_or(UpstreamError::Timeout)?;
            slot = self
                .shared
                .idle
                .wait_timeout(slot, wait)
                .map_err(|_| UpstreamError::Io("transport_failed".into()))?
                .0;
        }
        let id = slot.next_id.max(FIRST_REQUEST_ID);
        let next_id = id.checked_add(1).ok_or_else(backend)?;
        slot.busy = true;
        slot.next_id = next_id;
        let stream = slot.stream.take();
        drop(slot);
        let mut lease = Lease {
            shared: Arc::clone(&self.shared),
            stream,
            clean: false,
            deadline,
            id,
        };
        if lease.stream.is_none() {
            lease.stream = Some(self.connect(deadline).map_err(io_error)?);
        }
        Ok(lease)
    }
}

/// Exclusive use of the connection for one request. On drop the stream goes back
/// only if the exchange completed exactly; otherwise it is closed.
struct Lease {
    shared: Arc<Shared>,
    stream: Option<UnixStream>,
    clean: bool,
    deadline: Instant,
    id: u64,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let stream = if self.clean { self.stream.take() } else { None };
        if let Ok(mut slot) = self.shared.slot.lock() {
            slot.stream = stream;
            slot.busy = false;
        }
        self.shared.idle.notify_one();
    }
}
impl Read for Lease {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let stream = self.stream.as_mut().ok_or(io::ErrorKind::NotConnected)?;
        loop {
            sys::ready(stream, false, self.deadline)?;
            match stream.read(data) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                result => return result,
            }
        }
    }
}
impl Write for Lease {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let stream = self.stream.as_mut().ok_or(io::ErrorKind::NotConnected)?;
        loop {
            sys::ready(stream, true, self.deadline)?;
            match stream.write(data) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Exactly `remaining` body bytes. When the consumer stops early the rest is
/// drained (bounded by the request deadline) so the connection stays in sync.
struct ExactBody {
    lease: Lease,
    remaining: u64,
}
impl ExactBody {
    fn new(mut lease: Lease, remaining: u64) -> Self {
        lease.clean = remaining == 0;
        Self { lease, remaining }
    }
}
impl Read for ExactBody {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let count = data
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        if count == 0 {
            return Ok(0);
        }
        let n = self
            .lease
            .read(data.get_mut(..count).ok_or(io::ErrorKind::InvalidInput)?)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.remaining = self
            .remaining
            .checked_sub(n as u64)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.lease.clean = self.remaining == 0;
        Ok(n)
    }
}
impl Drop for ExactBody {
    fn drop(&mut self) {
        let mut sink = [0u8; 16 * 1024];
        while self.remaining > 0 {
            if !matches!(self.read(&mut sink), Ok(n) if n > 0) {
                break;
            }
        }
    }
}

impl Upstream for VsockUpstream {
    fn fetch(
        &self,
        descriptor: &[u8],
        deadline: Instant,
    ) -> Result<UpstreamResponse, UpstreamError> {
        if descriptor.len() > MAX_REQUEST_FRAME_SIZE {
            return Err(bad_request());
        }
        let request: WireRequest = serde_json::from_slice(descriptor).map_err(|_| bad_request())?;
        // Validate before waiting for or opening any endpoint.
        request.clone_frame(FIRST_REQUEST_ID)?;
        if Instant::now() >= deadline {
            return Err(UpstreamError::Timeout);
        }
        let mut lease = self.lease(deadline)?;
        let frame = request.frame(lease.id)?;
        let encoded = frame.encode().map_err(|_| bad_request())?;
        lease.write_all(&encoded).map_err(io_error)?;
        let (id, status, headers, length) =
            ResponseFrame::read_head_from(&mut lease, MAX_HTTP_BODY_BYTES).map_err(wire_error)?;
        if id != lease.id
            || !(200..=599).contains(&status)
            || ((frame.method == Method::Head || status == 204 || status == 304) && length != 0)
        {
            return Err(backend());
        }
        let mut content_length = None;
        for header in &headers {
            if header.name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some()
                    || header.value.is_empty()
                    || !header.value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(backend());
                }
                content_length = Some(header.value.parse::<u64>().map_err(|_| backend())?);
            }
        }
        if frame.method != Method::Head
            && status != 304
            && content_length.is_some_and(|n| n != length)
        {
            return Err(backend());
        }
        Ok(UpstreamResponse {
            status,
            headers: headers.into_iter().map(|h| (h.name, h.value)).collect(),
            body: Box::new(ExactBody::new(lease, length)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exhausted_request_ids_do_not_lock_the_connection_forever() {
        let up = VsockUpstream::unix("/absent");
        up.shared.slot.lock().unwrap().next_id = u64::MAX;
        assert!(up
            .lease(Instant::now() + std::time::Duration::from_secs(1))
            .is_err());
        assert!(!up.shared.slot.lock().unwrap().busy);
    }
}
