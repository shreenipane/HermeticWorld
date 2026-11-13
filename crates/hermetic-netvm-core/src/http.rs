//! Bounded, one-request-per-connection HTTP/1.1 filter and upstream streaming proxy.
//!
//! Why one request per connection (no keep-alive):
//! 1. Eliminates HTTP/1.1 request smuggling (CL.TE / TE.CL boundary desync) between
//!    the netvm and upstream because each TCP stream carries at most one request head.
//! 2. Prevents connection-slot hoarding where a client holds idle keep-alive sockets
//!    open to starve `MAX_CONCURRENT_CONNECTIONS` or outlive per-request deadlines.
//! 3. Guarantees deterministic isolation: every request starts on a clean socket
//!    with fresh `head_deadline` and `overall_deadline` budgets.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::headers::{filter_response_headers, parse_request_head};
use crate::Metrics;

/// Hard ceiling on simultaneous active HTTP TCP connections.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Maximum byte size of an incoming HTTP request head (request line + headers + `\r\n\r\n`).
pub const MAX_HTTP_HEAD_BYTES: usize = 8192;

/// Stack buffer size per socket read while accumulating the HTTP request head.
pub const HTTP_READ_CHUNK_BYTES: usize = 1024;

/// Maximum chunk size read from an `UpstreamResponse` body reader per iteration.
pub const HTTP_STREAM_CHUNK_BYTES: usize = 16 * 1024;

/// Hard cap on streamed response body size per request (64 MiB).
pub const MAX_HTTP_BODY_BYTES: u64 = 64 * 1024 * 1024;

/// Default deadline for reading a complete HTTP request head.
pub const DEFAULT_HTTP_HEAD_TIMEOUT_MS: u64 = 5_000;

/// Hard upper bound on configurable request head timeout.
pub const MAX_HTTP_HEAD_TIMEOUT_MS: u64 = 30_000;

/// Default per-chunk write deadline while streaming a response to the client.
pub const DEFAULT_HTTP_CHUNK_WRITE_TIMEOUT_MS: u64 = 2_000;

/// Hard upper bound on configurable per-chunk write timeout.
pub const MAX_HTTP_CHUNK_WRITE_TIMEOUT_MS: u64 = 30_000;

/// Default overall deadline for upstream fetch + full response transmission.
pub const DEFAULT_HTTP_OVERALL_TIMEOUT_MS: u64 = 30_000;

/// Hard upper bound on configurable overall request timeout.
pub const MAX_HTTP_OVERALL_TIMEOUT_MS: u64 = 120_000;

/// Poll interval used by the non-blocking accept loop to observe shutdown promptly.
pub const HTTP_ACCEPT_POLL_TIMEOUT: Duration = Duration::from_millis(15);

/// Exact HTTP/1.1 405 Method Not Allowed response bytes (no `Date` or `Server` header).
pub const NOT_ALLOWED_RESPONSE_BYTES: &[u8] =
    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Exact HTTP/1.1 502 Bad Gateway response bytes (no `Date` or `Server` header).
pub const BAD_GATEWAY_RESPONSE_BYTES: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Exact HTTP/1.1 504 Gateway Timeout response bytes (no `Date` or `Server` header).
pub const GATEWAY_TIMEOUT_RESPONSE_BYTES: &[u8] =
    b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Decision produced by [`RequestFilter::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterDecision {
    /// Forward the serialized JSON request descriptor to [`Upstream::fetch`].
    Forward(Vec<u8>),
    /// Respond with `HTTP/1.1 405 Method Not Allowed` and close.
    NotAllowed,
    /// Close the connection immediately without sending any bytes.
    Reject,
}

/// Pluggable request filter operating strictly on the parsed HTTP request head.
pub trait RequestFilter: Send + Sync {
    fn check(&self, head: &[u8], tls: bool, sni: Option<&str>) -> FilterDecision;
}

/// Streaming response returned by [`Upstream::fetch`].
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Box<dyn Read + Send>,
}

impl fmt::Debug for UpstreamResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body", &"<reader>")
            .finish()
    }
}

/// Typed errors returned by [`Upstream::fetch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamError {
    Timeout,
    BadRequest(String),
    Backend(String),
    Io(String),
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamError::Timeout => write!(f, "upstream deadline exceeded"),
            UpstreamError::BadRequest(msg) => write!(f, "upstream bad request: {msg}"),
            UpstreamError::Backend(msg) => write!(f, "upstream backend error: {msg}"),
            UpstreamError::Io(msg) => write!(f, "upstream I/O error: {msg}"),
        }
    }
}

impl std::error::Error for UpstreamError {}

/// Pluggable upstream world-server fetcher.
pub trait Upstream: Send + Sync {
    fn fetch(
        &self,
        request_json: &[u8],
        deadline: Instant,
    ) -> Result<UpstreamResponse, UpstreamError>;
}

/// Runtime HTTP proxy parameters, bounded by compile-time constants.
#[derive(Debug, Clone, Copy)]
pub struct HttpRuntimeConfig {
    pub max_connections: usize,
    pub head_timeout: Duration,
    pub chunk_write_timeout: Duration,
    pub overall_timeout: Duration,
    pub t_clock_epoch_secs: i64,
}

impl HttpRuntimeConfig {
    /// Creates a bounded configuration from raw values, clamping to named compile-time caps.
    pub fn bounded(
        max_connections: usize,
        head_timeout_ms: u64,
        chunk_write_timeout_ms: u64,
        overall_timeout_ms: u64,
        t_clock_epoch_secs: i64,
    ) -> Self {
        Self {
            max_connections: max_connections.clamp(1, MAX_CONCURRENT_CONNECTIONS),
            head_timeout: Duration::from_millis(head_timeout_ms.clamp(1, MAX_HTTP_HEAD_TIMEOUT_MS)),
            chunk_write_timeout: Duration::from_millis(
                chunk_write_timeout_ms.clamp(1, MAX_HTTP_CHUNK_WRITE_TIMEOUT_MS),
            ),
            overall_timeout: Duration::from_millis(
                overall_timeout_ms.clamp(1, MAX_HTTP_OVERALL_TIMEOUT_MS),
            ),
            t_clock_epoch_secs,
        }
    }
}

/// Canonical JSON payload emitted by [`MethodAllowFilter`] for forwarded `GET` and `HEAD` requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwardedRequest {
    pub method: String,
    pub target: String,
    pub host: Option<String>,
    pub tls: bool,
    pub sni: Option<String>,
    pub headers: Vec<(String, String)>,
}

/// Default test [`RequestFilter`] permitting only HTTP `GET` and `HEAD`.
#[derive(Debug, Clone, Default)]
pub struct MethodAllowFilter;

impl RequestFilter for MethodAllowFilter {
    fn check(&self, head: &[u8], tls: bool, sni: Option<&str>) -> FilterDecision {
        let parsed = match parse_request_head(head) {
            Ok(p) => p,
            Err(_) => return FilterDecision::Reject,
        };

        // TR-NET-4: a request without a usable Host is reset, never forwarded.
        if parsed.host.as_deref().is_none_or(str::is_empty) {
            return FilterDecision::Reject;
        }

        match parsed.method.as_str() {
            "GET" | "HEAD" => {
                let req = ForwardedRequest {
                    method: parsed.method,
                    target: parsed.target,
                    host: parsed.host,
                    tls,
                    sni: sni.map(ToOwned::to_owned),
                    headers: parsed.headers,
                };
                match serde_json::to_vec(&req) {
                    Ok(json) => FilterDecision::Forward(json),
                    Err(_) => FilterDecision::Reject,
                }
            }
            _ => FilterDecision::NotAllowed,
        }
    }
}

/// Canned route entry used by [`StaticUpstream`].
#[derive(Debug, Clone)]
pub struct StaticRouteResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay: Duration,
}

/// Deterministic in-memory [`Upstream`] implementation for tests and standalone binary runs.
#[derive(Debug, Clone, Default)]
pub struct StaticUpstream {
    routes: BTreeMap<(String, String), StaticRouteResponse>,
}

impl StaticUpstream {
    /// Creates an empty static upstream table.
    pub fn new() -> Self {
        Self {
            routes: BTreeMap::new(),
        }
    }

    /// Registers a response for `(method, target)`.
    pub fn insert(
        &mut self,
        method: &str,
        target: &str,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) {
        self.routes.insert(
            (method.to_ascii_uppercase(), target.to_string()),
            StaticRouteResponse {
                status,
                headers,
                body,
                delay: Duration::ZERO,
            },
        );
    }

    /// Registers a response with a bounded artificial delay (useful for deadline tests).
    pub fn insert_with_delay(
        &mut self,
        method: &str,
        target: &str,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        delay: Duration,
    ) {
        self.routes.insert(
            (method.to_ascii_uppercase(), target.to_string()),
            StaticRouteResponse {
                status,
                headers,
                body,
                delay,
            },
        );
    }
}

impl Upstream for StaticUpstream {
    fn fetch(
        &self,
        request_json: &[u8],
        deadline: Instant,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let req: ForwardedRequest = serde_json::from_slice(request_json)
            .map_err(|e| UpstreamError::BadRequest(e.to_string()))?;

        let lookup_key = (req.method.to_ascii_uppercase(), req.target.clone());
        let fallback_head_key = ("GET".to_string(), req.target.clone());

        let route = self
            .routes
            .get(&lookup_key)
            .or_else(|| {
                if req.method == "HEAD" {
                    self.routes.get(&fallback_head_key)
                } else {
                    None
                }
            })
            .cloned()
            .unwrap_or_else(|| StaticRouteResponse {
                status: 404,
                headers: vec![
                    (
                        "Content-Type".to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    ),
                    ("Content-Length".to_string(), "9".to_string()),
                ],
                body: b"not found".to_vec(),
                delay: Duration::ZERO,
            });

        if !route.delay.is_zero() {
            let now = Instant::now();
            if now >= deadline {
                return Err(UpstreamError::Timeout);
            }
            let remaining = deadline.saturating_duration_since(now);
            if route.delay > remaining {
                std::thread::sleep(remaining);
                return Err(UpstreamError::Timeout);
            }
            std::thread::sleep(route.delay);
        }

        if Instant::now() >= deadline {
            return Err(UpstreamError::Timeout);
        }

        Ok(UpstreamResponse {
            status: route.status,
            headers: route.headers,
            body: Box::new(Cursor::new(route.body)),
        })
    }
}

#[derive(Debug)]
enum HeadReadError {
    Timeout,
    TooLarge,
    UnexpectedEof,
    Io,
}

fn read_http_head(
    stream: &mut TcpStream,
    head_timeout: Duration,
) -> Result<Vec<u8>, HeadReadError> {
    let deadline = Instant::now() + head_timeout;
    let mut head_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; HTTP_READ_CHUNK_BYTES];

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(HeadReadError::Timeout);
        }
        let rem = deadline.saturating_duration_since(now);
        if stream.set_read_timeout(Some(rem)).is_err() {
            return Err(HeadReadError::Io);
        }

        let prev_len = head_buf.len();
        match stream.read(&mut chunk) {
            Ok(0) => return Err(HeadReadError::UnexpectedEof),
            Ok(n) => {
                let allowed = MAX_HTTP_HEAD_BYTES.saturating_sub(head_buf.len());
                if allowed == 0 {
                    return Err(HeadReadError::TooLarge);
                }
                let take = n.min(allowed);
                head_buf.extend_from_slice(&chunk[..take]);

                let search_start = prev_len.saturating_sub(3);
                if let Some(rel) = find_crlf_crlf(&head_buf[search_start..]) {
                    let end = search_start + rel + 4;
                    head_buf.truncate(end);
                    return Ok(head_buf);
                }

                if n > allowed || head_buf.len() >= MAX_HTTP_HEAD_BYTES {
                    return Err(HeadReadError::TooLarge);
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(HeadReadError::Timeout);
            }
            Err(_) => return Err(HeadReadError::Io),
        }
    }
}

fn find_crlf_crlf(slice: &[u8]) -> Option<usize> {
    slice.windows(4).position(|w| w == b"\r\n\r\n")
}

#[derive(Debug)]
enum StreamWriteError {
    Timeout,
    Io,
}

fn write_all_with_deadlines(
    stream: &mut TcpStream,
    mut data: &[u8],
    chunk_write_timeout: Duration,
    overall_deadline: Instant,
) -> Result<(), StreamWriteError> {
    while !data.is_empty() {
        let now = Instant::now();
        if now >= overall_deadline {
            return Err(StreamWriteError::Timeout);
        }
        let chunk_deadline = now + chunk_write_timeout;
        let effective_deadline = chunk_deadline.min(overall_deadline);
        let timeout = effective_deadline.saturating_duration_since(now);

        if stream.set_write_timeout(Some(timeout)).is_err() {
            return Err(StreamWriteError::Io);
        }

        match stream.write(data) {
            Ok(0) => return Err(StreamWriteError::Io),
            Ok(written) => {
                data = &data[written..];
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(StreamWriteError::Timeout);
            }
            Err(_) => return Err(StreamWriteError::Io),
        }
    }
    Ok(())
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        416 => "Range Not Satisfiable",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

fn format_response_head(status: u16, filtered_headers: &[(String, String)]) -> Vec<u8> {
    let mut head = Vec::with_capacity(256);
    let status_line = format!("HTTP/1.1 {} {}\r\n", status, reason_phrase(status));
    head.extend_from_slice(status_line.as_bytes());
    for (name, val) in filtered_headers {
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(val.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    head
}

/// Processes a single accepted TCP stream end-to-end (strictly one request per connection).
pub fn handle_http_connection(
    mut stream: TcpStream,
    tls: bool,
    sni: Option<&str>,
    config: HttpRuntimeConfig,
    filter: &dyn RequestFilter,
    upstream: &dyn Upstream,
    metrics: &Metrics,
) {
    let _ = stream.set_nodelay(true);

    let head = match read_http_head(&mut stream, config.head_timeout) {
        Ok(h) => h,
        Err(HeadReadError::Timeout) => {
            metrics.inc_http_head_timeouts();
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        Err(HeadReadError::TooLarge) => {
            metrics.inc_http_head_too_large();
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        Err(HeadReadError::UnexpectedEof | HeadReadError::Io) => {
            metrics.inc_http_rejected();
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
    };

    let is_head_request = head.starts_with(b"HEAD ");

    match filter.check(&head, tls, sni) {
        FilterDecision::Reject => {
            metrics.inc_http_rejected();
            let _ = stream.shutdown(Shutdown::Both);
        }
        FilterDecision::NotAllowed => {
            metrics.inc_http_not_allowed();
            let deadline = Instant::now() + config.overall_timeout;
            let _ = write_all_with_deadlines(
                &mut stream,
                NOT_ALLOWED_RESPONSE_BYTES,
                config.chunk_write_timeout,
                deadline,
            );
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
        FilterDecision::Forward(request_json) => {
            metrics.inc_http_forwarded();
            let overall_deadline = Instant::now() + config.overall_timeout;

            let mut resp = match upstream.fetch(&request_json, overall_deadline) {
                Ok(r) => r,
                Err(UpstreamError::Timeout) => {
                    metrics.inc_http_upstream_errors();
                    let err_deadline = Instant::now() + config.chunk_write_timeout;
                    let _ = write_all_with_deadlines(
                        &mut stream,
                        GATEWAY_TIMEOUT_RESPONSE_BYTES,
                        config.chunk_write_timeout,
                        err_deadline,
                    );
                    let _ = stream.shutdown(Shutdown::Both);
                    return;
                }
                Err(_) => {
                    metrics.inc_http_upstream_errors();
                    let err_deadline = Instant::now() + config.chunk_write_timeout;
                    let _ = write_all_with_deadlines(
                        &mut stream,
                        BAD_GATEWAY_RESPONSE_BYTES,
                        config.chunk_write_timeout,
                        err_deadline,
                    );
                    let _ = stream.shutdown(Shutdown::Both);
                    return;
                }
            };

            if !(100..=599).contains(&resp.status) {
                metrics.inc_http_upstream_errors();
                let err_deadline = Instant::now() + config.chunk_write_timeout;
                let _ = write_all_with_deadlines(
                    &mut stream,
                    BAD_GATEWAY_RESPONSE_BYTES,
                    config.chunk_write_timeout,
                    err_deadline,
                );
                let _ = stream.shutdown(Shutdown::Both);
                return;
            }

            let filtered_headers =
                filter_response_headers(&resp.headers, config.t_clock_epoch_secs);
            let response_head = format_response_head(resp.status, &filtered_headers);

            if write_all_with_deadlines(
                &mut stream,
                &response_head,
                config.chunk_write_timeout,
                overall_deadline,
            )
            .is_err()
            {
                metrics.inc_http_write_timeouts();
                let _ = stream.shutdown(Shutdown::Both);
                return;
            }

            let status_has_no_body =
                (100..=199).contains(&resp.status) || resp.status == 204 || resp.status == 304;

            if !is_head_request && !status_has_no_body {
                let mut buf = [0u8; HTTP_STREAM_CHUNK_BYTES];
                let mut total_body_bytes: u64 = 0;

                loop {
                    if Instant::now() >= overall_deadline {
                        metrics.inc_http_write_timeouts();
                        let _ = stream.shutdown(Shutdown::Both);
                        return;
                    }

                    match resp.body.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            total_body_bytes = total_body_bytes.saturating_add(n as u64);
                            if total_body_bytes > MAX_HTTP_BODY_BYTES {
                                metrics.inc_http_upstream_errors();
                                let _ = stream.shutdown(Shutdown::Both);
                                return;
                            }
                            if write_all_with_deadlines(
                                &mut stream,
                                &buf[..n],
                                config.chunk_write_timeout,
                                overall_deadline,
                            )
                            .is_err()
                            {
                                metrics.inc_http_write_timeouts();
                                let _ = stream.shutdown(Shutdown::Both);
                                return;
                            }
                        }
                        Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                        Err(_) => {
                            metrics.inc_http_upstream_errors();
                            let _ = stream.shutdown(Shutdown::Both);
                            return;
                        }
                    }
                }
            }

            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
            metrics.inc_http_responses_completed();
        }
    }
}

struct ConnectionSlotGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for ConnectionSlotGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_slot(
    active: &Arc<AtomicUsize>,
    max_connections: usize,
) -> Option<ConnectionSlotGuard> {
    let mut cur = active.load(Ordering::Acquire);
    loop {
        if cur >= max_connections {
            return None;
        }
        match active.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                return Some(ConnectionSlotGuard {
                    active: Arc::clone(active),
                });
            }
            Err(actual) => cur = actual,
        }
    }
}

/// Runs the bounded HTTP TCP accept loop until `shutdown` becomes `true`.
pub fn run_http_loop(
    listener: &TcpListener,
    config: HttpRuntimeConfig,
    filter: Arc<dyn RequestFilter>,
    upstream: Arc<dyn Upstream>,
    metrics: Arc<Metrics>,
    shutdown: &AtomicBool,
) {
    let _ = listener.set_nonblocking(true);
    let active_connections = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();

    while !shutdown.load(Ordering::Acquire) {
        // Reap finished worker handles opportunistically so the handle list stays bounded.
        workers.retain(|h: &std::thread::JoinHandle<()>| !h.is_finished());

        match listener.accept() {
            Ok((stream, _peer)) => {
                let Some(slot_guard) =
                    try_acquire_slot(&active_connections, config.max_connections)
                else {
                    metrics.inc_http_connections_rejected_cap();
                    let _ = stream.shutdown(Shutdown::Both);
                    drop(stream);
                    continue;
                };

                // Accepted sockets inherit non-blocking mode on some platforms; switch back
                // to blocking mode so socket read/write deadlines govern every syscall.
                if stream.set_nonblocking(false).is_err() {
                    let _ = stream.shutdown(Shutdown::Both);
                    drop(slot_guard);
                    continue;
                }

                metrics.inc_http_connections_accepted();

                let filter_cloned = Arc::clone(&filter);
                let upstream_cloned = Arc::clone(&upstream);
                let metrics_cloned = Arc::clone(&metrics);

                let spawn_res = std::thread::Builder::new()
                    .name("hermetic-http-conn".to_string())
                    .spawn(move || {
                        let _guard = slot_guard;
                        handle_http_connection(
                            stream,
                            false,
                            None,
                            config,
                            filter_cloned.as_ref(),
                            upstream_cloned.as_ref(),
                            metrics_cloned.as_ref(),
                        );
                    });

                match spawn_res {
                    Ok(handle) => workers.push(handle),
                    Err(_) => {
                        metrics.inc_http_connections_rejected_cap();
                    }
                }
            }
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                std::thread::sleep(HTTP_ACCEPT_POLL_TIMEOUT);
            }
            Err(_) => {
                std::thread::sleep(HTTP_ACCEPT_POLL_TIMEOUT);
            }
        }
    }

    for handle in workers {
        let _ = handle.join();
    }
}
