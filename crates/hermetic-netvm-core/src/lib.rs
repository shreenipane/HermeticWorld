#![forbid(unsafe_code)]

//! Hermetic World network VM core library.
//!
//! Provides bounded, deterministic DNS and HTTP/1.1 mediation between an
//! isolated benchmark environment and a frozen upstream world server.

pub mod dns;
pub mod headers;
pub mod http;

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use serde::{Deserialize, Deserializer, Serialize};

use crate::dns::{run_dns_loop, DnsResponder, SourceRateLimiter, StaticDnsResponder};
use crate::headers::parse_t_clock_str;
use crate::http::{
    run_http_loop, HttpRuntimeConfig, MethodAllowFilter, RequestFilter, StaticUpstream, Upstream,
    DEFAULT_HTTP_CHUNK_WRITE_TIMEOUT_MS, DEFAULT_HTTP_HEAD_TIMEOUT_MS,
    DEFAULT_HTTP_OVERALL_TIMEOUT_MS, MAX_CONCURRENT_CONNECTIONS,
};

/// Sink receiving structured JSON log lines (counters only; never timestamps or bodies).
pub trait LogSink: Send + Sync {
    fn write_line(&self, json_line: &str);
}

/// Default production [`LogSink`] writing JSON lines to `stderr`.
#[derive(Debug, Default)]
pub struct StderrLogSink;

impl LogSink for StderrLogSink {
    fn write_line(&self, json_line: &str) {
        let stderr = std::io::stderr();
        let mut locked = stderr.lock();
        let _ = writeln!(locked, "{json_line}");
    }
}

/// In-memory [`LogSink`] for deterministic offline tests.
#[derive(Debug, Default)]
pub struct VecLogSink {
    lines: Mutex<Vec<String>>,
}

impl VecLogSink {
    pub fn new() -> Self {
        Self {
            lines: Mutex::new(Vec::new()),
        }
    }

    pub fn lines(&self) -> Vec<String> {
        match self.lines.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl LogSink for VecLogSink {
    fn write_line(&self, json_line: &str) {
        let mut guard = match self.lines.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.push(json_line.to_string());
    }
}

/// Point-in-time snapshot of all monotonic counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub dns_received: u64,
    pub dns_answered: u64,
    pub dns_dropped_oversized: u64,
    pub dns_dropped_rate_limited: u64,
    pub dns_dropped_unanswered: u64,
    pub dns_send_errors: u64,
    pub http_connections_accepted: u64,
    pub http_connections_rejected_cap: u64,
    pub http_head_timeouts: u64,
    pub http_head_too_large: u64,
    pub http_forwarded: u64,
    pub http_not_allowed: u64,
    pub http_rejected: u64,
    pub http_upstream_errors: u64,
    pub http_write_timeouts: u64,
    pub http_responses_completed: u64,
}

#[derive(Debug, Serialize)]
struct StructuredLogRecord {
    event: &'static str,
    #[serde(flatten)]
    counters: MetricsSnapshot,
}

/// Atomic counter store that emits structured JSON counter lines to a [`LogSink`].
pub struct Metrics {
    dns_received: AtomicU64,
    dns_answered: AtomicU64,
    dns_dropped_oversized: AtomicU64,
    dns_dropped_rate_limited: AtomicU64,
    dns_dropped_unanswered: AtomicU64,
    dns_send_errors: AtomicU64,
    http_connections_accepted: AtomicU64,
    http_connections_rejected_cap: AtomicU64,
    http_head_timeouts: AtomicU64,
    http_head_too_large: AtomicU64,
    http_forwarded: AtomicU64,
    http_not_allowed: AtomicU64,
    http_rejected: AtomicU64,
    http_upstream_errors: AtomicU64,
    http_write_timeouts: AtomicU64,
    http_responses_completed: AtomicU64,
    sink: Arc<dyn LogSink>,
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metrics")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new(Arc::new(StderrLogSink))
    }
}

impl Metrics {
    /// Creates a new counter store wired to `sink`.
    pub fn new(sink: Arc<dyn LogSink>) -> Self {
        Self {
            dns_received: AtomicU64::new(0),
            dns_answered: AtomicU64::new(0),
            dns_dropped_oversized: AtomicU64::new(0),
            dns_dropped_rate_limited: AtomicU64::new(0),
            dns_dropped_unanswered: AtomicU64::new(0),
            dns_send_errors: AtomicU64::new(0),
            http_connections_accepted: AtomicU64::new(0),
            http_connections_rejected_cap: AtomicU64::new(0),
            http_head_timeouts: AtomicU64::new(0),
            http_head_too_large: AtomicU64::new(0),
            http_forwarded: AtomicU64::new(0),
            http_not_allowed: AtomicU64::new(0),
            http_rejected: AtomicU64::new(0),
            http_upstream_errors: AtomicU64::new(0),
            http_write_timeouts: AtomicU64::new(0),
            http_responses_completed: AtomicU64::new(0),
            sink,
        }
    }

    /// Reads a consistent point-in-time snapshot of all counters.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            dns_received: self.dns_received.load(Ordering::Relaxed),
            dns_answered: self.dns_answered.load(Ordering::Relaxed),
            dns_dropped_oversized: self.dns_dropped_oversized.load(Ordering::Relaxed),
            dns_dropped_rate_limited: self.dns_dropped_rate_limited.load(Ordering::Relaxed),
            dns_dropped_unanswered: self.dns_dropped_unanswered.load(Ordering::Relaxed),
            dns_send_errors: self.dns_send_errors.load(Ordering::Relaxed),
            http_connections_accepted: self.http_connections_accepted.load(Ordering::Relaxed),
            http_connections_rejected_cap: self
                .http_connections_rejected_cap
                .load(Ordering::Relaxed),
            http_head_timeouts: self.http_head_timeouts.load(Ordering::Relaxed),
            http_head_too_large: self.http_head_too_large.load(Ordering::Relaxed),
            http_forwarded: self.http_forwarded.load(Ordering::Relaxed),
            http_not_allowed: self.http_not_allowed.load(Ordering::Relaxed),
            http_rejected: self.http_rejected.load(Ordering::Relaxed),
            http_upstream_errors: self.http_upstream_errors.load(Ordering::Relaxed),
            http_write_timeouts: self.http_write_timeouts.load(Ordering::Relaxed),
            http_responses_completed: self.http_responses_completed.load(Ordering::Relaxed),
        }
    }

    /// Emits a structured JSON counter line to the configured [`LogSink`].
    pub fn emit(&self, event: &'static str) {
        let record = StructuredLogRecord {
            event,
            counters: self.snapshot(),
        };
        if let Ok(line) = serde_json::to_string(&record) {
            self.sink.write_line(&line);
        }
    }

    pub(crate) fn inc_dns_received(&self) {
        self.dns_received.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_dns_answered(&self) {
        self.dns_answered.fetch_add(1, Ordering::Relaxed);
        self.emit("dns_answered");
    }

    pub(crate) fn inc_dns_dropped_oversized(&self) {
        self.dns_dropped_oversized.fetch_add(1, Ordering::Relaxed);
        self.emit("dns_dropped_oversized");
    }

    pub(crate) fn inc_dns_dropped_rate_limited(&self) {
        self.dns_dropped_rate_limited
            .fetch_add(1, Ordering::Relaxed);
        self.emit("dns_dropped_rate_limited");
    }

    pub(crate) fn inc_dns_dropped_unanswered(&self) {
        self.dns_dropped_unanswered.fetch_add(1, Ordering::Relaxed);
        self.emit("dns_dropped_unanswered");
    }

    pub(crate) fn inc_dns_send_errors(&self) {
        self.dns_send_errors.fetch_add(1, Ordering::Relaxed);
        self.emit("dns_send_errors");
    }

    pub(crate) fn inc_http_connections_accepted(&self) {
        self.http_connections_accepted
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_http_connections_rejected_cap(&self) {
        self.http_connections_rejected_cap
            .fetch_add(1, Ordering::Relaxed);
        self.emit("http_connections_rejected_cap");
    }

    pub(crate) fn inc_http_head_timeouts(&self) {
        self.http_head_timeouts.fetch_add(1, Ordering::Relaxed);
        self.emit("http_head_timeouts");
    }

    pub(crate) fn inc_http_head_too_large(&self) {
        self.http_head_too_large.fetch_add(1, Ordering::Relaxed);
        self.emit("http_head_too_large");
    }

    pub(crate) fn inc_http_forwarded(&self) {
        self.http_forwarded.fetch_add(1, Ordering::Relaxed);
        self.emit("http_forwarded");
    }

    pub(crate) fn inc_http_not_allowed(&self) {
        self.http_not_allowed.fetch_add(1, Ordering::Relaxed);
        self.emit("http_not_allowed");
    }

    pub(crate) fn inc_http_rejected(&self) {
        self.http_rejected.fetch_add(1, Ordering::Relaxed);
        self.emit("http_rejected");
    }

    pub(crate) fn inc_http_upstream_errors(&self) {
        self.http_upstream_errors.fetch_add(1, Ordering::Relaxed);
        self.emit("http_upstream_errors");
    }

    pub(crate) fn inc_http_write_timeouts(&self) {
        self.http_write_timeouts.fetch_add(1, Ordering::Relaxed);
        self.emit("http_write_timeouts");
    }

    pub(crate) fn inc_http_responses_completed(&self) {
        self.http_responses_completed
            .fetch_add(1, Ordering::Relaxed);
        self.emit("http_responses_completed");
    }
}

/// Canned route specification in [`NetvmConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticRouteConfig {
    #[serde(default = "default_get_method")]
    pub method: String,
    pub target: String,
    #[serde(default = "default_ok_status")]
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: String,
}

fn default_get_method() -> String {
    "GET".to_string()
}

fn default_ok_status() -> u16 {
    200
}

fn default_max_connections() -> usize {
    MAX_CONCURRENT_CONNECTIONS
}

fn default_head_timeout_ms() -> u64 {
    DEFAULT_HTTP_HEAD_TIMEOUT_MS
}

fn default_chunk_write_timeout_ms() -> u64 {
    DEFAULT_HTTP_CHUNK_WRITE_TIMEOUT_MS
}

fn default_overall_timeout_ms() -> u64 {
    DEFAULT_HTTP_OVERALL_TIMEOUT_MS
}

fn deserialize_t_clock<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ClockRepr {
        Int(i64),
        Str(String),
    }

    match ClockRepr::deserialize(deserializer)? {
        ClockRepr::Int(v) => Ok(v),
        ClockRepr::Str(s) => parse_t_clock_str(&s).map_err(serde::de::Error::custom),
    }
}

/// Maximum byte size of a `hermetic-netvm` JSON configuration file.
pub const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

/// JSON configuration file schema for `hermetic-netvm`.
///
/// Unknown fields are rejected so a misspelled setting fails closed instead of silently
/// falling back to a default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetvmConfig {
    /// Cutoff timestamp (`T_clock`): `Last-Modified` headers strictly after this instant are dropped.
    #[serde(deserialize_with = "deserialize_t_clock")]
    pub t_clock: i64,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_head_timeout_ms")]
    pub head_timeout_ms: u64,
    #[serde(default = "default_chunk_write_timeout_ms")]
    pub chunk_write_timeout_ms: u64,
    #[serde(default = "default_overall_timeout_ms")]
    pub overall_timeout_ms: u64,
    /// Fixed DNS A-record table (`domain` -> `"a.b.c.d"`).
    #[serde(default)]
    pub dns_records: BTreeMap<String, String>,
    /// Static upstream routes used when running with built-in test implementations.
    #[serde(default)]
    pub static_routes: Vec<StaticRouteConfig>,
}

/// Top-level startup or configuration errors for `hermetic-netvm`.
#[derive(Debug)]
pub enum NetvmError {
    ConfigParse(String),
    InvalidDnsRecord(String),
    Io(std::io::Error),
    ThreadSpawn(std::io::Error),
}

impl fmt::Display for NetvmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetvmError::ConfigParse(msg) => write!(f, "configuration parse error: {msg}"),
            NetvmError::InvalidDnsRecord(msg) => write!(f, "invalid DNS record in config: {msg}"),
            NetvmError::Io(err) => write!(f, "I/O error: {err}"),
            NetvmError::ThreadSpawn(err) => write!(f, "thread spawn error: {err}"),
        }
    }
}

impl std::error::Error for NetvmError {}

impl From<std::io::Error> for NetvmError {
    fn from(value: std::io::Error) -> Self {
        NetvmError::Io(value)
    }
}

impl NetvmConfig {
    /// Parses a [`NetvmConfig`] from a JSON string.
    pub fn from_json_str(json: &str) -> Result<Self, NetvmError> {
        serde_json::from_str(json).map_err(|e| NetvmError::ConfigParse(e.to_string()))
    }

    /// Converts HTTP fields into a bounded [`HttpRuntimeConfig`].
    pub fn http_runtime_config(&self) -> HttpRuntimeConfig {
        HttpRuntimeConfig::bounded(
            self.max_connections,
            self.head_timeout_ms,
            self.chunk_write_timeout_ms,
            self.overall_timeout_ms,
            self.t_clock,
        )
    }

    /// Builds the test/default [`StaticDnsResponder`], [`MethodAllowFilter`], and [`StaticUpstream`].
    pub fn build_default_components(
        &self,
    ) -> Result<(StaticDnsResponder, MethodAllowFilter, StaticUpstream), NetvmError> {
        let mut dns = StaticDnsResponder::new();
        for (domain, ip_str) in &self.dns_records {
            let ipv4: std::net::Ipv4Addr = ip_str
                .parse()
                .map_err(|_| NetvmError::InvalidDnsRecord(format!("{domain} -> {ip_str}")))?;
            dns.insert(domain, ipv4.octets());
        }

        let mut upstream = StaticUpstream::new();
        for route in &self.static_routes {
            upstream.insert(
                &route.method,
                &route.target,
                route.status,
                route.headers.clone(),
                route.body.as_bytes().to_vec(),
            );
        }

        Ok((dns, MethodAllowFilter, upstream))
    }
}

/// Handle to a running DNS + HTTP `hermetic-netvm` server instance.
pub struct RunningNetvm {
    dns_addr: std::net::SocketAddr,
    http_addr: std::net::SocketAddr,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
    dns_thread: Option<JoinHandle<()>>,
    http_thread: Option<JoinHandle<()>>,
}

impl RunningNetvm {
    /// Starts both the DNS UDP loop and HTTP TCP loop on the provided bound sockets.
    pub fn start(
        dns_socket: UdpSocket,
        http_listener: TcpListener,
        http_config: HttpRuntimeConfig,
        dns_responder: Arc<dyn DnsResponder>,
        request_filter: Arc<dyn RequestFilter>,
        upstream: Arc<dyn Upstream>,
        log_sink: Arc<dyn LogSink>,
    ) -> Result<Self, NetvmError> {
        let dns_addr = dns_socket.local_addr()?;
        let http_addr = http_listener.local_addr()?;

        let metrics = Arc::new(Metrics::new(log_sink));
        let shutdown = Arc::new(AtomicBool::new(false));

        let dns_metrics = Arc::clone(&metrics);
        let dns_shutdown = Arc::clone(&shutdown);
        let dns_thread = std::thread::Builder::new()
            .name("hermetic-dns".to_string())
            .spawn(move || {
                let mut limiter = SourceRateLimiter::default();
                run_dns_loop(
                    &dns_socket,
                    dns_responder.as_ref(),
                    dns_metrics.as_ref(),
                    dns_shutdown.as_ref(),
                    &mut limiter,
                );
            })
            .map_err(NetvmError::ThreadSpawn)?;

        let http_metrics = Arc::clone(&metrics);
        let http_shutdown = Arc::clone(&shutdown);
        let http_thread = match std::thread::Builder::new()
            .name("hermetic-http".to_string())
            .spawn(move || {
                run_http_loop(
                    &http_listener,
                    http_config,
                    request_filter,
                    upstream,
                    http_metrics,
                    http_shutdown.as_ref(),
                );
            }) {
            Ok(handle) => handle,
            Err(err) => {
                shutdown.store(true, Ordering::Release);
                let _ = dns_thread.join();
                return Err(NetvmError::ThreadSpawn(err));
            }
        };

        metrics.emit("started");

        Ok(Self {
            dns_addr,
            http_addr,
            metrics,
            shutdown,
            dns_thread: Some(dns_thread),
            http_thread: Some(http_thread),
        })
    }

    pub fn dns_addr(&self) -> std::net::SocketAddr {
        self.dns_addr
    }

    pub fn http_addr(&self) -> std::net::SocketAddr {
        self.http_addr
    }

    pub fn metrics(&self) -> &Metrics {
        self.metrics.as_ref()
    }

    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Signals both loops to stop and joins their worker threads cleanly.
    pub fn stop(mut self) {
        self.shutdown_and_join();
    }

    fn shutdown_and_join(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(h) = self.dns_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.http_thread.take() {
            let _ = h.join();
        }
        self.metrics.emit("stopped");
    }
}

impl Drop for RunningNetvm {
    fn drop(&mut self) {
        self.shutdown_and_join();
    }
}
