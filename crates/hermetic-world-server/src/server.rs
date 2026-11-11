#![forbid(unsafe_code)]

use hermetic_common::{Method, RequestFrame, ResponseFrame, ResponseHeader, WireError};
use std::io::ErrorKind;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Instant;
use time::OffsetDateTime;

use crate::limits::{validate_rate, Limits};
use crate::log::{LogEventParams, LogManager};
use crate::safe_fs::Directory;
use crate::sandbox::{apply_sandbox, SandboxLandlockStatus};
use crate::store::{DirStore, MAX_BODY_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerExit {
    Normal = 0,
    StartupFailed = 1,
    Tampered = 3,
    LimitExceeded = 4,
    LogFailed = 5,
}

impl std::fmt::Display for ServerExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerExit::Normal => write!(f, "Normal exit"),
            ServerExit::StartupFailed => write!(f, "Startup failed"),
            ServerExit::Tampered => write!(f, "Tampered"),
            ServerExit::LimitExceeded => write!(f, "Limit exceeded"),
            ServerExit::LogFailed => write!(f, "Log failed"),
        }
    }
}

impl std::error::Error for ServerExit {}

pub struct ServerConfig {
    pub store_dir: PathBuf,
    pub socket_path: PathBuf,
    pub log_dir: PathBuf,
    pub t_clock: OffsetDateTime,
    pub rate_rps: Option<f64>,
    pub burst: Option<f64>,
    pub max_requests: Option<u64>,
    pub max_bytes: Option<u64>,
    pub allow_no_landlock: bool,
    pub no_sandbox: bool, // For in-process unit testing without restricting cargo test runner
    pub resume_log: bool,
    pub recover: bool,
}

/// Format an OffsetDateTime in IMF-fixdate format (RFC 7231 / RFC 9110), e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
pub fn format_imf_fixdate(dt: OffsetDateTime) -> String {
    let utc = dt.to_offset(time::UtcOffset::UTC);
    let weekday = match utc.weekday() {
        time::Weekday::Monday => "Mon",
        time::Weekday::Tuesday => "Tue",
        time::Weekday::Wednesday => "Wed",
        time::Weekday::Thursday => "Thu",
        time::Weekday::Friday => "Fri",
        time::Weekday::Saturday => "Sat",
        time::Weekday::Sunday => "Sun",
    };
    let month = match utc.month() {
        time::Month::January => "Jan",
        time::Month::February => "Feb",
        time::Month::March => "Mar",
        time::Month::April => "Apr",
        time::Month::May => "May",
        time::Month::June => "Jun",
        time::Month::July => "Jul",
        time::Month::August => "Aug",
        time::Month::September => "Sep",
        time::Month::October => "Oct",
        time::Month::November => "Nov",
        time::Month::December => "Dec",
    };
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        weekday,
        utc.day(),
        month,
        utc.year(),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

pub const MAX_SOCKET_NAME_BYTES: usize = 80;
pub const MAX_RUN_ELAPSED_MS: u64 = 24 * 60 * 60 * 1000;

pub fn guest_clock(base: OffsetDateTime, elapsed_ms: u64) -> Result<OffsetDateTime, ServerExit> {
    if elapsed_ms > MAX_RUN_ELAPSED_MS {
        return Err(ServerExit::LimitExceeded);
    }
    base.checked_add(time::Duration::milliseconds(
        i64::try_from(elapsed_ms).map_err(|_| ServerExit::LimitExceeded)?,
    ))
    .ok_or(ServerExit::LimitExceeded)
}

/// Allowed metadata headers for sidecars.
/// Conflicting transport headers (transfer-encoding, connection, etc.) are strictly excluded.
pub const ALLOWED_SIDECAR_HEADERS: &[&str] = &[
    "accept",
    "accept-ch",
    "accept-charset",
    "accept-encoding",
    "accept-language",
    "accept-ranges",
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-origin",
    "access-control-expose-headers",
    "access-control-max-age",
    "age",
    "allow",
    "alt-svc",
    "cache-control",
    "clear-site-data",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-location",
    "content-md5",
    "content-range",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "digest",
    "early-data",
    "etag",
    "expect-ct",
    "expires",
    "last-modified",
    "link",
    "location",
    "nel",
    "origin-agent-cluster",
    "permissions-policy",
    "pragma",
    "referrer-policy",
    "refresh",
    "report-to",
    "retry-after",
    "sec-ch-ua",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-mobile",
    "sec-ch-ua-model",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "server-timing",
    "sourcemap",
    "strict-transport-security",
    "timing-allow-origin",
    "upgrade-insecure-requests",
    "vary",
    "x-content-type-options",
    "x-dns-prefetch-control",
    "x-frame-options",
    "x-permitted-cross-domain-policies",
    "x-robots-tag",
    "x-xss-protection",
];

pub fn is_allowed_sidecar_header(name: &str) -> bool {
    ALLOWED_SIDECAR_HEADERS.contains(&name)
}

/// Only explicitly approved representation metadata may leave the store.
/// Drop invalid headers: not a lowercase token, not printable ASCII/HTAB, or exceeding caps.
pub fn filter_headers(
    extra_headers: Vec<(String, String)>,
    content_type: Option<&str>,
    content_length: usize,
    date_str: &str,
    content_range: Option<&str>,
) -> Vec<ResponseHeader> {
    let mut out = Vec::new();
    let mut total_bytes = 0;

    let try_push =
        |name: String, value: String, out: &mut Vec<ResponseHeader>, total: &mut usize| -> bool {
            if out.len() >= hermetic_common::MAX_RESPONSE_HEADERS {
                return false;
            }
            if name.len() > u16::MAX as usize || value.len() > u16::MAX as usize {
                return false;
            }
            let h_bytes = name.len() + value.len();
            if *total + h_bytes > hermetic_common::MAX_RESPONSE_HEADERS_BYTES {
                return false;
            }
            if hermetic_common::validate_header_name(name.as_bytes()).is_err() {
                return false;
            }
            if hermetic_common::validate_header_value(value.as_bytes()).is_err() {
                return false;
            }
            *total += h_bytes;
            out.push(ResponseHeader { name, value });
            true
        };

    // Standard headers
    try_push("date".into(), date_str.into(), &mut out, &mut total_bytes);
    try_push(
        "content-length".into(),
        content_length.to_string(),
        &mut out,
        &mut total_bytes,
    );
    try_push(
        "accept-ranges".into(),
        "bytes".into(),
        &mut out,
        &mut total_bytes,
    );

    if let Some(ct) = content_type {
        let content_range_bytes = content_range
            .map(|cr| "content-range".len() + cr.len())
            .unwrap_or(0);
        let ct_header_bytes = "content-type".len() + ct.len();
        let valid_ct = if hermetic_common::validate_header_value(ct.as_bytes()).is_ok()
            && ct.len() <= u16::MAX as usize
            && total_bytes + ct_header_bytes + content_range_bytes
                <= hermetic_common::MAX_RESPONSE_HEADERS_BYTES
        {
            ct
        } else {
            eprintln!("Sidecar content_type is invalid, falling back to application/octet-stream");
            "application/octet-stream"
        };
        try_push(
            "content-type".into(),
            valid_ct.into(),
            &mut out,
            &mut total_bytes,
        );
    }

    if let Some(cr) = content_range {
        try_push(
            "content-range".into(),
            cr.into(),
            &mut out,
            &mut total_bytes,
        );
    }

    // Extra headers with security stripping & validation
    for (name, val) in extra_headers {
        let lower = name.to_ascii_lowercase();
        if !is_allowed_sidecar_header(&lower) {
            continue;
        }
        try_push(lower, val, &mut out, &mut total_bytes);
    }

    out
}

pub struct WorldServer {
    config: ServerConfig,
    store: DirStore,
    limits: Limits,
    log: LogManager,
    start_time: Instant,
    elapsed_offset_ms: u64,
    socket_directory: Directory,
    socket_name: PathBuf,
}

impl WorldServer {
    pub fn new(mut config: ServerConfig) -> Result<Self, ServerExit> {
        if !validate_rate(config.rate_rps, config.burst)
            || config.t_clock.year() < 1601
            || guest_clock(config.t_clock, MAX_RUN_ELAPSED_MS).is_err()
            || (config.recover && !config.resume_log)
        {
            return Err(ServerExit::StartupFailed);
        }
        // Validate all configured roots and the endpoint before creating artifacts.
        let store = DirStore::try_new(&config.store_dir).map_err(|_| ServerExit::StartupFailed)?;
        config.store_dir =
            std::path::absolute(&config.store_dir).map_err(|_| ServerExit::StartupFailed)?;
        let socket_directory = Directory::open(
            config
                .socket_path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )
        .map_err(|_| ServerExit::StartupFailed)?;
        let socket_name = PathBuf::from(
            config
                .socket_path
                .file_name()
                .ok_or(ServerExit::StartupFailed)?,
        );
        if socket_name.as_os_str().len() > MAX_SOCKET_NAME_BYTES {
            return Err(ServerExit::StartupFailed);
        }
        let socket_entry = socket_directory
            .path(&socket_name)
            .map_err(|_| ServerExit::StartupFailed)?;
        match std::fs::symlink_metadata(&socket_entry) {
            Err(e) if e.kind() == ErrorKind::NotFound => (),
            _ => return Err(ServerExit::StartupFailed),
        }
        // Bind the run to its supplied clock, resource policy, store and sandbox policy.
        let binding_data = serde_json::to_vec(&(
            config.t_clock.unix_timestamp_nanos().to_string(),
            config.rate_rps.map(f64::to_bits),
            config.burst.map(f64::to_bits),
            config.max_requests,
            config.max_bytes,
            config.allow_no_landlock,
            config.no_sandbox,
            config.store_dir.as_os_str().as_encoded_bytes(),
        ))
        .map_err(|_| ServerExit::StartupFailed)?;
        let binding = blake3::hash(&binding_data).to_hex().to_string();
        if config.resume_log {
            LogManager::validate_binding(&config.log_dir, &binding)
                .map_err(|_| ServerExit::StartupFailed)?;
        }
        let mut log =
            LogManager::new_opts_recover(&config.log_dir, config.resume_log, config.recover)
                .map_err(|_| ServerExit::StartupFailed)?;
        let mut limits = Limits::new(
            config.rate_rps,
            config.burst,
            config.max_requests,
            config.max_bytes,
        );
        let elapsed_offset_ms = log.run_state().elapsed_ms;
        if config.resume_log {
            limits.restore(log.run_state().requests, log.run_state().bytes);
        } else {
            log.log_event(&LogEventParams {
                elapsed_ms: 0,
                request_id: 0,
                method: "",
                authority: "",
                path_and_query: &binding,
                range: None,
                status: "run_config",
                bytes: 0,
            })
            .map_err(|_| ServerExit::StartupFailed)?;
        }
        Ok(Self {
            config,
            store,
            limits,
            log,
            start_time: Instant::now(),
            elapsed_offset_ms,
            socket_directory,
            socket_name,
        })
    }

    fn elapsed_ms(&self) -> u64 {
        self.elapsed_offset_ms.saturating_add(
            u64::try_from(self.start_time.elapsed().as_millis()).unwrap_or(u64::MAX),
        )
    }

    fn record_sandbox(&mut self, status: Option<SandboxLandlockStatus>) -> Result<(), ServerExit> {
        let status = match status {
            Some(SandboxLandlockStatus::Enforced) => "sandbox_landlock_enforced",
            Some(SandboxLandlockStatus::NotEnforced) => "sandbox_landlock_not_enforced",
            None => "sandbox_disabled",
        };
        self.log
            .log_event(&LogEventParams {
                elapsed_ms: self.elapsed_ms(),
                request_id: 0,
                method: "",
                authority: "",
                path_and_query: "",
                range: None,
                status,
                bytes: 0,
            })
            .map_err(|_| ServerExit::LogFailed)
    }

    /// Run the server loop.
    pub fn run(mut self) -> Result<(), ServerExit> {
        // Existing endpoints, including stale sockets, are refused without unlinking.
        // The pinned parent prevents ancestor replacement from redirecting the bind.
        let socket = self
            .socket_directory
            .path(&self.socket_name)
            .map_err(|_| ServerExit::StartupFailed)?;
        let listener = UnixListener::bind(socket).map_err(|_| ServerExit::StartupFailed)?;
        let status = if self.config.no_sandbox {
            None
        } else {
            Some(
                apply_sandbox(
                    &self
                        .store
                        .descriptor_path()
                        .ok_or(ServerExit::StartupFailed)?,
                    &self
                        .log
                        .descriptor_path()
                        .map_err(|_| ServerExit::StartupFailed)?,
                    self.config.allow_no_landlock,
                )
                .map_err(|_| ServerExit::StartupFailed)?,
            )
        };
        self.record_sandbox(status)?;

        // Step 4: Accept connections
        for stream_res in listener.incoming() {
            let mut stream = match stream_res {
                Ok(s) => s,
                Err(_) => continue,
            };

            let exit = self.handle_connection(&mut stream);
            if exit != ServerExit::Normal {
                if let Err(e) = self.log.finish() {
                    eprintln!("log_failed: {e}");
                    return Err(ServerExit::LogFailed);
                }
                return Err(exit);
            }
        }

        if let Err(e) = self.log.finish() {
            eprintln!("log_failed: {e}");
            return Err(ServerExit::LogFailed);
        }
        Ok(())
    }

    /// Handle requests on a single connection sequentially until EOF or fatal error.
    fn handle_connection(&mut self, stream: &mut UnixStream) -> ServerExit {
        loop {
            let frame = match RequestFrame::read_from(stream) {
                Ok(f) => f,
                Err(WireError::Io(e))
                    if e.kind() == ErrorKind::UnexpectedEof
                        || e.kind() == ErrorKind::ConnectionReset
                        || e.kind() == ErrorKind::BrokenPipe =>
                {
                    // Clean EOF from client
                    return ServerExit::Normal;
                }
                Err(WireError::Malformed(reason)) => {
                    // Malformed frame: log tampered, exit code 3
                    let elapsed_ms = self.elapsed_ms();
                    eprintln!("Malformed frame received: {reason}");
                    if let Err(e) = self.log.log_event(&LogEventParams {
                        elapsed_ms,
                        request_id: 0,
                        method: "",
                        authority: "",
                        path_and_query: "",
                        range: None,
                        status: "tampered",
                        bytes: 0,
                    }) {
                        eprintln!("log_failed: {e}");
                        let _ = self.log.finish();
                        return ServerExit::LogFailed;
                    }
                    if let Err(e) = self.log.finish() {
                        eprintln!("log_failed: {e}");
                        return ServerExit::LogFailed;
                    }
                    return ServerExit::Tampered;
                }
                Err(e) => {
                    eprintln!("I/O error reading frame: {e}");
                    return ServerExit::Normal;
                }
            };

            // 1. Check request cap
            if self.limits.check_request_cap().is_err() {
                let elapsed_ms = self.elapsed_ms();
                if let Err(e) = self.log.log_event(&LogEventParams {
                    elapsed_ms,
                    request_id: frame.request_id,
                    method: match frame.method {
                        Method::Get => "GET",
                        Method::Head => "HEAD",
                    },
                    authority: &frame.authority,
                    path_and_query: &frame.path_and_query,
                    range: frame.range,
                    status: "limit_exceeded",
                    bytes: 0,
                }) {
                    eprintln!("log_failed: {e}");
                    let _ = self.log.finish();
                    return ServerExit::LogFailed;
                }
                if let Err(e) = self.log.finish() {
                    eprintln!("log_failed: {e}");
                    return ServerExit::LogFailed;
                }
                return ServerExit::LimitExceeded;
            }

            // 2. Token bucket delay
            if self.limits.acquire_token().is_err() {
                return ServerExit::LimitExceeded;
            }

            // 3. Process request
            let elapsed_ms = self.elapsed_ms();
            let current_clock = match guest_clock(self.config.t_clock, elapsed_ms) {
                Ok(clock) => clock,
                Err(exit) => {
                    if self
                        .log
                        .log_event(&LogEventParams {
                            elapsed_ms,
                            request_id: frame.request_id,
                            method: "",
                            authority: "",
                            path_and_query: "",
                            range: None,
                            status: "clock_exhausted",
                            bytes: 0,
                        })
                        .is_err()
                    {
                        return ServerExit::LogFailed;
                    }
                    return exit;
                }
            };
            let date_str = format_imf_fixdate(current_clock);

            let method_str = match frame.method {
                Method::Get => "GET",
                Method::Head => "HEAD",
            };

            let stored = self.store.open(&frame.authority, &frame.path_and_query);

            let (status, headers, body) = match stored {
                Some(mut obj) => {
                    let total_len = obj.len;
                    let (status, start, length, cr) = match frame.range {
                        Some((start, end))
                            if total_len == 0 || start >= total_len || start > end =>
                        {
                            (416u16, 0, 0, Some(format!("bytes */{total_len}")))
                        }
                        Some((start, end)) => {
                            let end = end.min(total_len.saturating_sub(1));
                            let length = end.saturating_sub(start).saturating_add(1);
                            (
                                206u16,
                                start,
                                length,
                                Some(format!("bytes {start}-{end}/{total_len}")),
                            )
                        }
                        None => (200u16, 0, total_len, None),
                    };
                    let body = if frame.method == Method::Head {
                        Vec::new()
                    } else {
                        if self.limits.check_bytes_cap(length).is_err() || length > MAX_BODY_BYTES {
                            if self
                                .log
                                .log_event(&LogEventParams {
                                    elapsed_ms,
                                    request_id: frame.request_id,
                                    method: method_str,
                                    authority: &frame.authority,
                                    path_and_query: &frame.path_and_query,
                                    range: frame.range,
                                    status: "limit_exceeded",
                                    bytes: 0,
                                })
                                .is_err()
                            {
                                return ServerExit::LogFailed;
                            }
                            return ServerExit::LimitExceeded;
                        }
                        match obj.read_range(start, length, MAX_BODY_BYTES) {
                            Ok(body) => body,
                            Err(_) => return ServerExit::StartupFailed,
                        }
                    };
                    let Ok(length) = usize::try_from(length) else {
                        return ServerExit::LimitExceeded;
                    };
                    let headers = filter_headers(
                        obj.extra_headers,
                        obj.content_type.as_deref(),
                        length,
                        &date_str,
                        cr.as_deref(),
                    );
                    (status, headers, body)
                }
                None => {
                    // Miss -> 404
                    let (st, ct, b) = self.store.get_404(&frame.authority);
                    let length = b.len();
                    let hdrs = filter_headers(Vec::new(), ct.as_deref(), length, &date_str, None);
                    let resp_body = if frame.method == Method::Head {
                        Vec::new()
                    } else {
                        b
                    };
                    (st, hdrs, resp_body)
                }
            };

            let response_bytes = body.len() as u64;

            // 4. Check byte cap
            if self.limits.check_bytes_cap(response_bytes).is_err() {
                if let Err(e) = self.log.log_event(&LogEventParams {
                    elapsed_ms,
                    request_id: frame.request_id,
                    method: method_str,
                    authority: &frame.authority,
                    path_and_query: &frame.path_and_query,
                    range: frame.range,
                    status: "limit_exceeded",
                    bytes: 0,
                }) {
                    eprintln!("log_failed: {e}");
                    let _ = self.log.finish();
                    return ServerExit::LogFailed;
                }
                if let Err(e) = self.log.finish() {
                    eprintln!("log_failed: {e}");
                    return ServerExit::LogFailed;
                }
                return ServerExit::LimitExceeded;
            }

            #[cfg(test)]
            review_tests::crash_at("before_intent");
            // Reserve usage durably before any response byte can leave the process.
            if self
                .log
                .log_event(&LogEventParams {
                    elapsed_ms,
                    request_id: frame.request_id,
                    method: method_str,
                    authority: &frame.authority,
                    path_and_query: &frame.path_and_query,
                    range: frame.range,
                    status: "transmission_intent",
                    bytes: response_bytes,
                })
                .is_err()
            {
                return ServerExit::LogFailed;
            }
            self.limits.record_request();
            self.limits.record_bytes(response_bytes);

            #[cfg(test)]
            review_tests::crash_at("after_intent");
            // 5. Send response frame
            let response = ResponseFrame {
                request_id: frame.request_id,
                status,
                headers,
                body,
            };

            let max_body = self.config.max_bytes.unwrap_or(u64::MAX);
            if let Err(e) = response.write_to(stream, max_body) {
                eprintln!("Error writing response frame: {e}");
                if let Err(log_err) = self.log.log_event(&LogEventParams {
                    elapsed_ms,
                    request_id: frame.request_id,
                    method: method_str,
                    authority: &frame.authority,
                    path_and_query: &frame.path_and_query,
                    range: frame.range,
                    status: "write_error",
                    bytes: response_bytes,
                }) {
                    eprintln!("log_failed: {log_err}");
                    let _ = self.log.finish();
                    return ServerExit::LogFailed;
                }
                if let Err(e) = self.log.finish() {
                    eprintln!("log_failed: {e}");
                    return ServerExit::LogFailed;
                }
                return ServerExit::Normal;
            }

            #[cfg(test)]
            review_tests::crash_at("after_send");
            // 6. Record usage and log event
            let status_str = status.to_string();
            if let Err(e) = self.log.log_event(&LogEventParams {
                elapsed_ms,
                request_id: frame.request_id,
                method: method_str,
                authority: &frame.authority,
                path_and_query: &frame.path_and_query,
                range: frame.range,
                status: &status_str,
                bytes: response_bytes,
            }) {
                eprintln!("log_failed: {e}");
                let _ = self.log.finish();
                return ServerExit::LogFailed;
            }
            #[cfg(test)]
            review_tests::crash_at("after_completion");
        }
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;
    use crate::log::LogWriter;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use tempfile::{tempdir, TempDir};
    use time::macros::datetime;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    thread_local! { static CRASH_BOUNDARY: std::cell::Cell<&'static str> = const { std::cell::Cell::new("") }; }
    pub(super) fn crash_at(boundary: &str) {
        CRASH_BOUNDARY
            .with(|selected| assert_ne!(selected.get(), boundary, "simulated transmission crash"));
    }

    fn fixture() -> TempDir {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("store/example.org")).unwrap();
        fs::write(temp.path().join("store/example.org/body"), b"abc").unwrap();
        temp
    }
    fn config(temp: &TempDir) -> ServerConfig {
        ServerConfig {
            store_dir: temp.path().join("store"),
            log_dir: temp.path().join("log"),
            socket_path: temp.path().join("socket"),
            t_clock: datetime!(2024-03-01 12:00:00 UTC),
            rate_rps: None,
            burst: None,
            max_requests: None,
            max_bytes: None,
            allow_no_landlock: true,
            no_sandbox: true,
            resume_log: false,
            recover: false,
        }
    }
    fn request() -> RequestFrame {
        RequestFrame {
            method: Method::Get,
            request_id: 1,
            authority: "example.org".into(),
            path_and_query: "/body".into(),
            range: None,
        }
    }
    fn exchange(
        mut server: WorldServer,
        request: RequestFrame,
    ) -> (WorldServer, Result<ResponseFrame, WireError>, ServerExit) {
        let (mut client, mut peer) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let exit = server.handle_connection(&mut peer);
            (server, exit)
        });
        client.write_all(&request.encode().unwrap()).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        thread::spawn(move || {
            sender
                .send(ResponseFrame::read_from(&mut client, MAX_BODY_BYTES))
                .unwrap();
        });
        let response = receiver.recv_timeout(TEST_TIMEOUT).unwrap();
        let (server, exit) = worker.join().unwrap();
        (server, response, exit)
    }

    #[test]
    fn crash_resume_enforces_cumulative_quotas_and_guest_time() {
        for byte_quota in [false, true] {
            let temp = fixture();
            let make_config = || {
                let mut c = config(&temp);
                if byte_quota {
                    c.max_bytes = Some(5);
                } else {
                    c.max_requests = Some(2);
                }
                c
            };
            let mut server = WorldServer::new(make_config()).unwrap();
            server.elapsed_offset_ms = 5000;
            let (server, first, exit) = exchange(server, request());
            assert_eq!(exit, ServerExit::Normal);
            let first = first.unwrap();
            let first_date = first
                .headers
                .iter()
                .find(|h| h.name == "date")
                .unwrap()
                .value
                .clone();
            drop(server); // no finish: crash after content was delivered
            let mut resume = make_config();
            resume.resume_log = true;
            resume.recover = true;
            let resumed = WorldServer::new(resume).unwrap();
            assert_eq!(resumed.limits.total_requests(), 1);
            assert_eq!(resumed.limits.total_bytes(), 3);
            assert!(resumed.elapsed_ms() >= 5000);
            let (server, response, exit) = exchange(resumed, request());
            if byte_quota {
                assert_eq!(exit, ServerExit::LimitExceeded);
                assert!(response.is_err());
            } else {
                assert_eq!(exit, ServerExit::Normal);
                let second = response.unwrap();
                let second_date = &second
                    .headers
                    .iter()
                    .find(|h| h.name == "date")
                    .unwrap()
                    .value;
                assert!(second_date >= &first_date);
                drop(server);
                let mut resume = make_config();
                resume.resume_log = true;
                resume.recover = true;
                let resumed = WorldServer::new(resume).unwrap();
                let (_, response, exit) = exchange(resumed, request());
                assert_eq!(exit, ServerExit::LimitExceeded);
                assert!(response.is_err());
            }
            let mut previous = 0;
            for line in fs::read_to_string(temp.path().join("log/requests.log"))
                .unwrap()
                .lines()
            {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                let elapsed = value["elapsed_ms"].as_u64().unwrap();
                assert!(elapsed >= previous);
                previous = elapsed;
            }
        }
    }

    #[test]
    fn resumed_configuration_mismatch_preserves_artifacts() {
        let temp = fixture();
        let mut server = WorldServer::new(config(&temp)).unwrap();
        server.log.finish().unwrap();
        drop(server);
        let paths = ["requests.log", "requests.log.head", "dedupe.json"];
        let originals: Vec<_> = paths
            .iter()
            .map(|name| fs::read(temp.path().join("log").join(name)).unwrap())
            .collect();
        for change_clock in [false, true] {
            let mut cfg = config(&temp);
            cfg.resume_log = true;
            cfg.recover = true;
            if change_clock {
                cfg.t_clock += time::Duration::seconds(1);
            } else {
                cfg.max_requests = Some(1);
            }
            assert!(WorldServer::new(cfg).is_err());
            for (name, original) in paths.iter().zip(&originals) {
                assert_eq!(
                    &fs::read(temp.path().join("log").join(name)).unwrap(),
                    original
                );
            }
        }
    }

    struct FailSync {
        file: File,
        successful_syncs: usize,
        calls: Arc<AtomicUsize>,
    }
    impl Write for FailSync {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.file.write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.file.flush()
        }
    }
    impl LogWriter for FailSync {
        fn sync_all(&mut self) -> std::io::Result<()> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call >= self.successful_syncs {
                return Err(std::io::Error::other("injected audit sync failure"));
            }
            self.file.sync_all()
        }
    }
    #[test]
    fn audit_failures_never_leave_delivered_content_without_intent() {
        for successful_syncs in [0, 1] {
            let temp = fixture();
            let mut server = WorldServer::new(config(&temp)).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let file = File::create(temp.path().join("log/requests.log")).unwrap();
            server.log = LogManager::new_with_writer(
                temp.path().join("log"),
                FailSync {
                    file,
                    successful_syncs,
                    calls: calls.clone(),
                },
            );
            let (server, response, exit) = exchange(server, request());
            assert_eq!(exit, ServerExit::LogFailed);
            assert!(calls.load(Ordering::SeqCst) > successful_syncs);
            if successful_syncs == 0 {
                assert!(response.is_err());
            } else {
                assert_eq!(response.unwrap().body, b"abc");
            }
            drop(server);
            let recovered =
                LogManager::new_opts_recover(temp.path().join("log"), true, true).unwrap();
            assert_eq!(recovered.run_state().requests, 1);
            assert_eq!(recovered.run_state().bytes, 3);
        }
    }

    #[test]
    fn crashes_at_transmission_boundaries_preserve_durable_intent() {
        for boundary in [
            "before_intent",
            "after_intent",
            "after_send",
            "after_completion",
        ] {
            let temp = fixture();
            let mut server = WorldServer::new(config(&temp)).unwrap();
            let (mut client, mut peer) = UnixStream::pair().unwrap();
            let worker = thread::spawn(move || {
                CRASH_BOUNDARY.set(boundary);
                server.handle_connection(&mut peer);
            });
            client.write_all(&request().encode().unwrap()).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let (sender, receiver) = std::sync::mpsc::channel();
            thread::spawn(move || {
                let mut delivered = Vec::new();
                client.read_to_end(&mut delivered).unwrap();
                sender.send(delivered).unwrap();
            });
            let delivered = receiver.recv_timeout(TEST_TIMEOUT).unwrap();
            assert!(worker.join().is_err());
            let recovered =
                LogManager::new_opts_recover(temp.path().join("log"), true, true).unwrap();
            let sent = boundary == "after_send" || boundary == "after_completion";
            assert_eq!(!delivered.is_empty(), sent);
            assert_eq!(
                recovered.run_state().requests,
                u64::from(boundary != "before_intent")
            );
            assert_eq!(
                recovered.run_state().incomplete_transmissions,
                u64::from(boundary == "after_intent" || boundary == "after_send")
            );
        }
    }

    #[test]
    fn unavailable_landlock_is_an_explicit_chained_startup_event() {
        let temp = fixture();
        let mut server = WorldServer::new(config(&temp)).unwrap();
        server
            .record_sandbox(Some(SandboxLandlockStatus::NotEnforced))
            .unwrap();
        server.log.finish().unwrap();
        let path = temp.path().join("log/requests.log");
        assert_eq!(crate::log::verify_log(&path).unwrap(), 2);
        let records: Vec<serde_json::Value> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(records[1]["status"], "sandbox_landlock_not_enforced");
        assert_eq!(records[1]["prev"], records[0]["hash"]);
    }

    #[test]
    fn elapsed_clock_exhaustion_is_audited_without_panicking() {
        let temp = fixture();
        let mut server = WorldServer::new(config(&temp)).unwrap();
        server.elapsed_offset_ms = MAX_RUN_ELAPSED_MS + 1;
        let (mut server, response, exit) = exchange(server, request());
        assert_eq!(exit, ServerExit::LimitExceeded);
        assert!(response.is_err());
        server.log.finish().unwrap();
        let log = fs::read_to_string(temp.path().join("log/requests.log")).unwrap();
        assert!(log.contains("clock_exhausted"));
    }

    #[test]
    fn sparse_head_ranges_and_sidecars_under_small_memory_budget() {
        if std::env::var_os("HERMETIC_SPARSE_REVIEW_CHILD").is_none() {
            let status = std::process::Command::new("bash")
                .args(["-c", "ulimit -v 262144; exec \"$@\"", "sparse-test"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", "server::review_tests::sparse_head_ranges_and_sidecars_under_small_memory_budget", "--nocapture"])
                .env("HERMETIC_SPARSE_REVIEW_CHILD", "1").status().unwrap();
            assert!(status.success());
            return;
        }
        let temp = fixture();
        let object = temp.path().join("store/example.org/body");
        let length = 8 * 1024 * 1024 * 1024u64;
        fs::OpenOptions::new()
            .write(true)
            .open(object)
            .unwrap()
            .set_len(length)
            .unwrap();
        File::create(temp.path().join("store/example.org/body.headers.json"))
            .unwrap()
            .set_len(length)
            .unwrap();
        File::create(temp.path().join("store/example.org/.404.json"))
            .unwrap()
            .set_len(length)
            .unwrap();
        let server = WorldServer::new(config(&temp)).unwrap();
        let mut req = request();
        req.method = Method::Head;
        let (server, response, exit) = exchange(server, req);
        assert_eq!(exit, ServerExit::Normal);
        let response = response.unwrap();
        assert_eq!(response.status, 200);
        assert!(response.body.is_empty());
        assert!(response
            .headers
            .iter()
            .any(|h| h.name == "content-length" && h.value == length.to_string()));
        let mut req = request();
        req.range = Some((length - 1, length - 1));
        let (server, response, exit) = exchange(server, req);
        assert_eq!(exit, ServerExit::Normal);
        assert_eq!(response.unwrap().body, [0]);
        let mut req = request();
        req.path_and_query = "/missing".into();
        let (_, response, exit) = exchange(server, req);
        assert_eq!(exit, ServerExit::Normal);
        assert_eq!(response.unwrap().status, 404);
    }
}
