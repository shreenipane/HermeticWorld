#![forbid(unsafe_code)]

use hermetic_common::{Method, RequestFrame, ResponseFrame, ResponseHeader};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

use crate::limits::{validate_rate, Limits};
use crate::log::{LogEventParams, LogManager};
use crate::safe_fs::Directory;
use crate::sandbox::{apply_sandbox, SandboxLandlockStatus};
use crate::store::DirStore;

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
    pub frame_deadline: Option<std::time::Duration>,
    pub transmission_deadline: Option<std::time::Duration>,
}

pub const DEFAULT_FRAME_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
pub const DEFAULT_TRANSMISSION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Format an OffsetDateTime in IMF-fixdate format (RFC 7231 / RFC 9110), e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
pub fn format_imf_fixdate(dt: OffsetDateTime) -> Result<String, ServerExit> {
    let utc = dt
        .checked_to_offset(time::UtcOffset::UTC)
        .ok_or(ServerExit::LimitExceeded)?;
    if utc.year() < 0 || utc.year() > 9999 {
        return Err(ServerExit::LimitExceeded);
    }
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
    Ok(format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        weekday,
        utc.day(),
        month,
        utc.year(),
        utc.hour(),
        utc.minute(),
        utc.second()
    ))
}

pub const MAX_SOCKET_NAME_BYTES: usize = 80;
pub const MAX_RUN_ELAPSED_MS: u64 = 24 * 60 * 60 * 1000;

pub fn guest_clock(base: OffsetDateTime, elapsed_ms: u64) -> Result<OffsetDateTime, ServerExit> {
    if elapsed_ms > MAX_RUN_ELAPSED_MS {
        return Err(ServerExit::LimitExceeded);
    }
    let utc_base = base
        .checked_to_offset(time::UtcOffset::UTC)
        .ok_or(ServerExit::LimitExceeded)?;
    let dt = utc_base
        .checked_add(time::Duration::milliseconds(
            i64::try_from(elapsed_ms).map_err(|_| ServerExit::LimitExceeded)?,
        ))
        .ok_or(ServerExit::LimitExceeded)?;
    if dt.year() < 1601 || dt.year() > 9999 {
        return Err(ServerExit::LimitExceeded);
    }
    Ok(dt)
}

/// Server-owned headers whose generated values are authoritative.
/// Conflicting sidecar copies (including case variants) are strictly excluded.
pub const SERVER_OWNED_HEADERS: &[&str] = &[
    "date",
    "content-length",
    "accept-ranges",
    "content-type",
    "content-range",
];

pub fn is_server_owned_header(name: &str) -> bool {
    SERVER_OWNED_HEADERS.contains(&name)
}

/// Allowed metadata headers for sidecars.
/// Conflicting transport headers (transfer-encoding, connection, etc.) are strictly excluded.
pub const ALLOWED_SIDECAR_HEADERS: &[&str] = &[
    "accept",
    "accept-ch",
    "accept-charset",
    "accept-encoding",
    "accept-language",
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

    // Extra headers with security stripping & validation, sorted alphabetically for determinism
    let mut valid_extras: Vec<(String, String)> = Vec::new();
    for (name, val) in extra_headers {
        let lower = name.to_ascii_lowercase();
        if is_server_owned_header(&lower) || !is_allowed_sidecar_header(&lower) {
            continue;
        }
        if hermetic_common::validate_header_name(lower.as_bytes()).is_err() {
            continue;
        }
        if hermetic_common::validate_header_value(val.as_bytes()).is_err() {
            continue;
        }
        valid_extras.push((lower, val));
    }

    valid_extras.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    for (lower, val) in valid_extras {
        try_push(lower, val, &mut out, &mut total_bytes);
    }

    out
}

fn path_is_ancestor_or_equal(ancestor: &Path, path: &Path) -> bool {
    let mut a_comps = ancestor.components();
    let mut p_comps = path.components();
    for a in &mut a_comps {
        match p_comps.next() {
            Some(p) if p == a => {}
            _ => return false,
        }
    }
    true
}

fn validate_root_separation(store_dir: &Directory, log_path: &Path) -> Result<(), ServerExit> {
    use std::os::unix::fs::MetadataExt;

    let store_fd_path = store_dir.descriptor_path();
    let store_canon = std::fs::read_link(&store_fd_path).map_err(|_| ServerExit::StartupFailed)?;
    let store_meta = std::fs::metadata(&store_canon).map_err(|_| ServerExit::StartupFailed)?;

    let norm_log = crate::safe_fs::normalize_path(log_path);
    let mut cur = norm_log.as_path();
    let mut log_dir_desc = None;
    while !cur.as_os_str().is_empty() {
        if let Ok(d) = Directory::open(cur) {
            log_dir_desc = Some((d, cur.to_path_buf()));
            break;
        }
        match cur.parent() {
            Some(p) if !p.as_os_str().is_empty() => cur = p,
            _ => break,
        }
    }
    let (log_d, existing_log_ancestor) = log_dir_desc.ok_or(ServerExit::StartupFailed)?;
    let log_fd_path = log_d.descriptor_path();
    let log_canon = std::fs::read_link(&log_fd_path).map_err(|_| ServerExit::StartupFailed)?;
    let log_meta = std::fs::metadata(&log_canon).map_err(|_| ServerExit::StartupFailed)?;

    let rel_suffix = norm_log
        .strip_prefix(&existing_log_ancestor)
        .unwrap_or(Path::new(""));
    let full_log_canon = log_canon.join(rel_suffix);

    if (norm_log == existing_log_ancestor
        && store_meta.dev() == log_meta.dev()
        && store_meta.ino() == log_meta.ino())
        || store_canon == full_log_canon
        || path_is_ancestor_or_equal(&store_canon, &full_log_canon)
        || path_is_ancestor_or_equal(&full_log_canon, &store_canon)
    {
        return Err(ServerExit::StartupFailed);
    }

    Ok(())
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

enum ReadFrameResult {
    Ok(RequestFrame),
    CleanEof,
    Malformed(String),
    FrameTimeout,
    RunTimeout,
    Io(std::io::Error),
}

fn read_request_frame_deadline(
    stream: &mut UnixStream,
    frame_deadline: Instant,
    run_deadline: Instant,
) -> ReadFrameResult {
    let mut header = [0u8; hermetic_common::REQUEST_HEADER_SIZE];
    let mut n = 0;
    while n < hermetic_common::REQUEST_HEADER_SIZE {
        let now = Instant::now();
        if now >= run_deadline {
            return ReadFrameResult::RunTimeout;
        }
        if now >= frame_deadline {
            return ReadFrameResult::FrameTimeout;
        }
        let rem = run_deadline
            .saturating_duration_since(now)
            .min(frame_deadline.saturating_duration_since(now))
            .max(Duration::from_millis(1));
        if let Err(e) = stream.set_read_timeout(Some(rem)) {
            return ReadFrameResult::Io(e);
        }
        match stream.read(&mut header[n..]) {
            Ok(0) => {
                if n == 0 {
                    return ReadFrameResult::CleanEof;
                } else {
                    return ReadFrameResult::Malformed("truncated header".into());
                }
            }
            Ok(bytes) => n += bytes,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                let now = Instant::now();
                if now >= run_deadline {
                    return ReadFrameResult::RunTimeout;
                } else {
                    return ReadFrameResult::FrameTimeout;
                }
            }
            Err(e) => return ReadFrameResult::Io(e),
        }
    }

    if &header[0..4] != hermetic_common::REQUEST_MAGIC.as_slice() {
        return ReadFrameResult::Malformed("bad request magic".into());
    }
    let authority_len = u16::from_le_bytes([header[16], header[17]]) as usize;
    let path_len = u16::from_le_bytes([header[18], header[19]]) as usize;
    if authority_len > hermetic_common::MAX_AUTHORITY_LEN {
        return ReadFrameResult::Malformed(format!(
            "authority too long: {authority_len} > {}",
            hermetic_common::MAX_AUTHORITY_LEN
        ));
    }
    if path_len > hermetic_common::MAX_PATH_LEN {
        return ReadFrameResult::Malformed(format!(
            "path too long: {path_len} > {}",
            hermetic_common::MAX_PATH_LEN
        ));
    }
    let payload_len = authority_len + path_len;
    let total_len = hermetic_common::REQUEST_HEADER_SIZE + payload_len;
    if total_len > hermetic_common::MAX_REQUEST_FRAME_SIZE {
        return ReadFrameResult::Malformed("request frame too large".into());
    }

    let mut frame_buf = Vec::with_capacity(total_len);
    frame_buf.extend_from_slice(&header);
    frame_buf.resize(total_len, 0);

    let mut m = hermetic_common::REQUEST_HEADER_SIZE;
    while m < total_len {
        let now = Instant::now();
        if now >= run_deadline {
            return ReadFrameResult::RunTimeout;
        }
        if now >= frame_deadline {
            return ReadFrameResult::FrameTimeout;
        }
        let rem = run_deadline
            .saturating_duration_since(now)
            .min(frame_deadline.saturating_duration_since(now))
            .max(Duration::from_millis(1));
        if let Err(e) = stream.set_read_timeout(Some(rem)) {
            return ReadFrameResult::Io(e);
        }
        match stream.read(&mut frame_buf[m..]) {
            Ok(0) => {
                return ReadFrameResult::Malformed("truncated payload".into());
            }
            Ok(bytes) => m += bytes,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                let now = Instant::now();
                if now >= run_deadline {
                    return ReadFrameResult::RunTimeout;
                } else {
                    return ReadFrameResult::FrameTimeout;
                }
            }
            Err(e) => return ReadFrameResult::Io(e),
        }
    }

    match RequestFrame::decode(&frame_buf) {
        Ok(req) => ReadFrameResult::Ok(req),
        Err(e) => ReadFrameResult::Malformed(e.to_string()),
    }
}

struct DeadlineWriter<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl<'a> Write for DeadlineWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let now = Instant::now();
        if now >= self.deadline {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "transmission deadline exceeded",
            ));
        }
        let rem = self
            .deadline
            .saturating_duration_since(now)
            .max(Duration::from_millis(1));
        self.stream.set_write_timeout(Some(rem))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl Drop for WorldServer {
    fn drop(&mut self) {
        if let Ok(entry) = self.socket_directory.path(&self.socket_name) {
            let _ = std::fs::remove_file(entry);
        }
    }
}

impl WorldServer {
    pub fn new(mut config: ServerConfig) -> Result<Self, ServerExit> {
        config.t_clock = config
            .t_clock
            .checked_to_offset(time::UtcOffset::UTC)
            .ok_or(ServerExit::StartupFailed)?;
        if !validate_rate(config.rate_rps, config.burst)
            || config.t_clock.year() < 1601
            || guest_clock(config.t_clock, MAX_RUN_ELAPSED_MS).is_err()
            || (config.recover && !config.resume_log)
        {
            return Err(ServerExit::StartupFailed);
        }
        // Validate all configured roots and the endpoint before creating artifacts.
        let store_directory =
            Directory::open(&config.store_dir).map_err(|_| ServerExit::StartupFailed)?;
        validate_root_separation(&store_directory, &config.log_dir)?;

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
            Ok(meta) => {
                use std::os::unix::fs::{FileTypeExt, MetadataExt};
                if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
                    return Err(ServerExit::StartupFailed);
                }
                if !config.recover {
                    return Err(ServerExit::StartupFailed);
                }
                let parent_fd_path = socket_directory.descriptor_path();
                let parent_canon =
                    std::fs::read_link(&parent_fd_path).map_err(|_| ServerExit::StartupFailed)?;
                let parent_meta =
                    std::fs::metadata(&parent_canon).map_err(|_| ServerExit::StartupFailed)?;
                if meta.uid() != parent_meta.uid() {
                    return Err(ServerExit::StartupFailed);
                }
                match UnixStream::connect(&socket_entry) {
                    Ok(_) => {
                        return Err(ServerExit::StartupFailed);
                    }
                    Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                        std::fs::remove_file(&socket_entry)
                            .map_err(|_| ServerExit::StartupFailed)?;
                    }
                    Err(_) => return Err(ServerExit::StartupFailed),
                }
            }
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
        let mut log = LogManager::new_opts_recover_binding(
            &config.log_dir,
            config.resume_log,
            config.recover,
            if config.resume_log {
                Some(&binding)
            } else {
                None
            },
        )
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
            if !self.config.no_sandbox {
                if let Err(e) = self.log.finish() {
                    eprintln!("log_failed: {e}");
                    return Err(ServerExit::LogFailed);
                }
                return Ok(());
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
        let frame_timeout = self.config.frame_deadline.unwrap_or(DEFAULT_FRAME_DEADLINE);
        let trans_timeout = self
            .config
            .transmission_deadline
            .unwrap_or(DEFAULT_TRANSMISSION_DEADLINE);

        loop {
            let remaining_run_ms = MAX_RUN_ELAPSED_MS.saturating_sub(self.elapsed_ms());
            let run_deadline = Instant::now() + Duration::from_millis(remaining_run_ms);
            let frame_deadline = Instant::now() + frame_timeout;

            let frame = match read_request_frame_deadline(stream, frame_deadline, run_deadline) {
                ReadFrameResult::Ok(f) => f,
                ReadFrameResult::CleanEof => return ServerExit::Normal,
                ReadFrameResult::FrameTimeout => {
                    let elapsed_ms = self.elapsed_ms();
                    if let Err(e) = self.log.log_event(&LogEventParams {
                        elapsed_ms,
                        request_id: 0,
                        method: "",
                        authority: "",
                        path_and_query: "",
                        range: None,
                        status: "frame_timeout",
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
                    return ServerExit::Normal;
                }
                ReadFrameResult::RunTimeout => {
                    let elapsed_ms = self.elapsed_ms();
                    let _ = self.log.log_event(&LogEventParams {
                        elapsed_ms,
                        request_id: 0,
                        method: "",
                        authority: "",
                        path_and_query: "",
                        range: None,
                        status: "clock_exhausted",
                        bytes: 0,
                    });
                    let _ = self.log.finish();
                    return ServerExit::LimitExceeded;
                }
                ReadFrameResult::Malformed(reason) => {
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
                ReadFrameResult::Io(e) => {
                    if e.kind() == ErrorKind::UnexpectedEof
                        || e.kind() == ErrorKind::ConnectionReset
                        || e.kind() == ErrorKind::BrokenPipe
                    {
                        return ServerExit::Normal;
                    }
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
                    let _ = self.log.log_event(&LogEventParams {
                        elapsed_ms,
                        request_id: frame.request_id,
                        method: "",
                        authority: "",
                        path_and_query: "",
                        range: None,
                        status: "clock_exhausted",
                        bytes: 0,
                    });
                    let _ = self.log.finish();
                    return exit;
                }
            };
            let date_str = match format_imf_fixdate(current_clock) {
                Ok(s) => s,
                Err(exit) => {
                    let _ = self.log.log_event(&LogEventParams {
                        elapsed_ms,
                        request_id: frame.request_id,
                        method: "",
                        authority: "",
                        path_and_query: "",
                        range: None,
                        status: "clock_exhausted",
                        bytes: 0,
                    });
                    let _ = self.log.finish();
                    return exit;
                }
            };

            let method_str = match frame.method {
                Method::Get => "GET",
                Method::Head => "HEAD",
            };

            let stored = self.store.open(&frame.authority, &frame.path_and_query);

            let (status, headers, response_bytes, body_file_info, body_mem) = match stored {
                Some(obj) => {
                    let total_len = obj.len;
                    let (status, start, length, cr) = match frame.range {
                        Some((start, end))
                            if total_len == 0 || start >= total_len || start > end =>
                        {
                            (416u16, 0u64, 0u64, Some(format!("bytes */{total_len}")))
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
                        None => (200u16, 0u64, total_len, None),
                    };
                    let Ok(header_content_len) = usize::try_from(length) else {
                        return ServerExit::LimitExceeded;
                    };
                    let headers = filter_headers(
                        obj.extra_headers,
                        obj.content_type.as_deref(),
                        header_content_len,
                        &date_str,
                        cr.as_deref(),
                    );
                    let resp_bytes = if frame.method == Method::Head {
                        0u64
                    } else {
                        length
                    };
                    (
                        status,
                        headers,
                        resp_bytes,
                        Some((obj.file, start, length)),
                        None,
                    )
                }
                None => {
                    // Miss -> 404
                    let (st, ct, b) = if DirStore::is_internal_metadata_path(&frame.path_and_query)
                    {
                        (
                            404,
                            Some("text/html".to_string()),
                            b"<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>".to_vec(),
                        )
                    } else {
                        self.store.get_404(&frame.authority)
                    };
                    let length = b.len();
                    let headers =
                        filter_headers(Vec::new(), ct.as_deref(), length, &date_str, None);
                    let resp_bytes = if frame.method == Method::Head {
                        0u64
                    } else {
                        length as u64
                    };
                    let mem_body = if frame.method == Method::Head {
                        None
                    } else {
                        Some(b)
                    };
                    (st, headers, resp_bytes, None, mem_body)
                }
            };

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

            // 5. Send response frame with transmission deadline and bounded streaming
            let trans_deadline = Instant::now() + trans_timeout;
            let effective_trans_deadline = trans_deadline.min(run_deadline);
            let max_body = self.config.max_bytes.unwrap_or(u64::MAX);

            let mut writer = DeadlineWriter {
                stream,
                deadline: effective_trans_deadline,
            };

            let send_result = (|| -> std::io::Result<()> {
                ResponseFrame::write_header_and_headers(
                    frame.request_id,
                    status,
                    &headers,
                    response_bytes,
                    max_body,
                    &mut writer,
                )
                .map_err(|e| std::io::Error::other(e.to_string()))?;

                if frame.method == Method::Get && response_bytes > 0 {
                    if let Some((mut file, start, length)) = body_file_info {
                        file.seek(SeekFrom::Start(start))?;
                        let mut chunk_buf = [0u8; 64 * 1024];
                        let mut remaining = length;
                        while remaining > 0 {
                            let to_read = (remaining as usize).min(chunk_buf.len());
                            file.read_exact(&mut chunk_buf[..to_read])?;
                            writer.write_all(&chunk_buf[..to_read])?;
                            remaining -= to_read as u64;
                        }
                    } else if let Some(mem_body) = body_mem {
                        writer.write_all(&mem_body)?;
                    }
                }
                writer.flush()?;
                Ok(())
            })();

            if let Err(e) = send_result {
                eprintln!("Error writing response frame: {e}");
                if Instant::now() >= run_deadline {
                    let _ = self.log.log_event(&LogEventParams {
                        elapsed_ms: self.elapsed_ms(),
                        request_id: frame.request_id,
                        method: "",
                        authority: "",
                        path_and_query: "",
                        range: None,
                        status: "clock_exhausted",
                        bytes: 0,
                    });
                    let _ = self.log.finish();
                    return ServerExit::LimitExceeded;
                }
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
    use crate::store::MAX_BODY_BYTES;
    use hermetic_common::WireError;
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
            frame_deadline: None,
            transmission_deadline: None,
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
