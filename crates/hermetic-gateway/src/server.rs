#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{Cursor, ErrorKind, Read};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tiny_http::{Header, Method, Request, RequestDeadlines, Response, Server};

use crate::anthropic::{parse_and_validate_request, ANTHROPIC_ADAPTER_VERSION};
use crate::config::GatewayConfig;
use crate::error::{
    standard_message_for_type, AnthropicErrorResponse, API_ERROR, INVALID_REQUEST_ERROR,
    NOT_FOUND_ERROR, OVERLOADED_ERROR, RATE_LIMIT_ERROR, REQUEST_TOO_LARGE,
};
use crate::history::HistoryLog;
use crate::log::{HostLogEntry, HostLogger, MAX_HOST_LOG_BYTES};
use crate::nonce::RunNonce;
use crate::quota::{QuotaBreach, QuotaTracker};
use crate::response::{
    filter_response_headers, format_imf_fixdate, sanitize_error_body, sanitize_json_body,
    GuestClock, SanitizingSseReader, StreamSlotGuard, StreamUsage,
};
use crate::upstream::{UpstreamClient, UpstreamResponse};

pub const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024 * 1024; // 32 MiB

/// Most agent requests handled at once (one thread each). A request arriving while this many
/// are in flight has its connection closed without a response; nothing of it is read.
pub const MAX_IN_FLIGHT_REQUESTS: usize = 64;

/// Most request-body bytes buffered at once across all in-flight requests. A request whose
/// body would push the total over this gets a 529 `overloaded_error` (not a quota breach).
/// Together with `MAX_IN_FLIGHT_REQUESTS` this bounds the memory agent requests can pin.
pub const MAX_BUFFERED_BODY_BYTES: usize = 3 * MAX_REQUEST_BODY_BYTES;

/// Absolute deadline for a request's line and headers, counted from when the gateway starts
/// waiting for it (so it also bounds the idle time of a kept-alive connection). Past it the
/// connection is closed without a response.
pub const REQUEST_HEAD_DEADLINE: Duration = Duration::from_secs(60);

/// Absolute deadline for a request body, counted from the end of its headers; it also bounds
/// discarding the unread body of a refused request. Past it the request gets a 400.
pub const REQUEST_BODY_DEADLINE: Duration = Duration::from_secs(120);

/// Absolute deadline for writing a whole non-streaming response (or error) to the agent,
/// counted from when writing starts. Enforced by the vendored tiny_http before every socket
/// write; past it the connection is dropped and the handler is freed.
pub const RESPONSE_WRITE_DEADLINE: Duration = Duration::from_secs(120);

/// Minimum-progress rule for streams: every chunk of a stream handed to the writer (at most
/// one SSE event or 8 KiB) must be written within this absolute deadline, so a reader that
/// stops or slows below that pace loses the stream and frees the handler.
pub const STREAM_CHUNK_WRITE_DEADLINE: Duration = Duration::from_secs(30);

/// Overall bound on writing one stream to the agent, counted from when writing starts. The
/// per-chunk renewals never extend past it, so a reader that keeps draining slowly (each chunk
/// within `STREAM_CHUNK_WRITE_DEADLINE`) still frees the handler at this bound. Past it the
/// stream is cut (the agent sees the connection end) and the handler and slot are released.
pub const STREAM_TOTAL_WRITE_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// Renews the connection's write deadline each time a chunk of the stream is handed out,
/// capped at the stream's overall deadline; past the overall deadline it stops the stream.
struct ChunkDeadlineReader<R: Read> {
    inner: R,
    handle: Option<tiny_http::DeadlineHandle>,
    per_chunk: Duration,
    overall_end: std::time::Instant,
}

impl<R: Read> Read for ChunkDeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if std::time::Instant::now() >= self.overall_end {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "stream overall write deadline passed",
            ));
        }
        let n = self.inner.read(buf)?;
        if n > 0 {
            if let Some(h) = self.handle.as_ref() {
                let next = std::time::Instant::now() + self.per_chunk;
                h.set(Some(next.min(self.overall_end)));
            }
        }
        Ok(n)
    }
}

/// Body bytes read (and reserved from the budget) per step.
const BODY_READ_CHUNK: usize = 64 * 1024;

/// Shared budget of buffered request-body bytes.
struct BodyBudget {
    used: Mutex<usize>,
    limit: usize,
}

impl BodyBudget {
    fn try_reserve(&self, bytes: usize) -> bool {
        let mut used = match self.used.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        match used.checked_add(bytes) {
            Some(total) if total <= self.limit => {
                *used = total;
                true
            }
            _ => false,
        }
    }

    fn release(&self, bytes: usize) {
        let mut used = match self.used.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *used = used.saturating_sub(bytes);
    }
}

/// Bytes reserved from the `BodyBudget` by one request; returned on drop.
struct BodyReservation {
    budget: Arc<BodyBudget>,
    bytes: usize,
}

impl BodyReservation {
    fn grow(&mut self, bytes: usize) -> bool {
        if self.budget.try_reserve(bytes) {
            self.bytes = self.bytes.saturating_add(bytes);
            true
        } else {
            false
        }
    }
}

impl Drop for BodyReservation {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

/// Decrements the in-flight request count when a handler thread ends.
struct InFlightSlot(Arc<AtomicUsize>);

impl Drop for InFlightSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Why reading an agent request body stopped early.
enum BodyReadError {
    TooLarge,
    Overloaded,
    Io(std::io::Error),
}

#[derive(Clone)]
pub struct GatewayServer {
    config: Arc<GatewayConfig>,
    clock: GuestClock,
    nonce: RunNonce,
    quota: Arc<QuotaTracker>,
    history: Arc<HistoryLog>,
    logger: Arc<HostLogger>,
    upstream: Arc<UpstreamClient>,
    running: Arc<AtomicBool>,
    /// Guest `Date` used if formatting the current guest time ever fails: the latest guest
    /// instant validated at startup (T_clock + wall-time limit, or T_clock).
    fallback_date: Arc<String>,
    in_flight: Arc<AtomicUsize>,
    max_in_flight: usize,
    body_budget: Arc<BodyBudget>,
    client_deadlines: RequestDeadlines,
    /// (whole non-streaming response, per stream chunk) write deadlines.
    write_deadlines: (Duration, Duration),
    /// Overall bound on writing one stream.
    stream_total_deadline: Duration,
}

impl GatewayServer {
    pub fn new(config: GatewayConfig, t_clock: time::OffsetDateTime) -> Result<Self, String> {
        Self::new_with_clock(config, GuestClock::new(t_clock))
    }

    /// Builds the gateway with a given guest clock (tests use `GuestClock::frozen`).
    ///
    /// Refuses to start unless T_clock and T_clock + the wall-time limit both format as
    /// IMF-fixdate, so every response can carry a guest `Date`.
    pub fn new_with_clock(config: GatewayConfig, clock: GuestClock) -> Result<Self, String> {
        // Validate T_clock is formattable as IMF-fixdate
        let mut fallback_date = format_imf_fixdate(clock.t_clock())
            .map_err(|e| format!("Invalid t_clock: cannot format as IMF-fixdate: {e}"))?;

        // Validate T_clock + configured wall-time limit is formattable as IMF-fixdate
        if let Some(wall_limit) = config.quotas.max_wall_time_seconds {
            let dur = i64::try_from(wall_limit)
                .map(time::Duration::seconds)
                .map_err(|_| {
                    format!("Configured wall-time limit {wall_limit}s exceeds i64 range")
                })?;
            let t_end = clock.t_clock().checked_add(dur).ok_or_else(|| {
                format!("T_clock + wall-time limit ({wall_limit}s) overflows datetime")
            })?;
            fallback_date = format_imf_fixdate(t_end).map_err(|e| {
                format!("Invalid T_clock + wall-time limit: cannot format as IMF-fixdate: {e}")
            })?;
        }
        Header::from_bytes(&b"Date"[..], fallback_date.as_bytes())
            .map_err(|_| "Invalid guest Date header value".to_string())?;

        let config_arc = Arc::new(config);
        let nonce = RunNonce::generate()?;
        // A slot held by a request whose client left is released only when its upstream work
        // ends, which takes at most about the upstream read timeout; wait that long for it.
        let drain_wait = Duration::from_secs(config_arc.upstream_read_timeout_s.saturating_add(10));
        let quota = Arc::new(QuotaTracker::with_drain_wait(
            config_arc.quotas.clone(),
            drain_wait,
        ));
        let history = Arc::new(HistoryLog::new());
        let logger = Arc::new(
            HostLogger::open(
                &config_arc.log_dir,
                vec![config_arc.api_key().to_string()],
                MAX_HOST_LOG_BYTES,
            )
            .map_err(|e| format!("Failed to create host logger: {e}"))?,
        );
        let upstream = Arc::new(UpstreamClient::new(config_arc.clone()));
        let running = Arc::new(AtomicBool::new(true));

        Ok(Self {
            config: config_arc,
            clock,
            nonce,
            quota,
            history,
            logger,
            upstream,
            running,
            fallback_date: Arc::new(fallback_date),
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: MAX_IN_FLIGHT_REQUESTS,
            body_budget: Arc::new(BodyBudget {
                used: Mutex::new(0),
                limit: MAX_BUFFERED_BODY_BYTES,
            }),
            client_deadlines: RequestDeadlines {
                head: Some(REQUEST_HEAD_DEADLINE),
                body: Some(REQUEST_BODY_DEADLINE),
            },
            write_deadlines: (RESPONSE_WRITE_DEADLINE, STREAM_CHUNK_WRITE_DEADLINE),
            stream_total_deadline: STREAM_TOTAL_WRITE_DEADLINE,
        })
    }

    /// Overrides `REQUEST_HEAD_DEADLINE` and `REQUEST_BODY_DEADLINE` (tests use short ones).
    pub fn with_client_deadlines(mut self, head: Duration, body: Duration) -> Self {
        self.client_deadlines = RequestDeadlines {
            head: Some(head),
            body: Some(body),
        };
        self
    }

    /// Overrides `RESPONSE_WRITE_DEADLINE` and `STREAM_CHUNK_WRITE_DEADLINE` (tests).
    pub fn with_response_write_deadlines(
        mut self,
        response: Duration,
        stream_chunk: Duration,
    ) -> Self {
        self.write_deadlines = (response, stream_chunk);
        self
    }

    /// Overrides `STREAM_TOTAL_WRITE_DEADLINE` (tests).
    pub fn with_stream_total_deadline(mut self, total: Duration) -> Self {
        self.stream_total_deadline = total;
        self
    }

    /// Overrides how long a request waits for a slot held by a draining request (tests).
    pub fn with_drain_wait(mut self, wait: Duration) -> Self {
        self.quota = Arc::new(QuotaTracker::with_drain_wait(
            self.config.quotas.clone(),
            wait,
        ));
        self
    }

    /// Reopens the host log with a budget of `bytes` instead of `MAX_HOST_LOG_BYTES`.
    pub fn with_host_log_budget(mut self, bytes: u64) -> Result<Self, String> {
        self.logger = Arc::new(
            HostLogger::open(
                &self.config.log_dir,
                vec![self.config.api_key().to_string()],
                bytes,
            )
            .map_err(|e| format!("Failed to create host logger: {e}"))?,
        );
        Ok(self)
    }

    /// Writes a host-log entry. When the log can no longer be written (its budget is used up
    /// or the file failed), the gateway enters the terminal limit_exceeded state: it must not
    /// keep serving requests it can no longer record.
    fn log_entry(&self, entry: &HostLogEntry) {
        if !self.logger.log(entry) {
            self.quota
                .trigger_limit_exceeded("host log cannot be written".to_string());
        }
    }

    /// Time left under the wall-time quota, if one is configured.
    fn wall_time_left(&self) -> Option<Duration> {
        let limit = self.config.quotas.max_wall_time_seconds?;
        let elapsed = self.clock.elapsed_secs();
        Some(Duration::from_secs(limit.saturating_sub(elapsed).max(1)))
    }

    /// Makes sure `headers` carries exactly one `Date`, holding guest time. The HTTP layer
    /// (vendored tiny_http) never adds a Date of its own, so every response must get it here.
    fn ensure_date_header(&self, headers: &mut Vec<Header>) {
        if headers.iter().any(|h| h.field.equiv("Date")) {
            return;
        }
        let date_str = self
            .clock
            .format_imf_fixdate()
            .unwrap_or_else(|_| self.fallback_date.as_str().to_string());
        let header = Header::from_bytes(&b"Date"[..], date_str.as_bytes())
            .or_else(|_| Header::from_bytes(&b"Date"[..], self.fallback_date.as_bytes()));
        // The fallback was validated as a header value at startup, so this always succeeds.
        if let Ok(h) = header {
            headers.push(h);
        }
    }

    pub fn nonce(&self) -> &RunNonce {
        &self.nonce
    }

    pub fn quota(&self) -> &QuotaTracker {
        &self.quota
    }

    pub fn history(&self) -> &HistoryLog {
        &self.history
    }

    pub fn clock(&self) -> &GuestClock {
        &self.clock
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Overrides `MAX_IN_FLIGHT_REQUESTS` and `MAX_BUFFERED_BODY_BYTES` (tests use small
    /// values so the caps can be exercised without large memory use). Call before serving.
    pub fn with_request_limits(
        mut self,
        max_in_flight: usize,
        max_buffered_body_bytes: usize,
    ) -> Self {
        self.max_in_flight = max_in_flight;
        self.body_budget = Arc::new(BodyBudget {
            used: Mutex::new(0),
            limit: max_buffered_body_bytes,
        });
        self
    }

    /// Number of agent requests currently being handled.
    pub fn in_flight_requests(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Request-body bytes currently buffered across all in-flight requests.
    pub fn buffered_body_bytes(&self) -> usize {
        match self.body_budget.used.lock() {
            Ok(g) => *g,
            Err(p) => *p.into_inner(),
        }
    }

    pub fn run_loop(&self, server: Server) {
        server.set_request_deadlines(self.client_deadlines);
        while self.running.load(Ordering::SeqCst) {
            // Use recv_timeout so the loop can check running flag
            match server.recv_timeout(Duration::from_millis(200)) {
                Ok(Some(request)) => {
                    if self.in_flight.fetch_add(1, Ordering::AcqRel) >= self.max_in_flight {
                        self.in_flight.fetch_sub(1, Ordering::AcqRel);
                        // Over the cap: close without reading or answering (no thread, no
                        // memory). A reply here would need a thread to write it.
                        request.close_without_response();
                        continue;
                    }
                    let slot = InFlightSlot(self.in_flight.clone());
                    let server_clone = self.clone();
                    // If the thread cannot be spawned the closure is dropped: the slot is
                    // returned and the request's connection is closed without a response.
                    let _ = std::thread::Builder::new()
                        .name("gateway-request".to_string())
                        .spawn(move || {
                            let _slot = slot;
                            server_clone.handle_agent_request(request);
                        });
                }
                Ok(None) => {}
                Err(_) => {
                    break;
                }
            }
        }
    }

    fn respond_with_error(
        &self,
        request: Request,
        status: u16,
        err_type: &str,
        message: &str,
        endpoint: &str,
    ) {
        let (resp_msg, log_msg) = if err_type == API_ERROR {
            (standard_message_for_type(API_ERROR), message)
        } else {
            (message, message)
        };
        let resp_body = AnthropicErrorResponse::new(err_type, resp_msg).to_json_string();
        let body_bytes = resp_body.into_bytes();
        let body_len = body_bytes.len();

        let mut headers = Vec::new();
        if let Ok(h) = Header::from_bytes(
            &b"Content-Type"[..],
            &b"application/json; charset=utf-8"[..],
        ) {
            headers.push(h);
        }
        self.ensure_date_header(&mut headers);
        let response = Response::new(
            status.into(),
            headers,
            Cursor::new(body_bytes),
            Some(body_len),
            None,
        );

        self.log_entry(&HostLogEntry {
            timestamp: self
                .clock
                .now()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            adapter_version: ANTHROPIC_ADAPTER_VERSION.to_string(),
            endpoint: endpoint.to_string(),
            model: None,
            stream: false,
            client_status: status,
            upstream_status: None,
            dropped_headers: BTreeMap::new(),
            original_error_body: Some(log_msg.to_string()),
            history_rewrite: false,
            history_rewrites_total: self.history.rewrites_total(),
            quotas: self.quota.snapshot(),
        });

        self.arm_write_deadline(&request, self.write_deadlines.0);
        let _ = request.respond(response);
    }

    /// Arms the absolute write deadline for the response about to be written.
    fn arm_write_deadline(&self, request: &Request, d: Duration) {
        if let Some(h) = request.write_deadline() {
            h.set(Some(std::time::Instant::now() + d));
        }
    }

    pub fn handle_agent_request(&self, mut request: Request) {
        let peer = request.try_clone_peer_tcp_stream();
        let method = request.method().clone();
        let url = request.url().to_string();

        // Strip any query string
        let endpoint = url.split('?').next().unwrap_or("").to_string();

        // 1. Endpoint validation: POST /v1/messages or POST /v1/messages/count_tokens only
        if method != Method::Post
            || (endpoint != "/v1/messages" && endpoint != "/v1/messages/count_tokens")
        {
            self.respond_with_error(
                request,
                404,
                NOT_FOUND_ERROR,
                &format!("Endpoint '{endpoint}' not found"),
                &endpoint,
            );
            return;
        }

        // 2. Headers from agent validation:
        // - anthropic-version: must equal configured value
        // - anthropic-beta: each comma-separated flag must be in allowed_betas
        // - content-type: application/json
        // - all other headers dropped, agent's x-api-key ignored
        let mut client_anthropic_version: Option<String> = None;
        let mut client_anthropic_beta: Option<String> = None;
        let mut client_content_type: Option<String> = None;

        for h in request.headers() {
            let name = h.field.as_str().as_str();
            let value = h.value.as_str();
            if name.eq_ignore_ascii_case("anthropic-version") {
                client_anthropic_version = Some(value.trim().to_string());
            } else if name.eq_ignore_ascii_case("anthropic-beta") {
                client_anthropic_beta = Some(value.trim().to_string());
            } else if name.eq_ignore_ascii_case("content-type") {
                client_content_type = Some(value.trim().to_string());
            }
        }

        let version = match client_anthropic_version {
            Some(v) => v,
            None => {
                self.respond_with_error(
                    request,
                    400,
                    INVALID_REQUEST_ERROR,
                    "Missing required header: anthropic-version",
                    &endpoint,
                );
                return;
            }
        };

        if version != self.config.anthropic_version {
            self.respond_with_error(
                request,
                400,
                INVALID_REQUEST_ERROR,
                &format!(
                    "Invalid anthropic-version: got '{}', expected '{}'",
                    version, self.config.anthropic_version
                ),
                &endpoint,
            );
            return;
        }

        if let Some(ref beta_val) = client_anthropic_beta {
            for flag in beta_val.split(',') {
                let trimmed = flag.trim();
                if !trimmed.is_empty() && !self.config.allowed_betas.iter().any(|b| b == trimmed) {
                    self.respond_with_error(
                        request,
                        400,
                        INVALID_REQUEST_ERROR,
                        &format!("Unlisted anthropic-beta flag: '{trimmed}'"),
                        &endpoint,
                    );
                    return;
                }
            }
        }

        let content_type = client_content_type.unwrap_or_default();
        let ct_lower = content_type.to_lowercase();
        if !ct_lower.starts_with("application/json") {
            self.respond_with_error(
                request,
                400,
                INVALID_REQUEST_ERROR,
                &format!("Content-Type must be application/json, got '{content_type}'"),
                &endpoint,
            );
            return;
        }

        // 3. Once the gateway is in the terminal limit_exceeded state every request is refused:
        // do it before reading (and buffering) the body.
        if self.quota.is_limit_exceeded() {
            let reason = self
                .quota
                .snapshot()
                .limit_exceeded_reason
                .unwrap_or_else(|| "limit_exceeded".to_string());
            self.respond_with_error(
                request,
                429,
                RATE_LIMIT_ERROR,
                &format!("Limit exceeded: {reason}"),
                &endpoint,
            );
            return;
        }

        // 4. Read body bytes: at most 32 MiB per request, and only while the shared body budget
        // allows (checked per chunk, before the bytes are buffered).
        if let Some(len) = request.body_length() {
            if len > MAX_REQUEST_BODY_BYTES {
                self.respond_with_error(
                    request,
                    413,
                    REQUEST_TOO_LARGE,
                    "Request body exceeds 32 MiB limit",
                    &endpoint,
                );
                return;
            }
        }

        let mut reservation = BodyReservation {
            budget: self.body_budget.clone(),
            bytes: 0,
        };
        // The vendored tiny_http enforces REQUEST_BODY_DEADLINE on these reads.
        let body_result = read_body_bounded(request.as_reader(), &mut reservation);
        let body_bytes = match body_result {
            Ok(b) => b,
            Err(BodyReadError::TooLarge) => {
                self.respond_with_error(
                    request,
                    413,
                    REQUEST_TOO_LARGE,
                    "Request body exceeds 32 MiB limit",
                    &endpoint,
                );
                return;
            }
            Err(BodyReadError::Overloaded) => {
                self.respond_with_error(
                    request,
                    529,
                    OVERLOADED_ERROR,
                    standard_message_for_type(OVERLOADED_ERROR),
                    &endpoint,
                );
                return;
            }
            Err(BodyReadError::Io(e)) => {
                self.respond_with_error(
                    request,
                    400,
                    INVALID_REQUEST_ERROR,
                    &format!("Failed to read request body: {e}"),
                    &endpoint,
                );
                return;
            }
        };

        // 4b. Validate UTF-8
        let body_str = match std::str::from_utf8(&body_bytes) {
            Ok(s) => s,
            Err(_) => {
                self.respond_with_error(
                    request,
                    400,
                    INVALID_REQUEST_ERROR,
                    "Request body contains invalid UTF-8",
                    &endpoint,
                );
                return;
            }
        };

        // 5. Parse and validate Anthropic request struct
        let mut parsed_req = match parse_and_validate_request(body_str, &self.config.pinned_models)
        {
            Ok(r) => r,
            Err(e) => {
                self.respond_with_error(
                    request,
                    e.status_code(),
                    e.error_type(),
                    &e.to_string(),
                    &endpoint,
                );
                return;
            }
        };

        // 6. Check quotas before request
        if let Err(breach) = self.quota.check_and_acquire(self.clock.elapsed_secs()) {
            if breach == QuotaBreach::Busy {
                self.respond_with_error(
                    request,
                    529,
                    OVERLOADED_ERROR,
                    standard_message_for_type(OVERLOADED_ERROR),
                    &endpoint,
                );
            } else {
                self.respond_with_error(
                    request,
                    429,
                    RATE_LIMIT_ERROR,
                    &format!("Limit exceeded: {}", breach.reason()),
                    &endpoint,
                );
            }
            return;
        }

        // The slot is now held. Every path below releases it through `slot` (exactly once,
        // also on drop) when the upstream work has ended; a client that closes its side first
        // only marks it draining (see `watch_disconnect`).
        let slot = Arc::new(StreamSlotGuard::new(
            self.quota.clone(),
            Arc::new(Mutex::new(StreamUsage::default())),
        ));
        spawn_disconnect_watcher(peer, &slot);

        // 7. Inject Run Nonce into system prompt
        parsed_req.inject_nonce(&self.nonce);

        // 8. Rebuild JSON upstream
        let rebuilt_json = match parsed_req.rebuild_json() {
            Ok(j) => j,
            Err(e) => {
                let _ = slot.record_and_release();
                self.respond_with_error(
                    request,
                    400,
                    INVALID_REQUEST_ERROR,
                    &format!("Failed to serialize request: {e}"),
                    &endpoint,
                );
                return;
            }
        };

        // 9. History-consistency check
        let system_canonical = match &parsed_req.system {
            Some(s) => serde_json::to_vec(s).unwrap_or_default(),
            None => Vec::new(),
        };
        let messages_canonical: Vec<Vec<u8>> = parsed_req
            .messages
            .iter()
            .map(|m| serde_json::to_vec(m).unwrap_or_default())
            .collect();

        let (is_rewrite, total_rewrites) = self
            .history
            .check_and_record(&system_canonical, &messages_canonical);

        // 10. Call Upstream
        let is_stream = parsed_req.stream == Some(true) && endpoint == "/v1/messages";
        let upstream_res = self.upstream.send_request(
            &endpoint,
            &rebuilt_json,
            client_anthropic_beta.as_deref(),
            is_stream,
            self.wall_time_left(),
        );

        match upstream_res {
            Ok(UpstreamResponse::Body {
                status,
                headers,
                body: upstream_body,
            }) => {
                let filtered = match filter_response_headers(&headers, &self.clock) {
                    Ok(f) => f,
                    Err(e) => {
                        let _ = slot.record_and_release();
                        self.respond_with_error(
                            request,
                            e.status_code(),
                            e.error_type(),
                            &e.to_string(),
                            &endpoint,
                        );
                        return;
                    }
                };

                if !(200..300).contains(&status) {
                    // Non-2xx upstream error: sanitize body, preserve an error status (a 1xx
                    // or 3xx, which is no error the agent could act on, becomes 502).
                    let _ = slot.record_and_release();
                    let status = if status < 400 { 502 } else { status };
                    let (sanitized_body, _) = sanitize_error_body(status, &upstream_body);
                    let body_bytes = sanitized_body.into_bytes();
                    let body_len = body_bytes.len();

                    let mut resp_headers = Vec::new();
                    if let Ok(h) = Header::from_bytes(
                        &b"Content-Type"[..],
                        &b"application/json; charset=utf-8"[..],
                    ) {
                        resp_headers.push(h);
                    }

                    for (k, v) in &filtered.agent_headers {
                        let k_lower = k.to_lowercase();
                        if k_lower != "content-type"
                            && k_lower != "content-length"
                            && k_lower != "content-encoding"
                        {
                            if let Ok(h) = Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                                resp_headers.push(h);
                            }
                        }
                    }
                    self.ensure_date_header(&mut resp_headers);

                    let resp = Response::new(
                        status.into(),
                        resp_headers,
                        Cursor::new(body_bytes),
                        Some(body_len),
                        None,
                    );

                    self.log_entry(&HostLogEntry {
                        timestamp: self
                            .clock
                            .now()
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default(),
                        adapter_version: ANTHROPIC_ADAPTER_VERSION.to_string(),
                        endpoint,
                        model: Some(parsed_req.model.clone()),
                        stream: false,
                        client_status: status,
                        upstream_status: Some(status),
                        dropped_headers: filtered.dropped_headers,
                        original_error_body: Some(upstream_body),
                        history_rewrite: is_rewrite,
                        history_rewrites_total: total_rewrites,
                        quotas: self.quota.snapshot(),
                    });

                    self.arm_write_deadline(&request, self.write_deadlines.0);
                    let _ = request.respond(resp);
                } else {
                    // 2xx upstream response: fail-closed sanitisation. A body that is not one
                    // JSON object serde accepts is never forwarded.
                    let Some((final_body, usage)) = sanitize_json_body(&upstream_body, &self.clock)
                    else {
                        let _ = slot.record_and_release();
                        self.respond_with_error(
                            request,
                            502,
                            API_ERROR,
                            "Upstream 2xx body is not a JSON object",
                            &endpoint,
                        );
                        return;
                    };

                    slot.set_usage(usage.input_tokens, usage.output_tokens);
                    if let Err(breach) = slot.record_and_release() {
                        // This response crossed a hard token cap: it is not delivered.
                        self.respond_with_error(
                            request,
                            429,
                            RATE_LIMIT_ERROR,
                            &format!("Limit exceeded: {}", breach.reason()),
                            &endpoint,
                        );
                        return;
                    }

                    let body_bytes = final_body.into_bytes();
                    let body_len = body_bytes.len();

                    let mut resp_headers = Vec::new();
                    for (k, v) in &filtered.agent_headers {
                        if !k.eq_ignore_ascii_case("content-length") {
                            if let Ok(h) = Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                                resp_headers.push(h);
                            }
                        }
                    }
                    self.ensure_date_header(&mut resp_headers);

                    let resp = Response::new(
                        status.into(),
                        resp_headers,
                        Cursor::new(body_bytes),
                        Some(body_len),
                        None,
                    );

                    self.log_entry(&HostLogEntry {
                        timestamp: self
                            .clock
                            .now()
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default(),
                        adapter_version: ANTHROPIC_ADAPTER_VERSION.to_string(),
                        endpoint,
                        model: Some(parsed_req.model.clone()),
                        stream: false,
                        client_status: status,
                        upstream_status: Some(status),
                        dropped_headers: filtered.dropped_headers,
                        original_error_body: None,
                        history_rewrite: is_rewrite,
                        history_rewrites_total: total_rewrites,
                        quotas: self.quota.snapshot(),
                    });

                    self.arm_write_deadline(&request, self.write_deadlines.0);
                    let _ = request.respond(resp);
                }
            }
            Ok(UpstreamResponse::Stream {
                status,
                headers,
                reader,
            }) => {
                let filtered = match filter_response_headers(&headers, &self.clock) {
                    Ok(f) => f,
                    Err(e) => {
                        let _ = slot.record_and_release();
                        self.respond_with_error(
                            request,
                            e.status_code(),
                            e.error_type(),
                            &e.to_string(),
                            &endpoint,
                        );
                        return;
                    }
                };

                // The stream reader records the streamed usage into `slot` and stops at its next
                // read once the disconnect watcher has cancelled `slot`.
                let sse_reader = SanitizingSseReader::with_slot_guard(
                    reader,
                    self.clock.clone(),
                    slot.usage_handle(),
                    slot.clone(),
                );

                let mut resp_headers = Vec::new();
                for (k, v) in &filtered.agent_headers {
                    if !k.eq_ignore_ascii_case("content-length") {
                        if let Ok(h) = Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                            resp_headers.push(h);
                        }
                    }
                }
                self.ensure_date_header(&mut resp_headers);

                let overall_end = std::time::Instant::now() + self.stream_total_deadline;
                let sse_reader = ChunkDeadlineReader {
                    inner: sse_reader,
                    handle: request.write_deadline(),
                    per_chunk: self.write_deadlines.1,
                    overall_end,
                };
                let tiny_response =
                    Response::new(status.into(), resp_headers, sse_reader, None, None);

                if let Some(h) = request.write_deadline() {
                    let first = std::time::Instant::now() + self.write_deadlines.1;
                    h.set(Some(first.min(overall_end)));
                }
                let _ = request.respond(tiny_response);
                let _ = slot.record_and_release();

                self.log_entry(&HostLogEntry {
                    timestamp: self
                        .clock
                        .now()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                    adapter_version: ANTHROPIC_ADAPTER_VERSION.to_string(),
                    endpoint,
                    model: Some(parsed_req.model.clone()),
                    stream: true,
                    client_status: status,
                    upstream_status: Some(status),
                    dropped_headers: filtered.dropped_headers,
                    original_error_body: None,
                    history_rewrite: is_rewrite,
                    history_rewrites_total: total_rewrites,
                    quotas: self.quota.snapshot(),
                });
            }
            Err(e) => {
                let _ = slot.record_and_release();
                // The upstream deadline is the time left under the wall-time quota: if that is
                // what ended the call, this is the wall-time breach, not an upstream failure.
                if let Err(breach) = self.quota.check_live(0, 0, self.clock.elapsed_secs()) {
                    self.respond_with_error(
                        request,
                        429,
                        RATE_LIMIT_ERROR,
                        &format!("Limit exceeded: {}", breach.reason()),
                        &endpoint,
                    );
                    return;
                }
                self.respond_with_error(
                    request,
                    e.status_code(),
                    e.error_type(),
                    &e.to_string(),
                    &endpoint,
                );
            }
        }
    }
}

/// Reads an agent request body: at most `MAX_REQUEST_BODY_BYTES`, reserving every chunk from
/// the shared body budget before buffering it.
fn read_body_bounded(
    reader: &mut dyn Read,
    reservation: &mut BodyReservation,
) -> Result<Vec<u8>, BodyReadError> {
    let mut body = Vec::new();
    let mut chunk = vec![0u8; BODY_READ_CHUNK];
    loop {
        let n = match reader.read(&mut chunk) {
            Ok(0) => return Ok(body),
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(BodyReadError::Io(e)),
        };
        if body.len().saturating_add(n) > MAX_REQUEST_BODY_BYTES {
            return Err(BodyReadError::TooLarge);
        }
        if !reservation.grow(n) {
            return Err(BodyReadError::Overloaded);
        }
        let Some(read) = chunk.get(..n) else {
            return Err(BodyReadError::Io(std::io::Error::new(
                ErrorKind::InvalidData,
                "reader reported more bytes than its buffer",
            )));
        };
        body.extend_from_slice(read);
    }
}

/// Starts a thread that watches the agent's connection while its request is in flight.
///
/// While a request waits on upstream (before or during a stream), the gateway neither reads
/// nor writes the agent's socket. The watcher blocks in `TcpStream::peek`, which consumes
/// nothing:
///
/// - `Ok(0)`: the client closed its sending side. That is either a half-close (it may still be
///   reading the response) or the first half of an abandonment; the two look the same until a
///   write fails. The slot is only marked *draining* (`mark_client_closed`): it stays held, so
///   upstream concurrency never exceeds the limit, but a request waiting for a slot now waits
///   for it to be released instead of counting a concurrency breach. The watcher keeps
///   watching for a reset.
/// - a reset (`ConnectionReset`, `BrokenPipe`, ...): the client is certainly gone.
///   `slot.cancel()` also makes a stream stop at its next upstream event, which drops the
///   upstream connection and then releases the slot.
/// - data (`Ok(n > 0)`, e.g. the next request on a keep-alive connection): the watcher stops.
/// - a read timeout (set on the shared socket once tiny_http waits for the next request, which
///   only happens after this request has ended): the watcher stops once the slot is released.
///
/// The slot itself is always released by the request's own thread when its upstream work ends
/// (`StreamSlotGuard::record_and_release`). The watcher holds only a weak reference and ends
/// when the connection does or the next request starts; connections are capped by tiny_http's
/// `MAX_CONNECTIONS`. If no socket handle or thread is available, no watcher runs.
fn spawn_disconnect_watcher(stream: Option<TcpStream>, slot: &Arc<StreamSlotGuard>) {
    let Some(stream) = stream else {
        return;
    };
    let weak = Arc::downgrade(slot);
    let _ = std::thread::Builder::new()
        .name("gateway-disconnect-watch".to_string())
        .spawn(move || watch_disconnect(stream, weak));
}

fn watch_disconnect(stream: TcpStream, slot: Weak<StreamSlotGuard>) {
    let mut probe = [0u8; 1];
    let mut closed_seen = false;
    loop {
        match stream.peek(&mut probe) {
            Ok(0) => {
                let Some(s) = slot.upgrade() else { return };
                if s.is_slot_released() {
                    return;
                }
                if !closed_seen {
                    closed_seen = true;
                    s.mark_client_closed();
                }
                // After a FIN, peek returns 0 at once; poll gently for a reset or the end.
                drop(s);
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(_) => return,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                        | ErrorKind::NotConnected
                ) =>
            {
                if let Some(s) = slot.upgrade() {
                    s.cancel();
                }
                return;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                match slot.upgrade() {
                    Some(s) if !s.is_slot_released() => continue,
                    _ => return,
                }
            }
            Err(_) => return,
        }
    }
}
