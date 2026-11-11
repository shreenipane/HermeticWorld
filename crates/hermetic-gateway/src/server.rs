#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server};

use crate::anthropic::{parse_and_validate_request, ANTHROPIC_ADAPTER_VERSION};
use crate::config::GatewayConfig;
use crate::error::{
    standard_message_for_type, AnthropicErrorResponse, API_ERROR, INVALID_REQUEST_ERROR,
    NOT_FOUND_ERROR, RATE_LIMIT_ERROR, REQUEST_TOO_LARGE,
};
use crate::history::HistoryLog;
use crate::log::{HostLogEntry, HostLogger};
use crate::nonce::RunNonce;
use crate::quota::QuotaTracker;
use crate::response::{
    filter_response_headers, rewrite_json_timestamps, sanitize_error_body, GuestClock,
    SanitizingSseReader, StreamSlotGuard, StreamUsage,
};
use crate::upstream::{UpstreamClient, UpstreamResponse};

pub const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024 * 1024; // 32 MiB

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
}

impl GatewayServer {
    pub fn new(config: GatewayConfig, t_clock: time::OffsetDateTime) -> Result<Self, String> {
        let config_arc = Arc::new(config);
        let clock = GuestClock::new(t_clock);
        let nonce = RunNonce::generate()?;
        let quota = Arc::new(QuotaTracker::new(config_arc.quotas.clone()));
        let history = Arc::new(HistoryLog::new());
        let logger = Arc::new(
            HostLogger::new(&config_arc.log_dir)
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
        })
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

    pub fn run_loop(&self, server: Server) {
        while self.running.load(Ordering::SeqCst) {
            // Use recv_timeout so the loop can check running flag
            match server.recv_timeout(Duration::from_millis(200)) {
                Ok(Some(request)) => {
                    let server_clone = self.clone();
                    std::thread::spawn(move || {
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
        if let Ok(date_hdr) = self.clock.format_imf_fixdate() {
            if let Ok(h) = Header::from_bytes(&b"Date"[..], date_hdr.as_bytes()) {
                headers.push(h);
            }
        }
        let response = Response::new(
            status.into(),
            headers,
            Cursor::new(body_bytes),
            Some(body_len),
            None,
        );

        self.logger.log(&HostLogEntry {
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

        let _ = request.respond(response);
    }

    pub fn handle_agent_request(&self, mut request: Request) {
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

        // 3. Read body bytes (cap 32 MiB)
        let declared_len = request.body_length();
        if let Some(len) = declared_len {
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

        let mut body_bytes = Vec::new();
        let mut reader = request
            .as_reader()
            .take((MAX_REQUEST_BODY_BYTES + 1) as u64);
        if let Err(e) = reader.read_to_end(&mut body_bytes) {
            self.respond_with_error(
                request,
                400,
                INVALID_REQUEST_ERROR,
                &format!("Failed to read request body: {e}"),
                &endpoint,
            );
            return;
        }

        if body_bytes.len() > MAX_REQUEST_BODY_BYTES {
            self.respond_with_error(
                request,
                413,
                REQUEST_TOO_LARGE,
                "Request body exceeds 32 MiB limit",
                &endpoint,
            );
            return;
        }

        // 4. Validate UTF-8
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
            self.respond_with_error(
                request,
                429,
                RATE_LIMIT_ERROR,
                &format!("Limit exceeded: {}", breach.reason()),
                &endpoint,
            );
            return;
        }

        // 7. Inject Run Nonce into system prompt
        parsed_req.inject_nonce(&self.nonce);

        // 8. Rebuild JSON upstream
        let rebuilt_json = match parsed_req.rebuild_json() {
            Ok(j) => j,
            Err(e) => {
                self.quota.release_concurrent();
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
                        self.quota.release_concurrent();
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
                    // Non-2xx upstream error: sanitize body, preserve status
                    self.quota.release_concurrent();
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

                    let resp = Response::new(
                        status.into(),
                        resp_headers,
                        Cursor::new(body_bytes),
                        Some(body_len),
                        None,
                    );

                    self.logger.log(&HostLogEntry {
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

                    let _ = request.respond(resp);
                } else {
                    // 2xx upstream response: rewrite body timestamps
                    let mut input_tokens = 0u64;
                    let mut output_tokens = 0u64;

                    let final_body = if let Ok(mut json_val) =
                        serde_json::from_str::<serde_json::Value>(&upstream_body)
                    {
                        rewrite_json_timestamps(&mut json_val, &self.clock);
                        if let Some(usage_obj) = json_val.get("usage").and_then(|u| u.as_object()) {
                            if let Some(in_t) =
                                usage_obj.get("input_tokens").and_then(|t| t.as_u64())
                            {
                                input_tokens = in_t;
                            }
                            if let Some(out_t) =
                                usage_obj.get("output_tokens").and_then(|t| t.as_u64())
                            {
                                output_tokens = out_t;
                            }
                        }
                        serde_json::to_string(&json_val).unwrap_or(upstream_body)
                    } else {
                        upstream_body
                    };

                    let _ = self
                        .quota
                        .record_usage_and_release(input_tokens, output_tokens);

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

                    let resp = Response::new(
                        status.into(),
                        resp_headers,
                        Cursor::new(body_bytes),
                        Some(body_len),
                        None,
                    );

                    self.logger.log(&HostLogEntry {
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
                        self.quota.release_concurrent();
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

                let shared_usage = Arc::new(Mutex::new(StreamUsage::default()));
                let slot_guard = Arc::new(StreamSlotGuard::new(
                    self.quota.clone(),
                    shared_usage.clone(),
                ));

                let sse_reader = SanitizingSseReader::with_slot_guard(
                    reader,
                    self.clock.clone(),
                    shared_usage,
                    slot_guard.clone(),
                );

                let mut resp_headers = Vec::new();
                for (k, v) in &filtered.agent_headers {
                    if !k.eq_ignore_ascii_case("content-length") {
                        if let Ok(h) = Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                            resp_headers.push(h);
                        }
                    }
                }

                let tiny_response =
                    Response::new(status.into(), resp_headers, sse_reader, None, None);

                let _ = request.respond(tiny_response);
                slot_guard.record_and_release();

                self.logger.log(&HostLogEntry {
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
                self.quota.release_concurrent();
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
