#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::error::{
    is_recognised_error_type, AnthropicErrorResponse, DateFormatError, GatewayError, API_ERROR,
    AUTHENTICATION_ERROR, INVALID_REQUEST_ERROR, NOT_FOUND_ERROR, OVERLOADED_ERROR,
    PERMISSION_ERROR, RATE_LIMIT_ERROR, REQUEST_TOO_LARGE,
};
use crate::quota::{QuotaBreach, QuotaTracker};

#[derive(Debug, Clone)]
pub struct GuestClock {
    t_clock: OffsetDateTime,
    start_instant: Instant,
    frozen_elapsed: Option<std::time::Duration>,
}

impl GuestClock {
    pub fn new(t_clock: OffsetDateTime) -> Self {
        Self {
            t_clock,
            start_instant: Instant::now(),
            frozen_elapsed: None,
        }
    }

    /// Test constructor with frozen elapsed time.
    pub fn frozen(t_clock: OffsetDateTime, elapsed: std::time::Duration) -> Self {
        Self {
            t_clock,
            start_instant: Instant::now(),
            frozen_elapsed: Some(elapsed),
        }
    }

    pub fn t_clock(&self) -> OffsetDateTime {
        self.t_clock
    }

    pub fn now(&self) -> OffsetDateTime {
        let elapsed = self
            .frozen_elapsed
            .unwrap_or_else(|| self.start_instant.elapsed());
        let seconds = elapsed.as_secs();
        let nanos = elapsed.subsec_nanos();
        let dur = Duration::new(seconds as i64, nanos as i32);
        self.t_clock.saturating_add(dur)
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.frozen_elapsed
            .map(|d| d.as_secs())
            .unwrap_or_else(|| self.start_instant.elapsed().as_secs())
    }

    /// Formats guest time in IMF-fixdate format (RFC 7231 / RFC 9110):
    /// `Sun, 06 Nov 1994 08:49:37 GMT`
    pub fn format_imf_fixdate(&self) -> Result<String, DateFormatError> {
        format_imf_fixdate(self.now())
    }
}

pub fn format_imf_fixdate(dt: OffsetDateTime) -> Result<String, DateFormatError> {
    let utc_dt = dt
        .checked_to_offset(time::UtcOffset::UTC)
        .ok_or(DateFormatError)?;

    if !(0..=9999).contains(&utc_dt.year()) {
        return Err(DateFormatError);
    }

    let weekday = match utc_dt.weekday() {
        time::Weekday::Monday => "Mon",
        time::Weekday::Tuesday => "Tue",
        time::Weekday::Wednesday => "Wed",
        time::Weekday::Thursday => "Thu",
        time::Weekday::Friday => "Fri",
        time::Weekday::Saturday => "Sat",
        time::Weekday::Sunday => "Sun",
    };
    let month = match utc_dt.month() {
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
        utc_dt.day(),
        month,
        utc_dt.year(),
        utc_dt.hour(),
        utc_dt.minute(),
        utc_dt.second()
    ))
}

/// Parse an HTTP-date (IMF-fixdate) or RFC 3339 string into OffsetDateTime.
pub fn parse_date_or_rfc3339(s: &str) -> Option<OffsetDateTime> {
    let trimmed = s.trim();

    // Try RFC 3339 first
    if let Ok(dt) = OffsetDateTime::parse(trimmed, &Rfc3339) {
        return Some(dt);
    }

    // Try parsing IMF-fixdate: "Wed, 21 Oct 2026 07:28:00 GMT"
    parse_imf_fixdate(trimmed)
}

fn parse_imf_fixdate(s: &str) -> Option<OffsetDateTime> {
    // Example: "Wed, 21 Oct 2026 07:28:00 GMT"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    let day: u8 = parts.get(1)?.parse().ok()?;
    let month_str = *parts.get(2)?;
    let year: i32 = parts.get(3)?.parse().ok()?;
    let time_parts: Vec<&str> = parts.get(4)?.split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: u8 = time_parts.first()?.parse().ok()?;
    let min: u8 = time_parts.get(1)?.parse().ok()?;
    let sec: u8 = time_parts.get(2)?.parse().ok()?;

    let month = match month_str {
        "Jan" => time::Month::January,
        "Feb" => time::Month::February,
        "Mar" => time::Month::March,
        "Apr" => time::Month::April,
        "May" => time::Month::May,
        "Jun" => time::Month::June,
        "Jul" => time::Month::July,
        "Aug" => time::Month::August,
        "Sep" => time::Month::September,
        "Oct" => time::Month::October,
        "Nov" => time::Month::November,
        "Dec" => time::Month::December,
        _ => return None,
    };

    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let time = time::Time::from_hms(hour, min, sec).ok()?;
    Some(date.with_time(time).assume_utc())
}

/// Longest `Retry-After` delay forwarded to the agent, in seconds.
pub const MAX_RETRY_AFTER_SECS: u64 = 24 * 60 * 60;

/// `Retry-After` sent to the agent when upstream gives an absolute date that cannot be turned
/// into a delay safely (no parseable upstream `Date` to measure it against).
pub const FALLBACK_RETRY_AFTER_SECS: u64 = 60;

/// Converts a `Retry-After` header value to integer seconds.
///
/// - An integer seconds value is kept (capped at `MAX_RETRY_AFTER_SECS`).
/// - An HTTP-date or RFC 3339 value is converted to a delay measured against upstream's own
///   `Date` header only (rounded up, clamped to `0..=MAX_RETRY_AFTER_SECS`). Both instants come
///   from upstream's clock, so their difference reveals nothing about the real date.
/// - If upstream sent no parseable `Date`, the absolute value is never compared with guest or
///   host time (either would leak the real date through `guest_now + Retry-After`); the fixed
///   `FALLBACK_RETRY_AFTER_SECS` is used instead.
/// - Anything else becomes `0`.
pub fn convert_retry_after(retry_after_raw: &str, upstream_date_header: Option<&str>) -> String {
    let trimmed = retry_after_raw.trim();

    // Check if integer seconds
    if let Ok(secs) = trimmed.parse::<u64>() {
        return secs.min(MAX_RETRY_AFTER_SECS).to_string();
    }

    // Try parsing as timestamp
    if let Some(target_dt) = parse_date_or_rfc3339(trimmed) {
        let Some(base_dt) = upstream_date_header.and_then(parse_date_or_rfc3339) else {
            return FALLBACK_RETRY_AFTER_SECS.to_string();
        };

        let diff = target_dt - base_dt;
        let mut whole_secs = diff.whole_seconds();
        if diff.subsec_nanoseconds() > 0 {
            whole_secs = whole_secs.saturating_add(1);
        }
        let final_secs = u64::try_from(whole_secs).unwrap_or(0);
        return final_secs.min(MAX_RETRY_AFTER_SECS).to_string();
    }

    "0".to_string()
}

pub struct FilteredHeaders {
    /// Headers to forward to the agent: (name, value)
    pub agent_headers: Vec<(String, String)>,
    /// Headers dropped from upstream for host logging: (name, value)
    pub dropped_headers: BTreeMap<String, String>,
}

/// Filter response headers: only content-type, content-length, content-encoding, and retry-after.
/// Date is replaced with guest time. All other headers dropped and logged.
pub fn filter_response_headers(
    raw_headers: &[(String, String)],
    clock: &GuestClock,
) -> Result<FilteredHeaders, GatewayError> {
    let mut agent_headers = Vec::new();
    let mut dropped_headers = BTreeMap::new();

    let upstream_date = raw_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("date"))
        .map(|(_, v)| v.as_str());

    for (k, v) in raw_headers {
        let k_lower = k.to_lowercase();
        match k_lower.as_str() {
            "content-type" => {
                agent_headers.push(("Content-Type".to_string(), v.clone()));
            }
            "content-length" => {
                // Content-Length is automatically calculated from the actual final body
            }
            "content-encoding" => {
                agent_headers.push(("Content-Encoding".to_string(), v.clone()));
            }
            "retry-after" => {
                let converted = convert_retry_after(v, upstream_date);
                agent_headers.push(("Retry-After".to_string(), converted));
            }
            "date" => {
                // Drop upstream date into dropped_headers log, replace with guest time
                dropped_headers.insert(k_lower, v.clone());
            }
            _ => {
                dropped_headers.insert(k_lower, v.clone());
            }
        }
    }

    // Always provide guest Date header
    agent_headers.push(("Date".to_string(), clock.format_imf_fixdate()?));

    Ok(FilteredHeaders {
        agent_headers,
        dropped_headers,
    })
}

const TIMESTAMP_KEYS: [&str; 4] = ["created", "created_at", "updated_at", "expires_at"];

/// Recursively rewrite any field named created, created_at, updated_at, expires_at holding a
/// number (Unix seconds) or an RFC 3339 string to guest time in the same format. Objects and
/// arrays are always descended into, including ones held by a timestamp-named field.
///
/// The one opaque subtree is the `input` of a `tool_use` content block (the tool arguments the
/// model wrote, which the agent's tools must receive unchanged), and only at the places the
/// Messages API puts tool content:
/// - an element of the `content` array of a message: the top-level object of a non-streaming
///   response when its `type` is `"message"`, or the `message` of an event whose `type` is
///   `"message_start"` (and whose `message.type`, if present, is `"message"`);
/// - the `content_block` of an event whose `type` is `"content_block_start"`.
///
/// The exemption is decided from the top-level `type`, so the same shapes under any other
/// event or object type (e.g. a `ping` carrying a `message`) are rewritten.
///
/// A `{"type":"tool_use","input":...}` object anywhere else is rewritten like any other value.
/// Recursion depth is bounded by serde_json's parse limit.
pub fn rewrite_json_timestamps(val: &mut serde_json::Value, clock: &GuestClock) {
    let now = clock.now();
    let guest_unix = now.unix_timestamp();
    let now_secs = now.replace_nanosecond(0).unwrap_or(now);
    let guest_rfc3339 = now_secs.format(&Rfc3339).unwrap_or_default();
    let ts = (guest_unix, guest_rfc3339.as_str());
    let Some(root) = val.as_object_mut() else {
        rewrite_inner(val, ts, Place::Other);
        return;
    };
    let root_type = root
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    let is_message = root_type == "message";
    let is_message_start = root_type == "message_start"
        && root
            .get("message")
            .and_then(|m| m.as_object())
            .map(|m| {
                matches!(
                    m.get("type").and_then(|t| t.as_str()),
                    None | Some("message")
                )
            })
            .unwrap_or(false);
    let is_block_start = root_type == "content_block_start";
    for (k, v) in root.iter_mut() {
        let place = match k.as_str() {
            "content" if is_message => Place::MessageContent,
            "message" if is_message_start => Place::Message,
            "content_block" if is_block_start => Place::ToolSlot,
            _ => Place::Other,
        };
        rewrite_field(k, v, ts, place);
    }
}

/// Where a value sits, as far as the tool-input exemption is concerned.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    /// The `message` object of a `message_start` event.
    Message,
    /// The `content` array of a message.
    MessageContent,
    /// A content block position (element of a message's `content`, or `content_block`).
    ToolSlot,
    Other,
}

fn rewrite_field(k: &str, v: &mut serde_json::Value, ts: (i64, &str), place: Place) {
    if TIMESTAMP_KEYS.contains(&k) {
        match v {
            serde_json::Value::Number(_) => {
                *v = serde_json::Value::Number(ts.0.into());
                return;
            }
            serde_json::Value::String(s) if OffsetDateTime::parse(s, &Rfc3339).is_ok() => {
                *v = serde_json::Value::String(ts.1.to_string());
                return;
            }
            _ => {}
        }
    }
    rewrite_inner(v, ts, place);
}

fn rewrite_inner(val: &mut serde_json::Value, ts: (i64, &str), place: Place) {
    match val {
        serde_json::Value::Object(map) => {
            let is_tool_use = place == Place::ToolSlot
                && map.get("type").and_then(|t| t.as_str()) == Some("tool_use");
            for (k, v) in map.iter_mut() {
                if is_tool_use && k == "input" {
                    continue;
                }
                let child = if place == Place::Message && k == "content" {
                    Place::MessageContent
                } else {
                    Place::Other
                };
                rewrite_field(k, v, ts, child);
            }
        }
        serde_json::Value::Array(arr) => {
            let child = if place == Place::MessageContent {
                Place::ToolSlot
            } else {
                Place::Other
            };
            for v in arr {
                rewrite_inner(v, ts, child);
            }
        }
        _ => {}
    }
}

/// Maps HTTP status code to default recognised error type.
pub fn status_code_to_recognised_type(code: u16) -> &'static str {
    match code {
        400 => INVALID_REQUEST_ERROR,
        401 => AUTHENTICATION_ERROR,
        403 => PERMISSION_ERROR,
        404 => NOT_FOUND_ERROR,
        413 => REQUEST_TOO_LARGE,
        429 => RATE_LIMIT_ERROR,
        529 => OVERLOADED_ERROR,
        _ => API_ERROR,
    }
}

/// Sanitise upstream non-2xx error body.
/// Keeps recognised type, but replaces message with standard message.
/// An explicit unrecognised type becomes `api_error`; a body without a type
/// (or not JSON) maps from the status code.
pub fn sanitize_error_body(status: u16, original_body: &str) -> (String, String) {
    let mut recognised_type = status_code_to_recognised_type(status);

    if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(original_body) {
        if let Some(err_obj) = json_val.get("error").and_then(|e| e.as_object()) {
            if let Some(err_type) = err_obj.get("type").and_then(|t| t.as_str()) {
                // An explicit but unrecognised upstream type is not trusted to
                // match the status; it becomes api_error.
                if !is_recognised_error_type(err_type) {
                    recognised_type = API_ERROR;
                } else {
                    recognised_type = match err_type {
                        INVALID_REQUEST_ERROR => INVALID_REQUEST_ERROR,
                        AUTHENTICATION_ERROR => AUTHENTICATION_ERROR,
                        PERMISSION_ERROR => PERMISSION_ERROR,
                        NOT_FOUND_ERROR => NOT_FOUND_ERROR,
                        REQUEST_TOO_LARGE => REQUEST_TOO_LARGE,
                        RATE_LIMIT_ERROR => RATE_LIMIT_ERROR,
                        OVERLOADED_ERROR => OVERLOADED_ERROR,
                        _ => API_ERROR,
                    };
                }
            }
        }
    }

    let error_resp = AnthropicErrorResponse::standard(recognised_type);
    (error_resp.to_json_string(), recognised_type.to_string())
}

/// Token usage parsed from SSE message events.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StreamUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// SSE event names forwarded to the agent; any other event is dropped.
pub const ALLOWED_SSE_EVENTS: [&str; 8] = [
    "message_start",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
    "message_delta",
    "message_stop",
    "ping",
    "error",
];

/// What to do with one upstream SSE event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SseOutcome {
    /// Forward this sanitised event text.
    Forward(String, StreamUsage),
    /// Drop the event (unknown event name, or no data).
    Drop,
    /// The event cannot be verified (its data is not a JSON object): end the stream with a
    /// standard error event instead.
    Reject,
}

/// A complete standard SSE error event (`event: error` + standard error body).
pub fn standard_error_event(error_type: &str) -> String {
    format!(
        "event: error\ndata: {}\n\n",
        AnthropicErrorResponse::standard(error_type).to_json_string()
    )
}

fn usage_from(json_val: &serde_json::Value, usage: &mut StreamUsage) {
    let mut take = |obj: &serde_json::Map<String, serde_json::Value>| {
        if let Some(n) = obj.get("input_tokens").and_then(|t| t.as_u64()) {
            usage.input_tokens = n;
        }
        if let Some(n) = obj.get("output_tokens").and_then(|t| t.as_u64()) {
            usage.output_tokens = n;
        }
    };
    if let Some(u) = json_val.get("usage").and_then(|u| u.as_object()) {
        take(u);
    }
    if let Some(u) = json_val
        .get("message")
        .and_then(|m| m.get("usage"))
        .and_then(|u| u.as_object())
    {
        take(u);
    }
}

/// Sanitizes one SSE event (e.g. `event: ...\ndata: ...\n\n`), fail-closed:
/// - only the `event` and `data` fields are kept; comments, `id`, `retry` and any other line
///   are dropped;
/// - an event whose name is not in `ALLOWED_SSE_EVENTS`, or that has no data, is dropped;
/// - `event: error` is replaced with the standard error body;
/// - any other data must be one JSON object (else `Reject`); its timestamps are rewritten and
///   it is re-serialised, so nothing of the original text survives unparsed.
pub fn sanitize_sse_event(event_block: &str, clock: &GuestClock) -> SseOutcome {
    let mut event_name: Option<String> = None;
    let mut data_lines: Vec<&str> = Vec::new();

    for line in event_block.lines() {
        if let Some(ev) = line.strip_prefix("event:") {
            event_name = Some(ev.trim().to_string());
        } else if let Some(dt) = line.strip_prefix("data:") {
            data_lines.push(dt.strip_prefix(' ').unwrap_or(dt));
        }
    }

    if let Some(ref ev) = event_name {
        if !ALLOWED_SSE_EVENTS.contains(&ev.as_str()) {
            return SseOutcome::Drop;
        }
    }
    if data_lines.is_empty() {
        return SseOutcome::Drop;
    }
    let raw_data = data_lines.join("\n");

    if event_name.as_deref() == Some("error") {
        let (sanitized_err_json, _) = sanitize_error_body(500, &raw_data);
        return SseOutcome::Forward(
            format!("event: error\ndata: {sanitized_err_json}\n\n"),
            StreamUsage::default(),
        );
    }

    let mut json_val = match serde_json::from_str::<serde_json::Value>(&raw_data) {
        Ok(v) if v.is_object() => v,
        _ => return SseOutcome::Reject,
    };
    rewrite_json_timestamps(&mut json_val, clock);
    let mut usage = StreamUsage::default();
    usage_from(&json_val, &mut usage);
    let data = match serde_json::to_string(&json_val) {
        Ok(d) => d,
        Err(_) => return SseOutcome::Reject,
    };

    let mut out = String::new();
    if let Some(ref ev) = event_name {
        out.push_str("event: ");
        out.push_str(ev);
        out.push('\n');
    }
    out.push_str("data: ");
    out.push_str(&data);
    out.push_str("\n\n");
    SseOutcome::Forward(out, usage)
}

/// Sanitizes a 2xx JSON body, fail-closed: returns the rewritten body and its usage, or
/// `None` if the body is not one JSON object serde accepts (invalid, or nested deeper than
/// serde_json's limit). The caller must then send a standard error instead.
pub fn sanitize_json_body(body: &str, clock: &GuestClock) -> Option<(String, StreamUsage)> {
    let mut json_val = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) if v.is_object() => v,
        _ => return None,
    };
    rewrite_json_timestamps(&mut json_val, clock);
    let mut usage = StreamUsage::default();
    usage_from(&json_val, &mut usage);
    let out = serde_json::to_string(&json_val).ok()?;
    Some((out, usage))
}

#[derive(Debug, Default)]
struct SlotState {
    released: bool,
    draining: bool,
    /// Usage last reported to the quota's live sum.
    live: (u64, u64),
}

/// Guard over one request's concurrency slot and token usage.
///
/// The slot is released exactly once, when the request's upstream work has really ended
/// (`record_and_release`, also run on drop), so upstream concurrency never exceeds the limit.
/// When the client closes its side first, `mark_client_closed` marks the slot draining: a
/// waiting request then waits for it instead of counting a concurrency breach. On a reset
/// (the client is certainly gone) `cancel` also stops a stream at its next upstream event.
pub struct StreamSlotGuard {
    quota: Arc<QuotaTracker>,
    usage: Arc<Mutex<StreamUsage>>,
    slot: Mutex<SlotState>,
    cancelled: AtomicBool,
}

impl StreamSlotGuard {
    pub fn new(quota: Arc<QuotaTracker>, usage: Arc<Mutex<StreamUsage>>) -> Self {
        Self {
            quota,
            usage,
            slot: Mutex::new(SlotState::default()),
            cancelled: AtomicBool::new(false),
        }
    }

    fn slot_state(&self) -> std::sync::MutexGuard<'_, SlotState> {
        match self.slot.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// The usage cell this guard records from (shared with a `SanitizingSseReader`).
    pub fn usage_handle(&self) -> Arc<Mutex<StreamUsage>> {
        self.usage.clone()
    }

    fn current_usage(&self) -> StreamUsage {
        match self.usage.lock() {
            Ok(g) => *g,
            Err(p) => *p.into_inner(),
        }
    }

    /// Sets the usage to record when the request finishes (non-streaming responses).
    pub fn set_usage(&self, input_tokens: u64, output_tokens: u64) {
        let mut u = match self.usage.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        u.input_tokens = input_tokens;
        u.output_tokens = output_tokens;
    }

    /// Records the usage and releases the slot, once. Returns a token-cap breach caused by
    /// this usage (Ok if there was none or the slot was already released).
    pub fn record_and_release(&self) -> Result<(), QuotaBreach> {
        let mut st = self.slot_state();
        if st.released {
            return Ok(());
        }
        st.released = true;
        let u = self.current_usage();
        self.quota
            .finish(u.input_tokens, u.output_tokens, st.draining, st.live)
    }

    /// The client closed its sending side (it may still be reading): mark the slot draining.
    pub fn mark_client_closed(&self) {
        let mut st = self.slot_state();
        if !st.released && !st.draining {
            st.draining = true;
            self.quota.mark_draining();
        }
    }

    /// The client is certainly gone (reset): mark draining and stop a stream at its next read.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.mark_client_closed();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn is_slot_released(&self) -> bool {
        self.slot_state().released
    }

    /// Reports this request's usage so far to the quota's shared live sum and checks the caps
    /// against all running and completed usage (see `QuotaTracker::update_live`).
    pub fn check_live(&self, elapsed_secs: u64) -> Result<(), QuotaBreach> {
        let u = self.current_usage();
        let mut st = self.slot_state();
        if st.released {
            return self.quota.check_live(0, 0, elapsed_secs);
        }
        let now = (u.input_tokens, u.output_tokens);
        let prev = st.live;
        st.live = now;
        self.quota.update_live(prev, now, elapsed_secs)
    }
}

impl Drop for StreamSlotGuard {
    fn drop(&mut self) {
        let _ = self.record_and_release();
    }
}

/// Why reading the next upstream event stopped.
enum FetchError {
    /// A line longer than `MAX_LINE_BYTES` or an event longer than `MAX_EVENT_BYTES`.
    Oversized,
    /// Not UTF-8.
    Invalid,
    Io,
}

/// A reader that consumes an upstream SSE stream and produces the sanitised stream.
///
/// Fail-closed: an oversized line or event, invalid UTF-8, an unverifiable event or an upstream
/// read error ends the stream with a standard error event (nothing of the offending event is
/// emitted). With a slot guard it also enforces the quotas while the stream runs: after every
/// event the usage so far and the elapsed wall time are checked, and a breach ends the stream
/// with a standard `rate_limit_error` event instead of forwarding that event.
pub struct SanitizingSseReader<R: Read> {
    reader: BufReader<R>,
    clock: GuestClock,
    buffer: Vec<u8>,
    usage: Arc<Mutex<StreamUsage>>,
    slot_guard: Option<Arc<StreamSlotGuard>>,
    eof: bool,
    error_capture: Option<Arc<Mutex<Option<String>>>>,
}

/// Largest original upstream SSE error event kept for the host log.
pub const MAX_CAPTURED_SSE_ERROR_BYTES: usize = 64 * 1024;

impl<R: Read> SanitizingSseReader<R> {
    pub const MAX_LINE_BYTES: usize = 1024 * 1024; // 1 MiB per line limit
    pub const MAX_EVENT_BYTES: usize = 4 * 1024 * 1024; // 4 MiB per event limit

    pub fn new(reader: R, clock: GuestClock) -> Self {
        Self {
            reader: BufReader::new(reader),
            clock,
            buffer: Vec::new(),
            usage: Arc::new(Mutex::new(StreamUsage::default())),
            slot_guard: None,
            eof: false,
            error_capture: None,
        }
    }

    pub fn with_slot_guard(
        reader: R,
        clock: GuestClock,
        usage: Arc<Mutex<StreamUsage>>,
        slot_guard: Arc<StreamSlotGuard>,
    ) -> Self {
        Self {
            reader: BufReader::new(reader),
            clock,
            buffer: Vec::new(),
            usage,
            slot_guard: Some(slot_guard),
            eof: false,
            error_capture: None,
        }
    }

    /// Keep the first original upstream `error` event (bounded) in `cell` for the
    /// host log; the agent still only receives the sanitised event.
    pub fn with_error_capture(mut self, cell: Arc<Mutex<Option<String>>>) -> Self {
        self.error_capture = Some(cell);
        self
    }

    fn capture_error(&self, block: &str) {
        let Some(cell) = self.error_capture.as_ref() else {
            return;
        };
        let mut end = block.len().min(MAX_CAPTURED_SSE_ERROR_BYTES);
        while !block.is_char_boundary(end) {
            end -= 1;
        }
        let mut guard = match cell.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if guard.is_none() {
            *guard = Some(block[..end].to_string());
        }
    }

    pub fn usage(&self) -> StreamUsage {
        match self.usage.lock() {
            Ok(g) => *g,
            Err(p) => *p.into_inner(),
        }
    }

    /// Reads the next event block. `Ok(None)` at a clean end of stream.
    fn fetch_next_event(&mut self) -> Result<Option<String>, FetchError> {
        let mut event: Vec<u8> = Vec::new();
        let mut line: Vec<u8> = Vec::new();
        loop {
            line.clear();
            let n = (&mut self.reader)
                .take(Self::MAX_LINE_BYTES as u64 + 1)
                .read_until(b'\n', &mut line)
                .map_err(|_| FetchError::Io)?;
            if n == 0 {
                break;
            }
            if line.len() > Self::MAX_LINE_BYTES {
                return Err(FetchError::Oversized);
            }
            let blank = line == b"\n" || line == b"\r\n";
            if blank {
                if event.iter().any(|b| !b.is_ascii_whitespace()) {
                    break;
                }
                event.clear();
                continue;
            }
            if event.len() + line.len() > Self::MAX_EVENT_BYTES {
                return Err(FetchError::Oversized);
            }
            event.extend_from_slice(&line);
        }
        if event.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(None);
        }
        String::from_utf8(event)
            .map(Some)
            .map_err(|_| FetchError::Invalid)
    }

    fn is_cancelled(&self) -> bool {
        self.slot_guard
            .as_ref()
            .map(|g| g.is_cancelled())
            .unwrap_or(false)
    }

    /// Ends the stream after `event`.
    fn finish_with(&mut self, event: String) {
        self.buffer.extend_from_slice(event.as_bytes());
        self.eof = true;
    }

    fn live_breach(&self) -> Option<QuotaBreach> {
        let guard = self.slot_guard.as_ref()?;
        guard.check_live(self.clock.elapsed_secs()).err()
    }

    fn pump(&mut self) {
        match self.fetch_next_event() {
            Ok(Some(block)) => match sanitize_sse_event(&block, &self.clock) {
                SseOutcome::Forward(text, ev_usage) => {
                    if text.starts_with("event: error\n") {
                        self.capture_error(&block);
                    }
                    if let Ok(mut u) = self.usage.lock() {
                        u.input_tokens = u.input_tokens.max(ev_usage.input_tokens);
                        u.output_tokens = u.output_tokens.max(ev_usage.output_tokens);
                    }
                    if self.live_breach().is_some() {
                        self.finish_with(standard_error_event(RATE_LIMIT_ERROR));
                    } else {
                        self.buffer.extend_from_slice(text.as_bytes());
                    }
                }
                SseOutcome::Drop => {
                    if self.live_breach().is_some() {
                        self.finish_with(standard_error_event(RATE_LIMIT_ERROR));
                    }
                }
                SseOutcome::Reject => self.finish_with(standard_error_event(API_ERROR)),
            },
            Ok(None) => self.eof = true,
            Err(FetchError::Oversized) | Err(FetchError::Invalid) => {
                self.finish_with(standard_error_event(API_ERROR))
            }
            Err(FetchError::Io) => {
                let kind = if self.live_breach().is_some() {
                    RATE_LIMIT_ERROR
                } else {
                    API_ERROR
                };
                self.finish_with(standard_error_event(kind));
            }
        }
    }
}

impl<R: Read> Read for SanitizingSseReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.is_cancelled() {
            return Err(client_gone());
        }
        while self.buffer.is_empty() && !self.eof {
            self.pump();
            // The upstream read may have blocked for a long time; stop if the client left.
            if self.is_cancelled() {
                return Err(client_gone());
            }
        }

        if self.buffer.is_empty() {
            // Clean EOF and terminal error events both finish the response.
            // Commit usage before the HTTP writer can expose EOF to the client.
            // The handler's later release is idempotent.
            if let Some(guard) = &self.slot_guard {
                let _ = guard.record_and_release();
            }
            return Ok(0);
        }

        let to_copy = std::cmp::min(buf.len(), self.buffer.len());
        buf[..to_copy].copy_from_slice(&self.buffer[..to_copy]);
        self.buffer.drain(..to_copy);
        Ok(to_copy)
    }
}

fn client_gone() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        "client disconnected; stream cancelled",
    )
}
