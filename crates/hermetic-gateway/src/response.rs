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
use crate::quota::QuotaTracker;

#[derive(Debug, Clone)]
pub struct GuestClock {
    t_clock: OffsetDateTime,
    start_instant: Instant,
}

impl GuestClock {
    pub fn new(t_clock: OffsetDateTime) -> Self {
        Self {
            t_clock,
            start_instant: Instant::now(),
        }
    }

    pub fn now(&self) -> OffsetDateTime {
        let elapsed = self.start_instant.elapsed();
        let seconds = elapsed.as_secs();
        let nanos = elapsed.subsec_nanos();
        let dur = Duration::new(seconds as i64, nanos as i32);
        self.t_clock.saturating_add(dur)
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.start_instant.elapsed().as_secs()
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

/// Converts a `Retry-After` header value to integer seconds.
/// An integer seconds value is kept.
/// An HTTP-date or RFC 3339 value is converted relative to upstream's own `date` header
/// (or guest_time if upstream date is missing), rounded up, minimum 0.
pub fn convert_retry_after(
    retry_after_raw: &str,
    upstream_date_header: Option<&str>,
    clock: &GuestClock,
) -> String {
    let trimmed = retry_after_raw.trim();

    // Check if integer seconds
    if let Ok(secs) = trimmed.parse::<u64>() {
        return secs.to_string();
    }

    // Try parsing as timestamp
    if let Some(target_dt) = parse_date_or_rfc3339(trimmed) {
        let base_dt = upstream_date_header
            .and_then(parse_date_or_rfc3339)
            .unwrap_or_else(|| clock.now());

        let diff = target_dt - base_dt;
        let mut whole_secs = diff.whole_seconds();
        if diff.subsec_nanoseconds() > 0 {
            whole_secs += 1;
        }
        let final_secs = if whole_secs < 0 { 0 } else { whole_secs as u64 };
        return final_secs.to_string();
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
                let converted = convert_retry_after(v, upstream_date, clock);
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

/// Recursively rewrite any field named created, created_at, updated_at, expires_at
/// holding a number (Unix seconds) or an RFC 3339 string to guest time in the same format.
pub fn rewrite_json_timestamps(val: &mut serde_json::Value, clock: &GuestClock) {
    let now = clock.now();
    let guest_unix = now.unix_timestamp();
    let now_secs = now.replace_nanosecond(0).unwrap_or(now);
    let guest_rfc3339 = now_secs.format(&Rfc3339).unwrap_or_default();

    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                // Do not descend into any content block's "input" object or into "partial_json" strings
                if k == "input" || k == "partial_json" {
                    continue;
                }
                if k == "created" || k == "created_at" || k == "updated_at" || k == "expires_at" {
                    match v {
                        serde_json::Value::Number(_) => {
                            *v = serde_json::Value::Number(guest_unix.into());
                        }
                        serde_json::Value::String(s)
                            if OffsetDateTime::parse(s, &Rfc3339).is_ok() =>
                        {
                            *v = serde_json::Value::String(guest_rfc3339.clone());
                        }
                        _ => {}
                    }
                } else {
                    rewrite_json_timestamps(v, clock);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                rewrite_json_timestamps(v, clock);
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
/// If unrecognised or not JSON, maps to status code or api_error.
pub fn sanitize_error_body(status: u16, original_body: &str) -> (String, String) {
    let mut recognised_type = status_code_to_recognised_type(status);

    if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(original_body) {
        if let Some(err_obj) = json_val.get("error").and_then(|e| e.as_object()) {
            if let Some(err_type) = err_obj.get("type").and_then(|t| t.as_str()) {
                if is_recognised_error_type(err_type) {
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

/// Sanitizes an SSE event string (e.g. `event: ...\ndata: ...\n\n`).
/// Rewrites timestamps in JSON data.
/// Replaces `event: error` with standard error.
/// Extracts token usage from `message_start` / `message_delta`.
pub fn sanitize_sse_event(event_block: &str, clock: &GuestClock) -> (String, StreamUsage) {
    let mut event_name: Option<String> = None;
    let mut data_lines: Vec<String> = Vec::new();
    let mut other_lines: Vec<String> = Vec::new();
    let mut usage = StreamUsage::default();

    for line in event_block.lines() {
        if let Some(ev) = line.strip_prefix("event:") {
            event_name = Some(ev.trim().to_string());
        } else if let Some(dt) = line.strip_prefix("data:") {
            data_lines.push(dt.trim().to_string());
        } else if !line.is_empty() {
            other_lines.push(line.to_string());
        }
    }

    let raw_data = data_lines.join("\n");

    let is_error_event = event_name.as_deref() == Some("error");

    let sanitized_data = if is_error_event {
        let (sanitized_err_json, _) = sanitize_error_body(500, &raw_data);
        sanitized_err_json
    } else if let Ok(mut json_val) = serde_json::from_str::<serde_json::Value>(&raw_data) {
        rewrite_json_timestamps(&mut json_val, clock);

        // Check for token usage in message_start or message_delta
        if let Some(usage_obj) = json_val.get("usage").and_then(|u| u.as_object()) {
            if let Some(in_toks) = usage_obj.get("input_tokens").and_then(|t| t.as_u64()) {
                usage.input_tokens = in_toks;
            }
            if let Some(out_toks) = usage_obj.get("output_tokens").and_then(|t| t.as_u64()) {
                usage.output_tokens = out_toks;
            }
        }
        if let Some(msg_obj) = json_val.get("message").and_then(|m| m.as_object()) {
            if let Some(usage_obj) = msg_obj.get("usage").and_then(|u| u.as_object()) {
                if let Some(in_toks) = usage_obj.get("input_tokens").and_then(|t| t.as_u64()) {
                    usage.input_tokens = in_toks;
                }
                if let Some(out_toks) = usage_obj.get("output_tokens").and_then(|t| t.as_u64()) {
                    usage.output_tokens = out_toks;
                }
            }
        }

        serde_json::to_string(&json_val).unwrap_or(raw_data)
    } else {
        raw_data
    };

    let mut out = String::new();
    if let Some(ref ev) = event_name {
        out.push_str("event: ");
        out.push_str(ev);
        out.push('\n');
    }
    if !sanitized_data.is_empty() {
        out.push_str("data: ");
        out.push_str(&sanitized_data);
        out.push('\n');
    }
    for ol in other_lines {
        out.push_str(&ol);
        out.push('\n');
    }
    out.push('\n');

    (out, usage)
}

/// Guard that records token usage and releases the concurrency slot exactly once.
pub struct StreamSlotGuard {
    quota: Arc<QuotaTracker>,
    usage: Arc<Mutex<StreamUsage>>,
    released: AtomicBool,
}

impl StreamSlotGuard {
    pub fn new(quota: Arc<QuotaTracker>, usage: Arc<Mutex<StreamUsage>>) -> Self {
        Self {
            quota,
            usage,
            released: AtomicBool::new(false),
        }
    }

    pub fn record_and_release(&self) {
        if !self.released.swap(true, Ordering::SeqCst) {
            let u = match self.usage.lock() {
                Ok(g) => *g,
                Err(p) => *p.into_inner(),
            };
            let _ = self
                .quota
                .record_usage_and_release(u.input_tokens, u.output_tokens);
        }
    }
}

impl Drop for StreamSlotGuard {
    fn drop(&mut self) {
        self.record_and_release();
    }
}

/// A reader wrapper that consumes an incoming SSE stream, sanitises each event,
/// and produces sanitized SSE byte stream.
pub struct SanitizingSseReader<R: Read> {
    reader: BufReader<R>,
    clock: GuestClock,
    buffer: Vec<u8>,
    usage: Arc<Mutex<StreamUsage>>,
    slot_guard: Option<Arc<StreamSlotGuard>>,
    eof: bool,
}

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
        }
    }

    pub fn usage(&self) -> StreamUsage {
        match self.usage.lock() {
            Ok(g) => *g,
            Err(p) => *p.into_inner(),
        }
    }

    /// Read next event block from reader.
    fn fetch_next_event(&mut self) -> Result<Option<String>, std::io::Error> {
        let mut event_str = String::new();
        let mut line = String::new();

        while !self.eof {
            line.clear();
            let bytes_read = (&mut self.reader)
                .take(Self::MAX_LINE_BYTES as u64)
                .read_line(&mut line)?;

            if bytes_read == 0 {
                self.eof = true;
                break;
            }

            event_str.push_str(&line);
            if event_str.len() > Self::MAX_EVENT_BYTES {
                // Event exceeded maximum allowed size, break and sanitize what we have
                break;
            }

            if line == "\n" || line == "\r\n" {
                if !event_str.trim().is_empty() {
                    return Ok(Some(event_str));
                }
                event_str.clear();
            }
        }

        if !event_str.trim().is_empty() {
            Ok(Some(event_str))
        } else {
            Ok(None)
        }
    }
}

impl<R: Read> Read for SanitizingSseReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.buffer.is_empty() && !self.eof {
            if let Some(event_block) = self.fetch_next_event()? {
                let (sanitized_event, ev_usage) = sanitize_sse_event(&event_block, &self.clock);
                if let Ok(mut u) = self.usage.lock() {
                    u.input_tokens = u.input_tokens.max(ev_usage.input_tokens);
                    u.output_tokens = u.output_tokens.max(ev_usage.output_tokens);
                }
                self.buffer.extend_from_slice(sanitized_event.as_bytes());
            } else {
                break;
            }
        }

        if self.buffer.is_empty() {
            if let Some(guard) = &self.slot_guard {
                guard.record_and_release();
            }
            return Ok(0);
        }

        let to_copy = std::cmp::min(buf.len(), self.buffer.len());
        buf[..to_copy].copy_from_slice(&self.buffer[..to_copy]);
        self.buffer.drain(..to_copy);
        Ok(to_copy)
    }
}
