#![forbid(unsafe_code)]

//! Run-time real-date sentinel (D12, TR-SEC-5).
//!
//! Wraps the advisory D12 detector (`crate::d12::check_d12`) for use on live traffic: agent
//! requests and prompts sent to the model, upstream responses (whole bodies and SSE streams),
//! and command output leaving the VM.
//!
//! - Only counts are recorded, keyed `source:channel`. No matched text or context is kept, so
//!   the summary never echoes host data (the date, host names or host paths).
//! - Text is scanned raw and, when it differs, after decoding common escapes (`\uXXXX`, `\/`,
//!   `%XX`, `&#NN;`, `&#xHH;`, full-width digits and separators).
//! - Streams keep a tail of the previous window so a date split across chunks is seen. SSE
//!   streams are also decoded: the string values of each `data:` JSON payload are joined into
//!   one text stream, so a date split across two deltas is seen.
//! - Fail closed: any cap (total bytes per run, line length, detector cap) marks the summary
//!   `scan_incomplete`, and an incomplete scan counts as `date_leak_observed`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::d12::{check_d12, D12Options, MAX_TEXT_BYTES};

/// Bytes kept from the previous window of a stream (longest date form is well under this).
pub const STREAM_TAIL_BYTES: usize = 256;
/// Most bytes scanned over one sentinel's lifetime; beyond it the scan is incomplete.
pub const MAX_RUN_SCAN_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Longest SSE line decoded; a longer line is still scanned raw but marks the scan incomplete.
pub const MAX_SSE_LINE_BYTES: usize = 4 * 1024 * 1024;
/// Most distinct hit keys kept in a summary.
const MAX_HIT_KEYS: usize = 256;

/// Aggregated sentinel state: what goes into the run record's attestation input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SentinelSummary {
    /// True if any hit was recorded or the scan was incomplete (fail closed).
    pub date_leak_observed: bool,
    /// True if a cap stopped part of the traffic from being fully scanned.
    pub scan_incomplete: bool,
    /// Hit counts keyed `source:channel` (channel is real_date, host_name or host_path).
    pub hits: BTreeMap<String, u64>,
    /// Incomplete-scan reasons keyed `source:reason`.
    pub incomplete: BTreeMap<String, u64>,
    /// Total bytes offered for scanning.
    pub bytes_scanned: u64,
}

impl SentinelSummary {
    /// Combines several summaries (gateway, harness, probe) into one run-level result.
    pub fn merge(parts: &[SentinelSummary]) -> SentinelSummary {
        let mut out = SentinelSummary::default();
        for p in parts {
            out.scan_incomplete |= p.scan_incomplete;
            out.bytes_scanned = out.bytes_scanned.saturating_add(p.bytes_scanned);
            for (k, v) in &p.hits {
                bump(&mut out.hits, k, *v);
            }
            for (k, v) in &p.incomplete {
                bump(&mut out.incomplete, k, *v);
            }
        }
        out.date_leak_observed = parts.iter().any(|p| p.date_leak_observed)
            || out.scan_incomplete
            || !out.hits.is_empty();
        out
    }
}

fn bump(map: &mut BTreeMap<String, u64>, key: &str, n: u64) {
    if let Some(v) = map.get_mut(key) {
        *v = v.saturating_add(n);
    } else if map.len() < MAX_HIT_KEYS {
        map.insert(key.to_string(), n);
    } else {
        let v = map.entry("overflow:other".to_string()).or_insert(0);
        *v = v.saturating_add(n);
    }
}

/// Shared run-time sentinel. Cheap to clone through `Arc`.
pub struct DateSentinel {
    opts: D12Options,
    max_bytes: u64,
    state: Mutex<SentinelSummary>,
}

impl std::fmt::Debug for DateSentinel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Host names and paths are host data: never printed.
        f.debug_struct("DateSentinel").finish_non_exhaustive()
    }
}

impl DateSentinel {
    pub fn new(opts: D12Options) -> Result<Self, &'static str> {
        Self::with_max_bytes(opts, MAX_RUN_SCAN_BYTES)
    }

    /// Same as `new` with a custom lifetime byte cap (tests).
    pub fn with_max_bytes(opts: D12Options, max_bytes: u64) -> Result<Self, &'static str> {
        opts.validate()?;
        Ok(Self {
            opts,
            max_bytes,
            state: Mutex::new(SentinelSummary::default()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SentinelSummary> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn summary(&self) -> SentinelSummary {
        self.lock().clone()
    }

    pub fn date_leak_observed(&self) -> bool {
        self.lock().date_leak_observed
    }

    /// Records that part of `source` could not be fully scanned.
    pub fn mark_incomplete(&self, source: &str, reason: &str) {
        let mut s = self.lock();
        s.scan_incomplete = true;
        s.date_leak_observed = true;
        bump(&mut s.incomplete, &format!("{source}:{reason}"), 1);
    }

    /// Reserves `n` bytes of the lifetime budget; false (and incomplete) when exhausted.
    fn reserve(&self, source: &str, n: usize) -> bool {
        let over = {
            let mut s = self.lock();
            s.bytes_scanned = s.bytes_scanned.saturating_add(n as u64);
            s.bytes_scanned > self.max_bytes
        };
        if over {
            self.mark_incomplete(source, "run_byte_cap");
        }
        !over
    }

    /// Per-channel hit counts for one window (raw and decoded views), without recording.
    fn count(&self, source: &str, text: &str) -> BTreeMap<&'static str, u64> {
        let mut counts = BTreeMap::new();
        if text.is_empty() {
            return counts;
        }
        let mut views = vec![std::borrow::Cow::Borrowed(text)];
        if let Some(decoded) = decode_escapes(text) {
            views.push(std::borrow::Cow::Owned(decoded));
        }
        let mut best: BTreeMap<&'static str, u64> = BTreeMap::new();
        for view in &views {
            if view.len() > MAX_TEXT_BYTES {
                self.mark_incomplete(source, "text_cap");
                continue;
            }
            let mut per: BTreeMap<&'static str, u64> = BTreeMap::new();
            for f in check_d12(source, view, &self.opts) {
                let ch: &'static str = match f.channel.as_str() {
                    "real_date" => "real_date",
                    "host_name" => "host_name",
                    "host_path" => "host_path",
                    _ => {
                        self.mark_incomplete(source, "detector_error");
                        continue;
                    }
                };
                *per.entry(ch).or_insert(0) += 1;
            }
            for (k, v) in per {
                let e = best.entry(k).or_insert(0);
                *e = (*e).max(v);
            }
        }
        counts.extend(best);
        counts
    }

    fn record(&self, source: &str, counts: &BTreeMap<&'static str, u64>) {
        if counts.values().all(|v| *v == 0) {
            return;
        }
        let mut s = self.lock();
        for (ch, n) in counts {
            if *n > 0 {
                bump(&mut s.hits, &format!("{source}:{ch}"), *n);
                s.date_leak_observed = true;
            }
        }
    }

    /// Scans one complete text (a prompt, an observation, a whole body).
    pub fn scan_text(&self, source: &str, text: &str) {
        if !self.reserve(source, text.len()) {
            return;
        }
        if text.len() > MAX_TEXT_BYTES {
            // Too large for one detector pass: scan as a stream instead of skipping.
            let mut st = TextStream::new_unreserved(self, source);
            for piece in chunk_str(text, 1024 * 1024) {
                st.feed(piece);
            }
            return;
        }
        let c = self.count(source, text);
        self.record(source, &c);
    }

    /// Scans raw bytes (lossy UTF-8; also the UTF-16LE/BE views when they decode cleanly).
    pub fn scan_bytes(&self, source: &str, bytes: &[u8]) {
        match std::str::from_utf8(bytes) {
            Ok(s) if !s.contains('\0') => self.scan_text(source, s),
            _ => {
                self.scan_text(source, &String::from_utf8_lossy(bytes));
                for view in utf16_views(bytes) {
                    self.scan_text(source, &view);
                }
            }
        }
    }

    /// Scans a JSON document: the raw text plus its decoded string values joined by newlines.
    /// Text that is not JSON is scanned raw only.
    pub fn scan_json(&self, source: &str, text: &str) {
        self.scan_text(source, text);
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
            let mut joined = String::new();
            collect_strings(&v, &mut joined, "\n");
            self.scan_text(source, &joined);
        }
    }

    /// A chunked text stream for `source`.
    pub fn stream<'a>(&'a self, source: &str) -> TextStream<'a> {
        TextStream {
            sentinel: self,
            source: source.to_string(),
            tail: String::new(),
            reserve: true,
        }
    }
}

fn chunk_str(s: &str, max: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < s.len() {
        let mut end = (start + max).min(s.len());
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        out.push(&s[start..end]);
        start = end;
    }
    out
}

fn utf16_views(bytes: &[u8]) -> Vec<String> {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for le in [true, false] {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        if let Ok(s) = String::from_utf16(&units) {
            out.push(s);
        }
    }
    out
}

/// Structural SSE keys whose values are event names, not content: skipped when joining
/// delta text, so `"text_delta"` does not split a date carried across two deltas.
const SSE_STRUCTURAL_KEYS: &[&str] = &["type", "id", "role", "model", "stop_reason", "signature"];

fn collect_strings(v: &serde_json::Value, out: &mut String, sep: &str) {
    collect_strings_skipping(v, out, sep, &[]);
}

fn collect_strings_skipping(v: &serde_json::Value, out: &mut String, sep: &str, skip: &[&str]) {
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        match v {
            serde_json::Value::String(s) => {
                out.push_str(s);
                out.push_str(sep);
            }
            serde_json::Value::Array(a) => stack.extend(a.iter().rev()),
            serde_json::Value::Object(o) => stack.extend(
                o.iter()
                    .rev()
                    .filter(|(k, _)| !skip.contains(&k.as_str()))
                    .map(|(_, v)| v),
            ),
            _ => {}
        }
    }
}

/// Decodes common escape forms so an encoded date is still seen. `None` if nothing changed.
pub fn decode_escapes(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    let mut i = 0;
    let hex = |s: &[u8]| -> Option<u32> {
        let s = std::str::from_utf8(s).ok()?;
        u32::from_str_radix(s, 16).ok()
    };
    while i < b.len() {
        let c = b[i];
        if c == b'\\' && i + 1 < b.len() {
            if b[i + 1] == b'u' && i + 6 <= b.len() {
                if let Some(cp) = hex(&b[i + 2..i + 6]).and_then(char::from_u32) {
                    out.push(cp);
                    i += 6;
                    changed = true;
                    continue;
                }
            }
            if b[i + 1] == b'/' {
                out.push('/');
                i += 2;
                changed = true;
                continue;
            }
        }
        if c == b'%' && i + 3 <= b.len() {
            if let Some(v) = hex(&b[i + 1..i + 3]) {
                if v < 0x80 {
                    out.push(v as u8 as char);
                    i += 3;
                    changed = true;
                    continue;
                }
            }
        }
        if c == b'&' && i + 3 < b.len() && b[i + 1] == b'#' {
            if let Some(rel) = b[i + 2..b.len().min(i + 12)]
                .iter()
                .position(|x| *x == b';')
            {
                let body = &b[i + 2..i + 2 + rel];
                let cp = if body.first().map(|x| *x | 0x20) == Some(b'x') {
                    hex(&body[1..])
                } else {
                    std::str::from_utf8(body).ok().and_then(|s| s.parse().ok())
                };
                if let Some(ch) = cp.and_then(char::from_u32) {
                    out.push(ch);
                    i += 3 + rel;
                    changed = true;
                    continue;
                }
            }
        }
        // Copy one char (full-width digits and separators fold to ASCII).
        let ch = text[i..].chars().next().unwrap_or('\u{FFFD}');
        let folded = match ch {
            '\u{FF10}'..='\u{FF19}' => {
                char::from_u32('0' as u32 + (ch as u32 - 0xFF10)).unwrap_or(ch)
            }
            '\u{FF0D}' | '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2212}' => '-',
            '\u{FF0F}' => '/',
            '\u{FF0E}' => '.',
            '\u{FF1A}' => ':',
            '\u{3000}' | '\u{00A0}' => ' ',
            other => other,
        };
        if folded != ch {
            changed = true;
        }
        out.push(folded);
        i += ch.len_utf8();
    }
    changed.then_some(out)
}

/// Chunked text stream: each chunk is scanned together with the tail of the previous one, so
/// a date split across chunks is seen; hits already present in the tail alone are not
/// counted twice.
pub struct TextStream<'a> {
    sentinel: &'a DateSentinel,
    source: String,
    tail: String,
    reserve: bool,
}

impl<'a> TextStream<'a> {
    fn new_unreserved(sentinel: &'a DateSentinel, source: &str) -> Self {
        Self {
            sentinel,
            source: source.to_string(),
            tail: String::new(),
            reserve: false,
        }
    }

    pub fn feed(&mut self, chunk: &str) {
        if chunk.is_empty() {
            return;
        }
        if self.reserve && !self.sentinel.reserve(&self.source, chunk.len()) {
            return;
        }
        let mut window = String::with_capacity(self.tail.len() + chunk.len());
        window.push_str(&self.tail);
        window.push_str(chunk);
        let total = self.sentinel.count(&self.source, &window);
        let old = self.sentinel.count(&self.source, &self.tail);
        let mut fresh = BTreeMap::new();
        for (k, v) in total {
            let prev = old.get(k).copied().unwrap_or(0);
            fresh.insert(k, v.saturating_sub(prev));
        }
        self.sentinel.record(&self.source, &fresh);
        let mut start = window.len().saturating_sub(STREAM_TAIL_BYTES);
        while !window.is_char_boundary(start) {
            start += 1;
        }
        self.tail = window[start..].to_string();
    }
}

/// Incremental SSE scanner over the bytes of an event stream.
///
/// Every byte is scanned raw (as a text stream), and the string values of each `data:` JSON
/// payload are fed, in order and without separators, to a second text stream, so a date split
/// across deltas is seen.
pub struct SseScanner {
    sentinel: Arc<DateSentinel>,
    source: String,
    raw_tail: String,
    text_tail: String,
    line: Vec<u8>,
    line_overflow: bool,
    pending_utf8: Vec<u8>,
}

impl SseScanner {
    pub fn new(sentinel: Arc<DateSentinel>, source: &str) -> Self {
        Self {
            sentinel,
            source: source.to_string(),
            raw_tail: String::new(),
            text_tail: String::new(),
            line: Vec::new(),
            line_overflow: false,
            pending_utf8: Vec::new(),
        }
    }

    fn feed_stream(sentinel: &DateSentinel, source: &str, tail: &mut String, s: &str) {
        let mut st = TextStream {
            sentinel,
            source: source.to_string(),
            tail: std::mem::take(tail),
            reserve: false,
        };
        st.feed(s);
        *tail = st.tail;
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if !self.sentinel.reserve(&self.source, bytes.len()) {
            return;
        }
        // Raw view: carry an incomplete UTF-8 sequence to the next chunk.
        let mut buf = std::mem::take(&mut self.pending_utf8);
        buf.extend_from_slice(bytes);
        let valid_up_to = match std::str::from_utf8(&buf) {
            Ok(_) => buf.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => buf.len(),
        };
        let (head, rest) = buf.split_at(valid_up_to);
        let raw = String::from_utf8_lossy(head).into_owned();
        self.pending_utf8 = rest.to_vec();
        let sentinel = self.sentinel.clone();
        Self::feed_stream(&sentinel, &self.source, &mut self.raw_tail, &raw);

        // Decoded view: split into lines.
        for &b in bytes {
            if b == b'\n' {
                let line = std::mem::take(&mut self.line);
                if self.line_overflow {
                    self.line_overflow = false;
                } else {
                    self.handle_line(&line);
                }
            } else if self.line_overflow {
                continue;
            } else if self.line.len() >= MAX_SSE_LINE_BYTES {
                self.line.clear();
                self.line_overflow = true;
                self.sentinel.mark_incomplete(&self.source, "sse_line_cap");
            } else {
                self.line.push(b);
            }
        }
    }

    fn handle_line(&mut self, line: &[u8]) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(data) = line.strip_prefix(b"data:") else {
            return;
        };
        let data = data.strip_prefix(b" ").unwrap_or(data);
        let Ok(text) = std::str::from_utf8(data) else {
            return;
        };
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
            let mut joined = String::new();
            collect_strings_skipping(&v, &mut joined, "", SSE_STRUCTURAL_KEYS);
            let sentinel = self.sentinel.clone();
            Self::feed_stream(&sentinel, &self.source, &mut self.text_tail, &joined);
        }
    }

    /// Flushes a final unterminated line and incomplete UTF-8.
    pub fn finish(&mut self) {
        if !self.pending_utf8.is_empty() {
            let raw = String::from_utf8_lossy(&std::mem::take(&mut self.pending_utf8)).into_owned();
            let sentinel = self.sentinel.clone();
            Self::feed_stream(&sentinel, &self.source, &mut self.raw_tail, &raw);
        }
        let line = std::mem::take(&mut self.line);
        if !self.line_overflow && !line.is_empty() {
            self.handle_line(&line);
        }
        self.line_overflow = false;
    }
}

impl Drop for SseScanner {
    fn drop(&mut self) {
        self.finish();
    }
}
