#![forbid(unsafe_code)]

//! Detector D12: Real-date sentinel.
//!
//! Advisory detector that scans text and files for occurrences of the real run
//! date in various formats (ISO, US, European, month names, RFC 2822, HTTP dates,
//! and Unix epoch timestamps), as well as host names and host paths.

use std::collections::HashSet;

use crate::scan::{Finding, Severity, Visibility};

pub const MAX_TEXT_BYTES: usize = 64 * 1024 * 1024;
const MAX_OPTION_ITEMS: usize = 10_000;

/// Options for detector D12.
#[derive(Debug, Clone)]
pub struct D12Options {
    /// The real date to compare against.
    pub real_date: time::Date,
    /// Tolerance in days (default 1).
    pub tolerance_days: u32,
    /// Host names to search for (case-insensitive, bounded).
    pub host_names: Vec<String>,
    /// Host paths to search for (as substrings).
    pub host_paths: Vec<String>,
}

impl D12Options {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.host_names.len() > MAX_OPTION_ITEMS
            || self.host_paths.len() > MAX_OPTION_ITEMS
            || self
                .host_names
                .iter()
                .chain(&self.host_paths)
                .any(|s| s.len() > crate::safe_fs::MAX_PATH_BYTES)
        {
            return Err("D12 option cap exceeded");
        }
        Ok(())
    }
}

impl Default for D12Options {
    fn default() -> Self {
        Self {
            real_date: time::OffsetDateTime::now_utc().date(),
            tolerance_days: 1,
            host_names: Vec::new(),
            host_paths: Vec::new(),
        }
    }
}

fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-'
}

/// Extract evidence string: matched text plus up to 40 characters of context each side.
fn extract_evidence(text: &str, start_byte: usize, end_byte: usize) -> Vec<String> {
    let before_str = text.get(..start_byte).unwrap_or("");
    let before_chars = before_str.chars().count();
    let skip = before_chars.saturating_sub(40);
    let ctx_start = before_str
        .char_indices()
        .nth(skip)
        .map(|(idx, _)| idx)
        .unwrap_or(0);
    let ctx_before = before_str.get(ctx_start..).unwrap_or("");

    let after_str = text.get(end_byte..).unwrap_or("");
    let ctx_end_offset = after_str
        .char_indices()
        .nth(40)
        .map(|(idx, _)| idx)
        .unwrap_or(after_str.len());
    let ctx_after = after_str.get(..ctx_end_offset).unwrap_or("");

    let match_str = text.get(start_byte..end_byte).unwrap_or("");

    vec![format!("{ctx_before}{match_str}{ctx_after}")]
}

fn make_date(year: i32, month: u8, day: u8) -> Option<time::Date> {
    if !(1000..=9999).contains(&year) {
        return None;
    }
    let m = time::Month::try_from(month).ok()?;
    time::Date::from_calendar_date(year, m, day).ok()
}

fn check_pair_in_window(
    year: i32,
    a: u8,
    b: u8,
    min_date: time::Date,
    max_date: time::Date,
) -> bool {
    // Reading 1: month = a, day = b
    if let Some(d1) = make_date(year, a, b) {
        if d1 >= min_date && d1 <= max_date {
            return true;
        }
    }
    // Reading 2: month = b, day = a
    if let Some(d2) = make_date(year, b, a) {
        if d2 >= min_date && d2 <= max_date {
            return true;
        }
    }
    false
}

fn parse_month_name(s: &str) -> Option<(u8, usize)> {
    let bytes = s.as_bytes();
    let months: &[(&[u8], u8)] = &[
        (b"january", 1),
        (b"february", 2),
        (b"march", 3),
        (b"april", 4),
        (b"may", 5),
        (b"june", 6),
        (b"july", 7),
        (b"august", 8),
        (b"september", 9),
        (b"october", 10),
        (b"november", 11),
        (b"december", 12),
        (b"jan", 1),
        (b"feb", 2),
        (b"mar", 3),
        (b"apr", 4),
        (b"may", 5),
        (b"jun", 6),
        (b"jul", 7),
        (b"aug", 8),
        (b"sep", 9),
        (b"oct", 10),
        (b"nov", 11),
        (b"dec", 12),
    ];

    for (name, m) in months {
        let len = name.len();
        if bytes.len() >= len && bytes[..len].eq_ignore_ascii_case(name) {
            if bytes.len() > len && bytes[len].is_ascii_alphabetic() {
                continue;
            }
            return Some((*m, len));
        }
    }
    None
}

fn parse_day_of_week(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let days: &[&[u8]] = &[
        b"monday",
        b"tuesday",
        b"wednesday",
        b"thursday",
        b"friday",
        b"saturday",
        b"sunday",
        b"mon",
        b"tue",
        b"wed",
        b"thu",
        b"fri",
        b"sat",
        b"sun",
    ];

    for name in days {
        let mut len = name.len();
        if bytes.len() >= len && bytes[..len].eq_ignore_ascii_case(name) {
            if bytes.len() > len {
                let next_b = bytes[len];
                if next_b.is_ascii_alphabetic() {
                    continue;
                }
                if next_b == b',' {
                    len += 1;
                }
            }
            // Skip trailing whitespace
            while len < bytes.len() && bytes[len].is_ascii_whitespace() {
                len += 1;
            }
            return Some(len);
        }
    }
    None
}

fn parse_digits_u32(s: &str) -> Option<(u32, usize)> {
    let mut count = 0;
    for b in s.bytes() {
        if b.is_ascii_digit() {
            count += 1;
        } else {
            break;
        }
    }
    if count == 0 {
        return None;
    }
    let val = s.get(..count)?.parse::<u32>().ok()?;
    Some((val, count))
}

fn is_bounded_digit_end(text: &str, end: usize) -> bool {
    match text.as_bytes().get(end) {
        Some(b) => !b.is_ascii_digit(),
        None => true,
    }
}

/// Check if optional HTTP time suffix follows (e.g. " 08:12:31 GMT" or " 08:12:31 +0000").
fn optional_http_time_len(s: &str) -> usize {
    let bytes = s.as_bytes();
    if bytes.len() < 9 {
        return 0;
    }
    let mut idx = 0;
    if bytes[idx] == b' ' {
        idx += 1;
    } else {
        return 0;
    }
    // HH:MM:SS
    if idx + 8 > bytes.len() {
        return 0;
    }
    if bytes[idx].is_ascii_digit()
        && bytes[idx + 1].is_ascii_digit()
        && bytes[idx + 2] == b':'
        && bytes[idx + 3].is_ascii_digit()
        && bytes[idx + 4].is_ascii_digit()
        && bytes[idx + 5] == b':'
        && bytes[idx + 6].is_ascii_digit()
        && bytes[idx + 7].is_ascii_digit()
    {
        idx += 8;
        // Optional timezone e.g. " GMT" or " +0000" or " UTC"
        if idx < bytes.len() && bytes[idx] == b' ' {
            let rest = &bytes[idx + 1..];
            if rest.starts_with(b"GMT") || rest.starts_with(b"UTC") {
                return idx + 1 + 3;
            }
            if rest.len() >= 5
                && (rest[0] == b'+' || rest[0] == b'-')
                && rest[1..5].iter().all(|b| b.is_ascii_digit())
            {
                return idx + 1 + 5;
            }
        }
        return idx;
    }
    0
}

struct MatchCandidate {
    start: usize,
    end: usize,
    channel: &'static str,
}

fn record_date_match(
    text: &str,
    start: usize,
    end: usize,
    seen: &mut HashSet<String>,
    candidates: &mut Vec<MatchCandidate>,
) -> bool {
    let m = match text.get(start..end) {
        Some(s) => s,
        None => return true,
    };
    let distinct_key = format!("real_date:{m}");
    if !seen.contains(&distinct_key) {
        if seen.len() >= 50 {
            return false;
        }
        seen.insert(distinct_key);
        candidates.push(MatchCandidate {
            start,
            end,
            channel: "real_date",
        });
    }
    true
}

fn scan_dates(
    text: &str,
    min_date: time::Date,
    max_date: time::Date,
    seen: &mut HashSet<String>,
    candidates: &mut Vec<MatchCandidate>,
) {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut i = 0;

    while i < n {
        if !text.is_char_boundary(i) {
            i += 1;
            continue;
        }
        if seen.len() >= 50 {
            return;
        }

        let b = bytes[i];
        if !b.is_ascii_alphanumeric() {
            i += 1;
            continue;
        }

        let left_bounded_digit = i == 0 || !bytes[i - 1].is_ascii_digit();

        // 1. Day-of-week prefixed formats: RFC 2822 ("Wed, 11 Nov 2026") & HTTP dates
        let left_bounded_alpha = i == 0 || !bytes[i - 1].is_ascii_alphabetic();
        if left_bounded_alpha && b.is_ascii_alphabetic() {
            if let Some(slice_i) = text.get(i..) {
                if let Some(dow_len) = parse_day_of_week(slice_i) {
                    let rest_idx = i + dow_len;
                    if let Some(rest) = text.get(rest_idx..) {
                        // Check Option A: asctime format ("Wed Nov 11 08:12:31 2026")
                        if let Some((m, m_len)) = parse_month_name(rest) {
                            let mut pos = m_len;
                            while pos < rest.len() && rest.as_bytes()[pos].is_ascii_whitespace() {
                                pos += 1;
                            }
                            if let Some(after_m) = rest.get(pos..) {
                                if let Some((d, d_len)) = parse_digits_u32(after_m) {
                                    if (1..=31).contains(&d) && (d_len == 1 || d_len == 2) {
                                        pos += d_len;
                                        while pos < rest.len()
                                            && rest.as_bytes()[pos].is_ascii_whitespace()
                                        {
                                            pos += 1;
                                        }
                                        // HH:MM:SS
                                        if pos + 8 <= rest.len()
                                            && rest.as_bytes()[pos].is_ascii_digit()
                                            && rest.as_bytes()[pos + 1].is_ascii_digit()
                                            && rest.as_bytes()[pos + 2] == b':'
                                            && rest.as_bytes()[pos + 3].is_ascii_digit()
                                            && rest.as_bytes()[pos + 4].is_ascii_digit()
                                            && rest.as_bytes()[pos + 5] == b':'
                                            && rest.as_bytes()[pos + 6].is_ascii_digit()
                                            && rest.as_bytes()[pos + 7].is_ascii_digit()
                                        {
                                            pos += 8;
                                            while pos < rest.len()
                                                && rest.as_bytes()[pos].is_ascii_whitespace()
                                            {
                                                pos += 1;
                                            }
                                            if let Some(after_time) = rest.get(pos..) {
                                                if let Some((y, y_len)) =
                                                    parse_digits_u32(after_time)
                                                {
                                                    if y_len == 4
                                                        && is_bounded_digit_end(rest, pos + y_len)
                                                    {
                                                        if let Some(date) =
                                                            make_date(y as i32, m, d as u8)
                                                        {
                                                            if date >= min_date && date <= max_date
                                                            {
                                                                let end_idx =
                                                                    rest_idx + pos + y_len;
                                                                if !record_date_match(
                                                                    text, i, end_idx, seen,
                                                                    candidates,
                                                                ) {
                                                                    return;
                                                                }
                                                                i = end_idx;
                                                                continue;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Check Option B: RFC 2822 / RFC 1123 / RFC 850 after day-of-week ("11 Nov 2026" or "11-Nov-26")
                        if let Some((d, d_len)) = parse_digits_u32(rest) {
                            if (1..=31).contains(&d) && (d_len == 1 || d_len == 2) {
                                let mut pos = d_len;
                                let sep = rest.as_bytes().get(pos).copied().unwrap_or(0);
                                if sep == b' ' || sep == b'-' || sep == b'/' || sep == b'.' {
                                    pos += 1;
                                    if let Some(after_sep) = rest.get(pos..) {
                                        if let Some((m, m_len)) = parse_month_name(after_sep) {
                                            pos += m_len;
                                            let sep2 =
                                                rest.as_bytes().get(pos).copied().unwrap_or(0);
                                            if sep2 == sep || sep2 == b' ' || sep2 == b'-' {
                                                pos += 1;
                                                if let Some(after_sep2) = rest.get(pos..) {
                                                    if let Some((raw_y, y_len)) =
                                                        parse_digits_u32(after_sep2)
                                                    {
                                                        let y = if y_len == 2 {
                                                            2000 + raw_y as i32
                                                        } else if y_len == 4 {
                                                            raw_y as i32
                                                        } else {
                                                            0
                                                        };
                                                        if (y_len == 2 || y_len == 4)
                                                            && is_bounded_digit_end(
                                                                rest,
                                                                pos + y_len,
                                                            )
                                                        {
                                                            if let Some(date) =
                                                                make_date(y, m, d as u8)
                                                            {
                                                                if date >= min_date
                                                                    && date <= max_date
                                                                {
                                                                    let mut end_idx =
                                                                        rest_idx + pos + y_len;
                                                                    if let Some(suffix) =
                                                                        text.get(end_idx..)
                                                                    {
                                                                        end_idx +=
                                                                            optional_http_time_len(
                                                                                suffix,
                                                                            );
                                                                    }
                                                                    if !record_date_match(
                                                                        text, i, end_idx, seen,
                                                                        candidates,
                                                                    ) {
                                                                        return;
                                                                    }
                                                                    i = end_idx;
                                                                    continue;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Month-name starting formats ("Nov 11, 2026", "November 11 2026")
        if left_bounded_alpha {
            if let Some(slice_i) = text.get(i..) {
                if let Some((m, m_len)) = parse_month_name(slice_i) {
                    let rest_idx = i + m_len;
                    if let Some(rest) = text.get(rest_idx..) {
                        let mut pos = 0;
                        while pos < rest.len() && rest.as_bytes()[pos].is_ascii_whitespace() {
                            pos += 1;
                        }
                        if pos > 0 {
                            if let Some(after_ws) = rest.get(pos..) {
                                if let Some((d, d_len)) = parse_digits_u32(after_ws) {
                                    if (1..=31).contains(&d) && (d_len == 1 || d_len == 2) {
                                        pos += d_len;
                                        if pos < rest.len() && rest.as_bytes()[pos] == b',' {
                                            pos += 1;
                                        }
                                        while pos < rest.len()
                                            && rest.as_bytes()[pos].is_ascii_whitespace()
                                        {
                                            pos += 1;
                                        }
                                        if let Some(after_d) = rest.get(pos..) {
                                            if let Some((y, y_len)) = parse_digits_u32(after_d) {
                                                if y_len == 4
                                                    && is_bounded_digit_end(rest, pos + y_len)
                                                {
                                                    if let Some(date) =
                                                        make_date(y as i32, m, d as u8)
                                                    {
                                                        if date >= min_date && date <= max_date {
                                                            let end_idx = rest_idx + pos + y_len;
                                                            if !record_date_match(
                                                                text, i, end_idx, seen, candidates,
                                                            ) {
                                                                return;
                                                            }
                                                            i = end_idx;
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 3. Digit-starting formats (only when left-bounded by non-digit)
        if left_bounded_digit && b.is_ascii_digit() {
            // Count consecutive digits starting at i
            let mut digit_len = 0;
            while i + digit_len < n && bytes[i + digit_len].is_ascii_digit() {
                digit_len += 1;
            }

            // Check A: Solid runs of digits bounded by non-digits
            // (8-digit YYYYMMDD, 10-digit epoch seconds, 13-digit epoch millis)
            let is_digit_run_bounded = is_bounded_digit_end(text, i + digit_len);
            if is_digit_run_bounded {
                if digit_len == 8 {
                    if let Some(s) = text.get(i..i + 8) {
                        let y = s.get(0..4).and_then(|v| v.parse::<i32>().ok()).unwrap_or(0);
                        let m = s.get(4..6).and_then(|v| v.parse::<u8>().ok()).unwrap_or(0);
                        let d = s.get(6..8).and_then(|v| v.parse::<u8>().ok()).unwrap_or(0);
                        // Year-first format YYYYMMDD: read only as year-month-day
                        if let Some(date) = make_date(y, m, d) {
                            if date >= min_date && date <= max_date {
                                if !record_date_match(text, i, i + 8, seen, candidates) {
                                    return;
                                }
                                i += 8;
                                continue;
                            }
                        }
                    }
                } else if digit_len == 10 {
                    if let Some(s) = text.get(i..i + 10) {
                        if let Ok(secs) = s.parse::<i64>() {
                            if let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(secs) {
                                let d = dt.date();
                                if d >= min_date && d <= max_date {
                                    if !record_date_match(text, i, i + 10, seen, candidates) {
                                        return;
                                    }
                                    i += 10;
                                    continue;
                                }
                            }
                        }
                    }
                } else if digit_len == 13 {
                    if let Some(s) = text.get(i..i + 13) {
                        if let Ok(millis) = s.parse::<i64>() {
                            let nanos = (millis as i128).saturating_mul(1_000_000);
                            if let Ok(dt) = time::OffsetDateTime::from_unix_timestamp_nanos(nanos) {
                                let d = dt.date();
                                if d >= min_date && d <= max_date {
                                    if !record_date_match(text, i, i + 13, seen, candidates) {
                                        return;
                                    }
                                    i += 13;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }

            // Check B: YYYY-MM-DD or YYYY/MM/DD or YYYY-Nov-11 or YYYY/Nov/11
            if digit_len == 4 {
                if let Some(y) = text.get(i..i + 4).and_then(|v| v.parse::<i32>().ok()) {
                    if i + 4 < n {
                        let sep = bytes[i + 4];
                        if sep == b'-' || sep == b'/' {
                            if let Some(rest) = text.get(i + 5..) {
                                // Sub-case: YYYY-Nov-11
                                if let Some((m, m_len)) = parse_month_name(rest) {
                                    if rest.len() > m_len && rest.as_bytes()[m_len] == sep {
                                        if let Some(after_sep) = rest.get(m_len + 1..) {
                                            if let Some((d, d_len)) = parse_digits_u32(after_sep) {
                                                if (d_len == 1 || d_len == 2)
                                                    && (1..=31).contains(&d)
                                                    && is_bounded_digit_end(after_sep, d_len)
                                                {
                                                    if let Some(date) = make_date(y, m, d as u8) {
                                                        if date >= min_date && date <= max_date {
                                                            let end_idx = i + 5 + m_len + 1 + d_len;
                                                            if !record_date_match(
                                                                text, i, end_idx, seen, candidates,
                                                            ) {
                                                                return;
                                                            }
                                                            i = end_idx;
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                // Sub-case: YYYY-MM-DD or YYYY/MM/DD (read only as year-month-day)
                                if let Some((m, m_len)) = parse_digits_u32(rest) {
                                    if (m_len == 1 || m_len == 2)
                                        && rest.len() > m_len
                                        && rest.as_bytes()[m_len] == sep
                                    {
                                        if let Some(after_sep) = rest.get(m_len + 1..) {
                                            if let Some((d, d_len)) = parse_digits_u32(after_sep) {
                                                if (d_len == 1 || d_len == 2)
                                                    && is_bounded_digit_end(after_sep, d_len)
                                                {
                                                    if let Some(date) =
                                                        make_date(y, m as u8, d as u8)
                                                    {
                                                        if date >= min_date && date <= max_date {
                                                            let end_idx = i + 5 + m_len + 1 + d_len;
                                                            if !record_date_match(
                                                                text, i, end_idx, seen, candidates,
                                                            ) {
                                                                return;
                                                            }
                                                            i = end_idx;
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check C: D(D) <sep> Month <sep> Year (e.g. "11 November 2026", "11 Nov 2026", "11-Nov-2026")
            if digit_len == 1 || digit_len == 2 {
                let d = text
                    .get(i..i + digit_len)
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(0);
                if (1..=31).contains(&d) && i + digit_len < n {
                    let sep = bytes[i + digit_len];
                    if sep == b' ' || sep == b'-' || sep == b'/' || sep == b'.' {
                        if let Some(rest) = text.get(i + digit_len + 1..) {
                            if let Some((m, m_len)) = parse_month_name(rest) {
                                if rest.len() > m_len {
                                    let sep2 = rest.as_bytes()[m_len];
                                    if sep2 == sep || sep2 == b' ' || sep2 == b'-' {
                                        if let Some(after_sep2) = rest.get(m_len + 1..) {
                                            if let Some((raw_y, y_len)) =
                                                parse_digits_u32(after_sep2)
                                            {
                                                let y = if y_len == 2 {
                                                    2000 + raw_y as i32
                                                } else if y_len == 4 {
                                                    raw_y as i32
                                                } else {
                                                    0
                                                };
                                                if (y_len == 2 || y_len == 4)
                                                    && is_bounded_digit_end(after_sep2, y_len)
                                                {
                                                    if let Some(date) = make_date(y, m, d as u8) {
                                                        if date >= min_date && date <= max_date {
                                                            let mut end_idx = i
                                                                + digit_len
                                                                + 1
                                                                + m_len
                                                                + 1
                                                                + y_len;
                                                            if let Some(suffix) =
                                                                text.get(end_idx..)
                                                            {
                                                                end_idx +=
                                                                    optional_http_time_len(suffix);
                                                            }
                                                            if !record_date_match(
                                                                text, i, end_idx, seen, candidates,
                                                            ) {
                                                                return;
                                                            }
                                                            i = end_idx;
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Check D: US (MM/DD/YYYY, MM-DD-YYYY) and European (DD.MM.YYYY, DD/MM/YYYY)
                            // Kept ambiguous dual-reading for day-first or month-first formats
                            if sep == b'/' || sep == b'-' || sep == b'.' {
                                if let Some((num2, num2_len)) = parse_digits_u32(rest) {
                                    if (num2_len == 1 || num2_len == 2)
                                        && rest.len() > num2_len
                                        && rest.as_bytes()[num2_len] == sep
                                    {
                                        if let Some(after_sep2) = rest.get(num2_len + 1..) {
                                            if let Some((y, y_len)) = parse_digits_u32(after_sep2) {
                                                if y_len == 4
                                                    && is_bounded_digit_end(after_sep2, y_len)
                                                    && check_pair_in_window(
                                                        y as i32, d as u8, num2 as u8, min_date,
                                                        max_date,
                                                    )
                                                {
                                                    let end_idx =
                                                        i + digit_len + 1 + num2_len + 1 + y_len;
                                                    if !record_date_match(
                                                        text, i, end_idx, seen, candidates,
                                                    ) {
                                                        return;
                                                    }
                                                    i = end_idx;
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        i += 1;
    }
}

/// Check text for real-date sentinels, host names, and host paths (Detector D12).
pub fn check_d12(path: &str, text: &str, opts: &D12Options) -> Vec<Finding> {
    if text.len() > MAX_TEXT_BYTES || opts.validate().is_err() {
        return vec![Finding {
            detector: "D12".into(),
            channel: "scan_error".into(),
            path: path.into(),
            visibility: Visibility::AgentVisible,
            severity: Severity::Info,
            confidence: 0.0,
            hunk: None,
            evidence: vec!["text or option cap exceeded".into()],
        }];
    }
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    // Calculate tolerance date window
    let min_date = opts
        .real_date
        .checked_sub(time::Duration::days(opts.tolerance_days as i64))
        .unwrap_or(time::Date::MIN);
    let max_date = opts
        .real_date
        .checked_add(time::Duration::days(opts.tolerance_days as i64))
        .unwrap_or(time::Date::MAX);

    // 1. Channel "host_path": any opts.host_paths entry as a substring
    for target in &opts.host_paths {
        if target.is_empty() {
            continue;
        }
        let distinct_key = format!("host_path:{target}");
        if seen.contains(&distinct_key) {
            continue;
        }
        if seen.len() >= 50 {
            break;
        }
        if let Some((idx, _)) = text.match_indices(target).next() {
            seen.insert(distinct_key);
            candidates.push(MatchCandidate {
                start: idx,
                end: idx + target.len(),
                channel: "host_path",
            });
        }
    }

    // 2. Channel "host_name": any opts.host_names entry
    // (case-insensitive, bounded by non-alphanumeric, non-dot, non-dash characters)
    if !opts.host_names.is_empty() {
        let lower_text = text.to_ascii_lowercase();
        for target in &opts.host_names {
            if target.is_empty() {
                continue;
            }
            let lower_target = target.to_ascii_lowercase();
            let distinct_key = format!("host_name:{lower_target}");
            if seen.contains(&distinct_key) {
                continue;
            }
            if seen.len() >= 50 {
                break;
            }
            let target_len = target.len();

            for (idx, _) in lower_text.match_indices(&lower_target) {
                // Check boundary before
                if idx > 0 {
                    if let Some(prev) = text.get(..idx).and_then(|s| s.chars().next_back()) {
                        if is_host_char(prev) {
                            continue;
                        }
                    }
                }
                // Check boundary after
                let end_idx = idx + target_len;
                if end_idx < text.len() {
                    if let Some(next) = text.get(end_idx..).and_then(|s| s.chars().next()) {
                        if is_host_char(next) {
                            continue;
                        }
                    }
                }

                seen.insert(distinct_key);
                candidates.push(MatchCandidate {
                    start: idx,
                    end: end_idx,
                    channel: "host_name",
                });
                break;
            }
        }
    }

    // 3. Channel "real_date": dates in window across all supported formats
    scan_dates(text, min_date, max_date, &mut seen, &mut candidates);

    // Sort candidates by start position ascending, then longest match first
    candidates.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)));

    let mut findings = Vec::new();
    for cand in candidates {
        if findings.len() >= 50 {
            break;
        }
        let evidence = extract_evidence(text, cand.start, cand.end);
        findings.push(Finding {
            detector: "D12".to_string(),
            channel: cand.channel.to_string(),
            path: path.to_string(),
            visibility: Visibility::AgentVisible,
            severity: Severity::Review,
            confidence: 1.0,
            hunk: None,
            evidence,
        });
    }

    findings
}
