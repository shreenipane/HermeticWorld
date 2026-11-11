#![forbid(unsafe_code)]

//! Detector D12: Real-date sentinel.
//!
//! Advisory detector that scans text and files for occurrences of the real run
//! date in various formats (ISO, US, European, month names, RFC 2822, HTTP dates,
//! and Unix epoch timestamps), as well as host names and host paths.

use std::collections::HashSet;

use crate::scan::{Finding, Severity, Visibility};

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
    let before_str = &text[..start_byte];
    let before_chars = before_str.chars().count();
    let skip = before_chars.saturating_sub(40);
    let ctx_start = before_str
        .char_indices()
        .nth(skip)
        .map(|(idx, _)| idx)
        .unwrap_or(0);
    let ctx_before = &text[ctx_start..start_byte];

    let after_str = &text[end_byte..];
    let ctx_end = after_str
        .char_indices()
        .nth(40)
        .map(|(idx, _)| end_byte + idx)
        .unwrap_or(text.len());
    let ctx_after = &text[end_byte..ctx_end];

    vec![format!(
        "{}{}{}",
        ctx_before,
        &text[start_byte..end_byte],
        ctx_after
    )]
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
    let s_lower = s.to_ascii_lowercase();
    let months: &[(&str, u8)] = &[
        ("january", 1),
        ("february", 2),
        ("march", 3),
        ("april", 4),
        ("may", 5),
        ("june", 6),
        ("july", 7),
        ("august", 8),
        ("september", 9),
        ("october", 10),
        ("november", 11),
        ("december", 12),
        ("jan", 1),
        ("feb", 2),
        ("mar", 3),
        ("apr", 4),
        ("may", 5),
        ("jun", 6),
        ("jul", 7),
        ("aug", 8),
        ("sep", 9),
        ("oct", 10),
        ("nov", 11),
        ("dec", 12),
    ];

    for (name, m) in months {
        if s_lower.starts_with(name) {
            let len = name.len();
            if s.len() > len {
                if let Some(next_c) = s[len..].chars().next() {
                    if next_c.is_ascii_alphabetic() {
                        continue;
                    }
                }
            }
            return Some((*m, len));
        }
    }
    None
}

fn parse_day_of_week(s: &str) -> Option<usize> {
    let s_lower = s.to_ascii_lowercase();
    let days = &[
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
        "sunday",
        "mon",
        "tue",
        "wed",
        "thu",
        "fri",
        "sat",
        "sun",
    ];

    for name in days {
        if s_lower.starts_with(name) {
            let mut len = name.len();
            if s.len() > len {
                let rest = &s[len..];
                let mut chars = rest.chars();
                if let Some(c) = chars.next() {
                    if c.is_ascii_alphabetic() {
                        continue;
                    }
                    if c == ',' {
                        len += 1;
                    }
                }
            }
            // Skip trailing whitespace
            while len < s.len() && s.as_bytes()[len].is_ascii_whitespace() {
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
    let val = s[..count].parse::<u32>().ok()?;
    Some((val, count))
}

fn is_bounded_digit_end(text: &str, end: usize) -> bool {
    if end >= text.len() {
        true
    } else {
        !text.as_bytes()[end].is_ascii_digit()
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
            let rest = &s[idx + 1..];
            if rest.starts_with("GMT") || rest.starts_with("UTC") {
                return idx + 1 + 3;
            }
            if rest.len() >= 5
                && (rest.starts_with('+') || rest.starts_with('-'))
                && rest[1..5].chars().all(|c| c.is_ascii_digit())
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
    distinct_key: String,
}

fn scan_dates(text: &str, min_date: time::Date, max_date: time::Date) -> Vec<(usize, usize)> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut i = 0;

    while i < n {
        if !text.is_char_boundary(i) {
            i += 1;
            continue;
        }

        let left_bounded_digit = i == 0 || !bytes[i - 1].is_ascii_digit();

        // 1. Day-of-week prefixed formats: RFC 2822 ("Wed, 11 Nov 2026") & HTTP dates
        let left_bounded_alpha = i == 0 || !bytes[i - 1].is_ascii_alphabetic();
        if left_bounded_alpha {
            if let Some(dow_len) = parse_day_of_week(&text[i..]) {
                let rest_idx = i + dow_len;
                let rest = &text[rest_idx..];

                // Check Option A: asctime format ("Wed Nov 11 08:12:31 2026")
                if let Some((m, m_len)) = parse_month_name(rest) {
                    let mut pos = m_len;
                    while pos < rest.len() && rest.as_bytes()[pos].is_ascii_whitespace() {
                        pos += 1;
                    }
                    if let Some((d, d_len)) = parse_digits_u32(&rest[pos..]) {
                        if (1..=31).contains(&d) && (d_len == 1 || d_len == 2) {
                            pos += d_len;
                            while pos < rest.len() && rest.as_bytes()[pos].is_ascii_whitespace() {
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
                                while pos < rest.len() && rest.as_bytes()[pos].is_ascii_whitespace()
                                {
                                    pos += 1;
                                }
                                if let Some((y, y_len)) = parse_digits_u32(&rest[pos..]) {
                                    if y_len == 4 && is_bounded_digit_end(rest, pos + y_len) {
                                        if let Some(date) = make_date(y as i32, m, d as u8) {
                                            if date >= min_date && date <= max_date {
                                                let end_idx = rest_idx + pos + y_len;
                                                results.push((i, end_idx));
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

                // Check Option B: RFC 2822 / RFC 1123 / RFC 850 after day-of-week ("11 Nov 2026" or "11-Nov-26")
                if let Some((d, d_len)) = parse_digits_u32(rest) {
                    if (1..=31).contains(&d) && (d_len == 1 || d_len == 2) {
                        let mut pos = d_len;
                        let sep = if pos < rest.len() {
                            rest.as_bytes()[pos]
                        } else {
                            0
                        };
                        if sep == b' ' || sep == b'-' || sep == b'/' || sep == b'.' {
                            pos += 1;
                            if let Some((m, m_len)) = parse_month_name(&rest[pos..]) {
                                pos += m_len;
                                let sep2 = if pos < rest.len() {
                                    rest.as_bytes()[pos]
                                } else {
                                    0
                                };
                                if sep2 == sep || sep2 == b' ' || sep2 == b'-' {
                                    pos += 1;
                                    if let Some((raw_y, y_len)) = parse_digits_u32(&rest[pos..]) {
                                        let y = if y_len == 2 {
                                            2000 + raw_y as i32
                                        } else if y_len == 4 {
                                            raw_y as i32
                                        } else {
                                            0
                                        };
                                        if (y_len == 2 || y_len == 4)
                                            && is_bounded_digit_end(rest, pos + y_len)
                                        {
                                            if let Some(date) = make_date(y, m, d as u8) {
                                                if date >= min_date && date <= max_date {
                                                    let mut end_idx = rest_idx + pos + y_len;
                                                    let extra_time =
                                                        optional_http_time_len(&text[end_idx..]);
                                                    end_idx += extra_time;
                                                    results.push((i, end_idx));
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

        // 2. Month-name starting formats ("Nov 11, 2026", "November 11 2026")
        if left_bounded_alpha {
            if let Some((m, m_len)) = parse_month_name(&text[i..]) {
                let rest_idx = i + m_len;
                let rest = &text[rest_idx..];
                let mut pos = 0;
                while pos < rest.len() && rest.as_bytes()[pos].is_ascii_whitespace() {
                    pos += 1;
                }
                if pos > 0 {
                    if let Some((d, d_len)) = parse_digits_u32(&rest[pos..]) {
                        if (1..=31).contains(&d) && (d_len == 1 || d_len == 2) {
                            pos += d_len;
                            if pos < rest.len() && rest.as_bytes()[pos] == b',' {
                                pos += 1;
                            }
                            while pos < rest.len() && rest.as_bytes()[pos].is_ascii_whitespace() {
                                pos += 1;
                            }
                            if let Some((y, y_len)) = parse_digits_u32(&rest[pos..]) {
                                if y_len == 4 && is_bounded_digit_end(rest, pos + y_len) {
                                    if let Some(date) = make_date(y as i32, m, d as u8) {
                                        if date >= min_date && date <= max_date {
                                            let end_idx = rest_idx + pos + y_len;
                                            results.push((i, end_idx));
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

        // 3. Digit-starting formats (only when left-bounded by non-digit)
        if left_bounded_digit {
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
                    let s = &text[i..i + 8];
                    let y = s[0..4].parse::<i32>().unwrap_or(0);
                    let m = s[4..6].parse::<u8>().unwrap_or(0);
                    let d = s[6..8].parse::<u8>().unwrap_or(0);
                    if check_pair_in_window(y, m, d, min_date, max_date) {
                        results.push((i, i + 8));
                        i += 8;
                        continue;
                    }
                } else if digit_len == 10 {
                    let s = &text[i..i + 10];
                    if let Ok(secs) = s.parse::<i64>() {
                        if let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(secs) {
                            let d = dt.date();
                            if d >= min_date && d <= max_date {
                                results.push((i, i + 10));
                                i += 10;
                                continue;
                            }
                        }
                    }
                } else if digit_len == 13 {
                    let s = &text[i..i + 13];
                    if let Ok(millis) = s.parse::<i64>() {
                        let nanos = (millis as i128).saturating_mul(1_000_000);
                        if let Ok(dt) = time::OffsetDateTime::from_unix_timestamp_nanos(nanos) {
                            let d = dt.date();
                            if d >= min_date && d <= max_date {
                                results.push((i, i + 13));
                                i += 13;
                                continue;
                            }
                        }
                    }
                }
            }

            // Check B: YYYY-MM-DD or YYYY/MM/DD or YYYY-Nov-11 or YYYY/Nov/11
            if digit_len == 4 {
                let y = text[i..i + 4].parse::<i32>().unwrap_or(0);
                if i + 4 < n {
                    let sep = bytes[i + 4];
                    if sep == b'-' || sep == b'/' {
                        let rest = &text[i + 5..];
                        // Sub-case: YYYY-Nov-11
                        if let Some((m, m_len)) = parse_month_name(rest) {
                            if rest.len() > m_len && rest.as_bytes()[m_len] == sep {
                                let after_sep = &rest[m_len + 1..];
                                if let Some((d, d_len)) = parse_digits_u32(after_sep) {
                                    if (d_len == 1 || d_len == 2)
                                        && (1..=31).contains(&d)
                                        && is_bounded_digit_end(after_sep, d_len)
                                    {
                                        if let Some(date) = make_date(y, m, d as u8) {
                                            if date >= min_date && date <= max_date {
                                                let end_idx = i + 5 + m_len + 1 + d_len;
                                                results.push((i, end_idx));
                                                i = end_idx;
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // Sub-case: YYYY-MM-DD or YYYY/MM/DD
                        if let Some((m, m_len)) = parse_digits_u32(rest) {
                            if (m_len == 1 || m_len == 2)
                                && rest.len() > m_len
                                && rest.as_bytes()[m_len] == sep
                            {
                                let after_sep = &rest[m_len + 1..];
                                if let Some((d, d_len)) = parse_digits_u32(after_sep) {
                                    if (d_len == 1 || d_len == 2)
                                        && is_bounded_digit_end(after_sep, d_len)
                                        && check_pair_in_window(
                                            y, m as u8, d as u8, min_date, max_date,
                                        )
                                    {
                                        let end_idx = i + 5 + m_len + 1 + d_len;
                                        results.push((i, end_idx));
                                        i = end_idx;
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check C: D(D) <sep> Month <sep> Year (e.g. "11 November 2026", "11 Nov 2026", "11-Nov-2026")
            if digit_len == 1 || digit_len == 2 {
                let d = text[i..i + digit_len].parse::<u32>().unwrap_or(0);
                if (1..=31).contains(&d) && i + digit_len < n {
                    let sep = bytes[i + digit_len];
                    if sep == b' ' || sep == b'-' || sep == b'/' || sep == b'.' {
                        let rest = &text[i + digit_len + 1..];
                        if let Some((m, m_len)) = parse_month_name(rest) {
                            if rest.len() > m_len {
                                let sep2 = rest.as_bytes()[m_len];
                                if sep2 == sep || sep2 == b' ' || sep2 == b'-' {
                                    let after_sep2 = &rest[m_len + 1..];
                                    if let Some((raw_y, y_len)) = parse_digits_u32(after_sep2) {
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
                                                    let mut end_idx =
                                                        i + digit_len + 1 + m_len + 1 + y_len;
                                                    let extra_time =
                                                        optional_http_time_len(&text[end_idx..]);
                                                    end_idx += extra_time;
                                                    results.push((i, end_idx));
                                                    i = end_idx;
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Check D: US (MM/DD/YYYY, MM-DD-YYYY) and European (DD.MM.YYYY, DD/MM/YYYY)
                        if sep == b'/' || sep == b'-' || sep == b'.' {
                            if let Some((num2, num2_len)) = parse_digits_u32(rest) {
                                if (num2_len == 1 || num2_len == 2)
                                    && rest.len() > num2_len
                                    && rest.as_bytes()[num2_len] == sep
                                {
                                    let after_sep2 = &rest[num2_len + 1..];
                                    if let Some((y, y_len)) = parse_digits_u32(after_sep2) {
                                        if y_len == 4
                                            && is_bounded_digit_end(after_sep2, y_len)
                                            && check_pair_in_window(
                                                y as i32, d as u8, num2 as u8, min_date, max_date,
                                            )
                                        {
                                            let end_idx = i + digit_len + 1 + num2_len + 1 + y_len;
                                            results.push((i, end_idx));
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

        i += 1;
    }

    results
}

/// Check text for real-date sentinels, host names, and host paths (Detector D12).
pub fn check_d12(path: &str, text: &str, opts: &D12Options) -> Vec<Finding> {
    let mut candidates = Vec::new();

    // Calculate tolerance date window
    let min_date = opts
        .real_date
        .checked_sub(time::Duration::days(opts.tolerance_days as i64))
        .unwrap_or(opts.real_date);
    let max_date = opts
        .real_date
        .checked_add(time::Duration::days(opts.tolerance_days as i64))
        .unwrap_or(opts.real_date);

    // 1. Channel "host_path": any opts.host_paths entry as a substring
    for target in &opts.host_paths {
        if target.is_empty() {
            continue;
        }
        for (idx, m) in text.match_indices(target) {
            candidates.push(MatchCandidate {
                start: idx,
                end: idx + m.len(),
                channel: "host_path",
                distinct_key: format!("host_path:{m}"),
            });
        }
    }

    // 2. Channel "host_name": any opts.host_names entry
    // (case-insensitive, bounded by non-alphanumeric, non-dot, non-dash characters)
    let lower_text = text.to_ascii_lowercase();
    for target in &opts.host_names {
        if target.is_empty() {
            continue;
        }
        let lower_target = target.to_ascii_lowercase();
        let target_len = target.len();

        for (idx, _) in lower_text.match_indices(&lower_target) {
            // Check boundary before
            if idx > 0 {
                if let Some(prev) = text[..idx].chars().next_back() {
                    if is_host_char(prev) {
                        continue;
                    }
                }
            }
            // Check boundary after
            let end_idx = idx + target_len;
            if end_idx < text.len() {
                if let Some(next) = text[end_idx..].chars().next() {
                    if is_host_char(next) {
                        continue;
                    }
                }
            }

            candidates.push(MatchCandidate {
                start: idx,
                end: end_idx,
                channel: "host_name",
                distinct_key: format!("host_name:{lower_target}"),
            });
        }
    }

    // 3. Channel "real_date": dates in window across all supported formats
    let date_matches = scan_dates(text, min_date, max_date);
    for (start, end) in date_matches {
        let m = &text[start..end];
        candidates.push(MatchCandidate {
            start,
            end,
            channel: "real_date",
            distinct_key: format!("real_date:{m}"),
        });
    }

    // Sort candidates by start position ascending, then longest match first
    candidates.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| b.end.cmp(&a.end)));

    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for cand in candidates {
        if findings.len() >= 50 {
            break;
        }
        if !seen.insert(cand.distinct_key) {
            continue;
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
