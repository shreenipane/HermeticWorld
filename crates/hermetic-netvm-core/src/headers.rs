//! HTTP header hygiene, request-head parsing, and deterministic HTTP-date parsing.
//!
//! No host clock or timezone APIs are used anywhere in this module.

use std::fmt;

/// Maximum byte length of a single HTTP header name.
pub const MAX_HEADER_NAME_BYTES: usize = 128;

/// Maximum byte length of a single HTTP header value.
pub const MAX_HEADER_VALUE_BYTES: usize = 4096;

/// Maximum number of headers parsed from an incoming request head.
pub const MAX_REQUEST_HEADERS: usize = 64;

/// Maximum number of response headers emitted after hygiene filtering.
pub const MAX_RESPONSE_HEADERS: usize = 16;

/// Maximum byte length of an HTTP request method token.
pub const MAX_METHOD_BYTES: usize = 16;

/// Maximum byte length of an HTTP request target.
pub const MAX_TARGET_BYTES: usize = 4096;

/// Errors returned when parsing HTTP dates or `T_clock` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    InvalidDateFormat,
    InvalidDateComponent,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::InvalidDateFormat => write!(f, "invalid HTTP date format"),
            HeaderError::InvalidDateComponent => write!(f, "invalid HTTP date component"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// Errors returned when parsing an incoming HTTP/1.x request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestParseError {
    InvalidUtf8,
    MalformedRequestLine,
    InvalidMethod,
    InvalidTarget,
    UnsupportedVersion,
    MalformedHeader,
    TooManyHeaders,
}

impl fmt::Display for RequestParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestParseError::InvalidUtf8 => write!(f, "request head is not valid UTF-8"),
            RequestParseError::MalformedRequestLine => write!(f, "malformed HTTP request line"),
            RequestParseError::InvalidMethod => write!(f, "invalid HTTP method token"),
            RequestParseError::InvalidTarget => write!(f, "invalid HTTP request target"),
            RequestParseError::UnsupportedVersion => write!(f, "unsupported HTTP version"),
            RequestParseError::MalformedHeader => write!(f, "malformed HTTP header"),
            RequestParseError::TooManyHeaders => write!(f, "too many HTTP headers"),
        }
    }
}

impl std::error::Error for RequestParseError {}

/// Parsed representation of an HTTP/1.x request head (request line + headers only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRequestHead {
    pub method: String,
    pub target: String,
    pub version: String,
    pub host: Option<String>,
    pub headers: Vec<(String, String)>,
}

/// Returns `true` if `s` is a non-empty valid RFC 9110 HTTP token.
pub fn is_valid_http_token(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_METHOD_BYTES {
        return false;
    }
    s.bytes().all(is_tchar)
}

fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    ) || b.is_ascii_alphanumeric()
}

fn is_valid_header_value(s: &str) -> bool {
    if s.len() > MAX_HEADER_VALUE_BYTES {
        return false;
    }
    s.bytes()
        .all(|b| b == b'\t' || (0x20..=0x7E).contains(&b) || b >= 0x80)
}

/// Parses an HTTP/1.x request head buffer ending at `\r\n\r\n`.
pub fn parse_request_head(head: &[u8]) -> Result<ParsedRequestHead, RequestParseError> {
    let text = std::str::from_utf8(head).map_err(|_| RequestParseError::InvalidUtf8)?;
    let trimmed = text
        .strip_suffix("\r\n\r\n")
        .ok_or(RequestParseError::MalformedRequestLine)?;

    let mut lines = trimmed.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(RequestParseError::MalformedRequestLine)?;

    let mut parts = request_line.split(' ');
    let method = parts
        .next()
        .ok_or(RequestParseError::MalformedRequestLine)?;
    let target = parts
        .next()
        .ok_or(RequestParseError::MalformedRequestLine)?;
    let version = parts
        .next()
        .ok_or(RequestParseError::MalformedRequestLine)?;
    if parts.next().is_some() {
        return Err(RequestParseError::MalformedRequestLine);
    }

    if !is_valid_http_token(method) {
        return Err(RequestParseError::InvalidMethod);
    }
    if target.is_empty()
        || target.len() > MAX_TARGET_BYTES
        || target.bytes().any(|b| b <= 0x20 || b == 0x7F)
    {
        return Err(RequestParseError::InvalidTarget);
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(RequestParseError::UnsupportedVersion);
    }

    let mut headers = Vec::new();
    let mut host = None;

    for line in lines {
        if line.is_empty() {
            return Err(RequestParseError::MalformedHeader);
        }
        if headers.len() >= MAX_REQUEST_HEADERS {
            return Err(RequestParseError::TooManyHeaders);
        }
        let (raw_name, raw_val) = line
            .split_once(':')
            .ok_or(RequestParseError::MalformedHeader)?;
        if raw_name.is_empty()
            || raw_name.len() > MAX_HEADER_NAME_BYTES
            || !raw_name.bytes().all(is_tchar)
        {
            return Err(RequestParseError::MalformedHeader);
        }
        let val = raw_val.trim_matches(|c| c == ' ' || c == '\t');
        if !is_valid_header_value(val) {
            return Err(RequestParseError::MalformedHeader);
        }
        let lower_name = raw_name.to_ascii_lowercase();
        if lower_name == "host" && host.is_none() {
            host = Some(val.to_string());
        }
        headers.push((lower_name, val.to_string()));
    }

    Ok(ParsedRequestHead {
        method: method.to_string(),
        target: target.to_string(),
        version: version.to_string(),
        host,
        headers,
    })
}

/// Filters upstream response headers according to Hermetic World hygiene rules.
///
/// Only these headers are passed back:
/// - `content-type`
/// - `content-length`
/// - `etag`
/// - `last-modified` (only if valid HTTP date and `<= t_clock_epoch_secs`)
/// - `content-encoding`
/// - `accept-ranges`
/// - `content-range`
///
/// `Date`, `Server`, `Set-Cookie`, `Age`, `Via`, all `X-` headers, and any other
/// non-allowlisted headers are unconditionally dropped.
pub fn filter_response_headers(
    upstream_headers: &[(String, String)],
    t_clock_epoch_secs: i64,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut seen_mask: u8 = 0;

    for (raw_name, raw_value) in upstream_headers {
        if out.len() >= MAX_RESPONSE_HEADERS {
            break;
        }
        let name_trimmed = raw_name.trim();
        if name_trimmed.is_empty()
            || name_trimmed.len() > MAX_HEADER_NAME_BYTES
            || !name_trimmed.bytes().all(is_tchar)
        {
            continue;
        }
        let value_trimmed = raw_value.trim_matches(|c| c == ' ' || c == '\t');
        if !is_valid_header_value(value_trimmed) {
            continue;
        }

        let lower = name_trimmed.to_ascii_lowercase();

        // Explicit defense-in-depth block for forbidden headers and any X- prefix.
        if lower.starts_with("x-")
            || matches!(
                lower.as_str(),
                "date" | "server" | "set-cookie" | "age" | "via"
            )
        {
            continue;
        }

        let (bit, canonical_name) = match lower.as_str() {
            "content-type" => (1u8 << 0, "Content-Type"),
            "content-length" => {
                if value_trimmed.is_empty()
                    || !value_trimmed.bytes().all(|b| b.is_ascii_digit())
                    || value_trimmed.parse::<u64>().is_err()
                {
                    continue;
                }
                (1u8 << 1, "Content-Length")
            }
            "etag" => (1u8 << 2, "ETag"),
            "last-modified" => match parse_http_date_epoch_secs(value_trimmed) {
                Ok(ts) if ts <= t_clock_epoch_secs => (1u8 << 3, "Last-Modified"),
                _ => continue,
            },
            "content-encoding" => (1u8 << 4, "Content-Encoding"),
            "accept-ranges" => (1u8 << 5, "Accept-Ranges"),
            "content-range" => (1u8 << 6, "Content-Range"),
            _ => continue,
        };

        // Emit each singleton allowlisted header at most once.
        if (seen_mask & bit) != 0 {
            continue;
        }
        seen_mask |= bit;
        out.push((canonical_name.to_string(), value_trimmed.to_string()));
    }

    out
}

/// Parses a `T_clock` configuration value, accepting either Unix epoch seconds
/// (e.g. `"1700006400"`) or an HTTP-date string (e.g. `"Wed, 15 Nov 2023 00:00:00 GMT"`).
pub fn parse_t_clock_str(input: &str) -> Result<i64, HeaderError> {
    let s = input.trim();
    if let Ok(epoch) = s.parse::<i64>() {
        return Ok(epoch);
    }
    parse_http_date_epoch_secs(s)
}

/// Parses an HTTP-date string (IMF-fixdate, RFC 850, or ANSI C `asctime`) into
/// Unix epoch seconds (UTC) using deterministic integer calendar math.
pub fn parse_http_date_epoch_secs(input: &str) -> Result<i64, HeaderError> {
    let s = input.trim();
    if let Some((_dow, rest)) = s.split_once(',') {
        let rest = rest.trim();
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() == 5 && parts[4] == "GMT" {
            // IMF-fixdate: "15 Nov 2023 00:00:00 GMT"
            let day: u32 = parts[0]
                .parse()
                .map_err(|_| HeaderError::InvalidDateComponent)?;
            let month = parse_month_name(parts[1])?;
            let year: i64 = parts[2]
                .parse()
                .map_err(|_| HeaderError::InvalidDateComponent)?;
            let (hour, min, sec) = parse_hms(parts[3])?;
            civil_to_epoch_secs(year, month, day, hour, min, sec)
        } else if parts.len() == 3 && parts[2] == "GMT" && parts[0].contains('-') {
            // RFC 850: "06-Nov-94 08:49:37 GMT"
            let (day, month, year) = parse_rfc850_date(parts[0])?;
            let (hour, min, sec) = parse_hms(parts[1])?;
            civil_to_epoch_secs(year, month, day, hour, min, sec)
        } else {
            Err(HeaderError::InvalidDateFormat)
        }
    } else {
        // ANSI C asctime format: "Sun Nov  6 08:49:37 1994"
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(HeaderError::InvalidDateFormat);
        }
        let month = parse_month_name(parts[1])?;
        let day: u32 = parts[2]
            .parse()
            .map_err(|_| HeaderError::InvalidDateComponent)?;
        let (hour, min, sec) = parse_hms(parts[3])?;
        let year: i64 = parts[4]
            .parse()
            .map_err(|_| HeaderError::InvalidDateComponent)?;
        civil_to_epoch_secs(year, month, day, hour, min, sec)
    }
}

fn parse_rfc850_date(date_part: &str) -> Result<(u32, u32, i64), HeaderError> {
    let segs: Vec<&str> = date_part.split('-').collect();
    if segs.len() != 3 {
        return Err(HeaderError::InvalidDateFormat);
    }
    let day: u32 = segs[0]
        .parse()
        .map_err(|_| HeaderError::InvalidDateComponent)?;
    let month = parse_month_name(segs[1])?;
    let yy: i64 = segs[2]
        .parse()
        .map_err(|_| HeaderError::InvalidDateComponent)?;
    if !(0..=99).contains(&yy) {
        return Err(HeaderError::InvalidDateComponent);
    }
    let year = if yy >= 70 { 1900 + yy } else { 2000 + yy };
    Ok((day, month, year))
}

fn parse_month_name(m: &str) -> Result<u32, HeaderError> {
    match m {
        "Jan" => Ok(1),
        "Feb" => Ok(2),
        "Mar" => Ok(3),
        "Apr" => Ok(4),
        "May" => Ok(5),
        "Jun" => Ok(6),
        "Jul" => Ok(7),
        "Aug" => Ok(8),
        "Sep" => Ok(9),
        "Oct" => Ok(10),
        "Nov" => Ok(11),
        "Dec" => Ok(12),
        _ => Err(HeaderError::InvalidDateComponent),
    }
}

fn parse_hms(hms: &str) -> Result<(u32, u32, u32), HeaderError> {
    let segs: Vec<&str> = hms.split(':').collect();
    if segs.len() != 3 || segs[0].len() != 2 || segs[1].len() != 2 || segs[2].len() != 2 {
        return Err(HeaderError::InvalidDateFormat);
    }
    let hour: u32 = segs[0]
        .parse()
        .map_err(|_| HeaderError::InvalidDateComponent)?;
    let min: u32 = segs[1]
        .parse()
        .map_err(|_| HeaderError::InvalidDateComponent)?;
    let sec: u32 = segs[2]
        .parse()
        .map_err(|_| HeaderError::InvalidDateComponent)?;
    if hour > 23 || min > 59 || sec > 60 {
        return Err(HeaderError::InvalidDateComponent);
    }
    Ok((hour, min, sec.min(59)))
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Converts a UTC civil date/time to Unix epoch seconds using Howard Hinnant's
/// proleptic Gregorian algorithm.
fn civil_to_epoch_secs(
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
) -> Result<i64, HeaderError> {
    if !(1900..=9999).contains(&year) || !(1..=12).contains(&month) {
        return Err(HeaderError::InvalidDateComponent);
    }
    let max_day = days_in_month(year, month);
    if day == 0 || day > max_day {
        return Err(HeaderError::InvalidDateComponent);
    }

    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = i64::from(month);
    let d = i64::from(day);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days_since_unix_epoch = era * 146_097 + doe - 719_468;

    let secs = days_since_unix_epoch
        .checked_mul(86_400)
        .and_then(|s| s.checked_add(i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec)))
        .ok_or(HeaderError::InvalidDateComponent)?;
    Ok(secs)
}
