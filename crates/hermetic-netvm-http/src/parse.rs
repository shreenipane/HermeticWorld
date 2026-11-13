use std::fmt;

/// Maximum total byte size of an HTTP/1.1 request head (request line + headers + empty line).
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Maximum number of header fields allowed in a single request head.
pub const MAX_HEADERS: usize = 100;
/// Maximum byte length of the request target.
pub const MAX_TARGET_BYTES: usize = 8 * 1024;
/// Maximum byte length of a header field name.
pub const MAX_HEADER_NAME_BYTES: usize = 64;
/// Maximum byte length of a header field value (after trimming).
pub const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;
/// Maximum number of path segments checked during normalisation.
pub const MAX_PATH_SEGMENTS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Lower-cased canonical header name.
    pub name: String,
    /// Trimmed header value.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTarget {
    /// Scheme of an absolute-form target; must match the intercepted transport.
    pub authority_scheme: Option<String>,
    /// Host extracted from absolute-form target (lower-cased), if present.
    pub authority_host: Option<String>,
    /// Optional port extracted from absolute-form target, if present.
    pub authority_port: Option<u16>,
    /// Normalised path starting with `/`.
    pub path: String,
    /// Raw query string (without `?`), kept byte-for-byte, if `?` was present.
    pub query: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub target: RequestTarget,
    pub headers: Vec<Header>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    EmptyRequest,
    IncompleteHead,
    HeadTooLarge,
    BareLineFeed,
    BareCarriageReturn,
    NonAsciiOrNul,
    InvalidRequestLine,
    InvalidMethod,
    Http10Unsupported,
    Http2PrefaceUnsupported,
    UnsupportedHttpVersion,
    TargetTooLarge,
    UnsupportedTargetForm,
    InvalidTargetEncoding,
    ForbiddenPathCharacter,
    DotSegmentInPath,
    TooManyHeaders,
    ObsFoldForbidden,
    InvalidHeaderLine,
    InvalidHeaderName,
    HeaderNameTooLarge,
    InvalidHeaderValue,
    HeaderValueTooLarge,
    TransferEncodingForbidden,
    DuplicateContentLength,
    InvalidContentLength,
    NonZeroContentLength,
    DuplicateHost,
    MissingHost,
    InvalidHostHeader,
    HostAuthorityMismatch,
    ExpectHeaderForbidden,
    UpgradeForbidden,
    InvalidConnectionHeader,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for HttpError {}

#[inline]
pub(crate) fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

#[inline]
fn is_unreserved(b: u8) -> bool {
    matches!(
        b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    )
}

#[inline]
fn is_vchar_or_wsp(b: u8) -> bool {
    b == b'\t' || (0x20..=0x7E).contains(&b)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Validates global byte invariants and splits into CRLF-delimited lines up to the empty line.
fn split_crlf_lines(bytes: &[u8]) -> Result<Vec<&[u8]>, HttpError> {
    if bytes.is_empty() {
        return Err(HttpError::EmptyRequest);
    }
    if bytes.len() > MAX_HEAD_BYTES {
        return Err(HttpError::HeadTooLarge);
    }

    // Check ASCII/NUL and strict CRLF pairing across the entire provided slice.
    let mut i = 0usize;
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut line_start = 0usize;
    let mut found_end = false;

    while i < bytes.len() {
        let b = bytes[i];
        if b == 0x00 || b >= 0x80 {
            return Err(HttpError::NonAsciiOrNul);
        }
        if b == b'\n' {
            return Err(HttpError::BareLineFeed);
        }
        if b == b'\r' {
            let next = bytes.get(i + 1).copied();
            if next != Some(b'\n') {
                return Err(HttpError::BareCarriageReturn);
            }
            let line = bytes
                .get(line_start..i)
                .ok_or(HttpError::InvalidRequestLine)?;
            if line.is_empty() {
                // Empty line marks end of head.
                found_end = true;
                // Ensure no trailing bytes after the empty line.
                if i + 2 != bytes.len() {
                    return Err(HttpError::InvalidRequestLine);
                }
                break;
            }
            if lines.len() > MAX_HEADERS {
                // 1 request line + at most MAX_HEADERS header lines
                return Err(HttpError::TooManyHeaders);
            }
            lines.push(line);
            i += 2;
            line_start = i;
            continue;
        }
        i += 1;
    }

    if !found_end {
        return Err(HttpError::IncompleteHead);
    }

    Ok(lines)
}

fn parse_authority(auth: &[u8]) -> Result<(String, Option<u16>), HttpError> {
    if auth.is_empty() {
        return Err(HttpError::InvalidHostHeader);
    }
    // Reject userinfo (`@`) or whitespace
    if auth.contains(&b'@') {
        return Err(HttpError::InvalidHostHeader);
    }

    let (host_bytes, port_opt) = if auth.starts_with(b"[") {
        // IPv6 literal: [::1] or [::1]:8080
        let close = auth
            .iter()
            .position(|&b| b == b']')
            .ok_or(HttpError::InvalidHostHeader)?;
        let host_part = auth.get(..=close).ok_or(HttpError::InvalidHostHeader)?;
        if host_part.len() < 3 {
            return Err(HttpError::InvalidHostHeader);
        }
        let literal = host_part
            .get(1..close)
            .ok_or(HttpError::InvalidHostHeader)?;
        let literal = std::str::from_utf8(literal).map_err(|_| HttpError::InvalidHostHeader)?;
        literal
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| HttpError::InvalidHostHeader)?;
        let rest = auth.get(close + 1..).ok_or(HttpError::InvalidHostHeader)?;
        if rest.is_empty() {
            (host_part, None)
        } else if let Some(port_bytes) = rest.strip_prefix(b":") {
            (host_part, Some(parse_port(port_bytes)?))
        } else {
            return Err(HttpError::InvalidHostHeader);
        }
    } else if let Some(colon) = auth.iter().position(|&b| b == b':') {
        let host_part = auth.get(..colon).ok_or(HttpError::InvalidHostHeader)?;
        let port_bytes = auth.get(colon + 1..).ok_or(HttpError::InvalidHostHeader)?;
        (host_part, Some(parse_port(port_bytes)?))
    } else {
        (auth, None)
    };

    if host_bytes.is_empty() {
        return Err(HttpError::InvalidHostHeader);
    }

    if !host_bytes.starts_with(b"[") {
        // Validate reg-name / IPv4 characters: unreserved + sub-delims, no empty labels or leading/trailing dots
        for &b in host_bytes {
            let ok = b.is_ascii_alphanumeric() || b == b'.' || b == b'-';
            if !ok {
                return Err(HttpError::InvalidHostHeader);
            }
        }
        if host_bytes.starts_with(b".")
            || host_bytes.ends_with(b".")
            || host_bytes.windows(2).any(|w| w == b"..")
        {
            return Err(HttpError::InvalidHostHeader);
        }
    }

    let host_str = std::str::from_utf8(host_bytes)
        .map_err(|_| HttpError::InvalidHostHeader)?
        .to_ascii_lowercase();
    Ok((host_str, port_opt))
}

fn parse_port(bytes: &[u8]) -> Result<u16, HttpError> {
    if bytes.is_empty() || bytes.len() > 5 {
        return Err(HttpError::InvalidHostHeader);
    }
    let mut acc: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return Err(HttpError::InvalidHostHeader);
        }
        acc = acc
            .checked_mul(10)
            .and_then(|v| v.checked_add((b - b'0') as u32))
            .ok_or(HttpError::InvalidHostHeader)?;
    }
    if acc == 0 || acc > u16::MAX as u32 {
        return Err(HttpError::InvalidHostHeader);
    }
    Ok(acc as u16)
}

fn normalize_path(raw_path: &[u8]) -> Result<String, HttpError> {
    if !raw_path.starts_with(b"/") {
        return Err(HttpError::UnsupportedTargetForm);
    }
    if raw_path.contains(&b'#') {
        return Err(HttpError::InvalidTargetEncoding);
    }
    if raw_path.windows(2).any(|pair| pair == b"//") {
        return Err(HttpError::ForbiddenPathCharacter);
    }

    let mut decoded: Vec<u8> = Vec::with_capacity(raw_path.len());
    let mut i = 0usize;
    while i < raw_path.len() {
        let b = raw_path[i];
        if b == b'\\' || b == 0x00 {
            return Err(HttpError::ForbiddenPathCharacter);
        }
        if b == b'%' {
            let h1 = raw_path
                .get(i + 1)
                .copied()
                .and_then(hex_val)
                .ok_or(HttpError::InvalidTargetEncoding)?;
            let h2 = raw_path
                .get(i + 2)
                .copied()
                .and_then(hex_val)
                .ok_or(HttpError::InvalidTargetEncoding)?;
            let val = (h1 << 4) | h2;
            if val == 0x00 || val == b'/' || val == b'\\' {
                return Err(HttpError::ForbiddenPathCharacter);
            }
            if is_unreserved(val) {
                decoded.push(val);
            } else {
                // Keep non-unreserved valid percent-encodings uppercase-normalised
                decoded.push(b'%');
                let upper = format!("{:02X}", val);
                decoded.extend_from_slice(upper.as_bytes());
            }
            i += 3;
            continue;
        }
        // Reject raw control chars or spaces in target
        if b <= 0x20 || b >= 0x7F {
            return Err(HttpError::InvalidTargetEncoding);
        }
        decoded.push(b);
        i += 1;
    }

    // Check segments for "." or ".."
    let mut seg_count = 0usize;
    for seg in decoded.split(|&b| b == b'/') {
        seg_count = seg_count.saturating_add(1);
        if seg_count > MAX_PATH_SEGMENTS {
            return Err(HttpError::TargetTooLarge);
        }
        if seg == b"." || seg == b".." {
            return Err(HttpError::DotSegmentInPath);
        }
    }

    let out = String::from_utf8(decoded).map_err(|_| HttpError::InvalidTargetEncoding)?;
    if !out.starts_with('/') {
        return Err(HttpError::UnsupportedTargetForm);
    }
    Ok(out)
}

fn validate_query(raw_query: &[u8]) -> Result<String, HttpError> {
    if raw_query.contains(&b'#') {
        return Err(HttpError::InvalidTargetEncoding);
    }
    let mut i = 0usize;
    while i < raw_query.len() {
        let b = raw_query[i];
        if b <= 0x20 || b >= 0x7F {
            return Err(HttpError::InvalidTargetEncoding);
        }
        if b == b'%' {
            let h1 = raw_query
                .get(i + 1)
                .copied()
                .and_then(hex_val)
                .ok_or(HttpError::InvalidTargetEncoding)?;
            let h2 = raw_query
                .get(i + 2)
                .copied()
                .and_then(hex_val)
                .ok_or(HttpError::InvalidTargetEncoding)?;
            let val = (h1 << 4) | h2;
            if val == 0x00 {
                return Err(HttpError::ForbiddenPathCharacter);
            }
            i += 3;
            continue;
        }
        i += 1;
    }
    std::str::from_utf8(raw_query)
        .map(|s| s.to_owned())
        .map_err(|_| HttpError::InvalidTargetEncoding)
}

fn parse_target(raw: &[u8]) -> Result<RequestTarget, HttpError> {
    if raw.is_empty() {
        return Err(HttpError::InvalidRequestLine);
    }
    if raw.len() > MAX_TARGET_BYTES {
        return Err(HttpError::TargetTooLarge);
    }
    if raw == b"*" {
        return Err(HttpError::UnsupportedTargetForm);
    }

    if raw.starts_with(b"/") {
        let (path_bytes, query_opt) = match raw.iter().position(|&b| b == b'?') {
            Some(qpos) => {
                let p = raw.get(..qpos).ok_or(HttpError::InvalidRequestLine)?;
                let q = raw.get(qpos + 1..).ok_or(HttpError::InvalidRequestLine)?;
                (p, Some(validate_query(q)?))
            }
            None => (raw, None),
        };
        let path = normalize_path(path_bytes)?;
        return Ok(RequestTarget {
            authority_scheme: None,
            authority_host: None,
            authority_port: None,
            path,
            query: query_opt,
        });
    }

    // Check for absolute-form http://... or https://...
    let (scheme, rest) = if let Some(r) = raw.strip_prefix(b"http://") {
        ("http", r)
    } else if let Some(r) = raw.strip_prefix(b"https://") {
        ("https", r)
    } else {
        // authority-form (e.g. example.com:443) or other scheme
        return Err(HttpError::UnsupportedTargetForm);
    };

    // Split authority from path/query
    let auth_end = rest
        .iter()
        .position(|&b| b == b'/' || b == b'?')
        .unwrap_or(rest.len());
    let auth_bytes = rest.get(..auth_end).ok_or(HttpError::InvalidRequestLine)?;
    let (auth_host, auth_port) = parse_authority(auth_bytes)?;

    let tail = rest.get(auth_end..).unwrap_or(b"");
    let (path_bytes, query_opt) = if tail.is_empty() {
        (&b"/"[..], None)
    } else if let Some(q_tail) = tail.strip_prefix(b"?") {
        (&b"/"[..], Some(validate_query(q_tail)?))
    } else {
        match tail.iter().position(|&b| b == b'?') {
            Some(qpos) => {
                let p = tail.get(..qpos).ok_or(HttpError::InvalidRequestLine)?;
                let q = tail.get(qpos + 1..).ok_or(HttpError::InvalidRequestLine)?;
                (p, Some(validate_query(q)?))
            }
            None => (tail, None),
        }
    };

    let path = normalize_path(path_bytes)?;
    Ok(RequestTarget {
        authority_scheme: Some(scheme.to_owned()),
        authority_host: Some(auth_host),
        authority_port: auth_port,
        path,
        query: query_opt,
    })
}

fn trim_ows(mut s: &[u8]) -> &[u8] {
    while let Some(&first) = s.first() {
        if first == b' ' || first == b'\t' {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(&last) = s.last() {
        if last == b' ' || last == b'\t' {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    s
}

/// Parses a single HTTP/1.1 request head with strict anti-smuggling validation.
pub fn parse_request_head(bytes: &[u8]) -> Result<RequestHead, HttpError> {
    let lines = split_crlf_lines(bytes)?;
    let req_line = *lines.first().ok_or(HttpError::EmptyRequest)?;

    if req_line == b"PRI * HTTP/2.0" {
        return Err(HttpError::Http2PrefaceUnsupported);
    }

    // Request line must have exact single SP delimiters: METHOD SP REQUEST-TARGET SP HTTP-VERSION
    let first_sp = req_line
        .iter()
        .position(|&b| b == b' ')
        .ok_or(HttpError::InvalidRequestLine)?;
    let second_sp_rel = req_line
        .get(first_sp + 1..)
        .and_then(|s| s.iter().position(|&b| b == b' '))
        .ok_or(HttpError::InvalidRequestLine)?;
    let second_sp = first_sp + 1 + second_sp_rel;

    let method_bytes = req_line
        .get(..first_sp)
        .ok_or(HttpError::InvalidRequestLine)?;
    let target_bytes = req_line
        .get(first_sp + 1..second_sp)
        .ok_or(HttpError::InvalidRequestLine)?;
    let version_bytes = req_line
        .get(second_sp + 1..)
        .ok_or(HttpError::InvalidRequestLine)?;

    // Reject extra spaces in method, target, or version
    if method_bytes.is_empty() || !method_bytes.iter().all(|&b| is_tchar(b)) {
        return Err(HttpError::InvalidMethod);
    }
    if target_bytes.is_empty() || target_bytes.contains(&b' ') {
        return Err(HttpError::InvalidRequestLine);
    }
    if version_bytes.contains(&b' ') {
        return Err(HttpError::InvalidRequestLine);
    }

    if version_bytes == b"HTTP/1.0" {
        return Err(HttpError::Http10Unsupported);
    }
    if version_bytes != b"HTTP/1.1" {
        return Err(HttpError::UnsupportedHttpVersion);
    }

    let method = std::str::from_utf8(method_bytes)
        .map_err(|_| HttpError::InvalidMethod)?
        .to_owned();
    let target = parse_target(target_bytes)?;

    let header_lines = lines.get(1..).unwrap_or(&[]);
    if header_lines.len() > MAX_HEADERS {
        return Err(HttpError::TooManyHeaders);
    }

    let mut headers: Vec<Header> = Vec::with_capacity(header_lines.len());
    let mut host_count = 0usize;
    let mut host_header_val: Option<String> = None;
    let mut cl_count = 0usize;

    for &hline in header_lines {
        if matches!(hline.first(), Some(b' ' | b'\t')) {
            return Err(HttpError::ObsFoldForbidden);
        }
        let colon = hline
            .iter()
            .position(|&b| b == b':')
            .ok_or(HttpError::InvalidHeaderLine)?;
        let name_bytes = hline.get(..colon).ok_or(HttpError::InvalidHeaderLine)?;
        if name_bytes.is_empty() {
            return Err(HttpError::InvalidHeaderName);
        }
        if name_bytes.len() > MAX_HEADER_NAME_BYTES {
            return Err(HttpError::HeaderNameTooLarge);
        }
        // Strict tchar check also rejects whitespace before colon (e.g. "Host : a")
        if !name_bytes.iter().all(|&b| is_tchar(b)) {
            return Err(HttpError::InvalidHeaderName);
        }

        let raw_val = hline.get(colon + 1..).ok_or(HttpError::InvalidHeaderLine)?;
        for &b in raw_val {
            if !is_vchar_or_wsp(b) {
                return Err(HttpError::InvalidHeaderValue);
            }
        }
        let trimmed_val = trim_ows(raw_val);
        if trimmed_val.len() > MAX_HEADER_VALUE_BYTES {
            return Err(HttpError::HeaderValueTooLarge);
        }

        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| HttpError::InvalidHeaderName)?
            .to_ascii_lowercase();
        let value = std::str::from_utf8(trimmed_val)
            .map_err(|_| HttpError::InvalidHeaderValue)?
            .to_owned();

        headers.push(Header { name, value });
    }

    for h in &headers {
        if h.name == "transfer-encoding" {
            return Err(HttpError::TransferEncodingForbidden);
        }
    }

    for h in &headers {
        match h.name.as_str() {
            "content-length" => {
                cl_count += 1;
                if cl_count > 1 {
                    return Err(HttpError::DuplicateContentLength);
                }
                if h.value.is_empty() || !h.value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(HttpError::InvalidContentLength);
                }
                if h.value.bytes().any(|b| b != b'0') {
                    return Err(HttpError::NonZeroContentLength);
                }
            }
            "host" => {
                host_count += 1;
                if host_count > 1 {
                    return Err(HttpError::DuplicateHost);
                }
                host_header_val = Some(h.value.clone());
            }
            "expect" => {
                return Err(HttpError::ExpectHeaderForbidden);
            }
            "upgrade" => {
                return Err(HttpError::UpgradeForbidden);
            }
            "connection" => {
                for tok in h.value.split(',') {
                    let t = tok.trim_matches([' ', '\t']);
                    if t.is_empty() || !t.bytes().all(is_tchar) {
                        return Err(HttpError::InvalidConnectionHeader);
                    }
                    if t.eq_ignore_ascii_case("upgrade") {
                        return Err(HttpError::UpgradeForbidden);
                    }
                    // Nominating an end-to-end or framing header makes its meaning ambiguous.
                    if matches!(
                        t.to_ascii_lowercase().as_str(),
                        "host"
                            | "content-length"
                            | "transfer-encoding"
                            | "connection"
                            | "accept"
                            | "accept-encoding"
                            | "range"
                            | "if-none-match"
                            | "if-modified-since"
                            | "user-agent"
                    ) {
                        return Err(HttpError::InvalidConnectionHeader);
                    }
                }
            }
            _ => {}
        }
    }

    let raw_host = host_header_val.ok_or(HttpError::MissingHost)?;
    let (parsed_host, parsed_port) = parse_authority(raw_host.as_bytes())?;

    if let Some(ref auth_host) = target.authority_host {
        if auth_host != &parsed_host || target.authority_port != parsed_port {
            return Err(HttpError::HostAuthorityMismatch);
        }
    }

    Ok(RequestHead {
        method,
        target,
        headers,
    })
}
