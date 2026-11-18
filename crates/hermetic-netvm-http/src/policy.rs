use std::collections::BTreeSet;

use serde::Serialize;

use crate::parse::{Header, RequestHead};

/// Maximum number of tokens evaluated in a single `Accept-Encoding` header.
pub const MAX_ACCEPT_ENCODING_TOKENS: usize = 32;
/// Maximum byte length of a single `Range` header accepted for parsing.
pub const MAX_RANGE_HEADER_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn expected_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForwardHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForwardRequest {
    pub dropped_headers: Vec<String>,
    pub headers: Vec<ForwardHeader>,
    pub host: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Forward(ForwardRequest),
    MethodNotAllowed,
    Reject(String),
}

fn split_host_and_port(raw_host: &str) -> Result<(String, Option<u16>), &'static str> {
    if raw_host.starts_with('[') {
        let close = raw_host.find(']').ok_or("invalid_host")?;
        let host = raw_host
            .get(..=close)
            .ok_or("invalid_host")?
            .to_ascii_lowercase();
        let rest = raw_host.get(close + 1..).ok_or("invalid_host")?;
        if rest.is_empty() {
            Ok((host, None))
        } else if let Some(p_str) = rest.strip_prefix(':') {
            let p: u16 = p_str.parse().map_err(|_| "invalid_port")?;
            Ok((host, Some(p)))
        } else {
            Err("invalid_host")
        }
    } else if let Some(colon) = raw_host.find(':') {
        let host = raw_host
            .get(..colon)
            .ok_or("invalid_host")?
            .to_ascii_lowercase();
        let p_str = raw_host.get(colon + 1..).ok_or("invalid_host")?;
        let p: u16 = p_str.parse().map_err(|_| "invalid_port")?;
        Ok((host, Some(p)))
    } else {
        Ok((raw_host.to_ascii_lowercase(), None))
    }
}

fn filter_accept_encoding(headers: &[Header]) -> Result<Option<String>, &'static str> {
    let Some(header) = headers.iter().find(|h| h.name == "accept-encoding") else {
        return Ok(None);
    };
    if header.value.is_empty() {
        return Ok(Some("identity".to_owned()));
    }
    let mut seen = BTreeSet::new();
    let mut kept = Vec::new();
    let mut identity = None;
    let mut gzip = None;
    let mut wildcard = None;
    for (idx, part) in header.value.split(',').enumerate() {
        if idx >= MAX_ACCEPT_ENCODING_TOKENS {
            return Err("too_many_accept_encoding_tokens");
        }
        let mut fields = part.trim().split(';');
        let coding = fields
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if coding.is_empty()
            || !coding.bytes().all(crate::parse::is_tchar)
            || !seen.insert(coding.clone())
        {
            return Err("invalid_accept_encoding");
        }
        let acceptable = if let Some(parameter) = fields.next() {
            let (name, value) = parameter
                .trim()
                .split_once('=')
                .ok_or("invalid_accept_encoding")?;
            let mut number = value.split('.');
            let whole = number.next().unwrap_or_default();
            let fraction = number.next();
            if !name.eq_ignore_ascii_case("q")
                || !matches!(whole, "0" | "1")
                || number.next().is_some()
                || fields.next().is_some()
                || fraction.is_some_and(|f| {
                    f.len() > 3
                        || !f.bytes().all(|b| b.is_ascii_digit())
                        || (whole == "1" && f.bytes().any(|b| b != b'0'))
                })
            {
                return Err("invalid_accept_encoding");
            }
            whole == "1" || fraction.is_some_and(|f| f.bytes().any(|b| b != b'0'))
        } else {
            true
        };
        match coding.as_str() {
            "identity" => identity = Some(acceptable),
            "gzip" => gzip = Some(acceptable),
            "*" => wildcard = Some(acceptable),
            _ => continue,
        }
        if coding != "*" {
            kept.push(if acceptable {
                coding
            } else {
                format!("{coding};q=0")
            });
        }
    }
    // Unsupported codings are removed, but explicit exclusions must survive filtering.
    if wildcard == Some(false) {
        if identity.is_none() {
            kept.push("identity;q=0".to_owned());
        }
        if gzip.is_none() {
            kept.push("gzip;q=0".to_owned());
        }
    }
    let identity_ok = identity.unwrap_or(wildcard != Some(false));
    let gzip_ok = gzip.unwrap_or(wildcard == Some(true));
    if !identity_ok && !gzip_ok {
        return Err("no_acceptable_encoding");
    }
    if identity_ok && identity.is_none() {
        kept.push("identity".to_owned());
    }
    if gzip_ok && gzip.is_none() {
        kept.push("gzip".to_owned());
    }
    Ok(Some(kept.join(", ")))
}

/// Validates a single byte range of the exact form `bytes=a-b` where `a` and `b` are ASCII digits
/// and `a <= b`. Multi-range, suffix-byte-range (`bytes=-500`), or open-ended (`bytes=500-`) are dropped.
fn filter_single_range(headers: &[Header]) -> Option<String> {
    let mut found: Option<String> = None;
    for h in headers.iter().filter(|h| h.name == "range") {
        if found.is_some() {
            // Multiple Range headers are ambiguous; drop.
            return None;
        }
        let v = h.value.trim();
        if v.len() > MAX_RANGE_HEADER_BYTES {
            return None;
        }
        let spec = v.strip_prefix("bytes=")?;
        if spec.contains(',') {
            return None;
        }
        let dash = spec.find('-')?;
        let a_str = spec.get(..dash)?;
        let b_str = spec.get(dash + 1..)?;
        if a_str.is_empty() || b_str.is_empty() {
            return None;
        }
        if !a_str.bytes().all(|b| b.is_ascii_digit()) || !b_str.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let a: u64 = a_str.parse().ok()?;
        let b: u64 = b_str.parse().ok()?;
        if a > b {
            return None;
        }
        found = Some(format!("bytes={}-{}", a, b));
    }
    found
}

fn collect_single_header(headers: &[Header], target_name: &str) -> Option<String> {
    let mut iter = headers.iter().filter(|h| h.name == target_name);
    let first = iter.next()?;
    if iter.next().is_some() {
        // Ambiguous duplicate conditional headers are dropped.
        return None;
    }
    Some(first.value.clone())
}

/// Evaluates forwarding policy for a validated `RequestHead`.
pub fn decide(head: &RequestHead, allowed_hosts: &BTreeSet<String>, scheme: Scheme) -> Decision {
    let is_git_upload_pack = head.method == "POST"
        && (head.target.path == "/git-upload-pack"
            || head.target.path.ends_with("/git-upload-pack"));

    if head.method != "GET" && head.method != "HEAD" && !is_git_upload_pack {
        return Decision::MethodNotAllowed;
    }

    let expected_scheme = match scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };
    if head
        .target
        .authority_scheme
        .as_deref()
        .is_some_and(|s| s != expected_scheme)
    {
        return Decision::Reject("scheme_mismatch".to_owned());
    }
    let mut seen = BTreeSet::new();
    for header in &head.headers {
        if matches!(
            header.name.as_str(),
            "accept"
                | "accept-encoding"
                | "range"
                | "if-none-match"
                | "if-modified-since"
                | "user-agent"
                | "content-type"
                | "git-protocol"
        ) && !seen.insert(&header.name)
        {
            return Decision::Reject("duplicate_forward_header".to_owned());
        }
    }

    if is_git_upload_pack {
        if let Some(ct) = head.headers.iter().find(|h| h.name == "content-type") {
            if !ct
                .value
                .eq_ignore_ascii_case("application/x-git-upload-pack-request")
            {
                return Decision::Reject("invalid_content_type".to_owned());
            }
        }
    }

    let raw_host = match head.headers.iter().find(|h| h.name == "host") {
        Some(h) => h.value.as_str(),
        None => return Decision::Reject("missing_host".to_owned()),
    };

    let (host, port_opt) = match split_host_and_port(raw_host) {
        Ok(hp) => hp,
        Err(reason) => return Decision::Reject(reason.to_owned()),
    };

    if let Some(port) = port_opt {
        if port != scheme.expected_port() {
            return Decision::Reject("disallowed_port".to_owned());
        }
    }

    if !allowed_hosts.contains(&host) {
        return Decision::Reject("host_not_allowed".to_owned());
    }

    let mut out_headers: Vec<ForwardHeader> = Vec::new();

    if is_git_upload_pack {
        // Output headers for git-upload-pack POST in fixed order:
        // 1. accept
        if let Some(val) = collect_single_header(&head.headers, "accept") {
            out_headers.push(ForwardHeader {
                name: "accept".to_owned(),
                value: val,
            });
        }
        // 2. content-length
        if let Some(val) = collect_single_header(&head.headers, "content-length") {
            out_headers.push(ForwardHeader {
                name: "content-length".to_owned(),
                value: val,
            });
        }
        // 3. content-type
        if let Some(val) = collect_single_header(&head.headers, "content-type") {
            out_headers.push(ForwardHeader {
                name: "content-type".to_owned(),
                value: val,
            });
        }
        // 4. git-protocol
        if let Some(val) = collect_single_header(&head.headers, "git-protocol") {
            out_headers.push(ForwardHeader {
                name: "git-protocol".to_owned(),
                value: val,
            });
        }
        // 5. user-agent (replaced by fixed string "hermetic-world/1")
        if head.headers.iter().any(|h| h.name == "user-agent") {
            out_headers.push(ForwardHeader {
                name: "user-agent".to_owned(),
                value: "hermetic-world/1".to_owned(),
            });
        }
    } else {
        // Fixed output order for GET/HEAD:
        // 1. accept
        if let Some(val) = collect_single_header(&head.headers, "accept") {
            out_headers.push(ForwardHeader {
                name: "accept".to_owned(),
                value: val,
            });
        }
        // 2. accept-encoding (only identity or gzip)
        let encoding = match filter_accept_encoding(&head.headers) {
            Ok(value) => value,
            Err(reason) => return Decision::Reject(reason.to_owned()),
        };
        if let Some(val) = encoding {
            out_headers.push(ForwardHeader {
                name: "accept-encoding".to_owned(),
                value: val,
            });
        }
        // 3. range (single bytes=a-b only)
        if let Some(val) = filter_single_range(&head.headers) {
            out_headers.push(ForwardHeader {
                name: "range".to_owned(),
                value: val,
            });
        }
        // 4. if-none-match
        if let Some(val) = collect_single_header(&head.headers, "if-none-match") {
            out_headers.push(ForwardHeader {
                name: "if-none-match".to_owned(),
                value: val,
            });
        }
        // 5. if-modified-since
        if let Some(val) = collect_single_header(&head.headers, "if-modified-since") {
            out_headers.push(ForwardHeader {
                name: "if-modified-since".to_owned(),
                value: val,
            });
        }
        // 6. user-agent (when present, replaced by fixed string "hermetic-world/1")
        if head.headers.iter().any(|h| h.name == "user-agent") {
            out_headers.push(ForwardHeader {
                name: "user-agent".to_owned(),
                value: "hermetic-world/1".to_owned(),
            });
        }
    }

    // Collect names (never values) of every dropped header, deterministically sorted & deduplicated.
    let mut dropped_set: BTreeSet<String> = BTreeSet::new();
    for h in &head.headers {
        let kept = out_headers.iter().any(|oh| oh.name == h.name);
        if !kept {
            dropped_set.insert(h.name.clone());
        }
    }

    Decision::Forward(ForwardRequest {
        dropped_headers: dropped_set.into_iter().collect(),
        headers: out_headers,
        host,
        method: head.method.clone(),
        path: head.target.path.clone(),
        query: head.target.query.clone(),
    })
}

/// Encodes a `ForwardRequest` as canonical compact JSON with sorted object keys.
pub fn encode_forward(req: &ForwardRequest) -> Vec<u8> {
    // Struct fields in `ForwardRequest` and `ForwardHeader` are declared in alphabetical order,
    // ensuring `serde_json::to_vec` produces canonical sorted-key JSON deterministically.
    serde_json::to_vec(req).unwrap_or_else(|_| b"{}".to_vec())
}
