#![forbid(unsafe_code)]

//! Minimal bounded HTTP/1.1 client for guest probes (TR-SEC-6).
//!
//! Connects over raw TCP with strict deadlines and bounded response buffers.
//! Never allocates unbounded memory or follows redirects.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub const MAX_HTTP_LINE_BYTES: usize = 8192;
pub const MAX_HTTP_HEADER_COUNT: usize = 128;
pub const MAX_HTTP_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CHUNK_HEADER_BYTES: usize = 1024;
pub const MAX_CHUNK_ITERATIONS: usize = 65536;
pub const HTTP_READ_CHUNK_SIZE: usize = 8192;
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_millis(5000);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    InvalidUrl,
    Io(String),
    Timeout,
    ResponseTooLarge,
    ProtocolViolation(&'static str),
    StatusParseError,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl => write!(f, "invalid http URL"),
            Self::Io(e) => write!(f, "HTTP I/O error: {e}"),
            Self::Timeout => write!(f, "HTTP operation timed out"),
            Self::ResponseTooLarge => write!(f, "HTTP response exceeded byte cap"),
            Self::ProtocolViolation(msg) => write!(f, "HTTP protocol violation: {msg}"),
            Self::StatusParseError => write!(f, "failed to parse HTTP status line"),
        }
    }
}

impl std::error::Error for HttpError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }
}

/// Parses an `http://` URL into `(host, port, path)`.
pub fn parse_url(url: &str) -> Result<(String, u16, String), HttpError> {
    let rest = url.strip_prefix("http://").ok_or(HttpError::InvalidUrl)?;
    let (authority, path_part) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(HttpError::InvalidUrl);
    }

    let (host, port) = match authority.rfind(':') {
        Some(idx) => {
            let host = &authority[..idx];
            let port_str = &authority[idx + 1..];
            let port: u16 = port_str.parse().map_err(|_| HttpError::InvalidUrl)?;
            (host.to_string(), port)
        }
        None => (authority.to_string(), 80),
    };

    let path = if path_part.is_empty() {
        "/".to_string()
    } else {
        path_part.to_string()
    };

    Ok((host, port, path))
}

/// Sends an HTTP/1.1 request and parses the response with timeouts and bounds.
pub fn request(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    timeout: Duration,
) -> Result<HttpResponse, HttpError> {
    let (host, port, path) = parse_url(url)?;

    let addrs: Vec<_> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| HttpError::Io(e.to_string()))?
        .collect();

    if addrs.is_empty() {
        return Err(HttpError::Io("failed to resolve address".to_string()));
    }

    let start_time = std::time::Instant::now();
    let deadline = start_time + timeout;

    let mut stream = None;
    for addr in addrs {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(HttpError::Timeout);
        }
        let remaining = deadline - now;
        if let Ok(s) = TcpStream::connect_timeout(&addr, remaining) {
            stream = Some(s);
            break;
        }
    }
    let mut stream = stream.ok_or(HttpError::Timeout)?;

    let now = std::time::Instant::now();
    if now >= deadline {
        return Err(HttpError::Timeout);
    }
    let remaining = deadline - now;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|e| HttpError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|e| HttpError::Io(e.to_string()))?;

    // Build HTTP/1.1 request wire format
    let mut req_bytes = Vec::new();
    let port_suffix = if port != 80 {
        format!(":{port}")
    } else {
        String::new()
    };
    req_bytes.extend_from_slice(
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}{port_suffix}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        )
        .as_bytes(),
    );

    for (k, v) in headers {
        req_bytes.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    req_bytes.extend_from_slice(b"\r\n");
    req_bytes.extend_from_slice(body);

    stream.write_all(&req_bytes).map_err(|e| {
        if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
            HttpError::Timeout
        } else {
            HttpError::Io(e.to_string())
        }
    })?;
    stream.flush().map_err(|e| {
        if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
            HttpError::Timeout
        } else {
            HttpError::Io(e.to_string())
        }
    })?;

    // Read full response bounded by MAX_HTTP_RESPONSE_BYTES and absolute elapsed deadline
    let mut resp_bytes = Vec::new();
    let mut buf = [0u8; HTTP_READ_CHUNK_SIZE];

    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(HttpError::Timeout);
        }
        let remaining = deadline - now;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|e| HttpError::Io(e.to_string()))?;

        let max_to_read = (MAX_HTTP_RESPONSE_BYTES + 1 - resp_bytes.len()).min(buf.len());
        if max_to_read == 0 {
            return Err(HttpError::ResponseTooLarge);
        }

        match stream.read(&mut buf[..max_to_read]) {
            Ok(0) => break,
            Ok(n) => {
                resp_bytes.extend_from_slice(&buf[..n]);
                if resp_bytes.len() > MAX_HTTP_RESPONSE_BYTES {
                    return Err(HttpError::ResponseTooLarge);
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    return Err(HttpError::Timeout);
                } else {
                    return Err(HttpError::Io(e.to_string()));
                }
            }
        }
    }

    parse_response(&resp_bytes)
}

/// Decodes a chunked response body strictly within MAX_HTTP_RESPONSE_BYTES.
fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut decoded = Vec::new();
    let mut iterations = 0;

    while !input.is_empty() {
        iterations += 1;
        if iterations > MAX_CHUNK_ITERATIONS {
            return Err(HttpError::ProtocolViolation("too many chunks"));
        }

        let crlf_pos = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(HttpError::ProtocolViolation("unterminated chunk header"))?;

        if crlf_pos > MAX_CHUNK_HEADER_BYTES {
            return Err(HttpError::ProtocolViolation("chunk header too long"));
        }

        let header_str = std::str::from_utf8(&input[..crlf_pos])
            .map_err(|_| HttpError::ProtocolViolation("non-utf8 chunk header"))?;

        let size_str = header_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|_| HttpError::ProtocolViolation("invalid chunk size"))?;

        input = &input[crlf_pos + 2..];

        if chunk_size == 0 {
            if !input.ends_with(b"\r\n") && !input.is_empty() {
                return Err(HttpError::ProtocolViolation(
                    "missing final chunk terminator",
                ));
            }
            return Ok(decoded);
        }

        if input.len() < chunk_size + 2 {
            return Err(HttpError::ProtocolViolation("incomplete chunk data"));
        }

        let chunk_data = &input[..chunk_size];
        if &input[chunk_size..chunk_size + 2] != b"\r\n" {
            return Err(HttpError::ProtocolViolation(
                "missing CRLF after chunk data",
            ));
        }

        if decoded.len() + chunk_size > MAX_HTTP_RESPONSE_BYTES {
            return Err(HttpError::ResponseTooLarge);
        }

        decoded.extend_from_slice(chunk_data);
        input = &input[chunk_size + 2..];
    }

    Err(HttpError::ProtocolViolation(
        "chunked stream ended without zero chunk",
    ))
}

/// Parses an HTTP/1.1 response buffer strictly.
pub fn parse_response(bytes: &[u8]) -> Result<HttpResponse, HttpError> {
    let header_end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(HttpError::ProtocolViolation("missing header terminator"))?;

    let header_bytes = &bytes[..header_end];
    let body_bytes = &bytes[header_end + 4..];

    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| HttpError::ProtocolViolation("non-utf8 headers"))?;

    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(HttpError::ProtocolViolation("empty response"))?;

    // Status line: HTTP/1.x <code> [reason]
    let mut status_parts = status_line.split_whitespace();
    let _version = status_parts.next().ok_or(HttpError::StatusParseError)?;
    let status_code_str = status_parts.next().ok_or(HttpError::StatusParseError)?;
    let status: u16 = status_code_str
        .parse()
        .map_err(|_| HttpError::StatusParseError)?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if headers.len() >= MAX_HTTP_HEADER_COUNT {
            return Err(HttpError::ProtocolViolation("too many headers"));
        }
        if line.len() > MAX_HTTP_LINE_BYTES {
            return Err(HttpError::ProtocolViolation("header line too long"));
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        } else {
            return Err(HttpError::ProtocolViolation("malformed header line"));
        }
    }

    let is_chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });

    let content_length: Option<usize> = {
        let mut cl = None;
        for (k, v) in &headers {
            if k.eq_ignore_ascii_case("content-length") {
                if cl.is_some() {
                    return Err(HttpError::ProtocolViolation(
                        "duplicate content-length header",
                    ));
                }
                let len: usize = v
                    .trim()
                    .parse()
                    .map_err(|_| HttpError::ProtocolViolation("invalid content-length value"))?;
                cl = Some(len);
            }
        }
        cl
    };

    let body = if is_chunked {
        decode_chunked(body_bytes)?
    } else if let Some(expected_len) = content_length {
        if expected_len > MAX_HTTP_RESPONSE_BYTES {
            return Err(HttpError::ResponseTooLarge);
        }
        if body_bytes.len() < expected_len {
            return Err(HttpError::ProtocolViolation("incomplete response body"));
        }
        body_bytes[..expected_len].to_vec()
    } else {
        body_bytes.to_vec()
    };

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}
