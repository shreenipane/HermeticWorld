//! Fixed binary wire frames for NetVM ↔ WorldServer communication.
//!
//! ## Request frame layout (NetVM → WorldServer), little-endian, ≤ 16 KiB total
//!
//! | Field            | Type   | Notes                                         |
//! |------------------|--------|-----------------------------------------------|
//! | magic            | [u8;4] | `HWRQ`                                        |
//! | version          | u8     | 1                                             |
//! | method           | u8     | 1 = GET, 2 = HEAD                             |
//! | flags            | u8     | bit 0: has range                              |
//! | reserved         | u8     | must be 0                                     |
//! | request_id       | u64    |                                               |
//! | authority_len    | u16    |                                               |
//! | path_len         | u16    |                                               |
//! | range_start      | u64   |                                                |
//! | range_end        | u64   | inclusive; meaningful only when flag bit 0 set  |
//! | authority        | bytes  | `authority_len` bytes                         |
//! | path_and_query   | bytes  | `path_len` bytes                              |
//!
//! ## Response frame layout (WorldServer → NetVM), little-endian
//!
//! | Field            | Type   | Notes                                         |
//! |------------------|--------|-----------------------------------------------|
//! | magic            | [u8;4] | `HWRS`                                        |
//! | version          | u8     | 1                                             |
//! | reserved         | [u8;3] | must be 0                                     |
//! | request_id       | u64    |                                               |
//! | status           | u16    |                                               |
//! | header_count     | u16    |                                               |
//! | body_len         | u64    |                                               |
//! | headers          | ...    | each: name_len u16, name, value_len u16, value|
//! | body             | bytes  | `body_len` bytes                              |

use std::io::{self, Read, Write};

/// Maximum total size of a request frame (header + payload).
pub const MAX_REQUEST_FRAME_SIZE: usize = 16 * 1024;

/// Fixed header size of a request frame (magic + version + method + flags + reserved
/// + request_id + authority_len + path_len + range_start + range_end).
pub const REQUEST_HEADER_SIZE: usize = 4 + 1 + 1 + 1 + 1 + 8 + 2 + 2 + 8 + 8; // = 36

/// Maximum authority length.
pub const MAX_AUTHORITY_LEN: usize = 255;

/// Maximum path_and_query length.
pub const MAX_PATH_LEN: usize = 8 * 1024;

/// Maximum number of response headers.
pub const MAX_RESPONSE_HEADERS: usize = 64;

/// Maximum total bytes of response headers (names + values, not the length fields).
pub const MAX_RESPONSE_HEADERS_BYTES: usize = 8 * 1024;

/// Response frame fixed header size.
pub const RESPONSE_HEADER_SIZE: usize = 4 + 1 + 3 + 8 + 2 + 2 + 8; // = 28

/// Request magic bytes.
pub const REQUEST_MAGIC: &[u8; 4] = b"HWRQ";

/// Response magic bytes.
pub const RESPONSE_MAGIC: &[u8; 4] = b"HWRS";

/// Wire protocol version.
pub const WIRE_VERSION: u8 = 1;

/// HTTP method encoded as a u8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get = 1,
    Head = 2,
}

impl Method {
    fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            1 => Ok(Method::Get),
            2 => Ok(Method::Head),
            _ => Err(WireError::Malformed(format!("unknown method byte: {v}"))),
        }
    }
}

/// Errors from wire-frame encoding/decoding.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("malformed frame: {0}")]
    Malformed(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// A decoded request frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFrame {
    pub method: Method,
    pub request_id: u64,
    pub authority: String,
    pub path_and_query: String,
    pub range: Option<(u64, u64)>,
}

/// A single response header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeader {
    pub name: String,
    pub value: String,
}

/// A decoded response frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseFrame {
    pub request_id: u64,
    pub status: u16,
    pub headers: Vec<ResponseHeader>,
    pub body: Vec<u8>,
}

// ── Validation helpers ──

fn validate_authority(auth: &[u8]) -> Result<(), WireError> {
    if auth.is_empty() {
        return Err(WireError::Malformed("authority is empty".into()));
    }
    if auth.len() > MAX_AUTHORITY_LEN {
        return Err(WireError::Malformed(format!(
            "authority too long: {} > {}",
            auth.len(),
            MAX_AUTHORITY_LEN
        )));
    }
    // Must match [a-z0-9.-]+(:[0-9]{1,5})?
    let s = std::str::from_utf8(auth)
        .map_err(|_| WireError::Malformed("authority is not valid UTF-8".into()))?;

    let parts: Vec<&str> = s.split(':').collect();
    match parts.len() {
        1 => {
            let host = parts[0];
            if host.is_empty()
                || !host
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
            {
                return Err(WireError::Malformed("invalid host in authority".into()));
            }
        }
        2 => {
            let host = parts[0];
            let port = parts[1];
            if host.is_empty()
                || !host
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
            {
                return Err(WireError::Malformed("invalid host in authority".into()));
            }
            if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
                return Err(WireError::Malformed("invalid port in authority".into()));
            }
        }
        _ => {
            return Err(WireError::Malformed("too many colons in authority".into()));
        }
    }
    Ok(())
}

fn validate_path_and_query(pq: &[u8]) -> Result<(), WireError> {
    if pq.is_empty() {
        return Err(WireError::Malformed("path_and_query is empty".into()));
    }
    if pq[0] != b'/' {
        return Err(WireError::Malformed(
            "path_and_query must start with '/'".into(),
        ));
    }
    if pq.len() > MAX_PATH_LEN {
        return Err(WireError::Malformed(format!(
            "path_and_query too long: {} > {}",
            pq.len(),
            MAX_PATH_LEN
        )));
    }
    for &b in pq {
        if !(0x21..=0x7E).contains(&b) {
            return Err(WireError::Malformed(format!(
                "path_and_query contains invalid byte 0x{b:02x}"
            )));
        }
    }
    Ok(())
}

fn validate_header_name(name: &[u8]) -> Result<(), WireError> {
    // HTTP token characters: any VCHAR except delimiters
    // RFC 7230 token = 1*tchar
    // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
    //         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
    if name.is_empty() {
        return Err(WireError::Malformed("header name is empty".into()));
    }
    for &b in name {
        if !is_token_char(b) {
            return Err(WireError::Malformed(format!(
                "header name contains invalid byte 0x{b:02x}"
            )));
        }
        // Must be lowercase ASCII
        if b.is_ascii_uppercase() {
            return Err(WireError::Malformed("header name must be lowercase".into()));
        }
    }
    Ok(())
}

fn is_token_char(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
        b'^' | b'_' | b'`' | b'|' | b'~' |
        b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'
    )
}

fn validate_header_value(value: &[u8]) -> Result<(), WireError> {
    // Printable ASCII (0x20..=0x7E) plus HTAB (0x09)
    for &b in value {
        if !(b == 0x09 || (0x20..=0x7E).contains(&b)) {
            return Err(WireError::Malformed(format!(
                "header value contains invalid byte 0x{b:02x}"
            )));
        }
    }
    Ok(())
}

// ── Encoding ──

impl RequestFrame {
    /// Encode this request frame into bytes.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let auth_bytes = self.authority.as_bytes();
        let pq_bytes = self.path_and_query.as_bytes();

        validate_authority(auth_bytes)?;
        validate_path_and_query(pq_bytes)?;

        let total = REQUEST_HEADER_SIZE + auth_bytes.len() + pq_bytes.len();
        if total > MAX_REQUEST_FRAME_SIZE {
            return Err(WireError::Malformed(format!(
                "request frame too large: {total} > {MAX_REQUEST_FRAME_SIZE}"
            )));
        }

        let flags: u8 = if self.range.is_some() { 1 } else { 0 };
        let (range_start, range_end) = self.range.unwrap_or((0, 0));

        let mut buf = Vec::with_capacity(total);
        buf.write_all(REQUEST_MAGIC)?;
        buf.push(WIRE_VERSION);
        buf.push(self.method as u8);
        buf.push(flags);
        buf.push(0u8); // reserved
        buf.write_all(&self.request_id.to_le_bytes())?;
        buf.write_all(&(auth_bytes.len() as u16).to_le_bytes())?;
        buf.write_all(&(pq_bytes.len() as u16).to_le_bytes())?;
        buf.write_all(&range_start.to_le_bytes())?;
        buf.write_all(&range_end.to_le_bytes())?;
        buf.write_all(auth_bytes)?;
        buf.write_all(pq_bytes)?;
        Ok(buf)
    }

    /// Decode a request frame from a byte slice.
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        if data.len() < REQUEST_HEADER_SIZE {
            return Err(WireError::Malformed(format!(
                "request frame too short: {} < {REQUEST_HEADER_SIZE}",
                data.len()
            )));
        }
        if data.len() > MAX_REQUEST_FRAME_SIZE {
            return Err(WireError::Malformed(format!(
                "request frame too large: {} > {MAX_REQUEST_FRAME_SIZE}",
                data.len()
            )));
        }
        if &data[0..4] != REQUEST_MAGIC.as_slice() {
            return Err(WireError::Malformed("bad request magic".into()));
        }
        if data[4] != WIRE_VERSION {
            return Err(WireError::Malformed(format!(
                "unsupported version: {}",
                data[4]
            )));
        }
        let method = Method::from_u8(data[5])?;
        let flags = data[6];
        let reserved = data[7];
        if reserved != 0 {
            return Err(WireError::Malformed(format!(
                "reserved byte is not zero: {reserved}"
            )));
        }
        // Unknown flag bits must be zero
        if flags & !0x01 != 0 {
            return Err(WireError::Malformed(format!(
                "unknown flag bits set: 0x{flags:02x}"
            )));
        }

        let request_id = u64::from_le_bytes(
            data[8..16]
                .try_into()
                .map_err(|_| WireError::Malformed("failed to read request_id".into()))?,
        );
        let authority_len = u16::from_le_bytes(
            data[16..18]
                .try_into()
                .map_err(|_| WireError::Malformed("failed to read authority_len".into()))?,
        ) as usize;
        let path_len = u16::from_le_bytes(
            data[18..20]
                .try_into()
                .map_err(|_| WireError::Malformed("failed to read path_len".into()))?,
        ) as usize;
        let _range_start = u64::from_le_bytes(
            data[20..28]
                .try_into()
                .map_err(|_| WireError::Malformed("failed to read range_start".into()))?,
        );
        let _range_end = u64::from_le_bytes(
            data[28..36]
                .try_into()
                .map_err(|_| WireError::Malformed("failed to read range_end".into()))?,
        );

        let expected_len = REQUEST_HEADER_SIZE + authority_len + path_len;
        if data.len() != expected_len {
            return Err(WireError::Malformed(format!(
                "frame length mismatch: got {} expected {expected_len}",
                data.len()
            )));
        }

        let auth_start = REQUEST_HEADER_SIZE;
        let auth_end = auth_start + authority_len;
        let pq_start = auth_end;
        let pq_end = pq_start + path_len;

        let auth_bytes = &data[auth_start..auth_end];
        let pq_bytes = &data[pq_start..pq_end];

        validate_authority(auth_bytes)?;
        validate_path_and_query(pq_bytes)?;

        let authority = String::from_utf8(auth_bytes.to_vec())
            .map_err(|_| WireError::Malformed("authority is not valid UTF-8".into()))?;
        let path_and_query = String::from_utf8(pq_bytes.to_vec())
            .map_err(|_| WireError::Malformed("path_and_query is not valid UTF-8".into()))?;

        let range = if flags & 0x01 != 0 {
            Some((_range_start, _range_end))
        } else {
            None
        };

        Ok(RequestFrame {
            method,
            request_id,
            authority,
            path_and_query,
            range,
        })
    }

    /// Read exactly one request frame from a `Read` source.
    ///
    /// Reads the fixed header first to determine the payload length, validates
    /// it before reading the payload, and then decodes the full frame.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, WireError> {
        let mut header = [0u8; REQUEST_HEADER_SIZE];
        let mut n = 0;
        while n < REQUEST_HEADER_SIZE {
            match reader.read(&mut header[n..]) {
                Ok(0) => {
                    if n == 0 {
                        return Err(WireError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "clean eof before request",
                        )));
                    } else {
                        return Err(WireError::Malformed(
                            "truncated request frame header".into(),
                        ));
                    }
                }
                Ok(bytes) => n += bytes,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(WireError::Io(e)),
            }
        }

        // Validate magic and extract lengths before reading more
        if &header[0..4] != REQUEST_MAGIC.as_slice() {
            return Err(WireError::Malformed("bad request magic".into()));
        }

        let authority_len = u16::from_le_bytes([header[16], header[17]]) as usize;
        let path_len = u16::from_le_bytes([header[18], header[19]]) as usize;

        if authority_len > MAX_AUTHORITY_LEN {
            return Err(WireError::Malformed(format!(
                "authority too long: {authority_len} > {MAX_AUTHORITY_LEN}"
            )));
        }
        if path_len > MAX_PATH_LEN {
            return Err(WireError::Malformed(format!(
                "path_and_query too long: {path_len} > {MAX_PATH_LEN}"
            )));
        }

        let payload_len = authority_len + path_len;
        let total_len = REQUEST_HEADER_SIZE + payload_len;
        if total_len > MAX_REQUEST_FRAME_SIZE {
            return Err(WireError::Malformed(format!(
                "request frame too large: {total_len} > {MAX_REQUEST_FRAME_SIZE}"
            )));
        }

        let mut frame = Vec::with_capacity(total_len);
        frame.extend_from_slice(&header);
        frame.resize(total_len, 0);
        reader
            .read_exact(&mut frame[REQUEST_HEADER_SIZE..])
            .map_err(|e| match e.kind() {
                io::ErrorKind::UnexpectedEof => {
                    WireError::Malformed("truncated request frame payload".into())
                }
                _ => WireError::Io(e),
            })?;

        Self::decode(&frame)
    }
}

impl ResponseFrame {
    /// Encode this response frame into bytes.
    pub fn encode(&self, max_body_len: u64) -> Result<Vec<u8>, WireError> {
        if self.headers.len() > MAX_RESPONSE_HEADERS {
            return Err(WireError::Malformed(format!(
                "too many headers: {} > {}",
                self.headers.len(),
                MAX_RESPONSE_HEADERS
            )));
        }

        // Validate and measure headers
        let mut headers_bytes: usize = 0;
        for h in &self.headers {
            validate_header_name(h.name.as_bytes())?;
            validate_header_value(h.value.as_bytes())?;
            headers_bytes += h.name.len() + h.value.len();
        }
        if headers_bytes > MAX_RESPONSE_HEADERS_BYTES {
            return Err(WireError::Malformed(format!(
                "headers too large: {headers_bytes} > {MAX_RESPONSE_HEADERS_BYTES}"
            )));
        }

        let body_len = self.body.len() as u64;
        if body_len > max_body_len {
            return Err(WireError::Malformed(format!(
                "body too large: {body_len} > {max_body_len}"
            )));
        }

        // header_data_len = sum of (2 + name_len + 2 + value_len) for each header
        let header_data_len: usize = self
            .headers
            .iter()
            .map(|h| 2 + h.name.len() + 2 + h.value.len())
            .sum();

        let total = RESPONSE_HEADER_SIZE + header_data_len + self.body.len();
        let mut buf = Vec::with_capacity(total);

        buf.write_all(RESPONSE_MAGIC)?;
        buf.push(WIRE_VERSION);
        buf.write_all(&[0u8; 3])?; // reserved
        buf.write_all(&self.request_id.to_le_bytes())?;
        buf.write_all(&self.status.to_le_bytes())?;
        buf.write_all(&(self.headers.len() as u16).to_le_bytes())?;
        buf.write_all(&body_len.to_le_bytes())?;

        for h in &self.headers {
            buf.write_all(&(h.name.len() as u16).to_le_bytes())?;
            buf.write_all(h.name.as_bytes())?;
            buf.write_all(&(h.value.len() as u16).to_le_bytes())?;
            buf.write_all(h.value.as_bytes())?;
        }

        buf.write_all(&self.body)?;
        Ok(buf)
    }

    /// Decode a response frame from a byte slice.
    pub fn decode(data: &[u8], max_body_len: u64) -> Result<Self, WireError> {
        if data.len() < RESPONSE_HEADER_SIZE {
            return Err(WireError::Malformed(format!(
                "response frame too short: {} < {RESPONSE_HEADER_SIZE}",
                data.len()
            )));
        }
        if &data[0..4] != RESPONSE_MAGIC.as_slice() {
            return Err(WireError::Malformed("bad response magic".into()));
        }
        if data[4] != WIRE_VERSION {
            return Err(WireError::Malformed(format!(
                "unsupported version: {}",
                data[4]
            )));
        }
        if data[5] != 0 || data[6] != 0 || data[7] != 0 {
            return Err(WireError::Malformed("reserved bytes not zero".into()));
        }

        let request_id = u64::from_le_bytes(
            data[8..16]
                .try_into()
                .map_err(|_| WireError::Malformed("failed to read request_id".into()))?,
        );
        let status = u16::from_le_bytes(
            data[16..18]
                .try_into()
                .map_err(|_| WireError::Malformed("failed to read status".into()))?,
        );
        let header_count = u16::from_le_bytes(
            data[18..20]
                .try_into()
                .map_err(|_| WireError::Malformed("failed to read header_count".into()))?,
        ) as usize;
        let body_len = u64::from_le_bytes(
            data[20..28]
                .try_into()
                .map_err(|_| WireError::Malformed("failed to read body_len".into()))?,
        );

        if header_count > MAX_RESPONSE_HEADERS {
            return Err(WireError::Malformed(format!(
                "too many headers: {header_count} > {MAX_RESPONSE_HEADERS}"
            )));
        }
        if body_len > max_body_len {
            return Err(WireError::Malformed(format!(
                "body too large: {body_len} > {max_body_len}"
            )));
        }

        let mut pos = RESPONSE_HEADER_SIZE;
        let mut headers = Vec::with_capacity(header_count);
        let mut headers_bytes: usize = 0;

        for _ in 0..header_count {
            if pos + 2 > data.len() {
                return Err(WireError::Malformed("truncated header name length".into()));
            }
            let name_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if pos + name_len > data.len() {
                return Err(WireError::Malformed("truncated header name".into()));
            }
            let name_bytes = &data[pos..pos + name_len];
            validate_header_name(name_bytes)?;
            pos += name_len;

            if pos + 2 > data.len() {
                return Err(WireError::Malformed("truncated header value length".into()));
            }
            let value_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if pos + value_len > data.len() {
                return Err(WireError::Malformed("truncated header value".into()));
            }
            let value_bytes = &data[pos..pos + value_len];
            validate_header_value(value_bytes)?;
            pos += value_len;

            headers_bytes += name_len + value_len;
            if headers_bytes > MAX_RESPONSE_HEADERS_BYTES {
                return Err(WireError::Malformed(format!(
                    "headers too large: {headers_bytes} > {MAX_RESPONSE_HEADERS_BYTES}"
                )));
            }

            let name = String::from_utf8(name_bytes.to_vec())
                .map_err(|_| WireError::Malformed("header name not UTF-8".into()))?;
            let value = String::from_utf8(value_bytes.to_vec())
                .map_err(|_| WireError::Malformed("header value not UTF-8".into()))?;

            headers.push(ResponseHeader { name, value });
        }

        let body_start = pos;
        let body_end = body_start + body_len as usize;
        if body_end != data.len() {
            return Err(WireError::Malformed(format!(
                "frame length mismatch: body ends at {body_end} but frame is {} bytes",
                data.len()
            )));
        }

        let body = data[body_start..body_end].to_vec();

        Ok(ResponseFrame {
            request_id,
            status,
            headers,
            body,
        })
    }

    /// Read exactly one response frame from a `Read` source.
    pub fn read_from<R: Read>(reader: &mut R, max_body_len: u64) -> Result<Self, WireError> {
        let mut header = [0u8; RESPONSE_HEADER_SIZE];
        let mut n = 0;
        while n < RESPONSE_HEADER_SIZE {
            match reader.read(&mut header[n..]) {
                Ok(0) => {
                    if n == 0 {
                        return Err(WireError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "clean eof before response",
                        )));
                    } else {
                        return Err(WireError::Malformed(
                            "truncated response frame header".into(),
                        ));
                    }
                }
                Ok(bytes) => n += bytes,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(WireError::Io(e)),
            }
        }

        // Validate magic before trusting any length
        if &header[0..4] != RESPONSE_MAGIC.as_slice() {
            return Err(WireError::Malformed("bad response magic".into()));
        }
        if header[4] != WIRE_VERSION {
            return Err(WireError::Malformed(format!(
                "unsupported version: {}",
                header[4]
            )));
        }
        if header[5] != 0 || header[6] != 0 || header[7] != 0 {
            return Err(WireError::Malformed("reserved bytes not zero".into()));
        }

        let request_id = u64::from_le_bytes(
            header[8..16]
                .try_into()
                .map_err(|_| WireError::Malformed("failed to read request_id".into()))?,
        );
        let status = u16::from_le_bytes(
            header[16..18]
                .try_into()
                .map_err(|_| WireError::Malformed("failed to read status".into()))?,
        );

        let header_count = u16::from_le_bytes([header[18], header[19]]) as usize;
        if header_count > MAX_RESPONSE_HEADERS {
            return Err(WireError::Malformed(format!(
                "too many headers: {header_count} > {MAX_RESPONSE_HEADERS}"
            )));
        }

        let body_len = u64::from_le_bytes(
            header[20..28]
                .try_into()
                .map_err(|_| WireError::Malformed("failed to read body_len".into()))?,
        );
        if body_len > max_body_len {
            return Err(WireError::Malformed(format!(
                "body too large: {body_len} > {max_body_len}"
            )));
        }

        // Read headers: each header is (2 + name_len + 2 + value_len) bytes.
        // We don't know the total header data size up front, so read them one by one,
        // tracking the total.
        let mut headers = Vec::with_capacity(header_count);
        let mut headers_bytes: usize = 0;

        for _ in 0..header_count {
            let mut len_buf = [0u8; 2];

            reader
                .read_exact(&mut len_buf)
                .map_err(|e| match e.kind() {
                    io::ErrorKind::UnexpectedEof => {
                        WireError::Malformed("truncated header name length".into())
                    }
                    _ => WireError::Io(e),
                })?;
            let name_len = u16::from_le_bytes(len_buf) as usize;

            // Cap name_len to prevent OOM before reading
            if headers_bytes + name_len > MAX_RESPONSE_HEADERS_BYTES {
                return Err(WireError::Malformed(
                    "headers too large before reading name".into(),
                ));
            }

            let mut name = vec![0u8; name_len];
            reader.read_exact(&mut name).map_err(|e| match e.kind() {
                io::ErrorKind::UnexpectedEof => {
                    WireError::Malformed("truncated header name".into())
                }
                _ => WireError::Io(e),
            })?;
            validate_header_name(&name)?;

            reader
                .read_exact(&mut len_buf)
                .map_err(|e| match e.kind() {
                    io::ErrorKind::UnexpectedEof => {
                        WireError::Malformed("truncated header value length".into())
                    }
                    _ => WireError::Io(e),
                })?;
            let value_len = u16::from_le_bytes(len_buf) as usize;

            headers_bytes += name_len + value_len;
            if headers_bytes > MAX_RESPONSE_HEADERS_BYTES {
                return Err(WireError::Malformed(format!(
                    "headers too large: {headers_bytes} > {MAX_RESPONSE_HEADERS_BYTES}"
                )));
            }

            let mut value = vec![0u8; value_len];
            reader.read_exact(&mut value).map_err(|e| match e.kind() {
                io::ErrorKind::UnexpectedEof => {
                    WireError::Malformed("truncated header value".into())
                }
                _ => WireError::Io(e),
            })?;
            validate_header_value(&value)?;

            let name_str = String::from_utf8(name)
                .map_err(|_| WireError::Malformed("header name not UTF-8".into()))?;
            let value_str = String::from_utf8(value)
                .map_err(|_| WireError::Malformed("header value not UTF-8".into()))?;

            headers.push(ResponseHeader {
                name: name_str,
                value: value_str,
            });
        }

        // Read body
        let mut body = vec![0u8; body_len as usize];
        reader.read_exact(&mut body).map_err(|e| match e.kind() {
            io::ErrorKind::UnexpectedEof => WireError::Malformed("truncated response body".into()),
            _ => WireError::Io(e),
        })?;

        Ok(ResponseFrame {
            request_id,
            status,
            headers,
            body,
        })
    }

    /// Write this response frame to a `Write` sink.
    pub fn write_to<W: Write>(&self, writer: &mut W, max_body_len: u64) -> Result<(), WireError> {
        let encoded = self.encode(max_body_len)?;
        writer.write_all(&encoded)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_request() -> RequestFrame {
        RequestFrame {
            method: Method::Get,
            request_id: 42,
            authority: "pypi.org".into(),
            path_and_query: "/simple/requests/".into(),
            range: None,
        }
    }

    fn sample_request_with_range() -> RequestFrame {
        RequestFrame {
            method: Method::Head,
            request_id: 99,
            authority: "files.pythonhosted.org".into(),
            path_and_query: "/packages/requests-2.28.0.tar.gz".into(),
            range: Some((100, 200)),
        }
    }

    fn sample_response() -> ResponseFrame {
        ResponseFrame {
            request_id: 42,
            status: 200,
            headers: vec![
                ResponseHeader {
                    name: "content-type".into(),
                    value: "text/html".into(),
                },
                ResponseHeader {
                    name: "content-length".into(),
                    value: "13".into(),
                },
            ],
            body: b"Hello, world!".to_vec(),
        }
    }

    #[test]
    fn request_round_trip() {
        let frame = sample_request();
        let encoded = frame.encode().unwrap();
        let decoded = RequestFrame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn request_with_range_round_trip() {
        let frame = sample_request_with_range();
        let encoded = frame.encode().unwrap();
        let decoded = RequestFrame::decode(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn response_round_trip() {
        let frame = sample_response();
        let max_body = 1024 * 1024;
        let encoded = frame.encode(max_body).unwrap();
        let decoded = ResponseFrame::decode(&encoded, max_body).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn request_streaming_round_trip() {
        let frame = sample_request();
        let encoded = frame.encode().unwrap();
        let mut cursor = Cursor::new(encoded);
        let decoded = RequestFrame::read_from(&mut cursor).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn response_streaming_round_trip() {
        let frame = sample_response();
        let max_body = 1024 * 1024;
        let encoded = frame.encode(max_body).unwrap();
        let mut cursor = Cursor::new(encoded);
        let decoded = ResponseFrame::read_from(&mut cursor, max_body).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn request_bad_magic() {
        let frame = sample_request();
        let mut encoded = frame.encode().unwrap();
        encoded[0] = b'X';
        assert!(RequestFrame::decode(&encoded).is_err());
    }

    #[test]
    fn request_bad_version() {
        let frame = sample_request();
        let mut encoded = frame.encode().unwrap();
        encoded[4] = 2;
        assert!(RequestFrame::decode(&encoded).is_err());
    }

    #[test]
    fn request_bad_method() {
        let frame = sample_request();
        let mut encoded = frame.encode().unwrap();
        encoded[5] = 0;
        assert!(RequestFrame::decode(&encoded).is_err());
    }

    #[test]
    fn request_bad_reserved() {
        let frame = sample_request();
        let mut encoded = frame.encode().unwrap();
        encoded[7] = 1;
        assert!(RequestFrame::decode(&encoded).is_err());
    }

    #[test]
    fn request_unknown_flag_bits() {
        let frame = sample_request();
        let mut encoded = frame.encode().unwrap();
        encoded[6] = 0x02;
        assert!(RequestFrame::decode(&encoded).is_err());
    }

    #[test]
    fn request_length_mismatch() {
        let frame = sample_request();
        let mut encoded = frame.encode().unwrap();
        // Append extra byte
        encoded.push(0);
        assert!(RequestFrame::decode(&encoded).is_err());
    }

    #[test]
    fn request_truncation() {
        let frame = sample_request();
        let encoded = frame.encode().unwrap();
        for len in 0..encoded.len() {
            let truncated = &encoded[..len];
            assert!(
                RequestFrame::decode(truncated).is_err(),
                "truncation at {len} should fail"
            );
        }
    }

    #[test]
    fn request_single_byte_flip() {
        let frame = sample_request();
        let encoded = frame.encode().unwrap();
        for i in 0..encoded.len() {
            let mut flipped = encoded.clone();
            flipped[i] ^= 0xFF;
            // It should either fail or produce a valid frame (not panic)
            let _ = RequestFrame::decode(&flipped);
        }
    }

    #[test]
    fn response_truncation() {
        let frame = sample_response();
        let max_body = 1024 * 1024;
        let encoded = frame.encode(max_body).unwrap();
        for len in 0..encoded.len() {
            let truncated = &encoded[..len];
            assert!(
                ResponseFrame::decode(truncated, max_body).is_err(),
                "truncation at {len} should fail"
            );
        }
    }

    #[test]
    fn response_single_byte_flip() {
        let frame = sample_response();
        let max_body = 1024 * 1024;
        let encoded = frame.encode(max_body).unwrap();
        for i in 0..encoded.len() {
            let mut flipped = encoded.clone();
            flipped[i] ^= 0xFF;
            // Should not panic
            let _ = ResponseFrame::decode(&flipped, max_body);
        }
    }

    #[test]
    fn request_streaming_truncation() {
        let frame = sample_request();
        let encoded = frame.encode().unwrap();
        for len in 0..encoded.len() {
            let truncated = &encoded[..len];
            let mut cursor = Cursor::new(truncated);
            assert!(
                RequestFrame::read_from(&mut cursor).is_err(),
                "streaming truncation at {len} should fail"
            );
        }
    }

    #[test]
    fn response_streaming_truncation() {
        let frame = sample_response();
        let max_body = 1024 * 1024;
        let encoded = frame.encode(max_body).unwrap();
        for len in 0..encoded.len() {
            let truncated = &encoded[..len];
            let mut cursor = Cursor::new(truncated);
            assert!(
                ResponseFrame::read_from(&mut cursor, max_body).is_err(),
                "streaming truncation at {len} should fail"
            );
        }
    }

    #[test]
    fn authority_validation() {
        // Valid
        assert!(validate_authority(b"example.com").is_ok());
        assert!(validate_authority(b"example.com:8080").is_ok());
        assert!(validate_authority(b"a.b.c").is_ok());
        assert!(validate_authority(b"127.0.0.1:443").is_ok());

        // Invalid: uppercase
        assert!(validate_authority(b"Example.com").is_err());
        // Invalid: empty
        assert!(validate_authority(b"").is_err());
        // Invalid: special chars
        assert!(validate_authority(b"example.com/path").is_err());
        // Invalid: spaces
        assert!(validate_authority(b"example .com").is_err());
    }

    #[test]
    fn path_validation() {
        // Valid
        assert!(validate_path_and_query(b"/").is_ok());
        assert!(validate_path_and_query(b"/simple/requests/").is_ok());
        assert!(validate_path_and_query(b"/a?b=c").is_ok());

        // Invalid: no leading /
        assert!(validate_path_and_query(b"simple").is_err());
        // Invalid: empty
        assert!(validate_path_and_query(b"").is_err());
        // Invalid: space
        assert!(validate_path_and_query(b"/a b").is_err());
        // Invalid: control char
        assert!(validate_path_and_query(b"/a\x00b").is_err());
    }

    #[test]
    fn response_bad_magic() {
        let frame = sample_response();
        let max_body = 1024 * 1024;
        let mut encoded = frame.encode(max_body).unwrap();
        encoded[0] = b'X';
        assert!(ResponseFrame::decode(&encoded, max_body).is_err());
    }

    #[test]
    fn response_bad_reserved() {
        let frame = sample_response();
        let max_body = 1024 * 1024;
        let mut encoded = frame.encode(max_body).unwrap();
        encoded[5] = 1;
        assert!(ResponseFrame::decode(&encoded, max_body).is_err());
    }
}
