#![forbid(unsafe_code)]

//! Bounded pkt-line parser and serializer for the Git smart transfer protocol.
//!
//! Protocol framing specification:
//! - 4-hex-digit length prefix (ASCII hex).
//! - `0000` = Flush packet (`PKT_FLUSH`).
//! - `0001` = Delimiter packet (`PKT_DELIM`).
//! - `0002` = Response-end packet (`PKT_RESPONSE_END`).
//! - `0003` = Invalid (reserved).
//! - Normal lines: `4 <= len <= MAX_PKT_LINE_BYTES`.
//!
//! Every read and loop is bounded by a named constant.

use std::fmt;

/// Maximum byte length of a single pkt-line including the 4-byte header.
pub const MAX_PKT_LINE_BYTES: usize = 65520;

/// Byte length of the hex length prefix in a pkt-line.
pub const PKT_HEADER_BYTES: usize = 4;

/// Maximum payload bytes in a single sideband chunk (`MAX_PKT_LINE_BYTES - 4 - 1`).
pub const MAX_SIDEBAND_PAYLOAD: usize = MAX_PKT_LINE_BYTES - PKT_HEADER_BYTES - 1;

/// Maximum number of pkt-lines parsed in a single request frame.
pub const MAX_REQUEST_PKT_LINES: usize = 2048;

/// Sideband band 1: packfile data.
pub const BAND_DATA: u8 = 1;
/// Sideband band 2: progress message.
pub const BAND_PROGRESS: u8 = 2;
/// Sideband band 3: error message.
pub const BAND_ERROR: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PktLine<'a> {
    /// Normal packet line with payload (excluding the 4-byte header).
    Data(&'a [u8]),
    /// Flush packet (`0000`).
    Flush,
    /// Delimiter packet (`0001`).
    Delimiter,
    /// Response-end packet (`0002`).
    ResponseEnd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PktLineBuf {
    Data(Vec<u8>),
    Flush,
    Delimiter,
    ResponseEnd,
}

impl<'a> From<PktLine<'a>> for PktLineBuf {
    fn from(p: PktLine<'a>) -> Self {
        match p {
            PktLine::Data(d) => PktLineBuf::Data(d.to_vec()),
            PktLine::Flush => PktLineBuf::Flush,
            PktLine::Delimiter => PktLineBuf::Delimiter,
            PktLine::ResponseEnd => PktLineBuf::ResponseEnd,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PktLineError {
    /// Input buffer does not contain enough bytes to complete the line.
    Truncated,
    /// Non-hex character encountered in the 4-byte header.
    InvalidHex(u8),
    /// Declared length is invalid (e.g. 3, or < 4 while not 0, 1, or 2).
    InvalidLength(usize),
    /// Declared length exceeds `MAX_PKT_LINE_BYTES`.
    LineTooLong(usize),
    /// Invalid sideband channel byte (must be 1, 2, or 3).
    InvalidChannel(u8),
    /// Packet limit exceeded.
    TooManyLines,
}

impl fmt::Display for PktLineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PktLineError::Truncated => write!(f, "truncated pkt-line"),
            PktLineError::InvalidHex(b) => {
                write!(f, "invalid hex digit in pkt-line header: {b:#04x}")
            }
            PktLineError::InvalidLength(len) => write!(f, "invalid pkt-line length: {len}"),
            PktLineError::LineTooLong(len) => {
                write!(
                    f,
                    "pkt-line exceeds maximum bound {MAX_PKT_LINE_BYTES}: {len}"
                )
            }
            PktLineError::InvalidChannel(c) => write!(f, "invalid sideband channel: {c}"),
            PktLineError::TooManyLines => write!(f, "too many pkt-lines in request"),
        }
    }
}

impl std::error::Error for PktLineError {}

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[inline]
fn write_hex_u16(val: u16, out: &mut [u8; 4]) {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    out[0] = HEX_CHARS[((val >> 12) & 0x0f) as usize];
    out[1] = HEX_CHARS[((val >> 8) & 0x0f) as usize];
    out[2] = HEX_CHARS[((val >> 4) & 0x0f) as usize];
    out[3] = HEX_CHARS[(val & 0x0f) as usize];
}

/// Parses a single pkt-line from the start of `input`.
///
/// Returns `Ok((line, bytes_consumed))` on success.
pub fn parse_pkt_line(input: &[u8]) -> Result<(PktLine<'_>, usize), PktLineError> {
    if input.len() < PKT_HEADER_BYTES {
        return Err(PktLineError::Truncated);
    }

    let b0 = hex_val(input[0]).ok_or(PktLineError::InvalidHex(input[0]))?;
    let b1 = hex_val(input[1]).ok_or(PktLineError::InvalidHex(input[1]))?;
    let b2 = hex_val(input[2]).ok_or(PktLineError::InvalidHex(input[2]))?;
    let b3 = hex_val(input[3]).ok_or(PktLineError::InvalidHex(input[3]))?;

    let len = ((b0 as usize) << 12) | ((b1 as usize) << 8) | ((b2 as usize) << 4) | (b3 as usize);

    match len {
        0 => Ok((PktLine::Flush, PKT_HEADER_BYTES)),
        1 => Ok((PktLine::Delimiter, PKT_HEADER_BYTES)),
        2 => Ok((PktLine::ResponseEnd, PKT_HEADER_BYTES)),
        3 => Err(PktLineError::InvalidLength(3)),
        4..=MAX_PKT_LINE_BYTES => {
            if input.len() < len {
                return Err(PktLineError::Truncated);
            }
            let payload = &input[PKT_HEADER_BYTES..len];
            Ok((PktLine::Data(payload), len))
        }
        _ => Err(PktLineError::LineTooLong(len)),
    }
}

/// Encodes a data packet into `out`.
pub fn write_pkt_line(out: &mut Vec<u8>, data: &[u8]) -> Result<(), PktLineError> {
    let total_len = data.len().saturating_add(PKT_HEADER_BYTES);
    if total_len > MAX_PKT_LINE_BYTES {
        return Err(PktLineError::LineTooLong(total_len));
    }
    let mut header = [0u8; 4];
    write_hex_u16(total_len as u16, &mut header);
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    Ok(())
}

/// Writes a flush packet (`0000`).
pub fn write_flush(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0000");
}

/// Writes a delimiter packet (`0001`).
pub fn write_delim(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0001");
}

/// Writes a response-end packet (`0002`).
pub fn write_response_end(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0002");
}

/// Encodes a single sideband chunk (channel byte + data) into `out`.
pub fn write_sideband_chunk(out: &mut Vec<u8>, band: u8, data: &[u8]) -> Result<(), PktLineError> {
    if !matches!(band, BAND_DATA | BAND_PROGRESS | BAND_ERROR) {
        return Err(PktLineError::InvalidChannel(band));
    }
    let total_len = data.len().saturating_add(PKT_HEADER_BYTES + 1);
    if total_len > MAX_PKT_LINE_BYTES {
        return Err(PktLineError::LineTooLong(total_len));
    }
    let mut header = [0u8; 4];
    write_hex_u16(total_len as u16, &mut header);
    out.extend_from_slice(&header);
    out.push(band);
    out.extend_from_slice(data);
    Ok(())
}

/// Writes `data` over `band`, chunking into packets of at most `MAX_SIDEBAND_PAYLOAD` bytes.
pub fn write_sideband_data(
    out: &mut Vec<u8>,
    band: u8,
    mut data: &[u8],
) -> Result<(), PktLineError> {
    if !matches!(band, BAND_DATA | BAND_PROGRESS | BAND_ERROR) {
        return Err(PktLineError::InvalidChannel(band));
    }
    if data.is_empty() {
        return write_sideband_chunk(out, band, &[]);
    }
    while !data.is_empty() {
        let chunk_size = data.len().min(MAX_SIDEBAND_PAYLOAD);
        write_sideband_chunk(out, band, &data[..chunk_size])?;
        data = &data[chunk_size..];
    }
    Ok(())
}
