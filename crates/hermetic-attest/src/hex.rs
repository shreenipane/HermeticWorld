//! Safe hex encoding and decoding routines with no external dependencies.

#[derive(Clone, PartialEq, Eq)]
pub enum HexError {
    OddLength(usize),
    InvalidChar(char),
}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OddLength(len) => write!(f, "Hex string has odd length: {len}"),
            Self::InvalidChar(_) => write!(f, "Invalid hex character"),
        }
    }
}

impl std::error::Error for HexError {}
redacted_debug!(HexError);

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Encodes bytes to a lowercase hexadecimal string.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_CHARS_LOWER[(b >> 4) as usize] as char);
        out.push(HEX_CHARS_LOWER[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_nibble(byte: u8) -> Result<u8, HexError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(HexError::InvalidChar(other as char)),
    }
}

/// Decodes a hexadecimal string into bytes. Accepts lowercase and uppercase hex.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, HexError> {
    if !s.len().is_multiple_of(2) {
        return Err(HexError::OddLength(s.len()));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let (chunks, _) = bytes.as_chunks::<2>();
    for chunk in chunks {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Checks if string consists only of lowercase hexadecimal digits.
pub fn is_strict_lowercase_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let raw = b"test vector 1234\x00\xff";
        let enc = hex_encode(raw);
        assert!(is_strict_lowercase_hex(&enc));
        let dec = hex_decode(&enc).expect("decode");
        assert_eq!(dec, raw);
    }

    #[test]
    fn test_hex_odd_and_invalid() {
        assert!(matches!(hex_decode("abc"), Err(HexError::OddLength(3))));
        assert!(matches!(hex_decode("0g"), Err(HexError::InvalidChar('g'))));
    }
}
