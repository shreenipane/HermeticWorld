//! Safe, strict RFC 4648 Base64 encoding and decoding without external dependencies.

#[derive(Clone, PartialEq, Eq)]
pub enum Base64Error {
    InvalidLength,
    InvalidChar(char),
    InvalidPadding,
    NonZeroTrailingBits,
    InputTooLarge { size: usize, limit: usize },
}

impl std::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "Base64 input length is invalid"),
            Self::InvalidChar(_) => write!(f, "Invalid base64 character"),
            Self::InvalidPadding => write!(f, "Invalid base64 padding"),
            Self::NonZeroTrailingBits => {
                write!(f, "Base64 non-zero trailing bits in final quantum")
            }
            Self::InputTooLarge { size, limit } => {
                write!(
                    f,
                    "Base64 input too large: {size} bytes exceeds limit {limit}"
                )
            }
        }
    }
}

impl std::error::Error for Base64Error {}
redacted_debug!(Base64Error);

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub const MAX_BASE64_BYTES: usize = 16 * 1024 * 1024;

/// Encodes binary data into standard base64 with padding.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        let i0 = (b0 >> 2) as usize;
        let i1 = (((b0 & 0x03) << 4) | (b1 >> 4)) as usize;
        let i2 = (((b1 & 0x0f) << 2) | (b2 >> 6)) as usize;
        let i3 = (b2 & 0x3f) as usize;

        out.push(B64_ALPHABET[i0] as char);
        out.push(B64_ALPHABET[i1] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[i2] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[i3] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn decode_b64_char(c: u8) -> Result<u8, Base64Error> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        other => Err(Base64Error::InvalidChar(other as char)),
    }
}

/// Decodes standard base64 string with strict RFC 4648 validation.
pub fn base64_decode(input: &str, max_bytes: usize) -> Result<Vec<u8>, Base64Error> {
    let max_bytes = max_bytes.min(MAX_BASE64_BYTES);
    let encoded_limit = max_bytes.div_ceil(3).saturating_mul(4);
    if input.len() > encoded_limit {
        return Err(Base64Error::InputTooLarge {
            size: input.len(),
            limit: max_bytes,
        });
    }

    if input.is_empty() {
        return Ok(Vec::new());
    }

    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(Base64Error::InvalidLength);
    }

    let padding = bytes
        .iter()
        .rev()
        .take(2)
        .take_while(|&&b| b == b'=')
        .count();
    let decoded_len = bytes.len() / 4 * 3 - padding;
    if decoded_len > max_bytes {
        return Err(Base64Error::InputTooLarge {
            size: decoded_len,
            limit: max_bytes,
        });
    }

    let mut out = Vec::with_capacity(decoded_len);
    let (chunks, _) = bytes.as_chunks::<4>();

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        let is_last = (chunk_idx + 1) * 4 == bytes.len();
        let c0 = chunk[0];
        let c1 = chunk[1];
        let c2 = chunk[2];
        let c3 = chunk[3];

        if !is_last && (c2 == b'=' || c3 == b'=') {
            return Err(Base64Error::InvalidPadding);
        }

        let d0 = decode_b64_char(c0)?;
        let d1 = decode_b64_char(c1)?;

        if c2 == b'=' {
            if c3 != b'=' {
                return Err(Base64Error::InvalidPadding);
            }
            // 2 characters -> 1 byte. Remaining 4 bits in d1 must be 0.
            if d1 & 0x0f != 0 {
                return Err(Base64Error::NonZeroTrailingBits);
            }
            out.push((d0 << 2) | (d1 >> 4));
        } else if c3 == b'=' {
            let d2 = decode_b64_char(c2)?;
            // 3 characters -> 2 bytes. Remaining 2 bits in d2 must be 0.
            if d2 & 0x03 != 0 {
                return Err(Base64Error::NonZeroTrailingBits);
            }
            out.push((d0 << 2) | (d1 >> 4));
            out.push(((d1 & 0x0f) << 4) | (d2 >> 2));
        } else {
            let d2 = decode_b64_char(c2)?;
            let d3 = decode_b64_char(c3)?;
            out.push((d0 << 2) | (d1 >> 4));
            out.push(((d1 & 0x0f) << 4) | (d2 >> 2));
            out.push(((d2 & 0x03) << 6) | d3);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc4648_test_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");

        assert_eq!(base64_decode("", 100).expect("empty"), b"");
        assert_eq!(base64_decode("Zg==", 100).expect("f"), b"f");
        assert_eq!(base64_decode("Zm8=", 100).expect("fo"), b"fo");
        assert_eq!(base64_decode("Zm9v", 100).expect("foo"), b"foo");
        assert_eq!(base64_decode("Zm9vYg==", 100).expect("foob"), b"foob");
        assert_eq!(base64_decode("Zm9vYmE=", 100).expect("fooba"), b"fooba");
        assert_eq!(base64_decode("Zm9vYmFy", 100).expect("foobar"), b"foobar");
    }

    #[test]
    fn test_invalid_padding_and_trailing_bits() {
        // Non-zero trailing bits in 1-byte padding
        assert_eq!(
            base64_decode("Zh==", 100),
            Err(Base64Error::NonZeroTrailingBits)
        );
        // Premature padding
        assert_eq!(
            base64_decode("Z===Zm9v", 100),
            Err(Base64Error::InvalidPadding)
        );
        // Wrong chunk length
        assert_eq!(base64_decode("Zm9", 100), Err(Base64Error::InvalidLength));
    }
}
