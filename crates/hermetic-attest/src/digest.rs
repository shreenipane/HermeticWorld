//! Validated Digest newtype.
//!
//! A digest must have the format `<algorithm>:<lowercase_hex>`.
//! For SHA-256 and BLAKE3, the hex portion must be exactly 64 lowercase hex characters.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as Sha2Digest, Sha256};
use std::fmt;

use crate::hex::{hex_decode, hex_encode, is_strict_lowercase_hex, HexError};

#[derive(Clone, PartialEq, Eq)]
pub enum DigestError {
    MissingPrefix,
    EmptyAlgorithm,
    InvalidAlgorithm(String),
    EmptyHex,
    InvalidHexChar(char),
    UppercaseHexNotAllowed,
    InvalidLength {
        algo: String,
        expected: usize,
        actual: usize,
    },
    HexDecode(HexError),
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => write!(f, "Digest is missing ':' algorithm separator"),
            Self::EmptyAlgorithm => write!(f, "Digest algorithm prefix is empty"),
            Self::InvalidAlgorithm(_) => write!(f, "Invalid or unsupported digest algorithm"),
            Self::EmptyHex => write!(f, "Digest hex string is empty"),
            Self::InvalidHexChar(_) => write!(f, "Invalid character in digest hex"),
            Self::UppercaseHexNotAllowed => {
                write!(f, "Uppercase characters not allowed in digest hex")
            }
            Self::InvalidLength {
                algo,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Invalid digest length for {algo}: expected {expected} hex chars, got {actual}"
                )
            }
            Self::HexDecode(e) => write!(f, "Hex decoding error: {e}"),
        }
    }
}

impl std::error::Error for DigestError {}
redacted_debug!(DigestError);

pub const MAX_DIGEST_TEXT_BYTES: usize = 135;

/// A validated digest with algorithm prefix and lowercase hexadecimal value.
///
/// Example: `"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(String);

impl Digest {
    /// Parse and validate a digest string.
    pub fn parse(s: &str) -> Result<Self, DigestError> {
        if s.len() > MAX_DIGEST_TEXT_BYTES {
            return Err(DigestError::InvalidAlgorithm("unsupported".into()));
        }
        let (algo, hex_str) = s.split_once(':').ok_or(DigestError::MissingPrefix)?;
        if algo.is_empty() {
            return Err(DigestError::EmptyAlgorithm);
        }
        if !algo
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(DigestError::InvalidAlgorithm("invalid".into()));
        }
        if hex_str.is_empty() {
            return Err(DigestError::EmptyHex);
        }

        // Check for uppercase characters explicitly
        if hex_str.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(DigestError::UppercaseHexNotAllowed);
        }

        if !is_strict_lowercase_hex(hex_str) {
            let bad_char = hex_str
                .chars()
                .find(|c| !matches!(c, '0'..='9' | 'a'..='f'))
                .unwrap_or('?');
            return Err(DigestError::InvalidHexChar(bad_char));
        }

        // Validate known algorithm lengths
        match algo {
            "sha256" | "blake3" => {
                if hex_str.len() != 64 {
                    return Err(DigestError::InvalidLength {
                        algo: algo.to_string(),
                        expected: 64,
                        actual: hex_str.len(),
                    });
                }
            }
            "sha512" => {
                if hex_str.len() != 128 {
                    return Err(DigestError::InvalidLength {
                        algo: algo.to_string(),
                        expected: 128,
                        actual: hex_str.len(),
                    });
                }
            }
            _ => {
                return Err(DigestError::InvalidAlgorithm("unsupported".into()));
            }
        }

        Ok(Self(s.to_string()))
    }

    /// Compute the SHA-256 digest of bytes.
    pub fn from_sha256(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        Self(format!("sha256:{}", hex_encode(&hash)))
    }

    /// Construct a sha256 digest from a 64-char hex string.
    pub fn from_sha256_hex(hex_str: &str) -> Result<Self, DigestError> {
        let s = format!("sha256:{hex_str}");
        Self::parse(&s)
    }

    /// Construct a blake3 digest from a 64-char hex string.
    pub fn from_blake3_hex(hex_str: &str) -> Result<Self, DigestError> {
        let s = format!("blake3:{hex_str}");
        Self::parse(&s)
    }

    /// Return the full string representation, e.g. `"sha256:abcd..."`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the algorithm prefix, e.g. `"sha256"`.
    pub fn algorithm(&self) -> &str {
        self.0.split_once(':').map(|(a, _)| a).unwrap_or("")
    }

    /// Return the hex portion of the digest.
    pub fn hex(&self) -> &str {
        self.0.split_once(':').map(|(_, h)| h).unwrap_or("")
    }

    /// Decode the hex portion into raw bytes.
    pub fn raw_bytes(&self) -> Result<Vec<u8>, DigestError> {
        hex_decode(self.hex()).map_err(DigestError::HexDecode)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest(\"{}\")", self.0)
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Digest::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_digests() {
        let valid_sha256 =
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let d = Digest::parse(valid_sha256).expect("parse sha256");
        assert_eq!(d.algorithm(), "sha256");
        assert_eq!(
            d.hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(d.as_str(), valid_sha256);

        let valid_blake3 =
            "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let b = Digest::parse(valid_blake3).expect("parse blake3");
        assert_eq!(b.algorithm(), "blake3");
    }

    #[test]
    fn test_invalid_digests() {
        // Missing colon
        assert_eq!(
            Digest::parse("sha256abcdef"),
            Err(DigestError::MissingPrefix)
        );
        // Uppercase not allowed
        assert_eq!(
            Digest::parse(
                "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
            ),
            Err(DigestError::UppercaseHexNotAllowed)
        );
        // Wrong length
        assert!(matches!(
            Digest::parse("sha256:abcd"),
            Err(DigestError::InvalidLength { .. })
        ));
        // Non-hex
        assert!(matches!(
            Digest::parse(
                "sha256:zzb0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            Err(DigestError::InvalidHexChar('z'))
        ));
    }

    #[test]
    fn test_from_sha256() {
        let d = Digest::from_sha256(b"");
        assert_eq!(
            d.as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
