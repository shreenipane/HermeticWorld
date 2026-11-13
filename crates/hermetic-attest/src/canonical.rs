//! Canonical JSON encoding and run digest calculation.
//!
//! Produces deterministic, sorted, compact JSON byte representations:
//! - Object keys are sorted lexicographically by UTF-8 bytes.
//! - Whitespace between tokens is eliminated (compact).
//! - Numbers must be integers; floating-point values are rejected.
//! - SHA-256 over this canonical byte encoding forms the run digest.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};

use crate::digest::Digest;

pub const MAX_CANONICAL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CANONICAL_DEPTH: usize = 64;

/// Never include supplied JSON tokens in an error (including unknown field names).
pub(crate) fn json_error(error: serde_json::Error) -> String {
    match error.classify() {
        serde_json::error::Category::Data => "invalid or unknown field",
        serde_json::error::Category::Syntax => "invalid JSON syntax",
        serde_json::error::Category::Eof => "incomplete JSON",
        serde_json::error::Category::Io => "JSON resource limit exceeded",
    }
    .to_string()
}

struct BoundedJson {
    bytes: Vec<u8>,
    limit: usize,
    depth: usize,
    in_string: bool,
    escaped: bool,
}

impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("JSON size cap exceeded"));
        }
        for &byte in bytes {
            if self.in_string {
                if self.escaped {
                    self.escaped = false;
                } else if byte == b'\\' {
                    self.escaped = true;
                } else if byte == b'"' {
                    self.in_string = false;
                }
            } else {
                match byte {
                    b'"' => self.in_string = true,
                    b'[' | b'{' => {
                        if self.depth == MAX_CANONICAL_DEPTH {
                            return Err(io::Error::other("JSON depth cap exceeded"));
                        }
                        self.depth += 1;
                    }
                    b']' | b'}' => self.depth = self.depth.saturating_sub(1),
                    _ => {}
                }
            }
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn bounded_json_bytes<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<Vec<u8>, CanonicalJsonError> {
    let mut writer = BoundedJson {
        bytes: Vec::new(),
        limit: limit.min(MAX_CANONICAL_BYTES),
        depth: 0,
        in_string: false,
        escaped: false,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|e| CanonicalJsonError::JsonSerialization(json_error(e)))?;
    Ok(writer.bytes)
}

#[derive(Clone, PartialEq, Eq)]
pub enum CanonicalJsonError {
    JsonSerialization(String),
    FloatingPointNotPermitted(String),
    InputTooLarge { size: usize, limit: usize },
}

impl fmt::Display for CanonicalJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonSerialization(msg) => write!(f, "JSON serialization error: {msg}"),
            Self::FloatingPointNotPermitted(num) => {
                write!(
                    f,
                    "Floating-point numbers are not permitted in canonical JSON: {num}"
                )
            }
            Self::InputTooLarge { size, limit } => {
                write!(
                    f,
                    "JSON input too large: {size} bytes exceeds limit {limit}"
                )
            }
        }
    }
}

impl std::error::Error for CanonicalJsonError {}
redacted_debug!(CanonicalJsonError);

/// Convert a `serde_json::Value` into its canonical form.
///
/// Ensures all objects have sorted keys and no floating-point numbers exist.
pub fn canonicalize_value(val: &Value) -> Result<Value, CanonicalJsonError> {
    // The streaming serializer enforces both limits before any recursive cloning.
    bounded_json_bytes(val, MAX_CANONICAL_BYTES)?;
    canonicalize_bounded_value(val)
}

fn canonicalize_bounded_value(val: &Value) -> Result<Value, CanonicalJsonError> {
    match val {
        Value::Null => Ok(Value::Null),
        Value::Bool(b) => Ok(Value::Bool(*b)),
        Value::Number(n) => {
            if !n.is_i64() && !n.is_u64() {
                return Err(CanonicalJsonError::FloatingPointNotPermitted(n.to_string()));
            }
            Ok(Value::Number(n.clone()))
        }
        Value::String(s) => Ok(Value::String(s.clone())),
        Value::Array(arr) => {
            let mut canonical_arr = Vec::with_capacity(arr.len());
            for item in arr {
                canonical_arr.push(canonicalize_bounded_value(item)?);
            }
            Ok(Value::Array(canonical_arr))
        }
        Value::Object(map) => {
            let mut sorted_map = BTreeMap::new();
            for (k, v) in map {
                sorted_map.insert(k.clone(), canonicalize_bounded_value(v)?);
            }
            let mut canonical_obj = serde_json::Map::new();
            for (k, v) in sorted_map {
                canonical_obj.insert(k, v);
            }
            Ok(Value::Object(canonical_obj))
        }
    }
}

/// Serialize any serializable struct to canonical JSON bytes.
pub fn to_canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalJsonError> {
    let bytes = bounded_json_bytes(value, MAX_CANONICAL_BYTES)?;
    let val: Value = serde_json::from_slice(&bytes)
        .map_err(|e| CanonicalJsonError::JsonSerialization(json_error(e)))?;
    let canonical = canonicalize_bounded_value(&val)?;
    bounded_json_bytes(&canonical, MAX_CANONICAL_BYTES)
}

/// Parse untrusted JSON text (capped by `max_bytes`) and return its canonical JSON bytes.
pub fn canonical_json_from_str(s: &str, max_bytes: usize) -> Result<Vec<u8>, CanonicalJsonError> {
    let max_bytes = max_bytes.min(MAX_CANONICAL_BYTES);
    if s.len() > max_bytes {
        return Err(CanonicalJsonError::InputTooLarge {
            size: s.len(),
            limit: max_bytes,
        });
    }
    let val: Value = serde_json::from_str(s)
        .map_err(|e| CanonicalJsonError::JsonSerialization(json_error(e)))?;
    let canonical = canonicalize_value(&val)?;
    bounded_json_bytes(&canonical, max_bytes)
}

/// Compute the run digest as SHA-256 of the canonical JSON byte encoding of the statement.
pub fn compute_run_digest<T: Serialize>(statement: &T) -> Result<Digest, CanonicalJsonError> {
    let bytes = to_canonical_json_bytes(statement)?;
    Ok(Digest::from_sha256(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_json_key_sorting() {
        let val1 = json!({
            "zebra": 1,
            "apple": 2,
            "banana": {
                "yellow": true,
                "green": false
            }
        });
        let val2 = json!({
            "banana": {
                "green": false,
                "yellow": true
            },
            "apple": 2,
            "zebra": 1
        });

        let bytes1 = to_canonical_json_bytes(&val1).expect("canon 1");
        let bytes2 = to_canonical_json_bytes(&val2).expect("canon 2");
        assert_eq!(bytes1, bytes2);
        assert_eq!(
            String::from_utf8(bytes1).unwrap(),
            r#"{"apple":2,"banana":{"green":false,"yellow":true},"zebra":1}"#
        );
    }

    #[test]
    fn test_floating_point_rejected() {
        let val = json!({
            "score": 3.5
        });
        assert!(matches!(
            to_canonical_json_bytes(&val),
            Err(CanonicalJsonError::FloatingPointNotPermitted(_))
        ));
    }
}
