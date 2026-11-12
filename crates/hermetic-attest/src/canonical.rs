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

use crate::digest::Digest;

#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Convert a `serde_json::Value` into its canonical form.
///
/// Ensures all objects have sorted keys and no floating-point numbers exist.
pub fn canonicalize_value(val: &Value) -> Result<Value, CanonicalJsonError> {
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
                canonical_arr.push(canonicalize_value(item)?);
            }
            Ok(Value::Array(canonical_arr))
        }
        Value::Object(map) => {
            let mut sorted_map = BTreeMap::new();
            for (k, v) in map {
                sorted_map.insert(k.clone(), canonicalize_value(v)?);
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
    let val = serde_json::to_value(value)
        .map_err(|e| CanonicalJsonError::JsonSerialization(e.to_string()))?;
    let canonical = canonicalize_value(&val)?;
    serde_json::to_vec(&canonical).map_err(|e| CanonicalJsonError::JsonSerialization(e.to_string()))
}

/// Parse untrusted JSON text (capped by `max_bytes`) and return its canonical JSON bytes.
pub fn canonical_json_from_str(s: &str, max_bytes: usize) -> Result<Vec<u8>, CanonicalJsonError> {
    if s.len() > max_bytes {
        return Err(CanonicalJsonError::InputTooLarge {
            size: s.len(),
            limit: max_bytes,
        });
    }
    let val: Value = serde_json::from_str(s)
        .map_err(|e| CanonicalJsonError::JsonSerialization(e.to_string()))?;
    let canonical = canonicalize_value(&val)?;
    serde_json::to_vec(&canonical).map_err(|e| CanonicalJsonError::JsonSerialization(e.to_string()))
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
