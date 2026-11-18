#![forbid(unsafe_code)]

//! Core Git object types, error definitions, and hashing functions.

use std::fmt;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
}

impl ObjectType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectType::Commit => "commit",
            ObjectType::Tree => "tree",
            ObjectType::Blob => "blob",
            ObjectType::Tag => "tag",
        }
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(ObjectType::Commit),
            2 => Some(ObjectType::Tree),
            3 => Some(ObjectType::Blob),
            4 => Some(ObjectType::Tag),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitObject {
    pub obj_type: ObjectType,
    pub data: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Corrupt git repository: {0}")]
    Corrupt(String),
    #[error("Git object not found: {0}")]
    NotFound(String),
    #[error("Requested object is not reachable from sealed repository binding: {0}")]
    Unreachable(String),
    #[error("Git protocol violation: {0}")]
    Protocol(String),
    #[error("Resource limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("Unsupported Git feature: {0}")]
    Unsupported(String),
}

/// Checks that an OID string is exactly 40 ASCII hexadecimal digits.
pub fn is_hex_oid(oid: &str) -> bool {
    oid.len() == 40 && oid.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Computes the Git SHA-1 object ID for the given object type and raw uncompressed payload.
pub fn compute_sha1(obj_type: ObjectType, data: &[u8]) -> String {
    let header = format!("{} {}\0", obj_type.as_str(), data.len());
    let mut hasher = Sha1::new();
    hasher.update(header.as_bytes());
    hasher.update(data);
    hex::encode(hasher.finalize())
}
