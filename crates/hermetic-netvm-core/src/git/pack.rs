#![forbid(unsafe_code)]

//! Deterministic packfile generator for Git shallow clones.
//!
//! Encodes a slice of Git objects into a valid, self-contained Git PACK v2 file
//! with zlib compression and SHA-1 trailer checksum.

use std::io::Write;
use flate2::write::ZlibEncoder;
use sha1::{Digest, Sha1};

use super::types::{GitError, ObjectType};

/// Maximum objects allowed in a single dynamically generated shallow packfile.
pub const MAX_PACK_OBJECTS: usize = 50_000;

/// Hard ceiling on total uncompressed pack payload bytes (64 MiB).
pub const MAX_PACK_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

/// Encodes the variable-length Git pack object header (3-bit type, 4-bit low size, 7-bit continuation).
fn encode_pack_object_header(obj_type: ObjectType, mut size: usize, out: &mut Vec<u8>) {
    let mut byte = ((obj_type as u8) << 4) | ((size & 0x0f) as u8);
    size >>= 4;
    if size > 0 {
        byte |= 0x80;
    }
    out.push(byte);

    while size > 0 {
        let mut cont_byte = (size & 0x7f) as u8;
        size >>= 7;
        if size > 0 {
            cont_byte |= 0x80;
        }
        out.push(cont_byte);
    }
}

/// Builds a complete Git PACK v2 stream from uncompressed objects.
pub fn build_packfile(objects: &[(ObjectType, &[u8])]) -> Result<Vec<u8>, GitError> {
    if objects.len() > MAX_PACK_OBJECTS {
        return Err(GitError::LimitExceeded(format!(
            "packfile object count {} exceeds limit {}",
            objects.len(),
            MAX_PACK_OBJECTS
        )));
    }

    let mut total_payload = 0usize;
    for &(_, data) in objects {
        total_payload = total_payload.saturating_add(data.len());
        if total_payload > MAX_PACK_PAYLOAD_BYTES {
            return Err(GitError::LimitExceeded(format!(
                "packfile payload size exceeds {MAX_PACK_PAYLOAD_BYTES} bytes"
            )));
        }
    }

    // 12-byte PACK v2 header: 'PACK', version 2, count of objects
    let mut pack = Vec::with_capacity(12 + total_payload / 2);
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2u32.to_be_bytes());
    pack.extend_from_slice(&(objects.len() as u32).to_be_bytes());

    for &(obj_type, data) in objects {
        encode_pack_object_header(obj_type, data.len(), &mut pack);

        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder
            .write_all(data)
            .map_err(|e| GitError::Corrupt(format!("zlib compression error: {e}")))?;
        let compressed = encoder
            .finish()
            .map_err(|e| GitError::Corrupt(format!("zlib finish error: {e}")))?;
        pack.extend_from_slice(&compressed);
    }

    // 20-byte SHA-1 trailer over all preceding packfile bytes
    let mut hasher = Sha1::new();
    hasher.update(&pack);
    let checksum = hasher.finalize();
    pack.extend_from_slice(&checksum);

    Ok(pack)
}
