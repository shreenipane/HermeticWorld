//! Supervisor-only boot input on the result drive, overwritten by HGRD at exit.
use crate::{RunName, RESULT_DISK_BYTES};

/// HGRL, version 1 (big-endian u16), then two ASCII run bytes.
pub const RUN_LABEL_HEADER_BYTES: usize = 8;
pub const RUN_LABEL_MAGIC_VERSION: &[u8; 6] = b"HGRL\0\x01";

/// The full drive is fixed-size and zero-padded; no nonce or other data is accepted.
pub fn encode_run_label(run: RunName) -> Vec<u8> {
    let name = match run {
        RunName::R0 => b"R0",
        RunName::R1 => b"R1",
        RunName::R2 => b"R2",
        RunName::R3 => b"R3",
    };
    let mut image = Vec::with_capacity(RESULT_DISK_BYTES);
    image.extend_from_slice(RUN_LABEL_MAGIC_VERSION);
    image.extend_from_slice(name);
    image.resize(RESULT_DISK_BYTES, 0);
    image
}

pub fn decode_run_label(image: &[u8]) -> Option<RunName> {
    if image.len() != RESULT_DISK_BYTES
        || image.get(..6)? != RUN_LABEL_MAGIC_VERSION
        || image.get(RUN_LABEL_HEADER_BYTES..)?.iter().any(|b| *b != 0)
    {
        return None;
    }
    match image.get(6..RUN_LABEL_HEADER_BYTES)? {
        b"R0" => Some(RunName::R0),
        b"R1" => Some(RunName::R1),
        b"R2" => Some(RunName::R2),
        b"R3" => Some(RunName::R3),
        _ => None,
    }
}
