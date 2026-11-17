#![forbid(unsafe_code)]

use std::io::Cursor;

use hermetic_extract::disk::{
    parse_and_validate_disk, read_output_drive_stream, DiskError, ExtractDiskHeader,
    ExtractFailureCode, EXTRACT_DISK_HEADER_BYTES, EXTRACT_DISK_MAGIC, EXTRACT_DISK_VERSION,
};
use sha2::{Digest, Sha256};

const TEST_NONCE: [u8; 32] = [0x42; 32];

fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[test]
fn valid_output_drive_roundtrip() {
    let payload = b"HEXT\x01\x00\x00\x00dummy-hext-stream-content";
    let digest = compute_sha256(payload);
    let header = ExtractDiskHeader::new_success(TEST_NONCE, payload.len() as u64, digest);

    let mut drive = Vec::new();
    drive.extend_from_slice(&header.encode());
    drive.extend_from_slice(payload);
    // Trailing disk padding (e.g. 1 MiB drive)
    drive.resize(1024 * 1024, 0);

    let (decoded_hdr, decoded_payload) =
        parse_and_validate_disk(&drive, &TEST_NONCE, 10 * 1024 * 1024).unwrap();
    assert_eq!(decoded_hdr.magic, *EXTRACT_DISK_MAGIC);
    assert_eq!(decoded_hdr.version, EXTRACT_DISK_VERSION);
    assert_eq!(decoded_hdr.failure_code, 0);
    assert_eq!(decoded_hdr.payload_len, payload.len() as u64);
    assert_eq!(decoded_hdr.nonce, TEST_NONCE);
    assert_eq!(decoded_hdr.sha256, digest);
    assert_eq!(decoded_payload, payload);

    // Also test stream reader helper
    let mut cursor = Cursor::new(&drive);
    let (s_hdr, s_payload) =
        read_output_drive_stream(&mut cursor, &TEST_NONCE, 10 * 1024 * 1024).unwrap();
    assert_eq!(s_hdr, decoded_hdr);
    assert_eq!(s_payload, payload);
}

#[test]
fn truncated_header_refused() {
    let tiny = [0u8; 20];
    let err = parse_and_validate_disk(&tiny, &TEST_NONCE, 1024).unwrap_err();
    assert!(matches!(
        err,
        DiskError::TruncatedHeader {
            expected: EXTRACT_DISK_HEADER_BYTES,
            actual: 20
        }
    ));

    let mut cursor = Cursor::new(&tiny);
    let err = read_output_drive_stream(&mut cursor, &TEST_NONCE, 1024).unwrap_err();
    assert!(matches!(err, DiskError::TruncatedHeader { .. }));
}

#[test]
fn wrong_magic_refused() {
    let mut header = ExtractDiskHeader::new_success(TEST_NONCE, 0, [0u8; 32]).encode();
    header[0..4].copy_from_slice(b"BADM");

    let err = parse_and_validate_disk(&header, &TEST_NONCE, 1024).unwrap_err();
    assert_eq!(err, DiskError::InvalidMagic(*b"BADM"));
}

#[test]
fn unsupported_version_refused() {
    // Version 1 is now unsupported (bumped to 2)
    let mut header = ExtractDiskHeader::new_success(TEST_NONCE, 0, [0u8; 32]).encode();
    header[4..6].copy_from_slice(&1u16.to_be_bytes());

    let err = parse_and_validate_disk(&header, &TEST_NONCE, 1024).unwrap_err();
    assert_eq!(err, DiskError::UnsupportedVersion(1));

    // Version 3 is unsupported
    header[4..6].copy_from_slice(&3u16.to_be_bytes());
    let err = parse_and_validate_disk(&header, &TEST_NONCE, 1024).unwrap_err();
    assert_eq!(err, DiskError::UnsupportedVersion(3));
}

#[test]
fn nonce_mismatch_refused() {
    let payload = b"HEXT\x01\x00\x00\x00payload";
    let digest = compute_sha256(payload);
    let header = ExtractDiskHeader::new_success(TEST_NONCE, payload.len() as u64, digest);

    let mut drive = Vec::new();
    drive.extend_from_slice(&header.encode());
    drive.extend_from_slice(payload);

    let different_nonce = [0x99; 32];
    let err = parse_and_validate_disk(&drive, &different_nonce, 1024).unwrap_err();
    assert_eq!(
        err,
        DiskError::NonceMismatch {
            expected: different_nonce,
            actual: TEST_NONCE,
        }
    );

    let mut cursor = Cursor::new(&drive);
    let err = read_output_drive_stream(&mut cursor, &different_nonce, 1024).unwrap_err();
    assert_eq!(
        err,
        DiskError::NonceMismatch {
            expected: different_nonce,
            actual: TEST_NONCE,
        }
    );
}

#[test]
fn failure_code_refused() {
    for code in [
        ExtractFailureCode::Timeout,
        ExtractFailureCode::ConfigError,
        ExtractFailureCode::MountError,
        ExtractFailureCode::ExtractError,
        ExtractFailureCode::IoError,
        ExtractFailureCode::InternalError,
        ExtractFailureCode::InProgress,
        ExtractFailureCode::Unknown(99),
    ] {
        let header = ExtractDiskHeader::new_failure(code, TEST_NONCE);
        let drive = header.encode();
        let err = parse_and_validate_disk(&drive, &TEST_NONCE, 1024).unwrap_err();
        assert_eq!(err, DiskError::FailureCode(code.as_raw()));
    }
}

#[test]
fn oversize_payload_refused() {
    let payload = b"short";
    let digest = compute_sha256(payload);
    // Declared size 1000, cap 500
    let header = ExtractDiskHeader::new_success(TEST_NONCE, 1000, digest);

    let mut drive = Vec::new();
    drive.extend_from_slice(&header.encode());
    drive.resize(2000, 0);

    let err = parse_and_validate_disk(&drive, &TEST_NONCE, 500).unwrap_err();
    assert_eq!(
        err,
        DiskError::PayloadTooLarge {
            len: 1000,
            max: 500
        }
    );
}

#[test]
fn truncated_payload_refused() {
    let payload = b"some payload bytes";
    let digest = compute_sha256(payload);
    let header = ExtractDiskHeader::new_success(TEST_NONCE, 100, digest);

    let mut drive = Vec::new();
    drive.extend_from_slice(&header.encode());
    drive.extend_from_slice(payload); // only 18 bytes, not 100

    let err = parse_and_validate_disk(&drive, &TEST_NONCE, 1024).unwrap_err();
    assert_eq!(
        err,
        DiskError::TruncatedPayload {
            expected: 100,
            actual: payload.len() as u64
        }
    );
}

#[test]
fn hash_mismatch_refused() {
    let payload = b"hello world";
    let mut wrong_digest = compute_sha256(payload);
    wrong_digest[0] ^= 0xFF; // corrupt hash
    let header = ExtractDiskHeader::new_success(TEST_NONCE, payload.len() as u64, wrong_digest);

    let mut drive = Vec::new();
    drive.extend_from_slice(&header.encode());
    drive.extend_from_slice(payload);

    let err = parse_and_validate_disk(&drive, &TEST_NONCE, 1024).unwrap_err();
    assert!(matches!(err, DiskError::Sha256Mismatch { .. }));
}
