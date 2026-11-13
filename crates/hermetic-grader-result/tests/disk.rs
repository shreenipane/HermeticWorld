#![forbid(unsafe_code)]

use hermetic_grader_result::{
    encode_disk, parse_disk_bytes, read_disk, sha256_bytes, sha256_hex, validate_run_result,
    write_disk, DiskError, InvalidFileType, RunId, RunResult, SupervisorExit, SupervisorSummary,
    TamperReason, TestStatus, DISK_BYTES, HEADER_BYTES, MAX_NODE_ID_BYTES, PAYLOAD_CAP,
};
use std::collections::BTreeMap;
use std::fs;
use tempfile::tempdir;

const SAMPLE_VARIANT_SET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn sample_run_result() -> RunResult {
    let mut tests = BTreeMap::new();
    tests.insert("test_alpha".to_string(), TestStatus::Passed);
    RunResult {
        run: RunId::R0,
        variant_set: SAMPLE_VARIANT_SET.to_string(),
        tests,
        supervisor: SupervisorSummary {
            exit: SupervisorExit::Clean,
            tests_started: 1,
            tests_finished: 1,
        },
    }
}

fn craft_raw_disk(
    magic: [u8; 4],
    version: u16,
    flags: u16,
    payload_len_override: Option<u32>,
    hash_override: Option<[u8; 32]>,
    payload: &[u8],
) -> Vec<u8> {
    let mut image = vec![0u8; DISK_BYTES];
    image[0..4].copy_from_slice(&magic);
    image[4..6].copy_from_slice(&version.to_be_bytes());
    image[6..8].copy_from_slice(&flags.to_be_bytes());
    let len_u32 = payload_len_override.unwrap_or(payload.len() as u32);
    image[8..12].copy_from_slice(&len_u32.to_be_bytes());
    let hash = hash_override.unwrap_or_else(|| sha256_bytes(payload));
    image[12..44].copy_from_slice(&hash);
    let copy_len = payload.len().min(PAYLOAD_CAP);
    image[HEADER_BYTES..HEADER_BYTES + copy_len].copy_from_slice(&payload[..copy_len]);
    image
}

#[test]
fn round_trip_write_and_read_disk() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("r0.hgrd");
    let expected = sample_run_result();

    let written_sha = write_disk(&expected, &path).unwrap();
    let meta = fs::symlink_metadata(&path).unwrap();
    assert_eq!(meta.len(), DISK_BYTES as u64);

    let actual = read_disk(&path).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual.disk_sha256().unwrap(), written_sha);
}

#[test]
fn known_answer_sha256_and_fixed_image_bytes() {
    // Known-answer SHA-256 vector 1: empty byte slice.
    let empty_sha = sha256_hex(&sha256_bytes(b""));
    assert_eq!(
        empty_sha,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    // Known-answer SHA-256 vector 2: standard "abc" fixture.
    let abc_sha = sha256_hex(&sha256_bytes(b"abc"));
    assert_eq!(
        abc_sha,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // Known-answer SHA-256 vector 3: 1 MiB (DISK_BYTES) fixed all-zero image.
    let zero_disk = vec![0u8; DISK_BYTES];
    let zero_disk_sha = sha256_hex(&sha256_bytes(&zero_disk));
    assert_eq!(
        zero_disk_sha,
        "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58"
    );

    // Known-answer fixed HGRD image header and canonical payload bytes.
    let run = sample_run_result();
    let (image, disk_digest) = encode_disk(&run).unwrap();
    assert_eq!(image.len(), DISK_BYTES);

    let expected_payload = br#"{"run":"R0","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tests":{"test_alpha":"passed"},"supervisor":{"exit":"clean","tests_started":1,"tests_finished":1}}"#;
    assert_eq!(expected_payload.len(), 192);

    // Header bytes 0..12: magic "HGRD", version 1 (0x0001), flags 0 (0x0000), length 192 (0x000000C0).
    let expected_header_prefix: [u8; 12] = [
        b'H', b'G', b'R', b'D', 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0,
    ];
    assert_eq!(&image[0..12], &expected_header_prefix);

    let expected_payload_sha = sha256_bytes(expected_payload);
    assert_eq!(&image[12..44], &expected_payload_sha);
    assert_eq!(&image[44..236], expected_payload);
    assert!(image[236..].iter().all(|&b| b == 0));

    let dir = tempdir().unwrap();
    let disk_path = dir.path().join("fixed.hgrd");
    let written_digest = write_disk(&run, &disk_path).unwrap();
    assert_eq!(written_digest, disk_digest);
    assert_eq!(fs::read(&disk_path).unwrap(), image);
}

#[test]
fn reject_wrong_size_by_one_byte_either_way() {
    let dir = tempdir().unwrap();
    let run = sample_run_result();
    let (image, _) = encode_disk(&run).unwrap();

    let short_path = dir.path().join("short.hgrd");
    fs::write(&short_path, &image[..DISK_BYTES - 1]).unwrap();
    assert_eq!(
        read_disk(&short_path),
        Err(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: (DISK_BYTES - 1) as u64,
        }))
    );

    let mut long_image = image;
    long_image.push(0);
    let long_path = dir.path().join("long.hgrd");
    fs::write(&long_path, &long_image).unwrap();
    assert_eq!(
        read_disk(&long_path),
        Err(DiskError::Tamper(TamperReason::InvalidDiskSize {
            actual: (DISK_BYTES + 1) as u64,
        }))
    );
}

#[test]
fn reject_bad_magic_version_flags_and_hash() {
    let run = sample_run_result();
    let (valid_image, _) = encode_disk(&run).unwrap();

    // Bad magic
    let mut bad_magic = valid_image.clone();
    bad_magic[3] = b'X';
    assert_eq!(
        parse_disk_bytes(&bad_magic),
        Err(DiskError::Tamper(TamperReason::BadMagic))
    );

    // Unsupported version (0 and 2)
    let mut bad_ver_0 = valid_image.clone();
    bad_ver_0[4..6].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(
        parse_disk_bytes(&bad_ver_0),
        Err(DiskError::Tamper(TamperReason::UnsupportedVersion(0)))
    );

    let mut bad_ver_2 = valid_image.clone();
    bad_ver_2[4..6].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(
        parse_disk_bytes(&bad_ver_2),
        Err(DiskError::Tamper(TamperReason::UnsupportedVersion(2)))
    );

    // Non-zero flags
    let mut bad_flags = valid_image.clone();
    bad_flags[6..8].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(
        parse_disk_bytes(&bad_flags),
        Err(DiskError::Tamper(TamperReason::NonZeroFlags(1)))
    );

    // Hash mismatch
    let mut bad_hash = valid_image;
    bad_hash[12] ^= 0x01;
    assert_eq!(
        parse_disk_bytes(&bad_hash),
        Err(DiskError::Tamper(TamperReason::PayloadHashMismatch))
    );
}

#[test]
fn reject_non_zero_padding_at_first_and_last_offset() {
    let run = sample_run_result();
    let (valid_image, _) = encode_disk(&run).unwrap();
    let payload_len = u32::from_be_bytes([
        valid_image[8],
        valid_image[9],
        valid_image[10],
        valid_image[11],
    ]) as usize;
    let first_pad_offset = HEADER_BYTES + payload_len;
    let last_pad_offset = DISK_BYTES - 1;

    let mut first_pad_dirty = valid_image.clone();
    first_pad_dirty[first_pad_offset] = 1;
    assert_eq!(
        parse_disk_bytes(&first_pad_dirty),
        Err(DiskError::Tamper(TamperReason::NonZeroPadding {
            offset: first_pad_offset,
        }))
    );

    let mut last_pad_dirty = valid_image;
    last_pad_dirty[last_pad_offset] = 0xFF;
    assert_eq!(
        parse_disk_bytes(&last_pad_dirty),
        Err(DiskError::Tamper(TamperReason::NonZeroPadding {
            offset: last_pad_offset,
        }))
    );
}

#[test]
fn reject_oversized_payload_length() {
    let run = sample_run_result();
    let payload = serde_json::to_vec(&run).unwrap();
    let over_by_one = (PAYLOAD_CAP as u32) + 1;
    let image = craft_raw_disk(*b"HGRD", 1, 0, Some(over_by_one), None, &payload);
    assert_eq!(
        parse_disk_bytes(&image),
        Err(DiskError::Tamper(TamperReason::PayloadLengthExceedsCap {
            len: over_by_one,
        }))
    );

    let max_len_image = craft_raw_disk(*b"HGRD", 1, 0, Some(u32::MAX), None, &payload);
    assert_eq!(
        parse_disk_bytes(&max_len_image),
        Err(DiskError::Tamper(TamperReason::PayloadLengthExceedsCap {
            len: u32::MAX,
        }))
    );
}

#[test]
fn reject_duplicate_json_keys_and_unknown_fields() {
    // Duplicate key in tests map
    let dup_tests_json = br#"{"run":"R0","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tests":{"dup":"passed","dup":"failed"},"supervisor":{"exit":"clean","tests_started":1,"tests_finished":1}}"#;
    let dup_tests_disk = craft_raw_disk(*b"HGRD", 1, 0, None, None, dup_tests_json);
    assert_eq!(
        parse_disk_bytes(&dup_tests_disk),
        Err(DiskError::Tamper(TamperReason::DuplicateJsonKey))
    );

    // Duplicate key in outer object
    let dup_outer_json = br#"{"run":"R0","run":"R1","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tests":{},"supervisor":{"exit":"clean","tests_started":0,"tests_finished":0}}"#;
    let dup_outer_disk = craft_raw_disk(*b"HGRD", 1, 0, None, None, dup_outer_json);
    assert_eq!(
        parse_disk_bytes(&dup_outer_disk),
        Err(DiskError::Tamper(TamperReason::DuplicateJsonKey))
    );

    // Unknown field rejected by deny_unknown_fields
    let unknown_field_json = br#"{"run":"R0","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tests":{},"supervisor":{"exit":"clean","tests_started":0,"tests_finished":0},"extra":1}"#;
    let unknown_field_disk = craft_raw_disk(*b"HGRD", 1, 0, None, None, unknown_field_json);
    assert_eq!(
        parse_disk_bytes(&unknown_field_disk),
        Err(DiskError::Tamper(TamperReason::InvalidJson))
    );

    // Duplicate key in supervisor object
    let dup_sup_json = br#"{"run":"R0","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tests":{},"supervisor":{"exit":"clean","exit":"timeout","tests_started":0,"tests_finished":0}}"#;
    let dup_sup_disk = craft_raw_disk(*b"HGRD", 1, 0, None, None, dup_sup_json);
    assert_eq!(
        parse_disk_bytes(&dup_sup_disk),
        Err(DiskError::Tamper(TamperReason::DuplicateJsonKey))
    );
}

#[test]
fn reject_invalid_utf8_in_payload() {
    let bad_utf8_payload = b"{\"run\":\"R0\",\xFF\xFE}";
    let image = craft_raw_disk(*b"HGRD", 1, 0, None, None, bad_utf8_payload);
    assert_eq!(
        parse_disk_bytes(&image),
        Err(DiskError::Tamper(TamperReason::InvalidUtf8))
    );
}

#[test]
fn reject_non_canonical_json_spacing_and_ordering() {
    // Extra spaces in JSON
    let spaced_json = br#"{"run": "R0", "variant_set": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "tests": {}, "supervisor": {"exit": "clean", "tests_started": 0, "tests_finished": 0}}"#;
    let disk_spaced = craft_raw_disk(*b"HGRD", 1, 0, None, None, spaced_json);
    assert_eq!(
        parse_disk_bytes(&disk_spaced),
        Err(DiskError::Tamper(TamperReason::NonCanonicalJson))
    );

    // Unsorted keys in tests map ("z" before "a")
    let unsorted_tests_json = br#"{"run":"R0","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tests":{"z":"passed","a":"passed"},"supervisor":{"exit":"clean","tests_started":2,"tests_finished":2}}"#;
    let disk_unsorted = craft_raw_disk(*b"HGRD", 1, 0, None, None, unsorted_tests_json);
    assert_eq!(
        parse_disk_bytes(&disk_unsorted),
        Err(DiskError::Tamper(TamperReason::NonCanonicalJson))
    );
}

#[test]
fn reject_invalid_variant_set() {
    // Too short (63 chars)
    let short_var_json = br#"{"run":"R0","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde","tests":{},"supervisor":{"exit":"clean","tests_started":0,"tests_finished":0}}"#;
    let disk_short = craft_raw_disk(*b"HGRD", 1, 0, None, None, short_var_json);
    assert_eq!(
        parse_disk_bytes(&disk_short),
        Err(DiskError::Tamper(TamperReason::InvalidVariantSet))
    );

    // Non-hex chars ("zz...")
    let non_hex_json = br#"{"run":"R0","variant_set":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz","tests":{},"supervisor":{"exit":"clean","tests_started":0,"tests_finished":0}}"#;
    let disk_non_hex = craft_raw_disk(*b"HGRD", 1, 0, None, None, non_hex_json);
    assert_eq!(
        parse_disk_bytes(&disk_non_hex),
        Err(DiskError::Tamper(TamperReason::InvalidVariantSet))
    );

    // Uppercase hex chars
    let upper_hex_json = br#"{"run":"R0","variant_set":"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef","tests":{},"supervisor":{"exit":"clean","tests_started":0,"tests_finished":0}}"#;
    let disk_upper = craft_raw_disk(*b"HGRD", 1, 0, None, None, upper_hex_json);
    assert_eq!(
        parse_disk_bytes(&disk_upper),
        Err(DiskError::Tamper(TamperReason::InvalidVariantSet))
    );
}

#[test]
fn reject_invalid_node_ids_control_chars_and_empty() {
    // Empty node ID
    let empty_id_json = br#"{"run":"R0","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tests":{"":"passed"},"supervisor":{"exit":"clean","tests_started":1,"tests_finished":1}}"#;
    let disk_empty = craft_raw_disk(*b"HGRD", 1, 0, None, None, empty_id_json);
    assert_eq!(
        parse_disk_bytes(&disk_empty),
        Err(DiskError::Tamper(TamperReason::InvalidNodeId))
    );

    // Node ID with control char (\x01)
    let ctrl_id_json = br#"{"run":"R0","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tests":{"test\u0001bad":"passed"},"supervisor":{"exit":"clean","tests_started":1,"tests_finished":1}}"#;
    let disk_ctrl = craft_raw_disk(*b"HGRD", 1, 0, None, None, ctrl_id_json);
    assert_eq!(
        parse_disk_bytes(&disk_ctrl),
        Err(DiskError::Tamper(TamperReason::InvalidNodeId))
    );

    // Node ID with DEL (\x7F)
    let del_id_json = br#"{"run":"R0","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tests":{"test\u007fbad":"passed"},"supervisor":{"exit":"clean","tests_started":1,"tests_finished":1}}"#;
    let disk_del = craft_raw_disk(*b"HGRD", 1, 0, None, None, del_id_json);
    assert_eq!(
        parse_disk_bytes(&disk_del),
        Err(DiskError::Tamper(TamperReason::InvalidNodeId))
    );
}

#[test]
fn reject_too_many_tests_count() {
    let mut run = sample_run_result();
    run.tests.clear();
    for i in 0..=100_000 {
        run.tests.insert(format!("t{}", i), TestStatus::Passed);
    }
    assert_eq!(
        validate_run_result(&run),
        Err(DiskError::Tamper(TamperReason::TooManyTests {
            count: 100_001,
        }))
    );
}

#[test]
fn reject_inconsistent_counts_and_invalid_node_ids() {
    // tests_finished > tests_started
    let fin_gt_start_json = br#"{"run":"R0","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tests":{"a":"passed","b":"failed"},"supervisor":{"exit":"clean","tests_started":1,"tests_finished":2}}"#;
    let disk1 = craft_raw_disk(*b"HGRD", 1, 0, None, None, fin_gt_start_json);
    assert_eq!(
        parse_disk_bytes(&disk1),
        Err(DiskError::Tamper(TamperReason::InconsistentCounts {
            tests_count: 2,
            started: 1,
            finished: 2,
            passed_count: 1,
        }))
    );

    // tests_started > tests count
    let start_gt_count_json = br#"{"run":"R0","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tests":{"a":"passed"},"supervisor":{"exit":"clean","tests_started":2,"tests_finished":1}}"#;
    let disk2 = craft_raw_disk(*b"HGRD", 1, 0, None, None, start_gt_count_json);
    assert_eq!(
        parse_disk_bytes(&disk2),
        Err(DiskError::Tamper(TamperReason::InconsistentCounts {
            tests_count: 1,
            started: 2,
            finished: 1,
            passed_count: 1,
        }))
    );

    // A test marked passed must be counted as finished (passed_count > tests_finished)
    let passed_gt_fin_json = br#"{"run":"R0","variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tests":{"a":"passed","b":"passed"},"supervisor":{"exit":"clean","tests_started":2,"tests_finished":1}}"#;
    let disk3 = craft_raw_disk(*b"HGRD", 1, 0, None, None, passed_gt_fin_json);
    assert_eq!(
        parse_disk_bytes(&disk3),
        Err(DiskError::Tamper(TamperReason::InconsistentCounts {
            tests_count: 2,
            started: 2,
            finished: 1,
            passed_count: 2,
        }))
    );

    // Node ID exceeding MAX_NODE_ID_BYTES (1024)
    let mut long_node_run = sample_run_result();
    long_node_run.tests.clear();
    long_node_run
        .tests
        .insert("x".repeat(MAX_NODE_ID_BYTES + 1), TestStatus::Passed);
    assert_eq!(
        encode_disk(&long_node_run),
        Err(DiskError::Tamper(TamperReason::InvalidNodeId))
    );
}

#[cfg(unix)]
#[test]
fn refuse_symlinks_and_fifos() {
    use std::os::unix::fs::symlink;
    use std::process::Command;

    let dir = tempdir().unwrap();
    let real_path = dir.path().join("real.hgrd");
    let run = sample_run_result();
    write_disk(&run, &real_path).unwrap();

    // Symlink must be refused on both read and write
    let link_path = dir.path().join("link.hgrd");
    symlink(&real_path, &link_path).unwrap();
    assert_eq!(
        read_disk(&link_path),
        Err(DiskError::Tamper(TamperReason::NotRegularFile(
            InvalidFileType::Symlink
        )))
    );
    assert_eq!(
        write_disk(&run, &link_path),
        Err(DiskError::NotRegularFile(InvalidFileType::Symlink))
    );

    // FIFO must be refused immediately without blocking
    let fifo_path = dir.path().join("pipe.hgrd");
    let status = Command::new("mkfifo").arg(&fifo_path).status().unwrap();
    assert!(status.success());
    assert_eq!(
        read_disk(&fifo_path),
        Err(DiskError::Tamper(TamperReason::NotRegularFile(
            InvalidFileType::Fifo
        )))
    );
    assert_eq!(
        write_disk(&run, &fifo_path),
        Err(DiskError::NotRegularFile(InvalidFileType::Fifo))
    );

    // Directory must be refused on both read and write
    assert_eq!(
        read_disk(dir.path()),
        Err(DiskError::Tamper(TamperReason::NotRegularFile(
            InvalidFileType::Directory
        )))
    );
    assert_eq!(
        write_disk(&run, dir.path()),
        Err(DiskError::NotRegularFile(InvalidFileType::Directory))
    );
}

#[test]
fn truncation_at_many_offsets_never_panics() {
    let run = sample_run_result();
    let (image, _) = encode_disk(&run).unwrap();
    let offsets: [usize; 22] = [
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        11,
        12,
        31,
        43,
        44,
        45,
        100,
        235,
        236,
        4096,
        65536,
        DISK_BYTES - 2,
        DISK_BYTES - 1,
    ];

    for &cut in &offsets {
        let res = parse_disk_bytes(&image[..cut]);
        assert_eq!(
            res,
            Err(DiskError::Tamper(TamperReason::InvalidDiskSize {
                actual: cut as u64,
            }))
        );
    }
}
