#![forbid(unsafe_code)]

use std::fs;
use std::process::Command;
use tempfile::tempdir;

use hermetic_extract::format::{RawRecordArgs, StreamEncoder};

#[test]
fn test_cli_exit_codes_and_report_output() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-extract-validate");

    let tmp = tempdir().unwrap();
    let base = tmp.path().join("base");
    let out = tmp.path().join("out");
    let stream_file = tmp.path().join("stream.bin");
    let config_file = tmp.path().join("config.json");

    fs::create_dir(&base).unwrap();
    fs::create_dir(&out).unwrap();

    let config_json = r#"{
        "max_file_bytes": 1000000,
        "max_total_bytes": 10000000,
        "max_file_count": 100,
        "max_dir_count": 100
    }"#;
    fs::write(&config_file, config_json).unwrap();

    // 1. Success case -> exit 0
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "file.txt", 0o644, b"test content").unwrap();
    StreamEncoder::write_end(&mut stream, 1, 12).unwrap();
    fs::write(&stream_file, &stream).unwrap();

    let output_success = Command::new(bin_path)
        .arg("--stream")
        .arg(&stream_file)
        .arg("--base")
        .arg(&base)
        .arg("--out")
        .arg(&out)
        .arg("--class")
        .arg("patch")
        .arg("--config")
        .arg(&config_file)
        .output()
        .unwrap();

    assert_eq!(output_success.status.code(), Some(0));
    let stdout_str = String::from_utf8(output_success.stdout).unwrap();
    assert!(stdout_str.contains("tree_manifest_sha256"));
    assert!(stdout_str.contains("file.txt"));

    // 2. Rejection case -> exit 2
    // Create new empty out dir for rejection test
    let out_rejected = tmp.path().join("out_rejected");
    fs::create_dir(&out_rejected).unwrap();

    let mut bad_stream = Vec::new();
    StreamEncoder::write_stream_header(&mut bad_stream).unwrap();
    let bad_record = RawRecordArgs {
        record_type: 5, // hostile symlink record
        flags: 0,
        reserved: [0, 0],
        path: b"symlink",
        mode: 0o777,
        size: 0,
        record_count: 0,
        sha256: [0u8; 32],
        payload: b"",
    };
    StreamEncoder::write_raw_record(&mut bad_stream, &bad_record).unwrap();
    StreamEncoder::write_end(&mut bad_stream, 1, 0).unwrap();
    fs::write(&stream_file, &bad_stream).unwrap();

    let output_rejected = Command::new(bin_path)
        .arg("--stream")
        .arg(&stream_file)
        .arg("--base")
        .arg(&base)
        .arg("--out")
        .arg(&out_rejected)
        .arg("--class")
        .arg("patch")
        .arg("--config")
        .arg(&config_file)
        .output()
        .unwrap();

    assert_eq!(output_rejected.status.code(), Some(2));

    // 3. System Error case (e.g. missing required option) -> exit 1
    let output_error = Command::new(bin_path)
        .arg("--stream")
        .arg(&stream_file)
        .output()
        .unwrap();

    assert_eq!(output_error.status.code(), Some(1));
}
