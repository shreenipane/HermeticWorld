#![forbid(unsafe_code)]

use std::fs;
use std::io::Cursor;
use tempfile::tempdir;

use hermetic_extract::config::{ExtractConfig, TaskClass};
use hermetic_extract::format::{RawRecordArgs, StreamEncoder};
use hermetic_extract::validator::validate_stream;

#[test]
fn test_partial_output_removed_on_failure() {
    let parent = tempdir().unwrap();
    let base = parent.path().join("base");
    let out = parent.path().join("out");
    fs::create_dir(&base).unwrap();
    fs::create_dir(&out).unwrap();

    let config = ExtractConfig::default();

    // Create a stream where record 1 succeeds, but record 2 has a corrupted hash
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "good.txt", 0o644, b"valid content").unwrap();

    // Bad record
    let bad_record = RawRecordArgs {
        record_type: 1,
        flags: 0,
        reserved: [0, 0],
        path: b"bad.txt",
        mode: 0o644,
        size: 5,
        record_count: 0,
        sha256: [0xEE; 32],
        payload: b"wrong",
    };
    StreamEncoder::write_raw_record(&mut stream, &bad_record).unwrap();
    StreamEncoder::write_end(&mut stream, 2, 18).unwrap();

    let mut cursor = Cursor::new(stream);
    let res = validate_stream(&mut cursor, &base, &out, TaskClass::Patch, &config);
    assert!(res.is_err());

    // Verify out directory remains empty
    let entries: Vec<_> = fs::read_dir(&out).unwrap().collect();
    assert!(
        entries.is_empty(),
        "output directory must remain empty on failure"
    );

    // Verify no temporary sibling directory was left in parent
    let parent_entries: Vec<String> = fs::read_dir(parent.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();

    for name in parent_entries {
        assert!(
            !name.starts_with(".extract_tmp_"),
            "found uncleaned temporary directory: {name}"
        );
    }
}

#[test]
fn test_atomic_publication_on_success() {
    let parent = tempdir().unwrap();
    let base = parent.path().join("base");
    let out = parent.path().join("out");
    fs::create_dir(&base).unwrap();
    fs::create_dir(&out).unwrap();

    let config = ExtractConfig::default();

    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "file.txt", 0o644, b"success").unwrap();
    StreamEncoder::write_end(&mut stream, 1, 7).unwrap();

    let mut cursor = Cursor::new(stream);
    let report = validate_stream(&mut cursor, &base, &out, TaskClass::Patch, &config).unwrap();
    assert_eq!(report.accepted.len(), 1);

    // out now contains file.txt
    assert_eq!(fs::read(out.join("file.txt")).unwrap(), b"success");

    // No leftover temporary directory
    let parent_entries: Vec<String> = fs::read_dir(parent.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();

    for name in parent_entries {
        assert!(
            !name.starts_with(".extract_tmp_"),
            "found uncleaned temporary directory: {name}"
        );
    }
}
