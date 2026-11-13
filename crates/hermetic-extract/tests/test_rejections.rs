#![forbid(unsafe_code)]

use std::fs;
use std::io::Cursor;
use tempfile::tempdir;

use hermetic_extract::config::{ExtractConfig, TaskClass};
use hermetic_extract::error::{ExtractError, FormatError, PathError, TaskClassError};
use hermetic_extract::format::{RawRecordArgs, StreamEncoder};
use hermetic_extract::validator::validate_stream;

fn empty_base() -> tempfile::TempDir {
    tempdir().unwrap()
}

fn empty_out() -> tempfile::TempDir {
    tempdir().unwrap()
}

#[test]
fn test_reject_hostile_record_types() {
    let base = empty_base();
    let out = empty_out();
    let config = ExtractConfig::default();

    for bad_type in [5u8, 6, 7, 8, 9, 99] {
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        let args = RawRecordArgs {
            record_type: bad_type,
            flags: 0,
            reserved: [0, 0],
            path: b"evil",
            mode: 0o644,
            size: 0,
            record_count: 0,
            sha256: [0u8; 32],
            payload: b"",
        };
        StreamEncoder::write_raw_record(&mut stream, &args).unwrap();
        StreamEncoder::write_end(&mut stream, 1, 0).unwrap();

        let mut cursor = Cursor::new(stream);
        let err = validate_stream(
            &mut cursor,
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        )
        .unwrap_err();
        assert!(err.is_rejection());
        assert!(matches!(err, ExtractError::Format(_)));
    }
}

#[test]
fn test_reject_invalid_paths() {
    let base = empty_base();
    let out = empty_out();
    let config = ExtractConfig::default();

    let invalid_paths = vec![
        ("", "empty path"),
        ("/abs/path", "absolute path"),
        ("C:drive", "drive prefix"),
        ("foo\\bar", "backslash"),
        ("foo\0bar", "nul byte"),
        ("foo//bar", "empty component"),
        ("foo/./bar", "dot component"),
        ("foo/../bar", "dotdot component"),
        ("../escape", "leading dotdot"),
    ];

    for (p, _desc) in invalid_paths {
        let mut stream = Vec::new();
        StreamEncoder::write_stream_header(&mut stream).unwrap();
        StreamEncoder::write_file(&mut stream, p, 0o644, b"test").unwrap();
        StreamEncoder::write_end(&mut stream, 1, 4).unwrap();

        let mut cursor = Cursor::new(stream);
        let err = validate_stream(
            &mut cursor,
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        )
        .unwrap_err();
        assert!(err.is_rejection());
        assert!(matches!(err, ExtractError::PathValidation(_)));
    }
}

#[test]
fn test_reject_path_depth_and_length_exceeded() {
    let base = empty_base();
    let out = empty_out();
    let config = ExtractConfig {
        max_path_depth: 3,
        max_path_bytes: 20,
        ..Default::default()
    };

    // Depth exceeded (4 components > 3)
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "a/b/c/d", 0o644, b"test").unwrap();
    StreamEncoder::write_end(&mut stream, 1, 4).unwrap();
    let mut cursor = Cursor::new(stream);
    let err = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExtractError::PathValidation(PathError::DepthExceeded { .. })
    ));

    // Length exceeded (25 bytes > 20)
    let mut stream2 = Vec::new();
    StreamEncoder::write_stream_header(&mut stream2).unwrap();
    StreamEncoder::write_file(&mut stream2, "a/b/very_long_file_name_here", 0o644, b"test")
        .unwrap();
    StreamEncoder::write_end(&mut stream2, 1, 4).unwrap();
    let mut cursor2 = Cursor::new(stream2);
    let err2 = validate_stream(
        &mut cursor2,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap_err();
    assert!(err2.is_rejection());
}

#[test]
fn test_reject_traversal_through_regular_file() {
    let base = empty_base();
    let out = empty_out();
    let config = ExtractConfig::default();

    // Stream declares a/b as a regular file, then attempts a/b/c
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "a/b", 0o644, b"file content").unwrap();
    StreamEncoder::write_file(&mut stream, "a/b/c", 0o644, b"nested").unwrap();
    StreamEncoder::write_end(&mut stream, 2, 18).unwrap();

    let mut cursor = Cursor::new(stream);
    let err = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExtractError::PathValidation(PathError::TraversesRegularFile { .. })
    ));
}

#[test]
fn test_reject_directory_record_replaced_by_file_record() {
    let base = empty_base();
    let out = empty_out();
    let config = ExtractConfig::default();

    // Stream declares directory a/b, then attempts to declare a/b as regular file
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_directory(&mut stream, "a/b", 0o755).unwrap();
    StreamEncoder::write_file(&mut stream, "a/b", 0o644, b"replacement").unwrap();
    StreamEncoder::write_end(&mut stream, 2, 11).unwrap();

    let mut cursor = Cursor::new(stream);
    let err = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap_err();
    assert!(err.is_rejection());
}

#[test]
fn test_reject_duplicate_records() {
    let base = empty_base();
    let out = empty_out();
    let config = ExtractConfig::default();

    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "same.txt", 0o644, b"first").unwrap();
    StreamEncoder::write_file(&mut stream, "same.txt", 0o644, b"second").unwrap();
    StreamEncoder::write_end(&mut stream, 2, 11).unwrap();

    let mut cursor = Cursor::new(stream);
    let err = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExtractError::PathValidation(PathError::DuplicatePath(_))
    ));
}

#[test]
fn test_case_fold_collision_reported_not_rejected() {
    let base = empty_base();
    let out = empty_out();
    let config = ExtractConfig::default();

    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "hello.txt", 0o644, b"one").unwrap();
    StreamEncoder::write_file(&mut stream, "HELLO.TXT", 0o644, b"two").unwrap();
    StreamEncoder::write_end(&mut stream, 2, 6).unwrap();

    let mut cursor = Cursor::new(stream);
    let report = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap();
    assert!(report
        .flags
        .iter()
        .any(|f| f.flag_type == "case_fold_collision"));
}

#[test]
fn test_reject_task_class_violations() {
    let base = empty_base();
    let out = empty_out();

    // 1. Patch: outside declared repository directory
    let patch_config = ExtractConfig {
        repo_dir: Some("myrepo".to_string()),
        ..Default::default()
    };
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "outside.txt", 0o644, b"bad").unwrap();
    StreamEncoder::write_end(&mut stream, 1, 3).unwrap();
    let mut cursor = Cursor::new(stream);
    let err = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &patch_config,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExtractError::TaskClass(TaskClassError::OutsideRepoDir { .. })
    ));

    // 2. Artifact: undeclared artifact path
    let artifact_config = ExtractConfig {
        artifact_paths: vec!["build/output.bin".to_string()],
        ..Default::default()
    };
    let mut stream2 = Vec::new();
    StreamEncoder::write_stream_header(&mut stream2).unwrap();
    StreamEncoder::write_file(&mut stream2, "unwanted.bin", 0o644, b"bad").unwrap();
    StreamEncoder::write_end(&mut stream2, 1, 3).unwrap();
    let mut cursor2 = Cursor::new(stream2);
    let err2 = validate_stream(
        &mut cursor2,
        base.path(),
        out.path(),
        TaskClass::Artifact,
        &artifact_config,
    )
    .unwrap_err();
    assert!(matches!(
        err2,
        ExtractError::TaskClass(TaskClassError::UndeclaredArtifactPath { .. })
    ));

    // 3. State: non-empty stream
    let state_config = ExtractConfig::default();
    let mut stream3 = Vec::new();
    StreamEncoder::write_stream_header(&mut stream3).unwrap();
    StreamEncoder::write_file(&mut stream3, "anything.txt", 0o644, b"bad").unwrap();
    StreamEncoder::write_end(&mut stream3, 1, 3).unwrap();
    let mut cursor3 = Cursor::new(stream3);
    let err3 = validate_stream(
        &mut cursor3,
        base.path(),
        out.path(),
        TaskClass::State,
        &state_config,
    )
    .unwrap_err();
    assert!(matches!(
        err3,
        ExtractError::TaskClass(TaskClassError::StateTaskNonEmptyStream { .. })
    ));
}

#[test]
fn test_reject_non_empty_output_dir() {
    let base = empty_base();
    let out = empty_out();
    fs::write(out.path().join("preexisting.txt"), b"dirty").unwrap();

    let config = ExtractConfig::default();
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_end(&mut stream, 0, 0).unwrap();

    let mut cursor = Cursor::new(stream);
    let err = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap_err();
    assert!(!err.is_rejection());
    assert!(matches!(
        err,
        ExtractError::FsSecurity(hermetic_extract::error::FsSecurityError::OutputDirNotEmpty(
            _
        ))
    ));
    assert_eq!(
        fs::read(out.path().join("preexisting.txt")).unwrap(),
        b"dirty"
    );
}

#[test]
fn test_reject_symlink_in_base_tree() {
    let base = empty_base();
    let out = empty_out();
    std::os::unix::fs::symlink("/etc/passwd", base.path().join("link")).unwrap();

    let config = ExtractConfig::default();
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_end(&mut stream, 0, 0).unwrap();

    let mut cursor = Cursor::new(stream);
    let err = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap_err();
    assert!(err.is_rejection());
}

#[test]
fn test_reject_size_and_hash_mismatches() {
    let base = empty_base();
    let out = empty_out();
    let config = ExtractConfig::default();

    // 1. Hash mismatch
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    let bad_hash_args = RawRecordArgs {
        record_type: 1,
        flags: 0,
        reserved: [0, 0],
        path: b"corrupt.txt",
        mode: 0o644,
        size: 5,
        record_count: 0,
        sha256: [0xFF; 32], // Wrong hash
        payload: b"hello",
    };
    StreamEncoder::write_raw_record(&mut stream, &bad_hash_args).unwrap();
    StreamEncoder::write_end(&mut stream, 1, 5).unwrap();

    let mut cursor = Cursor::new(stream);
    let err = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ExtractError::Format(FormatError::HashMismatch { .. })
    ));

    // 2. Count mismatch in EndOfStream
    let mut stream2 = Vec::new();
    StreamEncoder::write_stream_header(&mut stream2).unwrap();
    StreamEncoder::write_file(&mut stream2, "one.txt", 0o644, b"1").unwrap();
    StreamEncoder::write_end(&mut stream2, 999, 1).unwrap(); // Declared 999 records, sent 1

    let mut cursor2 = Cursor::new(stream2);
    let err2 = validate_stream(
        &mut cursor2,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap_err();
    assert!(matches!(
        err2,
        ExtractError::Format(FormatError::CountMismatch { .. })
    ));

    // 3. Total bytes mismatch in EndOfStream
    let mut stream3 = Vec::new();
    StreamEncoder::write_stream_header(&mut stream3).unwrap();
    StreamEncoder::write_file(&mut stream3, "one.txt", 0o644, b"1").unwrap();
    StreamEncoder::write_end(&mut stream3, 1, 999).unwrap(); // Declared 999 bytes, sent 1

    let mut cursor3 = Cursor::new(stream3);
    let err3 = validate_stream(
        &mut cursor3,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap_err();
    assert!(matches!(
        err3,
        ExtractError::Format(FormatError::TotalBytesMismatch { .. })
    ));

    // 4. Trailing garbage after EndOfStream
    let mut stream4 = Vec::new();
    StreamEncoder::write_stream_header(&mut stream4).unwrap();
    StreamEncoder::write_file(&mut stream4, "one.txt", 0o644, b"1").unwrap();
    StreamEncoder::write_end(&mut stream4, 1, 1).unwrap();
    stream4.extend_from_slice(b"TRAILER_JUNK");

    let mut cursor4 = Cursor::new(stream4);
    let err4 = validate_stream(
        &mut cursor4,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap_err();
    assert!(matches!(
        err4,
        ExtractError::Format(FormatError::TrailingGarbage)
    ));
}
