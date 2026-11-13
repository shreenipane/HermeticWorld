#![forbid(unsafe_code)]

use std::io::Cursor;
use tempfile::tempdir;

use hermetic_extract::config::{ExtractConfig, TaskClass};
use hermetic_extract::format::StreamEncoder;
use hermetic_extract::validator::validate_stream;

#[test]
fn test_truncated_stream_at_every_offset_never_panics() {
    // Construct a complete, valid stream
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();
    StreamEncoder::write_file(&mut stream, "foo.txt", 0o644, b"hello world").unwrap();
    StreamEncoder::write_directory(&mut stream, "mydir", 0o755).unwrap();
    StreamEncoder::write_deletion(&mut stream, "old.txt").unwrap();
    StreamEncoder::write_end(&mut stream, 3, 11).unwrap();

    let total_len = stream.len();
    assert!(total_len > 100);

    let config = ExtractConfig::default();

    // Loop over every cut point from 0 to total_len - 1
    for cut in 0..total_len {
        let truncated = &stream[..cut];
        let mut cursor = Cursor::new(truncated);

        let base = tempdir().unwrap();
        let out = tempdir().unwrap();

        // Must return Err and NEVER panic
        let res = validate_stream(
            &mut cursor,
            base.path(),
            out.path(),
            TaskClass::Patch,
            &config,
        );
        assert!(
            res.is_err(),
            "cut point {cut}/{total_len} unexpectedly succeeded"
        );
    }
}
