#![forbid(unsafe_code)]

use std::fs;
use std::io::Cursor;
use tempfile::tempdir;

use hermetic_extract::config::{ExtractConfig, TaskClass};
use hermetic_extract::format::StreamEncoder;
use hermetic_extract::validator::validate_stream;

#[test]
fn test_shadowing_flags_stdlib_and_installed_packages() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();

    // In base, we already had a top-level module `sys.py` (pre-existing, should not be flagged)
    fs::write(base.path().join("sys.py"), b"# pre-existing sys").unwrap();

    let config = ExtractConfig {
        installed_packages: vec!["requests".to_string(), "numpy".to_string()],
        ..Default::default()
    };

    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();

    // 1. New top-level module matching stdlib `json.py`
    StreamEncoder::write_file(&mut stream, "json.py", 0o644, b"# malicious json").unwrap();

    // 2. New package at `src/sqlite3/__init__.py` (import root src)
    StreamEncoder::write_file(
        &mut stream,
        "src/sqlite3/__init__.py",
        0o644,
        b"# malicious sqlite3",
    )
    .unwrap();

    // 3. New module matching installed package `requests.py`
    StreamEncoder::write_file(&mut stream, "requests.py", 0o644, b"# fake requests").unwrap();

    // 4. Modifying pre-existing base `sys.py` (not new, so not flagged)
    StreamEncoder::write_file(&mut stream, "sys.py", 0o644, b"# updated sys").unwrap();

    // 5. Nested module `pkg/json.py` (not at top level, so not flagged)
    StreamEncoder::write_file(&mut stream, "pkg/json.py", 0o644, b"# nested json").unwrap();

    // 6. Benign module `my_util.py` (not stdlib, not installed package)
    StreamEncoder::write_file(&mut stream, "my_util.py", 0o644, b"# clean code").unwrap();

    let total = b"# malicious json".len()
        + b"# malicious sqlite3".len()
        + b"# fake requests".len()
        + b"# updated sys".len()
        + b"# nested json".len()
        + b"# clean code".len();

    StreamEncoder::write_end(&mut stream, 6, total as u64).unwrap();

    let mut cursor = Cursor::new(stream);
    let report = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap();

    // Flagged items should include json.py, src/sqlite3/__init__.py, and requests.py
    let flagged_paths: Vec<&str> = report.flags.iter().map(|f| f.path.as_str()).collect();
    assert!(flagged_paths.contains(&"json.py"));
    assert!(flagged_paths.contains(&"src/sqlite3/__init__.py"));
    assert!(flagged_paths.contains(&"requests.py"));

    // Should NOT flag pre-existing sys.py, nested pkg/json.py, or benign my_util.py
    assert!(!flagged_paths.contains(&"sys.py"));
    assert!(!flagged_paths.contains(&"pkg/json.py"));
    assert!(!flagged_paths.contains(&"my_util.py"));
}
