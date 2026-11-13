#![forbid(unsafe_code)]

use std::fs;
use std::io::Cursor;
use tempfile::tempdir;

use hermetic_extract::config::{ExtractConfig, TaskClass};
use hermetic_extract::format::StreamEncoder;
use hermetic_extract::validator::validate_stream;

#[test]
fn test_known_answer_report_deterministic() {
    let base = tempdir().unwrap();
    let out = tempdir().unwrap();

    // 1. Pristine base tree
    fs::write(base.path().join("README.md"), b"Prone project\n").unwrap();
    fs::write(base.path().join("conftest.py"), b"# Base conftest\n").unwrap();
    let base_cfg = "[metadata]\nname = demo\n\n[tool:pytest]\naddopts = -ra\n";
    fs::write(base.path().join("setup.cfg"), base_cfg).unwrap();

    // 2. Stream fixture
    let mut stream = Vec::new();
    StreamEncoder::write_stream_header(&mut stream).unwrap();

    // Record 1: src/lib.rs (new regular file)
    StreamEncoder::write_file(&mut stream, "src/lib.rs", 0o644, b"pub fn run() {}\n").unwrap();

    // Record 2: data (directory)
    StreamEncoder::write_directory(&mut stream, "data", 0o755).unwrap();

    // Record 3: conftest.py (malicious agent attempt -> dropped & restored)
    StreamEncoder::write_file(&mut stream, "conftest.py", 0o644, b"# hostile conftest\n").unwrap();

    // Record 4: setup.cfg (agent edit with tampered section)
    let agent_cfg =
        "[metadata]\nname = demo\nversion = 0.1.0\n\n[tool:pytest]\naddopts = --override\n";
    StreamEncoder::write_file(&mut stream, "setup.cfg", 0o644, agent_cfg.as_bytes()).unwrap();

    // Record 5: json.py (new module shadowing stdlib)
    StreamEncoder::write_file(&mut stream, "json.py", 0o644, b"# fake stdlib json\n").unwrap();

    let total_bytes = b"pub fn run() {}\n".len()
        + b"# hostile conftest\n".len()
        + agent_cfg.len()
        + b"# fake stdlib json\n".len();

    // EndOfStream: 5 entry records
    StreamEncoder::write_end(&mut stream, 5, total_bytes as u64).unwrap();

    let config = ExtractConfig::default();
    let mut cursor = Cursor::new(stream);
    let report = validate_stream(
        &mut cursor,
        base.path(),
        out.path(),
        TaskClass::Patch,
        &config,
    )
    .unwrap();

    // Verify deterministic structure
    assert_eq!(report.totals.records_received, 6); // 5 entries + 1 EOS
    assert_eq!(report.totals.files_accepted, 3); // src/lib.rs, setup.cfg, json.py
    assert_eq!(report.totals.directories_accepted, 1); // data
    assert_eq!(report.totals.paths_dropped, 1); // conftest.py
    assert_eq!(report.totals.paths_restored, 2); // conftest.py (whole), setup.cfg (sections)
    assert_eq!(report.totals.total_bytes_accepted, 110);

    // Check dropped paths
    assert_eq!(report.dropped.len(), 1);
    assert_eq!(report.dropped[0].path, "conftest.py");
    assert_eq!(report.dropped[0].reason, "conftest");

    // Check restored paths
    assert_eq!(report.restored.len(), 2);
    assert_eq!(report.restored[0].path, "conftest.py");
    assert_eq!(report.restored[0].reason, "restored_from_base");
    assert_eq!(report.restored[1].path, "setup.cfg");
    assert_eq!(report.restored[1].reason, "test_runner_sections_restored");

    // Check shadowing flags
    assert_eq!(report.flags.len(), 1);
    assert_eq!(report.flags[0].flag_type, "shadowing");
    assert_eq!(report.flags[0].path, "json.py");

    // Check JSON serialization determinism
    let json1 = serde_json::to_string_pretty(&report).unwrap();
    let json2 = serde_json::to_string_pretty(&report).unwrap();
    assert_eq!(json1, json2);

    // Verify manifest SHA-256 is non-empty and 64 hex characters
    assert_eq!(report.tree_manifest_sha256.len(), 64);
    assert!(report
        .tree_manifest_sha256
        .chars()
        .all(|c| c.is_ascii_hexdigit()));
}
