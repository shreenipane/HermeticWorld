use std::fs::{self, File};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};
use tempfile::tempdir;

use hermetic_sealcheck::{scan_tree, FingerprintSet, ScanOptions, Severity, Visibility};

fn build_pyc_header(flags: u32, mtime: u32, size: u32) -> [u8; 16] {
    let mut header = [0u8; 16];
    // Magic: Python 3.10 approx
    header[0..4].copy_from_slice(&[0x6f, 0x0d, 0x0d, 0x0a]);
    header[4..8].copy_from_slice(&flags.to_le_bytes());
    header[8..12].copy_from_slice(&mtime.to_le_bytes());
    header[12..16].copy_from_slice(&size.to_le_bytes());
    header
}

fn set_file_mtime(path: &Path, mtime_secs: u64) {
    let file = File::options().write(true).open(path).expect("open file");
    let target_time = UNIX_EPOCH + Duration::from_secs(mtime_secs);
    file.set_modified(target_time).expect("set_modified");
}

#[test]
fn test_d3_pyc_orphan() {
    let root_dir = tempdir().expect("tempdir");
    let pycache = root_dir.path().join("__pycache__");
    fs::create_dir_all(&pycache).expect("mkdir pycache");

    let pyc_path = pycache.join("orphan.cpython-310.pyc");
    let header = build_pyc_header(0, 1000, 100);
    fs::write(&pyc_path, header).expect("write pyc");

    let fp = FingerprintSet::from_task("", "", root_dir.path()).expect("fp");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    let findings = scan_tree(root_dir.path(), &fp, &opts);
    let orphans: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D3" && f.channel == "pyc_orphan" && f.severity == Severity::Gate)
        .collect();

    assert!(
        !orphans.is_empty(),
        "orphan pyc must produce D3 pyc_orphan gate finding"
    );
}

#[test]
fn test_d3_pyc_stale_mtime() {
    let root_dir = tempdir().expect("tempdir");
    let pycache = root_dir.path().join("__pycache__");
    fs::create_dir_all(&pycache).expect("mkdir pycache");

    let source_path = root_dir.path().join("module.py");
    fs::write(&source_path, "def run():\n    pass\n").expect("write source");
    let src_size = fs::metadata(&source_path).expect("meta").len() as u32;

    // Source mtime = 2000, header mtime = 1000 (mismatch)
    set_file_mtime(&source_path, 2000);

    let pyc_path = pycache.join("module.cpython-310.pyc");
    let header = build_pyc_header(0, 1000, src_size);
    fs::write(&pyc_path, header).expect("write pyc");

    let fp = FingerprintSet::from_task("", "", root_dir.path()).expect("fp");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    let findings = scan_tree(root_dir.path(), &fp, &opts);
    let stales: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D3" && f.channel == "pyc_stale" && f.severity == Severity::Gate)
        .collect();

    assert!(
        !stales.is_empty(),
        "stale mtime pyc must produce D3 pyc_stale gate finding"
    );
    assert!(
        stales[0].evidence[0].contains("mtime"),
        "evidence must show both values"
    );
}

#[test]
fn test_d3_pyc_stale_size() {
    let root_dir = tempdir().expect("tempdir");
    let source_path = root_dir.path().join("legacy.py");
    fs::write(&source_path, "x = 42\n").expect("write source");
    set_file_mtime(&source_path, 3000);

    // Legacy name.pyc in same dir, size mismatch (expected 500, actual is tiny)
    let pyc_path = root_dir.path().join("legacy.pyc");
    let header = build_pyc_header(0, 3000, 500);
    fs::write(&pyc_path, header).expect("write pyc");

    let fp = FingerprintSet::from_task("", "", root_dir.path()).expect("fp");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    let findings = scan_tree(root_dir.path(), &fp, &opts);
    let stales: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D3" && f.channel == "pyc_stale" && f.severity == Severity::Gate)
        .collect();

    assert!(
        !stales.is_empty(),
        "stale size pyc must produce D3 pyc_stale gate finding"
    );
    assert!(
        stales[0].evidence[0].contains("size"),
        "evidence must show both values"
    );
}

#[test]
fn test_d3_pyc_fresh() {
    let root_dir = tempdir().expect("tempdir");
    let pycache = root_dir.path().join("__pycache__");
    fs::create_dir_all(&pycache).expect("mkdir pycache");

    let source_path = root_dir.path().join("fresh.py");
    fs::write(&source_path, "def fresh():\n    return 1\n").expect("write source");
    let src_size = fs::metadata(&source_path).expect("meta").len() as u32;
    set_file_mtime(&source_path, 5000);

    let pyc_path = pycache.join("fresh.cpython-310.pyc");
    let header = build_pyc_header(0, 5000, src_size);
    fs::write(&pyc_path, header).expect("write pyc");

    let fp = FingerprintSet::from_task("", "", root_dir.path()).expect("fp");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    let findings = scan_tree(root_dir.path(), &fp, &opts);
    let d3_findings: Vec<_> = findings.iter().filter(|f| f.detector == "D3").collect();

    assert!(
        d3_findings.is_empty(),
        "fresh pyc must produce 0 D3 findings, got: {:?}",
        d3_findings
    );
}

#[test]
fn test_d3_pyc_hash_based() {
    let root_dir = tempdir().expect("tempdir");
    let pycache = root_dir.path().join("__pycache__");
    fs::create_dir_all(&pycache).expect("mkdir pycache");

    let source_path = root_dir.path().join("hashed.py");
    fs::write(&source_path, "def hashed():\n    return 2\n").expect("write source");

    let pyc_path = pycache.join("hashed.cpython-310.pyc");
    // Bit 0 set in flags
    let header = build_pyc_header(1, 0, 0);
    fs::write(&pyc_path, header).expect("write pyc");

    let fp = FingerprintSet::from_task("", "", root_dir.path()).expect("fp");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    let findings = scan_tree(root_dir.path(), &fp, &opts);
    let hash_findings: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.detector == "D3" && f.channel == "pyc_hash_unchecked" && f.severity == Severity::Info
        })
        .collect();

    assert!(
        !hash_findings.is_empty(),
        "hash-based pyc must produce pyc_hash_unchecked info finding"
    );
}
