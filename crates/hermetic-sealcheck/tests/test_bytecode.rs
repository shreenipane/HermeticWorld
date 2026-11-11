use std::fs::{self, File};
use std::path::{Path, PathBuf};
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

#[test]
fn test_h8_pyc_headers_old_and_invalid() {
    let root_dir = tempdir().expect("tempdir");
    let pycache = root_dir.path().join("__pycache__");
    fs::create_dir_all(&pycache).expect("mkdir pycache");

    let source_path = root_dir.path().join("old_mod.py");
    fs::write(&source_path, "def run():\n    return 42\n").expect("write source");
    let src_size = fs::metadata(&source_path).expect("meta").len() as u32;
    set_file_mtime(&source_path, 4000);

    let fp = FingerprintSet::from_task("", "", root_dir.path()).expect("fp");
    let opts = ScanOptions {
        visibility: Visibility::AgentVisible,
        ..Default::default()
    };

    // 1. Fresh 12-byte pyc (magic 3379)
    let fresh_12_path = pycache.join("old_mod.cpython-36.pyc");
    let mut header_12 = [0u8; 12];
    header_12[0..2].copy_from_slice(&3379u16.to_le_bytes());
    header_12[2..4].copy_from_slice(&[0x0d, 0x0a]);
    header_12[4..8].copy_from_slice(&4000u32.to_le_bytes()); // mtime
    header_12[8..12].copy_from_slice(&src_size.to_le_bytes()); // size
    fs::write(&fresh_12_path, header_12).expect("write 12-byte pyc");

    let findings_fresh = scan_tree(root_dir.path(), &fp, &opts);
    let d3_fresh: Vec<_> = findings_fresh
        .iter()
        .filter(|f| f.detector == "D3" && f.path.contains("old_mod.cpython-36.pyc"))
        .collect();
    assert!(
        d3_fresh.is_empty(),
        "fresh 12-byte pyc (magic 3379) must have 0 findings, got: {:?}",
        d3_fresh
    );

    // 2. Stale 12-byte pyc (mtime mismatch)
    let stale_12_path = pycache.join("stale_mod.cpython-36.pyc");
    let stale_source = root_dir.path().join("stale_mod.py");
    fs::write(&stale_source, "def stale(): pass\n").expect("write source");
    set_file_mtime(&stale_source, 4000);
    let stale_src_size = fs::metadata(&stale_source).expect("meta").len() as u32;
    let mut stale_hdr_12 = [0u8; 12];
    stale_hdr_12[0..2].copy_from_slice(&3379u16.to_le_bytes());
    stale_hdr_12[2..4].copy_from_slice(&[0x0d, 0x0a]);
    stale_hdr_12[4..8].copy_from_slice(&1000u32.to_le_bytes()); // mismatch mtime
    stale_hdr_12[8..12].copy_from_slice(&stale_src_size.to_le_bytes());
    fs::write(&stale_12_path, stale_hdr_12).expect("write stale pyc");

    let findings_stale = scan_tree(root_dir.path(), &fp, &opts);
    let d3_stale: Vec<_> = findings_stale
        .iter()
        .filter(|f| {
            f.detector == "D3"
                && f.channel == "pyc_stale"
                && f.severity == Severity::Gate
                && f.path.contains("stale_mod.cpython-36.pyc")
        })
        .collect();
    assert!(
        !d3_stale.is_empty(),
        "stale 12-byte pyc must give D3 pyc_stale gate"
    );

    // 3. Fresh 8-byte pyc (magic 62211, Python 2.7) with different source size
    let py27_source = root_dir.path().join("py27.py");
    fs::write(&py27_source, "print 'hello world'\n").expect("write source");
    set_file_mtime(&py27_source, 5000);
    let py27_path = root_dir.path().join("py27.pyc");
    let mut header_8 = [0u8; 8];
    header_8[0..2].copy_from_slice(&62211u16.to_le_bytes());
    header_8[2..4].copy_from_slice(&[0x0d, 0x0a]);
    header_8[4..8].copy_from_slice(&5000u32.to_le_bytes()); // mtime matches
    fs::write(&py27_path, header_8).expect("write 8-byte pyc");

    let findings_8 = scan_tree(root_dir.path(), &fp, &opts);
    let d3_py27: Vec<_> = findings_8
        .iter()
        .filter(|f| f.detector == "D3" && f.path.contains("py27.pyc"))
        .collect();
    assert!(
        d3_py27.is_empty(),
        "fresh 8-byte pyc (62211) must stay fresh even without size, got: {:?}",
        d3_py27
    );

    // 4. Too-short file gives pyc_invalid
    let short_path = root_dir.path().join("short.pyc");
    let short_bytes = [0x33, 0x0d, 0x0d, 0x0a, 0x00, 0x00];
    fs::write(&short_path, short_bytes).expect("write short");

    let findings_short = scan_tree(root_dir.path(), &fp, &opts);
    let d3_invalid: Vec<_> = findings_short
        .iter()
        .filter(|f| {
            f.detector == "D3"
                && f.channel == "pyc_invalid"
                && f.severity == Severity::Info
                && f.path.contains("short.pyc")
        })
        .collect();
    assert!(
        !d3_invalid.is_empty(),
        "too-short pyc file must give pyc_invalid info finding"
    );
}

#[test]
fn test_h9_dotted_and_opt_pyc_source_location() {
    let p1 = Path::new("/workspace/__pycache__/a.b.cpython-36.pyc");
    let src1 = hermetic_sealcheck::locate_pyc_source(p1);
    assert_eq!(
        src1,
        Some(PathBuf::from("/workspace/a.b.py")),
        "a.b.cpython-36.pyc must locate to a.b.py"
    );

    let p2 = Path::new("/workspace/__pycache__/a.cpython-36.opt-1.pyc");
    let src2 = hermetic_sealcheck::locate_pyc_source(p2);
    assert_eq!(
        src2,
        Some(PathBuf::from("/workspace/a.py")),
        "a.cpython-36.opt-1.pyc must locate to a.py"
    );
}
