#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use time::OffsetDateTime;

use hermetic_sealcheck::sarif::generate_sarif;
use hermetic_sealcheck::scan::{scan_tree, Finding, ScanOptions, Severity, Visibility};
use hermetic_sealcheck::{check_d8, write_index, FingerprintSet, IndexError};

#[test]
fn test_shared_path_policy_non_utf8_root_in_scan_tree_rejected() {
    let dummy = tempfile::tempdir().expect("tempdir");
    let fp = FingerprintSet::from_task("", "", dummy.path()).expect("fp");
    let non_utf8_path = Path::new(OsStr::from_bytes(b"/tmp/test_root_\xff_invalid"));
    let opts = ScanOptions::default();
    let findings = scan_tree(non_utf8_path, &fp, &opts);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.detector, "D2");
    assert_eq!(f.channel, "non_utf8_root");
    assert_eq!(f.severity, Severity::Gate);
    assert_eq!(f.path, ".");
    assert!(!f.evidence.is_empty());
}

#[test]
fn test_shared_path_policy_non_utf8_root_in_check_d8_rejected() {
    let non_utf8_path = Path::new(OsStr::from_bytes(b"/tmp/test_root_\xfe_d8"));
    let t_clock = OffsetDateTime::UNIX_EPOCH;
    let findings = check_d8(non_utf8_path, t_clock, Visibility::AgentVisible);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.detector, "D8");
    assert_eq!(f.channel, "non_utf8_root");
    assert_eq!(f.severity, Severity::Gate);
    assert_eq!(f.path, ".");
    assert!(!f.evidence.is_empty());
}

#[test]
fn test_shared_path_policy_non_utf8_root_in_index_rejected() {
    let non_utf8_path = Path::new(OsStr::from_bytes(b"/tmp/test_root_\xfd_index"));
    let out_dir = tempfile::tempdir().expect("tempdir");
    let out_file = out_dir.path().join("test.idx");

    let err = write_index(non_utf8_path, &out_file).unwrap_err();
    match err {
        IndexError::NonUtf8Root(p) => {
            assert_eq!(p.as_os_str().as_bytes(), b"/tmp/test_root_\xfd_index");
        }
        other => panic!("expected NonUtf8Root, got: {other:?}"),
    }
}

#[test]
fn test_shared_path_policy_non_utf8_path_entry_rejected_and_distinct_never_collide() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    // Create two files whose names differ only in invalid UTF-8 bytes:
    // With lossy decoding (U+FFFD), both would become "caf.txt" and collide.
    let name_a = OsStr::from_bytes(b"caf\xe8.txt");
    let name_b = OsStr::from_bytes(b"caf\xe9.txt");
    fs::write(root.join(name_a), b"a\n").expect("write a");
    fs::write(root.join(name_b), b"b\n").expect("write b");

    let fp = FingerprintSet::from_task("", "", root).expect("fp");
    let opts = ScanOptions::default();
    let findings = scan_tree(root, &fp, &opts);

    let non_utf8_gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D2" && f.channel == "non_utf8_path")
        .collect();
    assert_eq!(
        non_utf8_gates.len(),
        2,
        "both non-utf8 files must be detected"
    );

    // Verify percent-encoded representation prevents collision
    let paths: Vec<&str> = non_utf8_gates.iter().map(|f| f.path.as_str()).collect();
    assert!(paths.contains(&"caf%E8.txt"), "paths: {paths:?}");
    assert!(paths.contains(&"caf%E9.txt"), "paths: {paths:?}");
    assert_ne!(
        paths[0], paths[1],
        "distinct non-UTF-8 paths must never collide"
    );

    // SARIF log must represent both distinct artifact locations
    let sarif = generate_sarif(&findings);
    let uris: Vec<&str> = sarif.runs[0]
        .results
        .iter()
        .filter(|r| r.rule_id == "D2")
        .map(|r| {
            r.locations[0]
                .physical_location
                .artifact_location
                .uri
                .as_str()
        })
        .collect();
    assert!(uris.contains(&"caf%E8.txt"));
    assert!(uris.contains(&"caf%E9.txt"));
    for uri in &uris {
        assert!(!uri.starts_with('/'), "URI must never be absolute: {uri}");
        assert!(
            !uri.contains('\u{FFFD}'),
            "URI must not have lossy replacement char: {uri}"
        );
    }
}

#[test]
fn test_shared_path_policy_sarif_never_contains_absolute_host_path() {
    let findings = vec![
        Finding {
            detector: "D4".into(),
            channel: "tree_incomplete".into(),
            path: "/home/user/secret/host/path".into(),
            visibility: Visibility::AgentVisible,
            severity: Severity::Gate,
            confidence: 1.0,
            hunk: None,
            evidence: vec!["host leak test".into()],
        },
        Finding {
            detector: "D8".into(),
            channel: "os_release".into(),
            path: "etc/os-release".into(),
            visibility: Visibility::AgentVisible,
            severity: Severity::Gate,
            confidence: 1.0,
            hunk: None,
            evidence: vec!["os-release date".into()],
        },
    ];

    let sarif = generate_sarif(&findings);
    for result in &sarif.runs[0].results {
        for loc in &result.locations {
            let uri = &loc.physical_location.artifact_location.uri;
            assert!(
                !uri.starts_with('/'),
                "SARIF artifact URI must never be absolute host path: {uri}"
            );
            assert!(
                !uri.contains("flingboot"),
                "SARIF artifact URI must not leak host username: {uri}"
            );
        }
    }
}

#[test]
fn test_sarif_loose_git_pointer_preserves_artifact_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    assert!(root.is_absolute());
    fs::write(root.join(".git"), b"gitdir: /some/repo\n").expect("write .git pointer");

    let fp = FingerprintSet::from_task("", "", root).expect("fp");
    let opts = ScanOptions {
        t_clock: Some(time::OffsetDateTime::now_utc()),
        ..Default::default()
    };
    let findings = scan_tree(root, &fp, &opts);

    let d1_findings: Vec<_> = findings.iter().filter(|f| f.detector == "D1").collect();
    assert_eq!(d1_findings.len(), 1);
    assert_eq!(d1_findings[0].path, ".git");

    let sarif = generate_sarif(&findings);
    let d1_sarif: Vec<_> = sarif.runs[0]
        .results
        .iter()
        .filter(|r| r.rule_id == "D1")
        .collect();
    assert_eq!(d1_sarif.len(), 1);
    let uri = &d1_sarif[0].locations[0]
        .physical_location
        .artifact_location
        .uri;
    assert_eq!(
        uri, ".git",
        "SARIF artifact URI must retain the artifact name '.git', not '.'"
    );
}

#[test]
fn test_d4_backslash_path_distinct_from_nested_slash_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();

    let nested_dir = root.join("dir");
    fs::create_dir(&nested_dir).expect("create nested dir");
    fs::write(nested_dir.join("file"), b"nested file content\n").expect("write nested");

    let backslash_name = "dir\\file";
    fs::write(root.join(backslash_name), b"backslash file content\n").expect("write backslash");

    let fp = FingerprintSet::from_task("", "", root).expect("fp");
    let opts = ScanOptions {
        // Cutoff in the past so both files are flagged with late mtimes (D4 Gate)
        t_clock: Some(time::OffsetDateTime::UNIX_EPOCH),
        ..Default::default()
    };
    let findings = scan_tree(root, &fp, &opts);

    let d4_paths: Vec<&str> = findings
        .iter()
        .filter(|f| f.detector == "D4" && f.severity == Severity::Gate)
        .map(|f| f.path.as_str())
        .collect();

    assert!(
        d4_paths.contains(&"dir/file"),
        "d4_paths must contain nested path 'dir/file': {d4_paths:?}"
    );
    assert!(
        d4_paths.contains(&"dir\\file"),
        "d4_paths must contain literal backslash path 'dir\\file': {d4_paths:?}"
    );
    assert_ne!(
        d4_paths.len(),
        1,
        "both findings must be retained; one must not be dropped by collision"
    );
}
