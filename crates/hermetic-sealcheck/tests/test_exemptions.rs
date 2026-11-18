use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tempfile::tempdir;
use time::macros::datetime;
use time::OffsetDateTime;

use hermetic_sealcheck::exemptions::{
    ExemptionError, ExemptionMap, NamedExemption, MAX_EXEMPTIONS,
};
use hermetic_sealcheck::scan_oci;
use hermetic_sealcheck::{scan_tree, BenchmarkSignatures, FingerprintSet, ScanOptions, Severity};
use sha2::{Digest, Sha256};

const T_CLOCK_SECS: i64 = 1_704_153_600; // 2024-01-02T00:00:00Z

fn t_clock() -> OffsetDateTime {
    datetime!(2024-01-02 00:00:00 UTC)
}

fn empty_fp(dir: &Path) -> FingerprintSet {
    FingerprintSet::from_task("", "", &dir.join("nonexistent")).expect("fp")
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn backdate_tree_dirs(root: &Path) {
    let early = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS - 100) as u64);
    for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
        if entry.file_type().is_dir() {
            if let Ok(f) = File::open(entry.path()) {
                let _ = f.set_modified(early);
            }
        }
    }
}

#[test]
fn test_substrate_file_post_cutoff_exempted_passes() {
    let d = tempdir().expect("tempdir");
    let root = d.path();

    let sub_dir = root.join("usr/bin");
    fs::create_dir_all(&sub_dir).expect("create_dir_all");
    let py_path = sub_dir.join("python3");
    let content = b"#!/bin/sh\necho python3\n";
    fs::write(&py_path, content).expect("write python3");

    let late_time = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS + 500) as u64);
    File::open(&py_path)
        .expect("open")
        .set_modified(late_time)
        .expect("set_modified");
    backdate_tree_dirs(root);

    let fp = empty_fp(root);
    let mut opts_no_ex = ScanOptions {
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    // 1. Without exemption: fails with D4 Gate
    let findings = scan_tree(root, &fp, &opts_no_ex);
    let d4_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D4" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(d4_findings.len(), 1);
    assert_eq!(d4_findings[0].path, "usr/bin/python3");

    // 2. With matching exemption: passes!
    let ex = NamedExemption {
        path: "usr/bin/python3".into(),
        sha256: sha256_hex(content),
        detector: "D4".into(),
        reason: "base_os_interpreter".into(),
    };
    let map = ExemptionMap::from_entries(vec![ex]).expect("from_entries");
    opts_no_ex.exemptions = Arc::new(map);

    let findings_exempt = scan_tree(root, &fp, &opts_no_ex);
    let d4_after: Vec<_> = findings_exempt
        .iter()
        .filter(|f| f.detector == "D4" && f.severity == Severity::Gate)
        .collect();
    assert!(
        d4_after.is_empty(),
        "expected 0 D4 gate findings with exemption"
    );
}

#[test]
fn test_substrate_file_changed_digest_fails() {
    let d = tempdir().expect("tempdir");
    let root = d.path();

    let sub_dir = root.join("usr/bin");
    fs::create_dir_all(&sub_dir).expect("create_dir_all");
    let py_path = sub_dir.join("python3");
    let content = b"#!/bin/sh\necho python3\n";
    fs::write(&py_path, content).expect("write python3");

    let late_time = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS + 500) as u64);
    File::open(&py_path)
        .expect("open")
        .set_modified(late_time)
        .expect("set_modified");
    backdate_tree_dirs(root);

    let fp = empty_fp(root);
    // Exemption with a different hash (tampered or changed)
    let ex = NamedExemption {
        path: "usr/bin/python3".into(),
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        detector: "D4".into(),
        reason: "base_os_interpreter".into(),
    };
    let map = ExemptionMap::from_entries(vec![ex]).expect("from_entries");
    let opts = ScanOptions {
        t_clock: Some(t_clock()),
        exemptions: Arc::new(map),
        ..Default::default()
    };

    let findings = scan_tree(root, &fp, &opts);
    let d4_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D4" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(d4_findings.len(), 1, "changed digest must still fail");
    assert_eq!(d4_findings[0].path, "usr/bin/python3");
}

#[test]
fn test_repository_file_cannot_be_exempted() {
    // Attempting to exempt testbed or testbed/* must be rejected at load time
    let cases = vec![
        "testbed",
        "testbed/main.py",
        "/testbed/lib.py",
        "./testbed/src/mod.py",
        "sub/testbed/file.py",
    ];

    for path in cases {
        let ex = NamedExemption {
            path: path.into(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            detector: "D4".into(),
            reason: "try_exempt_repo".into(),
        };
        let res = ExemptionMap::from_entries(vec![ex]);
        assert!(
            matches!(res, Err(ExemptionError::ForbiddenPath(_))),
            "path '{path}' must be rejected with ForbiddenPath"
        );
    }
}

#[test]
fn test_task_dependency_closure_cannot_be_exempted() {
    let cases = vec![
        "opt/miniconda3/envs/testbed/lib/python.py",
        "/opt/miniconda3/envs/testbed/bin/pytest",
        "opt/conda/envs/myenv/lib/pkg.py",
    ];

    for path in cases {
        let ex = NamedExemption {
            path: path.into(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            detector: "D4".into(),
            reason: "try_exempt_task_env".into(),
        };
        let res = ExemptionMap::from_entries(vec![ex]);
        assert!(
            matches!(res, Err(ExemptionError::ForbiddenPath(_))),
            "path '{path}' must be rejected with ForbiddenPath"
        );
    }
}

#[test]
fn test_pattern_and_directory_exemptions_forbidden() {
    let cases = vec![
        "usr/bin/*",
        "usr/lib/?.so",
        "opt/[a-z].whl",
        "usr/bin/",
        "/usr/local/",
    ];

    for path in cases {
        let ex = NamedExemption {
            path: path.into(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            detector: "D4".into(),
            reason: "wildcard_or_dir".into(),
        };
        let res = ExemptionMap::from_entries(vec![ex]);
        assert!(
            matches!(res, Err(ExemptionError::PatternOrDirectoryForbidden(_))),
            "path '{path}' must be rejected with PatternOrDirectoryForbidden"
        );
    }
}

#[test]
fn test_caps_and_validation() {
    // 1. Exceed count cap
    let many: Vec<_> = (0..=MAX_EXEMPTIONS)
        .map(|i| NamedExemption {
            path: format!("usr/bin/tool_{i}"),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            detector: "D4".into(),
            reason: "cap_test".into(),
        })
        .collect();
    assert!(matches!(
        ExemptionMap::from_entries(many),
        Err(ExemptionError::CountCapExceeded)
    ));

    // 2. Duplicate entry
    let dupes = vec![
        NamedExemption {
            path: "usr/bin/tool".into(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            detector: "D4".into(),
            reason: "first".into(),
        },
        NamedExemption {
            path: "usr/bin/tool".into(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            detector: "D4".into(),
            reason: "second".into(),
        },
    ];
    assert!(matches!(
        ExemptionMap::from_entries(dupes),
        Err(ExemptionError::DuplicateEntry(_, _))
    ));

    // 3. Parent directory .. forbidden
    let parent_path = NamedExemption {
        path: "usr/../bin/tool".into(),
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        detector: "D4".into(),
        reason: "parent".into(),
    };
    assert!(matches!(
        ExemptionMap::from_entries(vec![parent_path]),
        Err(ExemptionError::InvalidPath(_))
    ));

    // 4. Invalid detector
    let bad_detector = NamedExemption {
        path: "usr/bin/tool".into(),
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        detector: "D0".into(),
        reason: "detector".into(),
    };
    assert!(matches!(
        ExemptionMap::from_entries(vec![bad_detector]),
        Err(ExemptionError::InvalidDetector(_))
    ));

    // 5. Invalid hash (length or uppercase)
    let bad_hash = NamedExemption {
        path: "usr/bin/tool".into(),
        sha256: "short_hash".into(),
        detector: "D4".into(),
        reason: "hash".into(),
    };
    assert!(matches!(
        ExemptionMap::from_entries(vec![bad_hash]),
        Err(ExemptionError::InvalidDigest(_))
    ));
}

#[test]
fn test_pip_wheel_member_exempted_passes() {
    let d = tempdir().expect("tempdir");
    let root = d.path();

    let whl_dir = root.join("opt/miniconda3/lib/python3.8/site-packages");
    fs::create_dir_all(&whl_dir).expect("create_dir_all");
    let whl_path = whl_dir.join("pip-23.0-py3-none-any.whl");

    let member_data = b"# pip vendored msgpack\n__version__ = '1.0.0'\n";
    let member_sha = sha256_hex(member_data);

    // Build wheel with a post-cutoff file inside
    {
        let file = File::create(&whl_path).expect("create whl");
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 6, 1, 12, 0, 0).unwrap());
        zip.start_file("pip/_vendor/msgpack/__init__.py", options)
            .expect("start_file");
        zip.write_all(member_data).expect("write_all");
        zip.finish().expect("finish");
    }

    // Live mtime of the .whl itself is set to clean cutoff
    let clean_time = SystemTime::UNIX_EPOCH + Duration::from_secs(T_CLOCK_SECS as u64);
    File::open(&whl_path)
        .expect("open")
        .set_modified(clean_time)
        .expect("set_modified");
    backdate_tree_dirs(root);

    let fp = empty_fp(root);
    let member_rel_path = "opt/miniconda3/lib/python3.8/site-packages/pip-23.0-py3-none-any.whl!/pip/_vendor/msgpack/__init__.py";

    // 1. Without exemption: fails with D4 member_mtime Gate
    let opts_no_ex = ScanOptions {
        t_clock: Some(t_clock()),
        ..Default::default()
    };
    let findings = scan_tree(root, &fp, &opts_no_ex);
    let d4_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D4" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(d4_findings.len(), 1);
    assert_eq!(d4_findings[0].path, member_rel_path);

    // 2. With matching exemption: passes!
    let ex = NamedExemption {
        path: member_rel_path.into(),
        sha256: member_sha,
        detector: "D4".into(),
        reason: "pip_23_vendored_member".into(),
    };
    let map = ExemptionMap::from_entries(vec![ex]).expect("from_entries");
    let opts_ex = ScanOptions {
        t_clock: Some(t_clock()),
        exemptions: Arc::new(map),
        ..Default::default()
    };
    let findings_ex = scan_tree(root, &fp, &opts_ex);
    let d4_after: Vec<_> = findings_ex
        .iter()
        .filter(|f| f.detector == "D4" && f.severity == Severity::Gate)
        .collect();
    assert!(
        d4_after.is_empty(),
        "expected 0 D4 gate findings after exemption"
    );

    // 3. With changed member digest: fails!
    let ex_tampered = NamedExemption {
        path: member_rel_path.into(),
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        detector: "D4".into(),
        reason: "pip_23_vendored_member".into(),
    };
    let map_tampered = ExemptionMap::from_entries(vec![ex_tampered]).expect("from_entries");
    let opts_tampered = ScanOptions {
        t_clock: Some(t_clock()),
        exemptions: Arc::new(map_tampered),
        ..Default::default()
    };
    let findings_tampered = scan_tree(root, &fp, &opts_tampered);
    let d4_tampered: Vec<_> = findings_tampered
        .iter()
        .filter(|f| f.detector == "D4" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(d4_tampered.len(), 1, "changed member digest must fail");
}

#[test]
fn test_d6_oci_created_exempted_passes() {
    let temp = tempdir().expect("tempdir");
    let inspect_path = temp.path().join("source-inspect.json");

    let inspect_json = r#"[
        {
            "Id": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "Created": "2026-08-15 06:04:51 +0000 UTC",
            "Config": { "Env": [], "Labels": {} }
        }
    ]"#;
    fs::write(&inspect_path, inspect_json).expect("write inspect");
    let inspect_sha = sha256_hex(inspect_json.as_bytes());

    let fp = empty_fp(temp.path());
    let signatures = BenchmarkSignatures::new(None);

    // 1. Without exemption: fails with D6 oci_created Gate
    let opts_no_ex = ScanOptions::default();
    let findings = scan_oci(
        Some(&inspect_path),
        None,
        Some(t_clock()),
        &fp,
        &signatures,
        &opts_no_ex,
    )
    .expect("scan_oci");

    let d6_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D6" && f.channel == "oci_created")
        .collect();
    assert_eq!(d6_findings.len(), 1);

    // 2. With matching exemption: passes!
    let ex = NamedExemption {
        path: "source-inspect.json".into(),
        sha256: inspect_sha,
        detector: "D6".into(),
        reason: "base_image_creation_date".into(),
    };
    let map = ExemptionMap::from_entries(vec![ex]).expect("from_entries");
    let opts_ex = ScanOptions {
        exemptions: Arc::new(map),
        ..Default::default()
    };

    let findings_ex = scan_oci(
        Some(&inspect_path),
        None,
        Some(t_clock()),
        &fp,
        &signatures,
        &opts_ex,
    )
    .expect("scan_oci");

    let d6_after: Vec<_> = findings_ex
        .iter()
        .filter(|f| f.detector == "D6" && f.channel == "oci_created")
        .collect();
    assert!(
        d6_after.is_empty(),
        "expected 0 D6 gate findings with exemption"
    );

    // 3. With changed digest: fails!
    let ex_bad = NamedExemption {
        path: "source-inspect.json".into(),
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        detector: "D6".into(),
        reason: "base_image_creation_date".into(),
    };
    let map_bad = ExemptionMap::from_entries(vec![ex_bad]).expect("from_entries");
    let opts_bad = ScanOptions {
        exemptions: Arc::new(map_bad),
        ..Default::default()
    };

    let findings_bad = scan_oci(
        Some(&inspect_path),
        None,
        Some(t_clock()),
        &fp,
        &signatures,
        &opts_bad,
    )
    .expect("scan_oci");

    let d6_bad: Vec<_> = findings_bad
        .iter()
        .filter(|f| f.detector == "D6" && f.channel == "oci_created")
        .collect();
    assert_eq!(d6_bad.len(), 1, "changed digest must still fail D6");
}

#[test]
fn test_repository_file_post_cutoff_still_fails() {
    let d = tempdir().expect("tempdir");
    let root = d.path();

    // 1. Substrate file with post-cutoff date
    let sub_dir = root.join("usr/bin");
    fs::create_dir_all(&sub_dir).expect("create_dir_all");
    let py_path = sub_dir.join("python3");
    let py_content = b"#!/bin/sh\necho python3\n";
    fs::write(&py_path, py_content).expect("write python3");

    // 2. Repository file with post-cutoff date
    let repo_dir = root.join("testbed/src");
    fs::create_dir_all(&repo_dir).expect("create_dir_all");
    let repo_file = repo_dir.join("app.py");
    let repo_content = b"def run(): pass\n";
    fs::write(&repo_file, repo_content).expect("write app.py");

    let late_time = SystemTime::UNIX_EPOCH + Duration::from_secs((T_CLOCK_SECS + 500) as u64);
    File::open(&py_path)
        .expect("open")
        .set_modified(late_time)
        .expect("set_modified");
    File::open(&repo_file)
        .expect("open")
        .set_modified(late_time)
        .expect("set_modified");
    backdate_tree_dirs(root);

    let fp = empty_fp(root);
    // Exemption for substrate python3 ONLY
    let ex = NamedExemption {
        path: "usr/bin/python3".into(),
        sha256: sha256_hex(py_content),
        detector: "D4".into(),
        reason: "base_interpreter".into(),
    };
    let map = ExemptionMap::from_entries(vec![ex]).expect("from_entries");
    let opts = ScanOptions {
        t_clock: Some(t_clock()),
        exemptions: Arc::new(map),
        ..Default::default()
    };

    let findings = scan_tree(root, &fp, &opts);
    let d4_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D4" && f.severity == Severity::Gate)
        .collect();

    // The substrate file is exempted, but the repository file STILL fails!
    assert_eq!(d4_findings.len(), 1);
    assert_eq!(d4_findings[0].path, "testbed/src/app.py");
}

#[test]
fn test_exemption_map_load_from_json_files() {
    let d = tempdir().expect("tempdir");

    // Test doc format {"exemptions": [...]}
    let doc_json = r#"{
        "exemptions": [
            {
                "path": "usr/bin/python3",
                "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "detector": "D4",
                "reason": "interpreter"
            }
        ]
    }"#;
    let doc_path = d.path().join("exemptions_doc.json");
    fs::write(&doc_path, doc_json).expect("write doc");

    let map1 = ExemptionMap::load(&doc_path).expect("load doc");
    assert_eq!(map1.len(), 1);
    assert!(map1.get("D4", "usr/bin/python3").is_some());

    // Test array format [...]
    let arr_json = r#"[
        {
            "path": "source-inspect.json",
            "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "detector": "D6",
            "reason": "image_create"
        }
    ]"#;
    let arr_path = d.path().join("exemptions_arr.json");
    fs::write(&arr_path, arr_json).expect("write arr");

    let map2 = ExemptionMap::load(&arr_path).expect("load arr");
    assert_eq!(map2.len(), 1);
    assert!(map2.get("D6", "source-inspect.json").is_some());
}

#[test]
fn test_repository_metadata_git_cannot_be_exempted() {
    let cases = vec![
        ".git",
        ".git/config",
        "/.git/HEAD",
        "sub/.git/config",
        "repo/.git",
    ];

    for path in cases {
        let ex = NamedExemption {
            path: path.into(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            detector: "D4".into(),
            reason: "git_metadata".into(),
        };
        let res = ExemptionMap::from_entries(vec![ex]);
        assert!(
            matches!(res, Err(ExemptionError::ForbiddenPath(_))),
            "git metadata path '{path}' must be rejected with ForbiddenPath"
        );
    }
}

#[test]
fn test_d4_basename_fallback_rejected_for_repository_path() {
    let ex = NamedExemption {
        path: "python3".into(),
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        detector: "D4".into(),
        reason: "interpreter".into(),
    };
    let map = ExemptionMap::from_entries(vec![ex]).expect("from_entries");

    // Exact match works
    assert!(map.get("D4", "python3").is_some());

    // Basename fallback must NOT match D4 for different paths (e.g. under testbed)
    assert!(map.get("D4", "testbed/python3").is_none());
    assert!(map.get("D4", "opt/conda/envs/task/bin/python3").is_none());

    // Basename fallback is preserved for D6
    let ex_d6 = NamedExemption {
        path: "docker-inspect.json".into(),
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        detector: "D6".into(),
        reason: "oci_metadata".into(),
    };
    let map_d6 = ExemptionMap::from_entries(vec![ex_d6]).expect("from_entries");
    assert!(map_d6.get("D6", "tmp/meta/docker-inspect.json").is_some());
}
