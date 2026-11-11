use std::fs;
use std::process::Command;

use hermetic_sealcheck::{
    parse_oci_date, scan_oci, BenchmarkSignatures, FingerprintSet, ScanOptions, Severity,
    Visibility,
};
use time::OffsetDateTime;

fn t_clock() -> OffsetDateTime {
    time::macros::datetime!(2026-01-01 00:00:00 UTC)
}

#[test]
fn test_d6_parse_dates() {
    // 1. RFC 3339 formats
    let dt1 = parse_oci_date("2026-08-15T06:04:51Z").expect("RFC 3339 Z");
    assert_eq!(dt1.year(), 2026);
    assert_eq!(dt1.month() as u8, 8);
    assert_eq!(dt1.day(), 15);
    assert_eq!(dt1.hour(), 6);
    assert_eq!(dt1.minute(), 4);
    assert_eq!(dt1.second(), 51);

    let dt2 = parse_oci_date("2026-08-15T06:04:51+00:00").expect("RFC 3339 offset");
    assert_eq!(dt2.unix_timestamp(), dt1.unix_timestamp());

    // 2. Docker formats
    let dt3 = parse_oci_date("2026-08-15 06:04:51 +0000 UTC").expect("Docker +0000 UTC");
    assert_eq!(dt3.unix_timestamp(), dt1.unix_timestamp());

    let dt4 = parse_oci_date("2026-08-15 06:04:51.123456789 +0000 UTC")
        .expect("Docker fractional +0000 UTC");
    assert_eq!(dt4.year(), 2026);
    assert_eq!(dt4.nanosecond(), 123456789);

    let dt5 = parse_oci_date("2026-08-15 06:04:51Z").expect("Docker space and Z");
    assert_eq!(dt5.unix_timestamp(), dt1.unix_timestamp());

    let dt6 = parse_oci_date("2026-08-15 06:04:51").expect("Docker date-time without timezone");
    assert_eq!(dt6.unix_timestamp(), dt1.unix_timestamp());

    // 3. Bad dates
    assert!(parse_oci_date("not-a-valid-date").is_err());
    assert!(parse_oci_date("").is_err());
}

#[test]
fn test_d6_old_dates_pass() {
    let temp = tempfile::tempdir().unwrap();
    let inspect_path = temp.path().join("inspect.json");
    let history_path = temp.path().join("history.jsonl");

    let inspect_json = r#"[
        {
            "Id": "sha256:1234567890abcdef",
            "Created": "2025-06-01T12:00:00Z",
            "Config": {
                "Env": ["PATH=/usr/bin:/bin", "FOO=bar"],
                "Labels": {
                    "maintainer": "test@example.com"
                }
            }
        }
    ]"#;
    fs::write(&inspect_path, inspect_json).unwrap();

    let history_jsonl = r#"{"CreatedAt": "2025-05-01 10:00:00 +0000 UTC", "CreatedBy": "RUN apt-get update"}
{"CreatedAt": "2025-06-01 12:00:00 +0000 UTC", "CreatedBy": "CMD [\"python\"]"}
"#;
    fs::write(&history_path, history_jsonl).unwrap();

    let base_tree = tempfile::tempdir().unwrap();
    let fp = FingerprintSet::from_task("", "", base_tree.path()).unwrap();
    let signatures = BenchmarkSignatures::new(None);
    let opts = ScanOptions {
        visibility: Visibility::ImageOnly,
        t_clock: Some(t_clock()),
        ..Default::default()
    };

    let findings = scan_oci(
        Some(&inspect_path),
        Some(&history_path),
        Some(t_clock()),
        &fp,
        &signatures,
        &opts,
    )
    .expect("scan_oci");

    assert!(
        findings.is_empty(),
        "expected 0 findings for clean old dates, got: {:?}",
        findings
    );
}

#[test]
fn test_d6_channel_oci_created() {
    let temp = tempfile::tempdir().unwrap();
    let inspect_path = temp.path().join("inspect.json");

    // Created after T_clock (2026-08-15 > 2026-01-01)
    let inspect_json = r#"[
        {
            "Id": "sha256:abc",
            "Created": "2026-08-15 06:04:51 +0000 UTC",
            "Config": { "Env": [], "Labels": {} }
        }
    ]"#;
    fs::write(&inspect_path, inspect_json).unwrap();

    let base_tree = tempfile::tempdir().unwrap();
    let fp = FingerprintSet::from_task("", "", base_tree.path()).unwrap();
    let signatures = BenchmarkSignatures::new(None);
    let opts = ScanOptions::default();

    let findings = scan_oci(
        Some(&inspect_path),
        None,
        Some(t_clock()),
        &fp,
        &signatures,
        &opts,
    )
    .expect("scan_oci");

    let f = findings
        .iter()
        .find(|f| f.detector == "D6" && f.channel == "oci_created")
        .expect("expected oci_created finding");

    assert_eq!(f.severity, Severity::Gate);
    assert_eq!(f.visibility, Visibility::ImageOnly);
}

#[test]
fn test_d6_channel_oci_history_date() {
    let temp = tempfile::tempdir().unwrap();
    let history_path = temp.path().join("history.jsonl");

    // Two history entries created after T_clock
    let history_jsonl = r#"{"CreatedAt": "2025-01-01 00:00:00 +0000 UTC", "CreatedBy": "old"}
{"CreatedAt": "2026-05-01 10:00:00 +0000 UTC", "CreatedBy": "future1"}
{"CreatedAt": "2026-08-15 06:04:51 +0000 UTC", "CreatedBy": "future2"}
"#;
    fs::write(&history_path, history_jsonl).unwrap();

    let base_tree = tempfile::tempdir().unwrap();
    let fp = FingerprintSet::from_task("", "", base_tree.path()).unwrap();
    let signatures = BenchmarkSignatures::new(None);
    let opts = ScanOptions::default();

    let findings = scan_oci(
        None,
        Some(&history_path),
        Some(t_clock()),
        &fp,
        &signatures,
        &opts,
    )
    .expect("scan_oci");

    let date_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D6" && f.channel == "oci_history_date")
        .collect();

    assert_eq!(
        date_findings.len(),
        1,
        "expected exactly one oci_history_date finding"
    );
    let f = date_findings[0];
    assert_eq!(f.severity, Severity::Gate);
    assert_eq!(f.visibility, Visibility::ImageOnly);
    assert!(f.evidence[0].contains("2 history entries"));
    assert!(f.evidence[0].contains("2026-08-15 06:04:51 +0000 UTC"));
}

#[test]
fn test_d6_channel_oci_env() {
    let temp = tempfile::tempdir().unwrap();
    let inspect_path = temp.path().join("inspect.json");

    let gold_patch = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,3 @@\n def f():\n+    secret_env_leak_payload_marker()\n     pass\n";
    let base_tree = tempfile::tempdir().unwrap();
    fs::write(base_tree.path().join("app.py"), "def f():\n    pass\n").unwrap();
    let fp = FingerprintSet::from_task(gold_patch, "", base_tree.path()).unwrap();

    let inspect_json = r#"[
        {
            "Id": "sha256:abc",
            "Created": "2025-01-01T00:00:00Z",
            "Config": {
                "Env": [
                    "PATH=/bin",
                    "LEAK=def f():\n    secret_env_leak_payload_marker()\n    pass"
                ],
                "Labels": {}
            }
        }
    ]"#;
    fs::write(&inspect_path, inspect_json).unwrap();

    let signatures = BenchmarkSignatures::new(None);
    let opts = ScanOptions::default();

    let findings = scan_oci(
        Some(&inspect_path),
        None,
        Some(t_clock()),
        &fp,
        &signatures,
        &opts,
    )
    .expect("scan_oci");

    let f = findings
        .iter()
        .find(|f| f.detector == "D6" && f.channel == "oci_env")
        .expect("expected oci_env finding");

    assert_eq!(f.severity, Severity::Gate);
    assert_eq!(f.visibility, Visibility::AgentVisible);
}

#[test]
fn test_d6_channel_oci_text() {
    let temp = tempfile::tempdir().unwrap();
    let inspect_path = temp.path().join("inspect.json");
    let history_path = temp.path().join("history.jsonl");

    let gold_patch = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,3 @@\n def f():\n+    secret_label_and_created_by_leak()\n     pass\n";
    let base_tree = tempfile::tempdir().unwrap();
    fs::write(base_tree.path().join("app.py"), "def f():\n    pass\n").unwrap();
    let fp = FingerprintSet::from_task(gold_patch, "", base_tree.path()).unwrap();

    // 1. Inspect label match
    let inspect_json = r#"[
        {
            "Id": "sha256:abc",
            "Created": "2025-01-01T00:00:00Z",
            "Config": {
                "Env": [],
                "Labels": {
                    "leak": "def f():\n    secret_label_and_created_by_leak()\n    pass"
                }
            }
        }
    ]"#;
    fs::write(&inspect_path, inspect_json).unwrap();

    // 2. History CreatedBy match
    let history_jsonl = r#"{"CreatedAt": "2025-01-01 00:00:00 +0000 UTC", "CreatedBy": "RUN def f():\n    secret_label_and_created_by_leak()\n    pass"}"#;
    fs::write(&history_path, history_jsonl).unwrap();

    let signatures = BenchmarkSignatures::new(None);
    let opts = ScanOptions::default();

    let findings = scan_oci(
        Some(&inspect_path),
        Some(&history_path),
        Some(t_clock()),
        &fp,
        &signatures,
        &opts,
    )
    .expect("scan_oci");

    let text_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D6" && f.channel == "oci_text")
        .collect();

    assert_eq!(
        text_findings.len(),
        2,
        "expected 2 oci_text findings (label and created_by)"
    );
    for f in text_findings {
        assert_eq!(f.severity, Severity::Gate);
        assert_eq!(f.visibility, Visibility::ImageOnly);
    }
}

#[test]
fn test_d6_channel_oci_bad_date() {
    let temp = tempfile::tempdir().unwrap();
    let inspect_path = temp.path().join("inspect.json");
    let history_path = temp.path().join("history.jsonl");

    let inspect_json = r#"[
        {
            "Id": "sha256:abc",
            "Created": "not-a-valid-date-string",
            "Config": { "Env": [], "Labels": {} }
        }
    ]"#;
    fs::write(&inspect_path, inspect_json).unwrap();

    let history_jsonl = r#"{"CreatedAt": "bad-history-date", "CreatedBy": "cmd"}"#;
    fs::write(&history_path, history_jsonl).unwrap();

    let base_tree = tempfile::tempdir().unwrap();
    let fp = FingerprintSet::from_task("", "", base_tree.path()).unwrap();
    let signatures = BenchmarkSignatures::new(None);
    let opts = ScanOptions::default();

    let findings = scan_oci(
        Some(&inspect_path),
        Some(&history_path),
        Some(t_clock()),
        &fp,
        &signatures,
        &opts,
    )
    .expect("scan_oci");

    let bad_date_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D6" && f.channel == "oci_bad_date")
        .collect();

    assert_eq!(
        bad_date_findings.len(),
        2,
        "expected 2 oci_bad_date info findings"
    );
    for f in bad_date_findings {
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.visibility, Visibility::ImageOnly);
    }
}

#[test]
fn test_d6_cli_run_both_files() {
    let temp = tempfile::tempdir().unwrap();
    let task_dir = temp.path().join("task");
    fs::create_dir_all(task_dir.join("staging")).unwrap();
    fs::create_dir_all(task_dir.join("agent")).unwrap();

    let base_tree = tempfile::tempdir().unwrap();
    fs::write(base_tree.path().join("dummy.txt"), "hello").unwrap();

    let inspect_path = temp.path().join("inspect.json");
    let history_path = temp.path().join("history.jsonl");

    // Clean dates before T_clock
    let inspect_json = r#"[
        {
            "Id": "sha256:abc",
            "Created": "2025-06-01T00:00:00Z",
            "Config": { "Env": ["SAFE=1"], "Labels": { "v": "1" } }
        }
    ]"#;
    fs::write(&inspect_path, inspect_json).unwrap();

    let history_jsonl =
        r#"{"CreatedAt": "2025-06-01 00:00:00 +0000 UTC", "CreatedBy": "RUN echo hi"}"#;
    fs::write(&history_path, history_jsonl).unwrap();

    fs::write(task_dir.join("staging/gold.patch"), "").unwrap();
    fs::write(task_dir.join("staging/test.patch"), "").unwrap();
    fs::write(
        task_dir.join("agent/problem_statement.md"),
        "clean statement",
    )
    .unwrap();
    let task_json = r#"{
        "instance_id": "test__d6-cli",
        "repo": "test/repo",
        "base_commit": "0123456789abcdef0123456789abcdef01234567",
        "cutoffs": {
            "t_world": "2026-01-01T00:00:00Z",
            "t_clock": "2026-01-01T00:00:00Z"
        }
    }"#;
    fs::write(task_dir.join("task.json"), task_json).unwrap();

    let scan_root = temp.path().join("root");
    fs::create_dir_all(&scan_root).unwrap();

    let exe = env!("CARGO_BIN_EXE_hermetic-sealcheck");

    // 1. Clean run with both files exits 0
    let output = Command::new(exe)
        .args([
            "scan",
            "--task",
            task_dir.to_str().unwrap(),
            "--base-tree",
            base_tree.path().to_str().unwrap(),
            "--root",
            scan_root.to_str().unwrap(),
            "--oci-inspect",
            inspect_path.to_str().unwrap(),
            "--oci-history",
            history_path.to_str().unwrap(),
        ])
        .output()
        .expect("run hermetic-sealcheck binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "clean D6 scan must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // 2. Unreadable oci file must exit 1 (usage error)
    let bad_output = Command::new(exe)
        .args([
            "scan",
            "--task",
            task_dir.to_str().unwrap(),
            "--base-tree",
            base_tree.path().to_str().unwrap(),
            "--root",
            scan_root.to_str().unwrap(),
            "--oci-inspect",
            "/nonexistent/path/to/inspect.json",
        ])
        .output()
        .expect("run hermetic-sealcheck binary");

    assert_eq!(
        bad_output.status.code(),
        Some(1),
        "unreadable OCI inspect file must exit 1, got code {:?}",
        bad_output.status.code()
    );
}

#[test]
fn test_d6_non_ascii_date_is_an_error_not_a_panic() {
    for bad in ["2026-08-1é 06:04:51 +0000 UTC", "2026-08-15 06:04:51 +aé1"] {
        assert!(hermetic_sealcheck::d6::parse_oci_date(bad).is_err());
    }
}
