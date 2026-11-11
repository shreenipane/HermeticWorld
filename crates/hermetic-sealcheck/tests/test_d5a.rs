use std::fs;
use std::process::Command;
use tempfile::tempdir;
use time::macros::datetime;

use hermetic_sealcheck::{scan_tree, FingerprintSet, ScanOptions, Severity};

#[test]
fn test_d5a_dist_info_newer_than_v_gates() {
    let scan_dir = tempdir().expect("tempdir");
    let dist_info = scan_dir.path().join("requests-3.1.0.dist-info");
    fs::create_dir_all(&dist_info).expect("mkdir dist-info");
    fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: requests\nVersion: 3.1.0\n\nBody",
    )
    .expect("write METADATA");

    let fp = FingerprintSet::from_task("", "", &scan_dir.path().join("nonexistent")).expect("fp");
    let opts = ScanOptions {
        target_packages: vec!["requests".to_string()],
        task_version: Some("3.0".to_string()),
        ..Default::default()
    };

    let findings = scan_tree(scan_dir.path(), &fp, &opts);
    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D5a" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].channel, "target_version");
    assert!(gates[0].evidence[0].contains("found version: 3.1.0"));
    assert!(gates[0].evidence[0].contains("task version: 3.0"));
}

#[test]
fn test_d5a_equal_version_passes() {
    let scan_dir = tempdir().expect("tempdir");
    let dist_info = scan_dir.path().join("requests-3.0.dist-info");
    fs::create_dir_all(&dist_info).expect("mkdir dist-info");
    fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: requests\nVersion: 3.0.1\n\nBody",
    )
    .expect("write METADATA");

    let fp = FingerprintSet::from_task("", "", &scan_dir.path().join("nonexistent")).expect("fp");
    // With task version "3.0", comparing the 2 components gives [3, 0] == [3, 0], so 3.0.1 passes!
    let opts = ScanOptions {
        target_packages: vec!["requests".to_string()],
        task_version: Some("3.0".to_string()),
        ..Default::default()
    };

    let findings = scan_tree(scan_dir.path(), &fp, &opts);
    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D5a" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(
        gates.len(),
        0,
        "equal release segment on task's components must pass"
    );
}

#[test]
fn test_d5a_dev_date_after_t_clock_gates() {
    let scan_dir = tempdir().expect("tempdir");
    let dist_info = scan_dir.path().join("requests-3.0.dev.dist-info");
    fs::create_dir_all(&dist_info).expect("mkdir dist-info");
    fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: requests\nVersion: 3.0.dev20240105\n\nBody",
    )
    .expect("write METADATA");

    let fp = FingerprintSet::from_task("", "", &scan_dir.path().join("nonexistent")).expect("fp");
    // T_clock is 2024-01-02, dev date is 2024-01-05 (later) -> gates on target_dev_date
    let opts = ScanOptions {
        target_packages: vec!["requests".to_string()],
        task_version: Some("3.0".to_string()),
        t_clock: Some(datetime!(2024-01-02 00:00:00 UTC)),
        ..Default::default()
    };

    let findings = scan_tree(scan_dir.path(), &fp, &opts);
    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D5a" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].channel, "target_dev_date");
}

#[test]
fn test_d5a_dev_date_before_t_clock_passes() {
    let scan_dir = tempdir().expect("tempdir");
    let dist_info = scan_dir.path().join("requests-3.0.dev.dist-info");
    fs::create_dir_all(&dist_info).expect("mkdir dist-info");
    fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: requests\nVersion: 3.0.dev20240101\n\nBody",
    )
    .expect("write METADATA");

    let fp = FingerprintSet::from_task("", "", &scan_dir.path().join("nonexistent")).expect("fp");
    // T_clock is 2024-01-02, dev date is 2024-01-01 (before) -> passes
    let opts = ScanOptions {
        target_packages: vec!["requests".to_string()],
        task_version: Some("3.0".to_string()),
        t_clock: Some(datetime!(2024-01-02 00:00:00 UTC)),
        ..Default::default()
    };

    let findings = scan_tree(scan_dir.path(), &fp, &opts);
    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D5a" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(gates.len(), 0, "dev date before T_clock must pass");
}

#[test]
fn test_d5a_egg_info_pkg_info() {
    let scan_dir = tempdir().expect("tempdir");
    let egg_info = scan_dir.path().join("requests-3.2.0.egg-info");
    fs::create_dir_all(&egg_info).expect("mkdir egg-info");
    fs::write(
        egg_info.join("PKG-INFO"),
        "Metadata-Version: 2.1\nName: requests\nVersion: 3.2.0\n",
    )
    .expect("write PKG-INFO");

    let fp = FingerprintSet::from_task("", "", &scan_dir.path().join("nonexistent")).expect("fp");
    let opts = ScanOptions {
        target_packages: vec!["requests".to_string()],
        task_version: Some("3.0".to_string()),
        ..Default::default()
    };

    let findings = scan_tree(scan_dir.path(), &fp, &opts);
    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D5a" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].channel, "target_version");
    assert!(gates[0].path.ends_with("PKG-INFO"));
}

#[test]
fn test_d5a_another_project_ignored() {
    let scan_dir = tempdir().expect("tempdir");
    let dist_info = scan_dir.path().join("urllib3-9.9.9.dist-info");
    fs::create_dir_all(&dist_info).expect("mkdir dist-info");
    fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: urllib3\nVersion: 9.9.9\n",
    )
    .expect("write METADATA");

    let fp = FingerprintSet::from_task("", "", &scan_dir.path().join("nonexistent")).expect("fp");
    let opts = ScanOptions {
        target_packages: vec!["requests".to_string()],
        task_version: Some("3.0".to_string()),
        ..Default::default()
    };

    let findings = scan_tree(scan_dir.path(), &fp, &opts);
    assert_eq!(
        findings.len(),
        0,
        "non-target project metadata must be ignored"
    );
}

#[test]
fn test_d5a_name_normalisation() {
    let scan_dir = tempdir().expect("tempdir");
    let dist_info = scan_dir.path().join("my_package.dist-info");
    fs::create_dir_all(&dist_info).expect("mkdir dist-info");
    // Name with mixed case, underscores, dots: "My_Package.Foo--Bar"
    fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: My_Package.Foo--Bar\nVersion: 4.0\n",
    )
    .expect("write METADATA");

    let fp = FingerprintSet::from_task("", "", &scan_dir.path().join("nonexistent")).expect("fp");
    // Target package configured as "my-package-foo-bar"
    let opts = ScanOptions {
        target_packages: vec!["my-package-foo-bar".to_string()],
        task_version: Some("3.0".to_string()),
        ..Default::default()
    };

    let findings = scan_tree(scan_dir.path(), &fp, &opts);
    let gates: Vec<_> = findings
        .iter()
        .filter(|f| f.detector == "D5a" && f.severity == Severity::Gate)
        .collect();
    assert_eq!(gates.len(), 1, "PEP 503 normalised names must match");
}

#[test]
fn test_d5a_cli_target_package_argument() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let parent_dir = tempdir().expect("tempdir");
    let parent = parent_dir.path();

    let base_tree = parent.join("repo");
    fs::create_dir_all(&base_tree).expect("mkdir repo");
    fs::write(base_tree.join("main.py"), "def base(): pass\n").expect("write base");

    let task = parent.join("task");
    fs::create_dir_all(task.join("staging")).expect("mkdir staging");
    fs::create_dir_all(task.join("agent")).expect("mkdir agent");
    // repo is "owner/my-repo", but PyPI name is "custom-pypi-package"
    let task_json = r#"{
        "schema": "hermetic-slice-task/v1",
        "instance_id": "test__d5a-cli",
        "repo": "owner/my-repo",
        "version": "1.0",
        "base_commit": "1234567890abcdef1234567890abcdef12345678",
        "cutoffs": {
            "t_world": "2024-01-01T00:00:00Z",
            "t_clock": "2024-01-02T00:00:00Z"
        }
    }"#;
    fs::write(task.join("task.json"), task_json).expect("write task.json");
    fs::write(task.join("staging/gold.patch"), "").expect("write gold");
    fs::write(task.join("staging/test.patch"), "").expect("write test");
    fs::write(task.join("agent/problem_statement.md"), "problem").expect("write problem");

    let scan_root = parent.join("root");
    let dist_info = scan_root.join("custom_pypi_package-2.0.dist-info");
    fs::create_dir_all(&dist_info).expect("mkdir dist-info");
    fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: custom-pypi-package\nVersion: 2.0\n",
    )
    .expect("write METADATA");

    // Scan with --target-package custom-pypi-package
    let status = Command::new(bin_path)
        .arg("scan")
        .arg("--task")
        .arg(&task)
        .arg("--base-tree")
        .arg(&base_tree)
        .arg("--root")
        .arg(&scan_root)
        .arg("--target-package")
        .arg("custom-pypi-package")
        .status()
        .expect("exec scan");

    assert_eq!(
        status.code(),
        Some(2),
        "post-fix version of --target-package must gate with exit code 2"
    );
}

#[test]
fn test_d5a_task_json_without_version_loads_and_gives_info() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-sealcheck");
    let parent_dir = tempdir().expect("tempdir");
    let parent = parent_dir.path();

    let base_tree = parent.join("repo");
    fs::create_dir_all(&base_tree).expect("mkdir repo");
    fs::write(base_tree.join("main.py"), "def base(): pass\n").expect("write base");

    let task = parent.join("task");
    fs::create_dir_all(task.join("staging")).expect("mkdir staging");
    fs::create_dir_all(task.join("agent")).expect("mkdir agent");
    // task.json has NO "version" field
    let task_json = r#"{
        "schema": "hermetic-slice-task/v1",
        "instance_id": "test__d5a-no-ver",
        "repo": "owner/requests",
        "base_commit": "1234567890abcdef1234567890abcdef12345678",
        "cutoffs": {
            "t_world": "2024-01-01T00:00:00Z",
            "t_clock": "2024-01-02T00:00:00Z"
        }
    }"#;
    fs::write(task.join("task.json"), task_json).expect("write task.json");
    fs::write(task.join("staging/gold.patch"), "").expect("write gold");
    fs::write(task.join("staging/test.patch"), "").expect("write test");
    fs::write(task.join("agent/problem_statement.md"), "problem").expect("write problem");

    let scan_root = parent.join("root");
    let dist_info = scan_root.join("requests-2.31.0.dist-info");
    fs::create_dir_all(&dist_info).expect("mkdir dist-info");
    fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n",
    )
    .expect("write METADATA");

    let output = Command::new(bin_path)
        .arg("scan")
        .arg("--task")
        .arg(&task)
        .arg("--base-tree")
        .arg(&base_tree)
        .arg("--root")
        .arg(&scan_root)
        .output()
        .expect("exec scan");

    assert_eq!(
        output.status.code(),
        Some(0),
        "task without version must not gate, should exit 0"
    );

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout_str.contains("target_version_unknown"),
        "must emit info finding with channel target_version_unknown"
    );
}
