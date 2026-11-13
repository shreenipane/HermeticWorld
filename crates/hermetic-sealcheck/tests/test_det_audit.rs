use hermetic_sealcheck::{check_d11, check_d12, safe_fs, D11Options, D12Options};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::Command;
use tempfile::tempdir;
use time::macros::{date, datetime};

#[test]
fn detector_reads_refuse_symlinks_ancestors_and_special_files() {
    let dir = tempdir().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("data"), "SECRET").unwrap();
    let alias = dir.path().join("alias");
    symlink(&real, &alias).unwrap();
    let link = dir.path().join("link");
    symlink(real.join("data"), &link).unwrap();
    for path in [link, alias.join("data")] {
        assert!(safe_fs::read(&path, 100).is_err());
        assert!(hermetic_sealcheck::d8::read_file_capped(&path, 100).is_err());
        assert!(hermetic_sealcheck::d8::read_log_capped(&path, 100).is_err());
        assert!(hermetic_sealcheck::check_pyc_bytecode(
            &path,
            hermetic_sealcheck::Visibility::AgentVisible
        )
        .is_err());
        assert!(
            hermetic_sealcheck::scan_ext4_image(&path, datetime!(2024-01-01 00:00 UTC)).is_err()
        );
    }
    assert!(safe_fs::read_dir(&alias).is_err());
    let socket_path = dir.path().join("socket");
    let _socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    assert!(safe_fs::open_regular(&socket_path).is_err());
    assert!(hermetic_sealcheck::d8::read_file_capped(&socket_path, 100).is_err());
}

#[test]
fn d8_directory_entry_cap_reports_incomplete_inspection() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("var/log");
    fs::create_dir_all(&log).unwrap();
    for n in 0..=safe_fs::MAX_DIRECTORY_ENTRIES {
        fs::write(log.join(format!("{n:05}.log")), "").unwrap();
    }
    assert!(safe_fs::read_dir(&log).is_err());
    let findings = hermetic_sealcheck::check_d8(
        dir.path(),
        datetime!(2024-01-01 00:00 UTC),
        hermetic_sealcheck::Visibility::AgentVisible,
    );
    assert!(findings
        .iter()
        .any(|f| f.channel == "d8_error" && f.evidence.iter().any(|e| e.contains("cap"))));
}

#[test]
fn d8_log_file_cap_is_visible_instead_of_silently_clean() {
    let dir = tempdir().unwrap();
    let log = dir.path().join("var/log");
    fs::create_dir_all(&log).unwrap();
    for n in 0..501 {
        fs::write(log.join(format!("{n:05}.log")), "").unwrap();
    }
    let findings = hermetic_sealcheck::check_d8(
        dir.path(),
        datetime!(2024-01-01 00:00 UTC),
        hermetic_sealcheck::Visibility::AgentVisible,
    );
    assert!(findings
        .iter()
        .any(|f| f.channel == "d8_error" && f.evidence.iter().any(|e| e.contains("log files"))));
}

#[test]
fn d11_and_d12_cli_byte_caps_fail_closed() {
    let dir = tempdir().unwrap();
    for (command, argument, size) in [
        ("d11", "--patch", hermetic_sealcheck::d11::MAX_PATCH_BYTES),
        ("d12", "--path", hermetic_sealcheck::d12::MAX_TEXT_BYTES),
    ] {
        let input = dir.path().join(command);
        fs::File::create(&input)
            .unwrap()
            .set_len(size as u64 + 1)
            .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_hermetic-sealcheck"))
            .args([command, argument])
            .arg(input)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{command}");
    }
}

#[test]
fn d4_sparse_image_is_refused_by_named_byte_cap() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("oversized.ext4");
    fs::File::create(&path)
        .unwrap()
        .set_len(hermetic_sealcheck::ext4::MAX_IMAGE_BYTES + 1)
        .unwrap();
    let error =
        hermetic_sealcheck::scan_ext4_image(&path, datetime!(2024-01-01 00:00 UTC)).unwrap_err();
    assert!(error.to_string().contains("cap"));
}

fn allocated_inode_image() -> Vec<u8> {
    let mut image = vec![0; 8192];
    image[1024 + 0x38..1024 + 0x3a].copy_from_slice(&0xef53u16.to_le_bytes());
    for (offset, value) in [(0, 1u32), (4, 8), (0x14, 1), (0x20, 8), (0x28, 1)] {
        image[1024 + offset..1024 + offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    image[1024 + 0x58..1024 + 0x5a].copy_from_slice(&256u16.to_le_bytes());
    image[2048 + 4..2048 + 8].copy_from_slice(&3u32.to_le_bytes());
    image[2048 + 8..2048 + 12].copy_from_slice(&4u32.to_le_bytes());
    image[3072] = 1;
    let late = datetime!(2024-01-02 00:00 UTC).unix_timestamp() as u32;
    image[4096 + 0x10..4096 + 0x14].copy_from_slice(&late.to_le_bytes());
    image
}

#[test]
fn d4_allocated_inode_cannot_hide_late_time_with_deletion_flag() {
    let mut image = allocated_inode_image();
    let clock = datetime!(2024-01-01 00:00 UTC);
    assert_eq!(
        hermetic_sealcheck::scan_ext4_slice("image", &image, clock)
            .unwrap()
            .len(),
        1
    );
    image[4096 + 0x14] = 1;
    assert!(hermetic_sealcheck::scan_ext4_slice("image", &image, clock).is_err());
}

#[test]
fn d4_dirty_journal_cannot_bypass_timestamp_verification() {
    let mut image = allocated_inode_image();
    image[1024 + 0x60] |= 4;
    let error =
        hermetic_sealcheck::scan_ext4_slice("image", &image, datetime!(2024-01-01 00:00 UTC))
            .unwrap_err();
    assert!(error.to_string().contains("journal recovery"));
}

#[test]
fn d4_invalid_inode_extra_times_and_sizes_fail_closed() {
    let mut image = allocated_inode_image();
    let clock = datetime!(2024-01-01 00:00 UTC);
    let early = (clock.unix_timestamp() - 1) as u32;
    image[4096 + 0x10..4096 + 0x14].copy_from_slice(&early.to_le_bytes());
    image[4096 + 0x80..4096 + 0x82].copy_from_slice(&16u16.to_le_bytes());
    image[4096 + 0x88..4096 + 0x8c].copy_from_slice(&4_000_000_000u32.to_le_bytes());
    assert!(hermetic_sealcheck::scan_ext4_slice("image", &image, clock).is_err());
    image[4096 + 0x88..4096 + 0x8c].fill(0);
    image[4096 + 0x80..4096 + 0x82].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(hermetic_sealcheck::scan_ext4_slice("image", &image, clock).is_err());
}

#[test]
fn d4_inherited_image_descriptor_remains_pinned_and_has_stable_evidence() {
    use std::os::fd::AsRawFd;
    let dir = tempdir().unwrap();
    let path = dir.path().join("image");
    fs::write(&path, allocated_inode_image()).unwrap();
    let image = fs::File::open(&path).unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&path, "replacement").unwrap();
    let capability = std::path::PathBuf::from(format!("/proc/self/fd/{}", image.as_raw_fd()));
    let findings =
        hermetic_sealcheck::scan_ext4_image(&capability, datetime!(2024-01-01 00:00 UTC)).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "<image>#inode/1");
    let _socket = std::os::unix::net::UnixListener::bind(dir.path().join("socket-fd")).unwrap();
    let socket_fd = std::path::PathBuf::from(format!("/proc/self/fd/{}", _socket.as_raw_fd()));
    assert!(safe_fs::open_regular(&socket_fd).is_err());
}

#[test]
fn d11_rename_metadata_and_empty_added_shadow_modules_are_detected() {
    let patch = "diff --git a/bench tests/hidden.py b/safe.py\nsimilarity index 100%\nrename from bench tests/hidden.py\nrename to safe.py\n";
    let opts = D11Options {
        benchmark_test_files: vec!["bench tests/hidden.py".into()],
        ..Default::default()
    };
    assert!(check_d11(patch, &opts)
        .iter()
        .any(|f| f.channel == "benchmark_test_file" && f.path == "bench tests/hidden.py"));
    for patch in [
        "diff --git a/json.py b/json.py\nnew file mode 100644\nindex 0000000..e69de29\n",
        "diff --git a/helpers.py b/json.py\nsimilarity index 100%\nrename from helpers.py\nrename to json.py\n",
    ] {
        assert!(check_d11(patch, &D11Options::default()).iter().any(|f| f.channel == "shadowing" && f.path == "json.py"));
    }
}

#[test]
fn d4_malformed_cli_emits_info_report_and_fails_closed() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bad.ext4");
    fs::write(&path, b"truncated").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hermetic-sealcheck"))
        .args(["d4-image", "--image"])
        .arg(path)
        .args(["--t-clock", "2024-01-01T00:00:00Z"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["findings"][0]["channel"], "image_malformed");
    assert_eq!(report["findings"][0]["severity"], "info");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&dir.path().display().to_string()));
}

#[test]
fn d4_scan_and_index_do_not_emit_host_root_paths() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("late"), "payload").unwrap();
    let fp =
        hermetic_sealcheck::FingerprintSet::from_task("", "", &dir.path().join("absent")).unwrap();
    let opts = hermetic_sealcheck::ScanOptions {
        t_clock: Some(datetime!(2000-01-01 00:00 UTC)),
        ..Default::default()
    };
    let scanned = hermetic_sealcheck::scan_tree(dir.path(), &fp, &opts);
    let indexes = tempdir().unwrap();
    let index = indexes.path().join("layer.idx");
    hermetic_sealcheck::write_index(dir.path(), &index).unwrap();
    let queried = hermetic_sealcheck::query_index(&index, &fp, &opts).unwrap();
    for findings in [scanned, queried] {
        let paths = findings
            .iter()
            .filter(|f| f.detector == "D4")
            .map(|f| f.path.as_str())
            .collect::<Vec<_>>();
        assert!(paths.contains(&"late"));
        assert!(paths
            .iter()
            .all(|p| !p.contains(&dir.path().display().to_string())));
    }
}

#[test]
fn d11_unified_and_quoted_paths_cannot_hide_infrastructure_changes() {
    for patch in [
        "--- a/conftest.py\n+++ b/conftest.py\n@@ -0,0 +1 @@\n+pass\n",
        "diff --git \"a/odd\\tname/conftest.py\" b/safe.py\nsimilarity index 100%\nrename from \"odd\\tname/conftest.py\"\nrename to safe.py\n",
        "diff --git \"a/odd\\tname/conftest.py\" \"b/odd\\tname/conftest.py\"\n--- \"a/odd\\tname/conftest.py\"\n+++ \"b/odd\\tname/conftest.py\"\n@@ -0,0 +1 @@\n+pass\n",
    ] {
        let findings = check_d11(patch, &D11Options::default());
        assert!(findings.iter().any(|f| f.channel == "test_infra_file" && f.path.ends_with("conftest.py")), "{findings:?}");
    }
}

#[test]
fn d11_patch_and_d12_option_caps_report_incomplete_inspection() {
    let text = "x".repeat(hermetic_sealcheck::d11::MAX_PATCH_BYTES + 1);
    assert_eq!(
        check_d11(&text, &D11Options::default())[0].evidence,
        ["patch or option cap exceeded"]
    );
    let opts = D12Options {
        real_date: date!(2026 - 11 - 11),
        tolerance_days: 0,
        host_names: vec!["host".to_string(); 10_001],
        host_paths: Vec::new(),
    };
    assert_eq!(check_d12("input", "host", &opts)[0].channel, "scan_error");
}

#[test]
fn d12_large_tolerance_saturates_instead_of_shrinking_the_window() {
    let opts = D12Options {
        real_date: date!(2026 - 11 - 11),
        tolerance_days: u32::MAX,
        host_names: Vec::new(),
        host_paths: Vec::new(),
    };
    let findings = check_d12("input", "2000-01-01", &opts);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].channel, "real_date");
}

#[test]
fn d11_cli_refuses_symlink_patch() {
    let dir = tempdir().unwrap();
    let real = dir.path().join("patch");
    fs::write(&real, "diff --git a/conftest.py b/conftest.py\n").unwrap();
    let alias = dir.path().join("alias");
    symlink(real, &alias).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hermetic-sealcheck"))
        .args(["d11", "--patch"])
        .arg(alias)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn d12_cli_refuses_symlink_directory_component() {
    let dir = tempdir().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("input"), "2026-11-11").unwrap();
    let alias = dir.path().join("alias");
    symlink(real, &alias).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hermetic-sealcheck"))
        .args(["d12", "--path"])
        .arg(alias.join("input"))
        .args(["--real-date", "2026-11-11"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&dir.path().display().to_string()));
}

#[test]
fn detector_reports_are_atomic_private_and_refuse_symlink_outputs() {
    let dir = tempdir().unwrap();
    let destination = dir.path().join("report");
    safe_fs::atomic_write(&destination, b"report").unwrap();
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let alias = dir.path().join("alias");
    symlink(&destination, &alias).unwrap();
    assert!(safe_fs::atomic_write(&alias, b"overwrite").is_err());
    assert_eq!(fs::read(destination).unwrap(), b"report");
    let patch = dir.path().join("input.patch");
    fs::write(&patch, "").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hermetic-sealcheck"))
        .args(["d11", "--patch"])
        .arg(patch)
        .arg("--out")
        .arg(alias)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn secret_output_mode_is_fixed_under_restrictive_umask() {
    let dir = tempdir().unwrap();
    let patch = dir.path().join("input.patch");
    let report = dir.path().join("report.json");
    fs::write(&patch, "").unwrap();
    let output = Command::new("sh")
        .args([
            "-c",
            "umask 0777; exec \"$1\" d11 --patch \"$2\" --out \"$3\"",
            "sh",
        ])
        .arg(env!("CARGO_BIN_EXE_hermetic-sealcheck"))
        .arg(patch)
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        fs::metadata(report).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn d8_findings_are_relative_and_stably_ordered() {
    let dir = tempdir().unwrap();
    for name in ["z.log", "a.log"] {
        fs::create_dir_all(dir.path().join("var/log")).unwrap();
        fs::write(
            dir.path().join("var/log").join(name),
            "2026-11-11T00:00:00Z message",
        )
        .unwrap();
    }
    let findings = hermetic_sealcheck::check_d8(
        dir.path(),
        datetime!(2024-01-01 00:00 UTC),
        hermetic_sealcheck::Visibility::AgentVisible,
    );
    assert_eq!(
        findings.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(),
        ["var/log/a.log", "var/log/z.log"]
    );
}

#[test]
fn d4_duplicate_archive_member_paths_have_one_finding() {
    let dir = tempdir().unwrap();
    let mut archive = tar::Builder::new(Vec::new());
    for seconds in [1u64, 2] {
        let mut header = tar::Header::new_gnu();
        header.set_path("same").unwrap();
        header.set_size(1);
        header.set_mode(0o644);
        header.set_mtime(seconds);
        header.set_cksum();
        archive.append(&header, std::io::Cursor::new(b"x")).unwrap();
    }
    fs::write(dir.path().join("input.tar"), archive.into_inner().unwrap()).unwrap();
    let fp =
        hermetic_sealcheck::FingerprintSet::from_task("", "", &dir.path().join("absent")).unwrap();
    let opts = hermetic_sealcheck::ScanOptions {
        t_clock: Some(datetime!(1970-01-01 00:00 UTC)),
        ..Default::default()
    };
    let scanned = hermetic_sealcheck::scan_tree(dir.path(), &fp, &opts);
    let indexes = tempdir().unwrap();
    let index = indexes.path().join("layer.idx");
    hermetic_sealcheck::write_index(dir.path(), &index).unwrap();
    let queried = hermetic_sealcheck::query_index(&index, &fp, &opts).unwrap();
    for findings in [scanned, queried] {
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.channel == "member_mtime")
                .count(),
            1
        );
    }
}

#[test]
fn tree_walker_excludes_files_as_well_as_directories() {
    let dir = tempdir().unwrap();
    let excluded = dir.path().join("excluded");
    fs::write(&excluded, "payload").unwrap();
    let fp =
        hermetic_sealcheck::FingerprintSet::from_task("", "", &dir.path().join("absent")).unwrap();
    let opts = hermetic_sealcheck::ScanOptions {
        t_clock: Some(datetime!(1970-01-01 00:00 UTC)),
        exclude_dirs: vec![excluded],
        ..Default::default()
    };
    let findings = hermetic_sealcheck::scan_tree(dir.path(), &fp, &opts);
    assert!(!findings.iter().any(|f| f.path.ends_with("excluded")));
}

#[test]
fn tree_timestamp_and_payload_stay_on_the_pinned_inode_when_path_is_replaced() {
    struct SwapSink {
        root: std::path::PathBuf,
        text: String,
    }
    impl hermetic_sealcheck::containers::UnitSink for SwapSink {
        fn fixed(&mut self, finding: hermetic_sealcheck::Finding) {
            panic!("unexpected refusal: {finding:?}");
        }
        fn path(&mut self, _: &str, _: &str) {}
        fn text(&mut self, _: &str, text: &str) {
            self.text = text.to_string();
        }
        fn binary(&mut self, _: &str, _: &str, _: hermetic_sealcheck::binary::BinaryStrings) {}
        fn pkg_metadata(&mut self, _: &str, _: &[u8]) {}
        fn member_time(&mut self, _: &str, _: i64) {}
        fn pyc_code_objects(
            &mut self,
            _: &str,
            _: &[hermetic_sealcheck::pyc_marshal::PycCodeObject],
        ) {
        }
    }
    impl hermetic_sealcheck::scan::TreeSink for SwapSink {
        fn git_repo(&mut self, _: &std::path::Path) {}
        fn d1_finding(&mut self, _: hermetic_sealcheck::Finding) {}
        fn pyc_file(&mut self, _: &std::path::Path, _: &str) {}
        fn loose_file(&mut self, _: &str, _: &fs::Metadata) {
            fs::rename(self.root.join("input"), self.root.join("removed")).unwrap();
            fs::write(self.root.join("input"), "replacement payload").unwrap();
        }
    }
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("input"), "original payload").unwrap();
    let sink = SwapSink {
        root: dir.path().to_path_buf(),
        text: String::new(),
    };
    let result = hermetic_sealcheck::scan::walk_tree(dir.path(), &Default::default(), sink);
    assert_eq!(result.text, "original payload");
}

#[test]
fn d4_tree_cap_reports_incomplete_timestamp_coverage() {
    let dir = tempdir().unwrap();
    let mut path = dir.path().to_path_buf();
    for _ in 0..=safe_fs::MAX_TREE_DEPTH {
        path.push("d");
        fs::create_dir(&path).unwrap();
    }
    let fp =
        hermetic_sealcheck::FingerprintSet::from_task("", "", &dir.path().join("absent")).unwrap();
    let opts = hermetic_sealcheck::ScanOptions {
        t_clock: Some(datetime!(2500-01-01 00:00 UTC)),
        ..Default::default()
    };
    let findings = hermetic_sealcheck::scan_tree(dir.path(), &fp, &opts);
    assert!(findings
        .iter()
        .any(|f| f.detector == "D4" && f.channel == "tree_incomplete"));
}

#[test]
fn d4_unreadable_regular_file_still_checks_its_mtime() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("unreadable");
    let file = fs::File::create(&path).unwrap();
    file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
        .unwrap();
    file.set_permissions(fs::Permissions::from_mode(0o000))
        .unwrap();
    let fp =
        hermetic_sealcheck::FingerprintSet::from_task("", "", &dir.path().join("absent")).unwrap();
    let opts = hermetic_sealcheck::ScanOptions {
        t_clock: Some(datetime!(1970-01-01 00:00 UTC)),
        ..Default::default()
    };
    let findings = hermetic_sealcheck::scan_tree(dir.path(), &fp, &opts);
    assert!(findings.iter().any(|f| f.detector == "D4"
        && f.path == "unreadable"
        && f.severity == hermetic_sealcheck::Severity::Gate));
}
