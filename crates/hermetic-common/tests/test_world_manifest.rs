use hermetic_common::world_manifest::{
    digest_file, digest_tree, verify_inclusion, Disposition, DispositionKind, ManifestCutoffs,
    PackagesRecord, ProofDirection, Resources, RunSpec, SealLevel, SubstrateAtT, SubstrateEntry,
    SubstrateExemption, TaskClass, WebRecord, WorldManifest, WorldManifestError,
};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::Command;
use tempfile::tempdir;

fn sample_manifest() -> WorldManifest {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    env.insert("LANG".to_string(), "C.UTF-8".to_string());

    WorldManifest {
        spec_version: "hermetic-world/v1".to_string(),
        task_id: "test-task-123".to_string(),
        task_class: TaskClass::Dated,
        seal_level: SealLevel::Strict,
        cutoffs: ManifestCutoffs {
            t_world: "2026-01-15T00:00:00Z".to_string(),
            t_clock: "2026-01-15T12:00:00Z".to_string(),
            base_commit: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
            pkg_cutoff: "2026-01-15T00:00:00Z".to_string(),
        },
        repo_tree_digest: "blake3:0000000000000000000000000000000000000000000000000000000000000001"
            .to_string(),
        rootfs_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000002"
            .to_string(),
        packages: PackagesRecord {
            closure_root: "blake3:0000000000000000000000000000000000000000000000000000000000000003"
                .to_string(),
            baseline_month: "2026-01".to_string(),
            baseline_root:
                "blake3:0000000000000000000000000000000000000000000000000000000000000004"
                    .to_string(),
        },
        web: Some(WebRecord {
            index_month: "2026-01".to_string(),
            capture_index_root:
                "blake3:0000000000000000000000000000000000000000000000000000000000000005"
                    .to_string(),
        }),
        substrate: vec![SubstrateEntry {
            name: "base-image".to_string(),
            version: "1.0.0".to_string(),
            digest: "blake3:0000000000000000000000000000000000000000000000000000000000000006"
                .to_string(),
            date: "2026-01-01T00:00:00Z".to_string(),
        }],
        substrate_at_t: SubstrateAtT::Full,
        exemptions: vec![SubstrateExemption {
            package: "test-pkg".to_string(),
            reason: "known-substrate".to_string(),
        }],
        dns_table: vec![
            "alpha.example.com".to_string(),
            "beta.example.com".to_string(),
        ],
        world_ca_cert_sha256:
            "sha256:0000000000000000000000000000000000000000000000000000000000000007".to_string(),
        trust_store_paths: vec!["/etc/ssl/certs/ca-certificates.crt".to_string()],
        test_services: Vec::new(),
        run_spec: RunSpec {
            env,
            workdir: "/workspace".to_string(),
            user: "root".to_string(),
            entrypoint: vec!["/bin/bash".to_string()],
            resources: Resources {
                vcpus: 4,
                memory_mib: 8192,
                disk_mib: 20480,
                wall_time_s: 1800,
            },
        },
        sealcheck_report_digest:
            "blake3:0000000000000000000000000000000000000000000000000000000000000008".to_string(),
        dispositions: vec![Disposition {
            kind: DispositionKind::Repaired,
            detector: "D0".to_string(),
            detail: "scrubbed".to_string(),
        }],
    }
}

#[test]
fn test_service_declaration_is_committed_by_world_root() {
    use hermetic_common::world_manifest::TestService;
    let mut manifest = sample_manifest();
    let old_root = manifest.world_root().unwrap();
    manifest.test_services.push(TestService::HttpbinV1);
    manifest.validate().unwrap();
    let json = serde_json::to_string(&manifest).unwrap();
    let restored = WorldManifest::from_json_str(&json).unwrap();
    assert_eq!(restored.test_services, vec![TestService::HttpbinV1]);
    let root = restored.world_root().unwrap();
    assert_ne!(root, old_root);
    let (value, proof) = restored.inclusion_proof("/test_services/0").unwrap();
    assert_eq!(value, "\"httpbin-v1\"");
    assert!(verify_inclusion(&root, "/test_services/0", &value, &proof).unwrap());
}

#[test]
fn test_unknown_or_duplicate_test_services_are_rejected() {
    use hermetic_common::world_manifest::TestService;
    let mut manifest = sample_manifest();
    manifest.test_services = vec![TestService::HttpbinV1, TestService::HttpbinV1];
    assert!(manifest.validate().is_err());
    let mut json = serde_json::to_value(sample_manifest()).unwrap();
    json["test_services"] = serde_json::json!(["arbitrary-command"]);
    assert!(WorldManifest::from_json_str(&json.to_string()).is_err());
}

#[test]
fn test_absent_and_empty_test_services_preserve_legacy_root() {
    let original = sample_manifest();
    let mut json = serde_json::to_value(&original).unwrap();
    assert!(json.get("test_services").is_none());
    json["test_services"] = serde_json::json!([]);
    let restored = WorldManifest::from_json_str(&json.to_string()).unwrap();
    assert_eq!(
        restored.world_root().unwrap(),
        original.world_root().unwrap()
    );
}

#[test]
fn test_known_answer_root() {
    let manifest = sample_manifest();
    assert!(manifest.validate().is_ok());

    let root = manifest.world_root().expect("world root calculation");
    // Known-answer test: exact hardcoded root for sample_manifest
    assert_eq!(
        root,
        "blake3:6912ea7001f998fdc8978e2ce8bd1603ab9d38f615ab30b3bb21bda1ad959a03"
    );
}

#[test]
fn test_field_order_and_env_insertion_invariance() {
    let manifest = sample_manifest();
    let original_root = manifest.world_root().expect("original root");

    // Serialize to serde_json::Value and rebuild with different key ordering
    let json_str = serde_json::to_string(&manifest).expect("serialize");
    let parsed_val: serde_json::Value = serde_json::from_str(&json_str).expect("parse val");

    // Reverse key order in top-level JSON object
    if let serde_json::Value::Object(map) = parsed_val {
        let mut reversed_map = serde_json::Map::new();
        let mut keys: Vec<String> = map.keys().cloned().collect();
        keys.reverse();
        for k in keys {
            if let Some(v) = map.get(&k) {
                reversed_map.insert(k, v.clone());
            }
        }
        let reversed_json = serde_json::to_string(&serde_json::Value::Object(reversed_map))
            .expect("serialize reversed");
        let manifest_reversed: WorldManifest =
            serde_json::from_str(&reversed_json).expect("parse reversed");
        assert_eq!(
            manifest_reversed.world_root().expect("reversed root"),
            original_root
        );
    }

    // Different insertion orders in env map
    let mut env1 = BTreeMap::new();
    env1.insert("A".to_string(), "1".to_string());
    env1.insert("B".to_string(), "2".to_string());

    let mut env2 = BTreeMap::new();
    env2.insert("B".to_string(), "2".to_string());
    env2.insert("A".to_string(), "1".to_string());

    let mut m1 = sample_manifest();
    m1.run_spec.env = env1;

    let mut m2 = sample_manifest();
    m2.run_spec.env = env2;

    assert_eq!(
        m1.world_root().expect("m1 root"),
        m2.world_root().expect("m2 root")
    );
}

#[test]
fn test_single_field_changes_per_group() {
    let base = sample_manifest();
    let base_root = base.world_root().expect("base root");

    // Group 1: Identity (task_id)
    let mut g1 = base.clone();
    g1.task_id = "modified-task-id".to_string();
    assert_ne!(g1.world_root().expect("root"), base_root);

    // Group 2: Cutoffs (t_world)
    let mut g2 = base.clone();
    g2.cutoffs.t_world = "2026-01-14T00:00:00Z".to_string();
    assert_ne!(g2.world_root().expect("root"), base_root);

    // Group 3: Content (repo_tree_digest)
    let mut g3 = base.clone();
    g3.repo_tree_digest =
        "blake3:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    assert_ne!(g3.world_root().expect("root"), base_root);

    // Group 4: Substrate (substrate[0].digest)
    let mut g4 = base.clone();
    g4.substrate[0].digest =
        "blake3:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    assert_ne!(g4.world_root().expect("root"), base_root);

    // Group 5: Network (world_ca_cert_sha256)
    let mut g5 = base.clone();
    g5.world_ca_cert_sha256 =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    assert_ne!(g5.world_root().expect("root"), base_root);

    // Group 6: Run spec (vcpus)
    let mut g6 = base.clone();
    g6.run_spec.resources.vcpus = 8;
    assert_ne!(g6.world_root().expect("root"), base_root);

    // Group 7: Evidence (sealcheck_report_digest)
    let mut g7 = base.clone();
    g7.sealcheck_report_digest =
        "blake3:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    assert_ne!(g7.world_root().expect("root"), base_root);
}

#[test]
fn test_inclusion_proofs_for_every_leaf() {
    let manifest = sample_manifest();
    let root = manifest.world_root().expect("root");
    let leaves = manifest.leaves().expect("leaves");

    assert!(!leaves.is_empty());

    for leaf in &leaves {
        let (val, proof) = manifest
            .inclusion_proof(&leaf.path)
            .expect("inclusion proof");
        assert_eq!(val, leaf.value);

        // Valid verification
        let ok = verify_inclusion(&root, &leaf.path, &val, &proof).expect("verify ok");
        assert!(ok, "Proof failed for leaf {}", leaf.path);

        // Fail for wrong value
        let fail_val = verify_inclusion(&root, &leaf.path, "\"tampered_value\"", &proof)
            .expect("verify tampered val");
        assert!(!fail_val);

        // Fail for wrong path
        let fail_path =
            verify_inclusion(&root, "/wrong/path", &val, &proof).expect("verify tampered path");
        assert!(!fail_path);

        // Fail for tampered proof step hash
        if !proof.is_empty() {
            let mut tampered_proof = proof.clone();
            tampered_proof[0].hash =
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
            let fail_tampered = verify_inclusion(&root, &leaf.path, &val, &tampered_proof)
                .expect("verify tampered step");
            assert!(!fail_tampered);

            // Fail for tampered direction
            let mut flipped_direction_proof = proof.clone();
            flipped_direction_proof[0].direction = match flipped_direction_proof[0].direction {
                ProofDirection::Left => ProofDirection::Right,
                ProofDirection::Right => ProofDirection::Left,
            };
            let fail_direction =
                verify_inclusion(&root, &leaf.path, &val, &flipped_direction_proof)
                    .expect("verify flipped direction");
            assert!(!fail_direction);
        }
    }
}

#[test]
fn test_validation_reports_multiple_errors_at_once() {
    let mut bad = sample_manifest();
    bad.spec_version = "invalid-spec-version".to_string();
    bad.task_id = "".to_string();
    bad.cutoffs.t_clock = "2025-01-01T00:00:00Z".to_string(); // earlier than t_world
    bad.repo_tree_digest = "md5:1234".to_string(); // bad format
    bad.packages.baseline_month = "2026-15".to_string(); // invalid month
    bad.dns_table = vec!["zeta.com".to_string(), "alpha.com".to_string()]; // unsorted
    bad.run_spec.resources.vcpus = 0; // zero resources

    let err = bad.validate().expect_err("should have validation errors");
    assert!(
        err.errors.len() >= 6,
        "Expected at least 6 errors, got {}: {:?}",
        err.errors.len(),
        err.errors
    );

    let err_str = err.to_string();
    assert!(err_str.contains("spec_version"));
    assert!(err_str.contains("task_id"));
    assert!(err_str.contains("earlier than t_world"));
    assert!(err_str.contains("repo_tree_digest"));
    assert!(err_str.contains("baseline_month"));
    assert!(err_str.contains("dns_table"));
    assert!(err_str.contains("resources.vcpus"));
}

#[test]
fn test_deny_unknown_fields() {
    let json_with_unknown = r#"{
        "unknown_extra_field": 123,
        "spec_version": "hermetic-world/v1",
        "task_id": "t",
        "task_class": "dated",
        "seal_level": "strict",
        "cutoffs": {
            "t_world": "2026-01-01T00:00:00Z",
            "t_clock": "2026-01-01T00:00:00Z",
            "pkg_cutoff": "2026-01-01T00:00:00Z"
        },
        "repo_tree_digest": "blake3:0000000000000000000000000000000000000000000000000000000000000001",
        "rootfs_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000002",
        "packages": {
            "closure_root": "blake3:0000000000000000000000000000000000000000000000000000000000000003",
            "baseline_month": "2026-01",
            "baseline_root": "blake3:0000000000000000000000000000000000000000000000000000000000000004"
        },
        "substrate_at_t": "full",
        "world_ca_cert_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000007",
        "run_spec": {
            "env": {},
            "workdir": "/workspace",
            "user": "root",
            "entrypoint": ["/bin/bash"],
            "resources": {
                "vcpus": 1,
                "memory_mib": 1024,
                "disk_mib": 1024,
                "wall_time_s": 60
            }
        },
        "sealcheck_report_digest": "blake3:0000000000000000000000000000000000000000000000000000000000000008"
    }"#;

    let res: Result<WorldManifest, _> = serde_json::from_str(json_with_unknown);
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("unknown field `unknown_extra_field`"));
}

#[test]
fn test_digest_tree_comprehensive() {
    let dir1 = tempdir().expect("tempdir 1");
    let dir2 = tempdir().expect("tempdir 2");

    // Populate dir1
    let file_a1 = dir1.path().join("a.txt");
    fs::write(&file_a1, b"hello tree").expect("write a1");
    let mut perms1 = fs::metadata(&file_a1).expect("meta").permissions();
    perms1.set_mode(0o644);
    fs::set_permissions(&file_a1, perms1).expect("set perms 1");

    let sub1 = dir1.path().join("subdir");
    fs::create_dir(&sub1).expect("create subdir 1");
    let file_b1 = sub1.join("b.txt");
    fs::write(&file_b1, b"second file").expect("write b1");

    let link1 = sub1.join("link_to_a");
    symlink("../a.txt", &link1).expect("symlink 1");

    // Populate dir2 in different order with different mtimes
    let sub2 = dir2.path().join("subdir");
    fs::create_dir(&sub2).expect("create subdir 2");
    let file_b2 = sub2.join("b.txt");
    fs::write(&file_b2, b"second file").expect("write b2");

    let link2 = sub2.join("link_to_a");
    symlink("../a.txt", &link2).expect("symlink 2");

    let file_a2 = dir2.path().join("a.txt");
    fs::write(&file_a2, b"hello tree").expect("write a2");
    let mut perms2 = fs::metadata(&file_a2).expect("meta").permissions();
    perms2.set_mode(0o644);
    fs::set_permissions(&file_a2, perms2).expect("set perms 2");

    // Identical trees in different dirs digest equal
    let d1 = digest_tree(dir1.path()).expect("digest 1");
    let d2 = digest_tree(dir2.path()).expect("digest 2");
    assert_eq!(d1, d2);

    // Changing a byte in a file changes digest
    fs::write(&file_a2, b"hello tree changed").expect("modify byte");
    let d2_changed = digest_tree(dir2.path()).expect("digest 2 changed");
    assert_ne!(d1, d2_changed);
    fs::write(&file_a2, b"hello tree").expect("restore");

    // Changing file name changes digest
    let file_a2_renamed = dir2.path().join("a_renamed.txt");
    fs::rename(&file_a2, &file_a2_renamed).expect("rename");
    let d2_renamed = digest_tree(dir2.path()).expect("digest 2 renamed");
    assert_ne!(d1, d2_renamed);
    fs::rename(&file_a2_renamed, &file_a2).expect("restore rename");

    // Changing executable bit changes digest
    let mut perms_exec = fs::metadata(&file_a2).expect("meta").permissions();
    perms_exec.set_mode(0o755);
    fs::set_permissions(&file_a2, perms_exec).expect("set exec perms");
    let d2_exec = digest_tree(dir2.path()).expect("digest 2 exec");
    assert_ne!(d1, d2_exec);
    let mut perms_orig = fs::metadata(&file_a2).expect("meta").permissions();
    perms_orig.set_mode(0o644);
    fs::set_permissions(&file_a2, perms_orig).expect("restore perms");

    // Changing symlink target changes digest
    fs::remove_file(&link2).expect("remove link");
    symlink("b.txt", &link2).expect("new link target");
    let d2_link_changed = digest_tree(dir2.path()).expect("digest link changed");
    assert_ne!(d1, d2_link_changed);
    fs::remove_file(&link2).expect("remove link");
    symlink("../a.txt", &link2).expect("restore link");

    // Symlink is not followed: point to outside file, changing outside file does not change digest
    let outside_dir = tempdir().expect("outside tempdir");
    let outside_file = outside_dir.path().join("target.txt");
    fs::write(&outside_file, b"outside content 1").expect("outside write");
    let outside_symlink = dir1.path().join("outside_link");
    symlink(&outside_file, &outside_symlink).expect("create outside symlink");

    let d_outside1 = digest_tree(dir1.path()).expect("digest outside 1");
    // Modify outside file contents
    fs::write(&outside_file, b"outside content 2 (modified!)").expect("modify outside");
    let d_outside2 = digest_tree(dir1.path()).expect("digest outside 2");
    assert_eq!(
        d_outside1, d_outside2,
        "Symlink should not be followed; modifying target file must not change tree digest"
    );

    // FIFO is an error naming the path
    let fifo_dir = tempdir().expect("fifo tempdir");
    let fifo_path = fifo_dir.path().join("test_fifo");
    let status = Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("mkfifo command");
    if status.success() {
        let err = digest_tree(fifo_dir.path()).expect_err("FIFO should cause error");
        match err {
            WorldManifestError::SpecialFile(path_name) => {
                assert!(path_name.contains("test_fifo"));
            }
            other => panic!("Expected SpecialFile error, got {:?}", other),
        }
    }
}

#[test]
fn test_cli_execution_and_exit_codes() {
    let bin_path = env!("CARGO_BIN_EXE_hermetic-manifest");
    let temp_dir = tempdir().expect("tempdir");
    let manifest_path = temp_dir.path().join("manifest.json");

    let manifest = sample_manifest();
    let expected_root = manifest.world_root().expect("root");
    let manifest_json = serde_json::to_string_pretty(&manifest).expect("json");
    fs::write(&manifest_path, &manifest_json).expect("write manifest");

    // 1. root command
    let output = Command::new(bin_path)
        .args(["root", "--manifest", manifest_path.to_str().expect("str")])
        .output()
        .expect("run root");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), expected_root);

    // 2. verify command matching -> exit 0
    let output = Command::new(bin_path)
        .args([
            "verify",
            "--manifest",
            manifest_path.to_str().expect("str"),
            "--expect",
            &expected_root,
        ])
        .output()
        .expect("run verify matching");
    assert_eq!(output.status.code(), Some(0));

    // 3. verify command mismatch -> exit 1 with computed root
    let wrong_root = "blake3:0000000000000000000000000000000000000000000000000000000000000000";
    let output = Command::new(bin_path)
        .args([
            "verify",
            "--manifest",
            manifest_path.to_str().expect("str"),
            "--expect",
            wrong_root,
        ])
        .output()
        .expect("run verify mismatch");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), expected_root);

    // 4. prove command
    let output = Command::new(bin_path)
        .args([
            "prove",
            "--manifest",
            manifest_path.to_str().expect("str"),
            "--path",
            "/cutoffs/t_clock",
        ])
        .output()
        .expect("run prove");
    assert_eq!(output.status.code(), Some(0));
    let prove_stdout = String::from_utf8_lossy(&output.stdout);
    assert!(prove_stdout.contains("/cutoffs/t_clock"));

    let proof_file = temp_dir.path().join("proof.json");
    fs::write(&proof_file, prove_stdout.into_owned()).expect("write proof file");

    // 5. check-proof command
    let output = Command::new(bin_path)
        .args([
            "check-proof",
            "--root",
            &expected_root,
            "--path",
            "/cutoffs/t_clock",
            "--value",
            "\"2026-01-15T12:00:00Z\"",
            "--proof",
            proof_file.to_str().expect("str"),
        ])
        .output()
        .expect("run check-proof");
    assert_eq!(output.status.code(), Some(0));

    // check-proof failure on wrong root
    let output = Command::new(bin_path)
        .args([
            "check-proof",
            "--root",
            wrong_root,
            "--path",
            "/cutoffs/t_clock",
            "--value",
            "\"2026-01-15T12:00:00Z\"",
            "--proof",
            proof_file.to_str().expect("str"),
        ])
        .output()
        .expect("run check-proof wrong root");
    assert_eq!(output.status.code(), Some(1));

    // 6. digest-file
    let test_file = temp_dir.path().join("test_file.txt");
    fs::write(&test_file, b"sample file for digest").expect("write test file");
    let output = Command::new(bin_path)
        .args(["digest-file", "--file", test_file.to_str().expect("str")])
        .output()
        .expect("run digest-file");
    assert_eq!(output.status.code(), Some(0));
    let file_digest = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(
        file_digest,
        digest_file(&test_file).expect("digest_file direct")
    );

    // 7. digest-tree
    let output = Command::new(bin_path)
        .args([
            "digest-tree",
            "--dir",
            temp_dir.path().to_str().expect("str"),
        ])
        .output()
        .expect("run digest-tree");
    assert_eq!(output.status.code(), Some(0));
    let tree_digest = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(
        tree_digest,
        digest_tree(temp_dir.path()).expect("digest_tree direct")
    );
}

#[test]
#[cfg(unix)]
fn test_regression_fix1_invalid_utf8_file_names_and_symlink_targets() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    // Two trees whose only difference is a file named b"\xff" versus b"\xfe" digest differently
    let dir_a = tempdir().expect("tempdir a");
    let dir_b = tempdir().expect("tempdir b");

    let file_a = dir_a.path().join(OsStr::from_bytes(b"\xff"));
    fs::write(&file_a, b"identical content").expect("write file a");

    let file_b = dir_b.path().join(OsStr::from_bytes(b"\xfe"));
    fs::write(&file_b, b"identical content").expect("write file b");

    let digest_a = digest_tree(dir_a.path()).expect("digest tree a");
    let digest_b = digest_tree(dir_b.path()).expect("digest tree b");
    assert_ne!(
        digest_a, digest_b,
        "Distinct invalid-UTF-8 file names b'\\xff' vs b'\\xfe' must not collide"
    );

    // A symlink target differing only in an invalid byte changes the digest
    let link_dir_a = tempdir().expect("link tempdir a");
    let link_dir_b = tempdir().expect("link tempdir b");

    let link_a = link_dir_a.path().join("symlink_entry");
    symlink(OsStr::from_bytes(b"target_\xff"), &link_a).expect("symlink a");

    let link_b = link_dir_b.path().join("symlink_entry");
    symlink(OsStr::from_bytes(b"target_\xfe"), &link_b).expect("symlink b");

    let link_digest_a = digest_tree(link_dir_a.path()).expect("digest link tree a");
    let link_digest_b = digest_tree(link_dir_b.path()).expect("digest link tree b");
    assert_ne!(
        link_digest_a, link_digest_b,
        "Symlink targets differing only in an invalid byte must change the digest"
    );
}

#[test]
#[cfg(unix)]
fn test_regression_fix2_directory_mode_owner_exec() {
    let dir1 = tempdir().expect("tempdir 1");
    let dir2 = tempdir().expect("tempdir 2");

    let sub1 = dir1.path().join("empty_subdir");
    fs::create_dir(&sub1).expect("create sub1");
    let mut perms1 = fs::metadata(&sub1).expect("metadata sub1").permissions();
    perms1.set_mode(0o755);
    fs::set_permissions(&sub1, perms1).expect("set perms 0755");

    let sub2 = dir2.path().join("empty_subdir");
    fs::create_dir(&sub2).expect("create sub2");
    let mut perms2 = fs::metadata(&sub2).expect("metadata sub2").permissions();
    perms2.set_mode(0o644);
    fs::set_permissions(&sub2, perms2).expect("set perms 0644");

    let d1 = digest_tree(dir1.path()).expect("digest tree 1 (0755)");
    let d2 = digest_tree(dir2.path()).expect("digest tree 2 (0644)");
    assert_ne!(
        d1, d2,
        "Two otherwise identical trees with an empty subdirectory at 0755 vs 0644 must digest differently"
    );

    // Restore permissions so tempdir cleanup is uninhibited
    let mut restore_perms = fs::metadata(&sub2).expect("metadata sub2").permissions();
    restore_perms.set_mode(0o755);
    let _ = fs::set_permissions(&sub2, restore_perms);
}

#[test]
fn test_regression_fix3_calendar_date_validation() {
    let mut manifest = sample_manifest();

    // 2024-02-29 is accepted (leap year)
    manifest.substrate[0].date = "2024-02-29".to_string();
    assert!(
        manifest.validate().is_ok(),
        "2024-02-29 must be accepted as a valid leap year date"
    );

    // 2026-02-29 is rejected (2026 is not a leap year)
    manifest.substrate[0].date = "2026-02-29".to_string();
    let err1 = manifest
        .validate()
        .expect_err("2026-02-29 must be rejected");
    assert!(
        err1.errors
            .iter()
            .any(|e| e.contains("substrate[0].date") && e.contains("2026-02-29")),
        "Expected validation error naming substrate[0].date for 2026-02-29, got: {:?}",
        err1.errors
    );

    // 2026-13-01 is rejected (month 13 does not exist)
    manifest.substrate[0].date = "2026-13-01".to_string();
    let err2 = manifest
        .validate()
        .expect_err("2026-13-01 must be rejected");
    assert!(
        err2.errors
            .iter()
            .any(|e| e.contains("substrate[0].date") && e.contains("2026-13-01")),
        "Expected validation error naming substrate[0].date for 2026-13-01, got: {:?}",
        err2.errors
    );

    // 2026-04-31 is rejected (April only has 30 days)
    manifest.substrate[0].date = "2026-04-31".to_string();
    let err3 = manifest
        .validate()
        .expect_err("2026-04-31 must be rejected");
    assert!(
        err3.errors
            .iter()
            .any(|e| e.contains("substrate[0].date") && e.contains("2026-04-31")),
        "Expected validation error naming substrate[0].date for 2026-04-31, got: {:?}",
        err3.errors
    );
}
