#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use hermetic_attest::dsse::Statement;
use hermetic_attest::{
    compute_run_digest, ed25519_key_id, verify_run_attestation, AgentMode, ClockLevel, Digest,
    DsseEnvelope, Ed25519Signer, Ed25519Verifier, HostBootRecord, ProbeResult, ReplayGuard,
    RunBinding, RunStatus, RunValidationError,
};
use hermetic_run::orchestrator::{
    assemble_and_sign_run_record, assemble_run_record, compute_clock_level,
    derive_escape_probe_result, derive_host_facts, host_facts, sign_run_record,
    sign_run_record_with_key_path, write_signed_run_record, HostFactsArtifact, OrchestratorError,
    ProbeLineWire, BUILD_SCHEMA, MAX_BOOT_RECORD_BYTES, MAX_GATEWAY_HEAD_BYTES,
    MAX_GATEWAY_HISTORY_BYTES, MAX_HARNESS_SUMMARY_BYTES, MAX_MANIFEST_BYTES, MAX_PROBE_BYTES,
    MAX_SENTINEL_BYTES, MAX_SUBMITTED_WORK_BYTES, MAX_VERDICT_BYTES, PROBE_RESULTS,
    REQUIRED_PROBES, RUN_SPEC_VERSION,
};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use serde::Deserialize;
use serde_json::json;

fn generate_test_key() -> (Vec<u8>, Ed25519Signer, Ed25519Verifier) {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .unwrap()
        .as_ref()
        .to_vec();
    let signer = Ed25519Signer::from_pkcs8(&pkcs8).unwrap();
    let pk = signer.public_key();
    let verifier = Ed25519Verifier::new(&[&pk]).unwrap();
    (pkcs8, signer, verifier)
}

struct FixturePaths {
    dir: tempfile::TempDir,
}

impl FixturePaths {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("hermetic-run-fixture-")
            .tempdir()
            .unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let s = Self { dir };
        s.write_default_artifacts();
        s
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn write_default_artifacts(&self) {
        // 1. Gateway date sentinel (no leak)
        let gateway = json!({
            "date_leak_observed": false,
            "scan_incomplete": false,
            "hits": {},
            "incomplete": {},
            "bytes_scanned": 12345
        });
        fs::write(self.path().join("date_sentinel.json"), gateway.to_string()).unwrap();

        // 2. Harness summary (no leak, full SentinelSummary schema)
        let harness = json!({
            "date_leak_observed": false,
            "scan_incomplete": false,
            "hits": {},
            "incomplete": {},
            "bytes_scanned": 54321
        });
        fs::write(
            self.path().join("harness_summary.json"),
            harness.to_string(),
        )
        .unwrap();

        // 3. Escape/clock probe output (clean microvm: clock_pairing_hc unavailable with kernel_canary blocked, 13 blocked)
        let probe_lines = [
            r#"{"probe":"clock_pairing_hc","result":"unavailable","detail":"hypercall blocked"}"#,
            r#"{"probe":"clocksource_sysfs","result":"blocked","detail":"masked"}"#,
            r#"{"probe":"cpuid","result":"blocked","detail":"masked"}"#,
            r#"{"probe":"cpuinfo","result":"blocked","detail":"filtered"}"#,
            r#"{"probe":"dmesg_dates","result":"blocked","detail":"clear"}"#,
            r#"{"probe":"hpet","result":"blocked","detail":"disabled"}"#,
            r#"{"probe":"kernel_canary","result":"blocked","detail":"canary blocked"}"#,
            r#"{"probe":"kvmclock_msr","result":"blocked","detail":"disabled"}"#,
            r#"{"probe":"module_load","result":"blocked","detail":"disabled"}"#,
            r#"{"probe":"posix_clocks","result":"blocked","detail":"locked"}"#,
            r#"{"probe":"proc_driver_rtc","result":"blocked","detail":"masked"}"#,
            r#"{"probe":"rdtsc","result":"blocked","detail":"trapped"}"#,
            r#"{"probe":"ring0_paths","result":"blocked","detail":"inaccessible"}"#,
            r#"{"probe":"rtc_sysfs_dev","result":"blocked","detail":"masked"}"#,
            r#"{"probe":"vmclock","result":"blocked","detail":"disabled"}"#,
        ]
        .join("\n");
        fs::write(self.path().join("probe_output.jsonl"), probe_lines).unwrap();

        // 4. Host boot record (trusted initramfs)
        let boot = json!({
            "vm_id": "agent-vm-0",
            "boot_path": "trusted_initramfs",
            "initrd_sha256": "f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        });
        fs::write(self.path().join("boot_record.json"), boot.to_string()).unwrap();

        // 5. Verdict
        let verdict = json!({
            "run_status": "resolved",
            "r0_result": "passed",
            "r1_result": "passed",
            "r2_result": "passed",
            "r3_result": "passed",
            "r1_coverage": 850,
            "unclean_shutdown": false,
            "submitted_work_digest": "sha256:e123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        });
        fs::write(self.path().join("verdict.json"), verdict.to_string()).unwrap();

        // 6. World manifest and digests
        // Note: No 'clock' field (clock is computed, not asserted).
        // 'world_version' is required.
        let manifest = json!({
            "task_id": "pytest-dev__pytest-6202",
            "task_class": "patch",
            "seal_level": "strict",
            "agent_mode": "H",
            "substrate": "microvm",
            "grader_isolation": "clean",
            "deployment": "single_host",
            "t_world": "2020-01-01T00:00:00Z",
            "t_clock": "2020-01-01T00:00:00Z",
            "base_commit": "abcdef0123456789abcdef0123456789abcdef01",
            "spec_version": "v1.1",
            "world_version": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "sealcheck_version": "v1.0",
            "grader_image_digest": "sha256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "world_root": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "task_rootfs_digest": "sha256:2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "netvm_image_digest": "sha256:3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "guest_kernel_digest": "sha256:4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "vm_config_digest": "sha256:5123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "cpu_template_digest": "sha256:6123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "firecracker_build_digest": "sha256:7123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "agent_volume_digest": "sha256:8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "sealcheck_report_digest": "sha256:9123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "substrate_at_t": "full",
            "exemption_list": ["pkg-a", "pkg-b"],
            "world_server_log_head": "sha256:b123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "dedupe_index_digest": "sha256:c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "request_count": 42,
            "harness_command_log_head": "sha256:d123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        });
        fs::write(
            self.path().join("world_manifest.json"),
            manifest.to_string(),
        )
        .unwrap();

        // 7. Host facts artifacts: Firecracker binary, build record, and pinned lock
        let fc_bytes = b"patched firecracker binary for orchestrator tests";
        fs::write(self.path().join("firecracker"), fc_bytes).unwrap();
        use sha2::{Digest as ShaDigest, Sha256};
        let fc_sha = format!("{:x}", Sha256::digest(fc_bytes));
        let patch_sha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let source_sha = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let release_sha = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

        let build_record = json!({
            "schema": "hermetic-firecracker-build/v1",
            "version": "1.18.0",
            "firecracker_sha256": fc_sha,
            "patch_sha256": patch_sha,
            "source_sha256": source_sha,
        });
        fs::write(
            self.path().join("firecracker_build.json"),
            build_record.to_string(),
        )
        .unwrap();

        let pinned_lock = json!({
            "version": "1.18.0",
            "firecracker_sha256": release_sha,
            "patch_sha256": patch_sha,
            "source_sha256": source_sha,
        });
        fs::write(
            self.path().join("pinned_lock.json"),
            pinned_lock.to_string(),
        )
        .unwrap();
    }
}

#[test]
fn test_known_answer_record_from_fixture_directory() {
    let f = FixturePaths::new();
    let record = assemble_run_record(f.path()).expect("assemble record");

    // Check assembled fields
    assert_eq!(record.task_id, "pytest-dev__pytest-6202");
    assert_eq!(record.clock, ClockLevel::Hidden);
    assert!(!record.date_leak_observed);
    assert_eq!(record.run_status, RunStatus::Resolved);
    assert_eq!(record.escape_probe_result, ProbeResult::Passed);
    assert_eq!(
        record.boot_record,
        Some(HostBootRecord {
            boot_path: "trusted_initramfs".to_string(),
            initrd_digest: Some(
                Digest::parse(
                    "sha256:f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
            ),
        })
    );

    // Compute canonical digest
    let digest = compute_run_digest(&record).expect("compute digest");

    // The probe output digest is deterministic based on the 15 probe lines above
    let probe_bytes = fs::read(f.path().join("probe_output.jsonl")).unwrap();
    let expected_probe_digest = Digest::from_sha256(&probe_bytes);
    assert_eq!(record.escape_probe_digest, expected_probe_digest);

    // Signing and verification check
    let (key_bytes, signer, verifier) = generate_test_key();
    let key_path = f.path().join("offline_key.p8");
    fs::write(&key_path, key_bytes).unwrap();

    let envelope = sign_run_record_with_key_path(&record, &key_path).expect("sign record");
    assert_eq!(envelope.signatures.len(), 1);
    assert_eq!(
        envelope.signatures[0].keyid.as_deref(),
        Some(ed25519_key_id(&signer.public_key()).as_str())
    );

    let mut guard = ReplayGuard::new();
    let binding = RunBinding {
        task_id: Some("pytest-dev__pytest-6202".to_string()),
        world_root: Some(record.world_root.clone()),
        world_bundle: Some(record.world_root.clone()),
        sealcheck_report_digest: Some(record.sealcheck_report_digest.clone()),
        grader_image_digest: Some(record.version_tuple.grader_image_digest.clone()),
        boot_record: record.boot_record.clone(),
    };
    let envelope_json = serde_json::to_string(&envelope).unwrap();
    let (statement, verified_digest) =
        verify_run_attestation(&envelope_json, &verifier, &binding, &mut guard).expect("verify");
    assert_eq!(statement.predicate, record);
    assert_eq!(verified_digest, digest);

    // Test entry point assemble_and_sign_run_record
    let (assembled, opt_env) =
        assemble_and_sign_run_record(f.path(), Some(&key_path)).expect("assemble and sign");
    assert_eq!(assembled, record);
    assert!(opt_env.is_some());

    // Test atomic publication
    let out_file = f.path().join("published_run_record.dsse.json");
    write_signed_run_record(&out_file, &opt_env.unwrap()).expect("write published record");
    assert!(out_file.exists());
}

#[test]
fn test_missing_artifacts_fail_closed() {
    let artifacts = [
        "date_sentinel.json",
        "harness_summary.json",
        "probe_output.jsonl",
        "boot_record.json",
        "verdict.json",
        "world_manifest.json",
    ];

    for missing in &artifacts {
        let f = FixturePaths::new();
        fs::remove_file(f.path().join(missing)).unwrap();
        let err = assemble_run_record(f.path());
        assert!(
            matches!(err, Err(OrchestratorError::MissingArtifact(name)) if name == *missing),
            "Expected MissingArtifact({missing}), got {err:?}"
        );
    }
}

#[test]
fn test_malformed_artifacts_fail_closed() {
    // 1. Malformed JSON in date_sentinel.json
    let f = FixturePaths::new();
    fs::write(f.path().join("date_sentinel.json"), b"not-valid-json").unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::Json {
            artifact: "date_sentinel.json",
            ..
        })
    ));

    // 2. Malformed JSON in harness_summary.json
    let f = FixturePaths::new();
    fs::write(f.path().join("harness_summary.json"), b"not-valid-json").unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::Json {
            artifact: "harness_summary.json",
            ..
        })
    ));

    // 3. Malformed probe output line
    let f = FixturePaths::new();
    fs::write(
        f.path().join("probe_output.jsonl"),
        b"{\"bad_probe_line\": true}\n",
    )
    .unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::Json {
            artifact: "probe_output.jsonl",
            ..
        })
    ));

    // 4. Empty probe output
    let f = FixturePaths::new();
    fs::write(f.path().join("probe_output.jsonl"), b"\n   \n").unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::MalformedArtifact {
            artifact: "probe_output.jsonl",
            ..
        })
    ));

    // 5. Unknown boot_path in boot_record.json
    let f = FixturePaths::new();
    let bad_boot = json!({
        "boot_path": "unauthorized_pxe",
        "initrd_sha256": null
    });
    fs::write(f.path().join("boot_record.json"), bad_boot.to_string()).unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::MalformedArtifact {
            artifact: "boot_record.json",
            ..
        })
    ));

    // 6. sealed_disk carrying initrd
    let f = FixturePaths::new();
    let bad_boot = json!({
        "boot_path": "sealed_disk",
        "initrd_sha256": "f123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    });
    fs::write(f.path().join("boot_record.json"), bad_boot.to_string()).unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::MalformedArtifact {
            artifact: "boot_record.json",
            ..
        })
    ));

    // 7. trusted_initramfs missing initrd
    let f = FixturePaths::new();
    let bad_boot = json!({
        "boot_path": "trusted_initramfs",
        "initrd_sha256": null
    });
    fs::write(f.path().join("boot_record.json"), bad_boot.to_string()).unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::MalformedArtifact {
            artifact: "boot_record.json",
            ..
        })
    ));

    // 8. Missing status in verdict.json
    let f = FixturePaths::new();
    let bad_verdict = json!({
        "r0_result": "passed",
        "submitted_work_digest": "sha256:e123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    });
    fs::write(f.path().join("verdict.json"), bad_verdict.to_string()).unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::MalformedArtifact {
            artifact: "verdict.json",
            ..
        })
    ));

    // 9. World manifest with world_version != world_root
    let f = FixturePaths::new();
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("world_manifest.json")).unwrap())
            .unwrap();
    manifest["world_version"] =
        json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    fs::write(f.path().join("world_manifest.json"), manifest.to_string()).unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::Validation(
            RunValidationError::WorldVersionMismatch
        ))
    ));
}

#[test]
fn test_oversized_artifacts_fail_closed() {
    let limits = [
        ("date_sentinel.json", MAX_SENTINEL_BYTES),
        ("harness_summary.json", MAX_HARNESS_SUMMARY_BYTES),
        ("probe_output.jsonl", MAX_PROBE_BYTES),
        ("boot_record.json", MAX_BOOT_RECORD_BYTES),
        ("verdict.json", MAX_VERDICT_BYTES),
        ("world_manifest.json", MAX_MANIFEST_BYTES),
    ];

    for (name, limit) in &limits {
        let f = FixturePaths::new();
        let huge = vec![b' '; limit + 1];
        fs::write(f.path().join(name), huge).unwrap();
        let err = assemble_run_record(f.path());
        assert!(
            matches!(err, Err(OrchestratorError::Fs { artifact, .. }) if artifact == *name),
            "Expected Fs error for oversized {name}, got {err:?}"
        );
    }
}

#[test]
fn test_symlinked_artifacts_fail_closed() {
    let artifacts = [
        "date_sentinel.json",
        "harness_summary.json",
        "probe_output.jsonl",
        "boot_record.json",
        "verdict.json",
        "world_manifest.json",
    ];

    for name in &artifacts {
        let f = FixturePaths::new();
        let target = f.path().join(format!("{name}.real"));
        fs::rename(f.path().join(name), &target).unwrap();
        symlink(&target, f.path().join(name)).unwrap();

        let err = assemble_run_record(f.path());
        assert!(
            matches!(err, Err(OrchestratorError::Fs { artifact, .. }) if artifact == *name),
            "Expected symlink refusal for {name}, got {err:?}"
        );
    }
}

#[test]
fn test_leak_in_any_one_part_sets_date_leak_observed() {
    // Baseline: no leak
    let f = FixturePaths::new();
    let record = assemble_run_record(f.path()).unwrap();
    assert!(!record.date_leak_observed);
    assert_eq!(record.clock, ClockLevel::Hidden);
    assert_eq!(record.run_status, RunStatus::Resolved);

    // 1. Gateway date sentinel has a leak hit
    let f = FixturePaths::new();
    let gateway = json!({
        "date_leak_observed": true,
        "scan_incomplete": false,
        "hits": {"gateway:real_date": 1},
        "incomplete": {},
        "bytes_scanned": 1000
    });
    fs::write(f.path().join("date_sentinel.json"), gateway.to_string()).unwrap();
    let record = assemble_run_record(f.path()).unwrap();
    assert!(record.date_leak_observed);
    assert_eq!(record.clock, ClockLevel::Faked);
    assert_eq!(record.run_status, RunStatus::Review);

    // 2. Gateway has incomplete scan (fails closed into leak)
    let f = FixturePaths::new();
    let gateway = json!({
        "date_leak_observed": false,
        "scan_incomplete": true,
        "hits": {},
        "incomplete": {"gateway:cap": 1},
        "bytes_scanned": 1000
    });
    fs::write(f.path().join("date_sentinel.json"), gateway.to_string()).unwrap();
    let record = assemble_run_record(f.path()).unwrap();
    assert!(record.date_leak_observed);
    assert_eq!(record.clock, ClockLevel::Faked);

    // 3. Harness summary has date_leak_observed: true
    let f = FixturePaths::new();
    let harness = json!({
        "date_leak_observed": true,
        "scan_incomplete": false,
        "hits": {},
        "incomplete": {},
        "bytes_scanned": 1000
    });
    fs::write(f.path().join("harness_summary.json"), harness.to_string()).unwrap();
    let record = assemble_run_record(f.path()).unwrap();
    assert!(record.date_leak_observed);
    assert_eq!(record.clock, ClockLevel::Faked);

    // 4. Harness summary has scan_incomplete: true (fails closed into leak)
    let f = FixturePaths::new();
    let harness = json!({
        "date_leak_observed": false,
        "scan_incomplete": true,
        "hits": {},
        "incomplete": {"harness:cap": 1},
        "bytes_scanned": 1000
    });
    fs::write(f.path().join("harness_summary.json"), harness.to_string()).unwrap();
    let record = assemble_run_record(f.path()).unwrap();
    assert!(record.date_leak_observed);
    assert_eq!(record.clock, ClockLevel::Faked);
}

// =========================================================================
// Defect 1: Semantics agreement with Python classifier & regression tests
// =========================================================================

#[test]
fn test_probe_unavailable_does_not_set_date_leak_observed() {
    // In Defect 1, unavailable escape probe lines were folded into SentinelSummary
    // scan_incomplete, falsely recording every run with an unavailable probe as a date leak.
    let f = FixturePaths::new();

    // Probe output has unavailable probe check
    let probe_lines = [
        r#"{"probe":"clock_pairing_hc","result":"unavailable","detail":"hypercall blocked"}"#,
        r#"{"probe":"clocksource_sysfs","result":"blocked","detail":"masked"}"#,
        r#"{"probe":"cpuid","result":"unavailable","detail":"cpuid unavailable"}"#,
        r#"{"probe":"cpuinfo","result":"blocked","detail":"filtered"}"#,
        r#"{"probe":"dmesg_dates","result":"blocked","detail":"clear"}"#,
        r#"{"probe":"hpet","result":"blocked","detail":"disabled"}"#,
        r#"{"probe":"kernel_canary","result":"blocked","detail":"canary blocked"}"#,
        r#"{"probe":"kvmclock_msr","result":"blocked","detail":"disabled"}"#,
        r#"{"probe":"module_load","result":"blocked","detail":"disabled"}"#,
        r#"{"probe":"posix_clocks","result":"blocked","detail":"locked"}"#,
        r#"{"probe":"proc_driver_rtc","result":"blocked","detail":"masked"}"#,
        r#"{"probe":"rdtsc","result":"blocked","detail":"trapped"}"#,
        r#"{"probe":"ring0_paths","result":"blocked","detail":"inaccessible"}"#,
        r#"{"probe":"rtc_sysfs_dev","result":"blocked","detail":"masked"}"#,
        r#"{"probe":"vmclock","result":"blocked","detail":"disabled"}"#,
    ]
    .join("\n");
    fs::write(f.path().join("probe_output.jsonl"), probe_lines).unwrap();

    let record = assemble_run_record(f.path()).expect("assemble record");

    // D12 date leak must be false! (Not folded into date_leak_observed)
    assert!(
        !record.date_leak_observed,
        "Probe unavailability must never trigger date_leak_observed"
    );
    // Escape probe result is failed because cpuid is unavailable
    assert_eq!(record.escape_probe_result, ProbeResult::Failed);
    // Clock is faked because cpuid probe is not blocked
    assert_eq!(record.clock, ClockLevel::Faked);
    // Run status remains Resolved (not demoted to Review because date_leak_observed is false)
    assert_eq!(record.run_status, RunStatus::Resolved);
}

#[test]
fn test_probe_result_outside_vocabulary_is_refused() {
    // Only PROBE_RESULTS = ["blocked", "leak", "unavailable", "error"] are accepted
    let f = FixturePaths::new();

    let bad_lines = [
        r#"{"probe":"clock_pairing_hc","result":"ok","detail":"not in vocabulary"}"#,
        r#"{"probe":"cpuid","result":"blocked","detail":"masked"}"#,
    ]
    .join("\n");
    fs::write(f.path().join("probe_output.jsonl"), bad_lines).unwrap();

    let err = assemble_run_record(f.path());
    assert!(matches!(
        err,
        Err(OrchestratorError::MalformedArtifact {
            artifact: "probe_output.jsonl",
            detail: "probe record has an unknown result"
        })
    ));
}

#[derive(Debug, Deserialize)]
struct DriftFixture {
    required_probes: Vec<String>,
    probe_results: Vec<String>,
    test_cases: Vec<DriftTestCase>,
}

#[derive(Debug, Deserialize)]
struct DriftTestCase {
    name: String,
    substrate: Option<String>,
    host: Option<HostFactsArtifact>,
    date_leak_observed: bool,
    records: Vec<ProbeLineWire>,
    expected_escape_probe_result: String,
    expected_clock_level: String,
    expected_clock_reasons: Vec<String>,
}

#[test]
fn test_probe_drift_fixture_matches_rust() {
    // Cross-language test: feeds python/tests/fixtures/probe_drift_fixture.json to Rust
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture_path = manifest_dir.join("../../python/tests/fixtures/probe_drift_fixture.json");
    let content = fs::read_to_string(&fixture_path).expect("read probe_drift_fixture.json");
    let fixture: DriftFixture = serde_json::from_str(&content).expect("parse drift fixture");

    // 1. Vocabulary and required probes constant match
    let rust_required: Vec<&str> = REQUIRED_PROBES.to_vec();
    let fixture_required: Vec<&str> = fixture.required_probes.iter().map(|s| s.as_str()).collect();
    assert_eq!(rust_required, fixture_required);

    let rust_results: Vec<&str> = PROBE_RESULTS.to_vec();
    let fixture_results: Vec<&str> = fixture.probe_results.iter().map(|s| s.as_str()).collect();
    assert_eq!(rust_results, fixture_results);

    // 2. All test cases agree exactly with the Python classifier
    for case in &fixture.test_cases {
        let derived_probe = derive_escape_probe_result(&case.records);
        let expected_probe = match case.expected_escape_probe_result.as_str() {
            "passed" => ProbeResult::Passed,
            "failed" => ProbeResult::Failed,
            other => panic!("unknown expected probe result: {other}"),
        };
        assert_eq!(
            derived_probe, expected_probe,
            "Probe result mismatch in test case '{}'",
            case.name
        );

        let (clock_level, mut clock_reasons) = compute_clock_level(
            case.substrate.as_deref(),
            case.host.as_ref(),
            &case.records,
            case.date_leak_observed,
        );
        clock_reasons.sort();
        let mut expected_reasons = case.expected_clock_reasons.clone();
        expected_reasons.sort();

        let expected_clock = match case.expected_clock_level.as_str() {
            "hidden" => ClockLevel::Hidden,
            "faked" => ClockLevel::Faked,
            "real" => ClockLevel::Real,
            other => panic!("unknown expected clock level: {other}"),
        };
        assert_eq!(
            clock_level, expected_clock,
            "Clock level mismatch in test case '{}'",
            case.name
        );
        assert_eq!(
            clock_reasons, expected_reasons,
            "Clock reasons mismatch in test case '{}'",
            case.name
        );
    }
}

// =========================================================================
// Defect 2: Clock level computation vs assertion & regression tests
// =========================================================================

#[test]
fn test_manifest_asserting_clock_level_is_refused() {
    // The clock level must NOT be asserted by an input file.
    // If world_manifest.json includes "clock", serde deny_unknown_fields rejects it.
    let f = FixturePaths::new();
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("world_manifest.json")).unwrap())
            .unwrap();
    manifest["clock"] = json!("hidden");
    fs::write(f.path().join("world_manifest.json"), manifest.to_string()).unwrap();

    let err = assemble_run_record(f.path());
    assert!(
        matches!(
            err,
            Err(OrchestratorError::Json {
                artifact: "world_manifest.json",
                ..
            })
        ),
        "Expected world_manifest with clock field to be rejected by deny_unknown_fields"
    );
}

#[test]
fn test_clock_level_computed_from_probe_and_host_facts() {
    let f = FixturePaths::new();

    // Subcase 1: Unpatched firecracker binary in run_dir -> Faked clock
    fs::write(
        f.path().join("firecracker"),
        b"different unpatched firecracker binary",
    )
    .unwrap();
    let record = assemble_run_record(f.path()).unwrap();
    assert_eq!(record.clock, ClockLevel::Faked);

    // Subcase 2: Container substrate -> Real clock
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("world_manifest.json")).unwrap())
            .unwrap();
    manifest["substrate"] = json!("container");
    fs::write(f.path().join("world_manifest.json"), manifest.to_string()).unwrap();
    let record = assemble_run_record(f.path()).unwrap();
    assert_eq!(record.clock, ClockLevel::Real);
}

#[test]
fn test_manifest_asserting_host_facts_is_refused() {
    let f = FixturePaths::new();
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("world_manifest.json")).unwrap())
            .unwrap();
    manifest["host"] = json!({
        "patched_firecracker": true,
        "hypercall_block": true
    });
    fs::write(f.path().join("world_manifest.json"), manifest.to_string()).unwrap();

    let err = assemble_run_record(f.path());
    assert!(matches!(
        err,
        Err(OrchestratorError::Json {
            artifact: "world_manifest.json",
            ..
        })
    ));
}

#[test]
fn test_host_facts_verified_patched_build() {
    use sha2::{Digest as ShaDigest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let fc = dir.path().join("firecracker");
    let fc_bytes = b"real verified patched firecracker build binary";
    fs::write(&fc, fc_bytes).unwrap();
    let fc_sha = format!("{:x}", Sha256::digest(fc_bytes));
    let patch_sha = "1111111111111111111111111111111111111111111111111111111111111111";
    let source_sha = "2222222222222222222222222222222222222222222222222222222222222222";
    let release_sha = "3333333333333333333333333333333333333333333333333333333333333333";

    let build = dir.path().join("build.json");
    fs::write(
        &build,
        json!({
            "schema": BUILD_SCHEMA,
            "version": "1.18.0",
            "firecracker_sha256": fc_sha,
            "patch_sha256": patch_sha,
            "source_sha256": source_sha,
        })
        .to_string(),
    )
    .unwrap();

    let lock = dir.path().join("lock.json");
    fs::write(
        &lock,
        json!({
            "version": "1.18.0",
            "firecracker_sha256": release_sha,
            "patch_sha256": patch_sha,
            "source_sha256": source_sha,
        })
        .to_string(),
    )
    .unwrap();

    let facts = host_facts(&fc, &build, &lock).expect("host_facts should succeed");
    assert_eq!(
        facts,
        HostFactsArtifact {
            patched_firecracker: true,
            hypercall_block: true,
        }
    );
    assert_eq!(derive_host_facts(&fc, &build, &lock).unwrap(), facts);
}

#[test]
fn test_host_facts_unpatched_or_mismatched_binary_gives_false() {
    let dir = tempfile::tempdir().unwrap();
    let fc = dir.path().join("firecracker");
    fs::write(&fc, b"some other unpatched binary").unwrap();
    let patch_sha = "1111111111111111111111111111111111111111111111111111111111111111";
    let source_sha = "2222222222222222222222222222222222222222222222222222222222222222";
    let release_sha = "3333333333333333333333333333333333333333333333333333333333333333";
    let expected_built = "4444444444444444444444444444444444444444444444444444444444444444";

    let build = dir.path().join("build.json");
    fs::write(
        &build,
        json!({
            "schema": BUILD_SCHEMA,
            "version": "1.18.0",
            "firecracker_sha256": expected_built,
            "patch_sha256": patch_sha,
            "source_sha256": source_sha,
        })
        .to_string(),
    )
    .unwrap();

    let lock = dir.path().join("lock.json");
    fs::write(
        &lock,
        json!({
            "version": "1.18.0",
            "firecracker_sha256": release_sha,
            "patch_sha256": patch_sha,
            "source_sha256": source_sha,
        })
        .to_string(),
    )
    .unwrap();

    // Actual binary sha256 does not match built sha256
    let facts = host_facts(&fc, &build, &lock).expect("valid files");
    assert_eq!(
        facts,
        HostFactsArtifact {
            patched_firecracker: false,
            hypercall_block: false,
        }
    );
}

#[test]
fn test_host_facts_matching_unpatched_release_gives_false() {
    use sha2::{Digest as ShaDigest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let fc = dir.path().join("firecracker");
    let fc_bytes = b"stock release unpatched binary";
    fs::write(&fc, fc_bytes).unwrap();
    let release_sha = format!("{:x}", Sha256::digest(fc_bytes));
    let patch_sha = "1111111111111111111111111111111111111111111111111111111111111111";
    let source_sha = "2222222222222222222222222222222222222222222222222222222222222222";

    // Build record claiming release hash is not a patched build
    let build = dir.path().join("build.json");
    fs::write(
        &build,
        json!({
            "schema": BUILD_SCHEMA,
            "version": "1.18.0",
            "firecracker_sha256": release_sha,
            "patch_sha256": patch_sha,
            "source_sha256": source_sha,
        })
        .to_string(),
    )
    .unwrap();

    let lock = dir.path().join("lock.json");
    fs::write(
        &lock,
        json!({
            "version": "1.18.0",
            "firecracker_sha256": release_sha,
            "patch_sha256": patch_sha,
            "source_sha256": source_sha,
        })
        .to_string(),
    )
    .unwrap();

    let facts = host_facts(&fc, &build, &lock).expect("valid files");
    assert_eq!(
        facts,
        HostFactsArtifact {
            patched_firecracker: false,
            hypercall_block: false,
        }
    );
}

#[test]
fn test_host_facts_mismatched_patch_or_source_gives_false() {
    use sha2::{Digest as ShaDigest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let fc = dir.path().join("firecracker");
    let fc_bytes = b"binary with wrong patch";
    fs::write(&fc, fc_bytes).unwrap();
    let built_sha = format!("{:x}", Sha256::digest(fc_bytes));
    let patch_sha = "1111111111111111111111111111111111111111111111111111111111111111";
    let source_sha = "2222222222222222222222222222222222222222222222222222222222222222";
    let release_sha = "3333333333333333333333333333333333333333333333333333333333333333";

    // 1. Mismatched patch
    let build = dir.path().join("build.json");
    fs::write(
        &build,
        json!({
            "schema": BUILD_SCHEMA,
            "version": "1.18.0",
            "firecracker_sha256": built_sha,
            "patch_sha256": "9999999999999999999999999999999999999999999999999999999999999999",
            "source_sha256": source_sha,
        })
        .to_string(),
    )
    .unwrap();

    let lock = dir.path().join("lock.json");
    fs::write(
        &lock,
        json!({
            "version": "1.18.0",
            "firecracker_sha256": release_sha,
            "patch_sha256": patch_sha,
            "source_sha256": source_sha,
        })
        .to_string(),
    )
    .unwrap();

    let facts = host_facts(&fc, &build, &lock).expect("valid files");
    assert_eq!(
        facts,
        HostFactsArtifact {
            patched_firecracker: false,
            hypercall_block: false,
        }
    );

    // 2. Mismatched source
    fs::write(
        &build,
        json!({
            "schema": BUILD_SCHEMA,
            "version": "1.18.0",
            "firecracker_sha256": built_sha,
            "patch_sha256": patch_sha,
            "source_sha256": "8888888888888888888888888888888888888888888888888888888888888888",
        })
        .to_string(),
    )
    .unwrap();
    let facts = host_facts(&fc, &build, &lock).expect("valid files");
    assert_eq!(
        facts,
        HostFactsArtifact {
            patched_firecracker: false,
            hypercall_block: false,
        }
    );
}

#[test]
fn test_host_facts_hostile_and_malformed_inputs_refused() {
    use sha2::{Digest as ShaDigest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let fc = dir.path().join("firecracker");
    let fc_bytes = b"real binary";
    fs::write(&fc, fc_bytes).unwrap();
    let fc_sha = format!("{:x}", Sha256::digest(fc_bytes));
    let patch_sha = "1111111111111111111111111111111111111111111111111111111111111111";
    let source_sha = "2222222222222222222222222222222222222222222222222222222222222222";
    let release_sha = "3333333333333333333333333333333333333333333333333333333333333333";

    let valid_build = json!({
        "schema": BUILD_SCHEMA,
        "version": "1.18.0",
        "firecracker_sha256": fc_sha,
        "patch_sha256": patch_sha,
        "source_sha256": source_sha,
    });
    let build = dir.path().join("build.json");
    fs::write(&build, valid_build.to_string()).unwrap();

    let valid_lock = json!({
        "version": "1.18.0",
        "firecracker_sha256": release_sha,
        "patch_sha256": patch_sha,
        "source_sha256": source_sha,
    });
    let lock = dir.path().join("lock.json");
    fs::write(&lock, valid_lock.to_string()).unwrap();

    // 1. Symlinked firecracker binary is refused
    let link_fc = dir.path().join("link_fc");
    symlink(&fc, &link_fc).unwrap();
    assert!(matches!(
        host_facts(&link_fc, &build, &lock),
        Err(OrchestratorError::Fs { .. })
    ));

    // 2. Symlinked build record is refused
    let link_build = dir.path().join("link_build");
    symlink(&build, &link_build).unwrap();
    assert!(matches!(
        host_facts(&fc, &link_build, &lock),
        Err(OrchestratorError::Fs { .. })
    ));

    // 3. Symlinked lock is refused
    let link_lock = dir.path().join("link_lock");
    symlink(&lock, &link_lock).unwrap();
    assert!(matches!(
        host_facts(&fc, &build, &link_lock),
        Err(OrchestratorError::Fs { .. })
    ));

    // 4. Directory instead of file is refused
    let sub_dir = dir.path().join("sub_dir");
    fs::create_dir(&sub_dir).unwrap();
    assert!(matches!(
        host_facts(&sub_dir, &build, &lock),
        Err(OrchestratorError::Fs { .. })
    ));

    // 5. Missing file is refused
    let missing = dir.path().join("nonexistent");
    assert!(matches!(
        host_facts(&missing, &build, &lock),
        Err(OrchestratorError::Fs { .. })
    ));

    // 6. Malformed JSON syntax in build
    let bad_build = dir.path().join("bad_build.json");
    fs::write(&bad_build, b"{ invalid json").unwrap();
    assert!(matches!(
        host_facts(&fc, &bad_build, &lock),
        Err(OrchestratorError::Json { .. })
    ));

    // 7. Non-object JSON in build (e.g. array)
    let array_build = dir.path().join("array_build.json");
    fs::write(&array_build, b"[]").unwrap();
    assert!(matches!(
        host_facts(&fc, &array_build, &lock),
        Err(OrchestratorError::Json { .. })
    ));

    // 8. Duplicate key in build JSON
    let dup_build = dir.path().join("dup_build.json");
    fs::write(
        &dup_build,
        format!(
            r#"{{"schema":"{}","schema":"other","firecracker_sha256":"{}","patch_sha256":"{}","source_sha256":"{}"}}"#,
            BUILD_SCHEMA, fc_sha, patch_sha, source_sha
        ),
    )
    .unwrap();
    assert!(matches!(
        host_facts(&fc, &dup_build, &lock),
        Err(OrchestratorError::Json { .. })
    ));

    // 9. Unknown schema in build
    let unknown_schema = dir.path().join("unknown_schema.json");
    fs::write(
        &unknown_schema,
        json!({
            "schema": "hermetic-firecracker-build/v0-unknown",
            "firecracker_sha256": fc_sha,
            "patch_sha256": patch_sha,
            "source_sha256": source_sha,
        })
        .to_string(),
    )
    .unwrap();
    assert!(matches!(
        host_facts(&fc, &unknown_schema, &lock),
        Err(OrchestratorError::MalformedArtifact { .. })
    ));

    // 10. Bad hex digest fields (too short, too long, uppercase)
    for bad_hex in [
        "abc",
        "X".repeat(64).as_str(),
        "0".repeat(63).as_str(),
        "0".repeat(65).as_str(),
    ] {
        let bad_hex_build = dir.path().join(format!("bad_hex_{bad_hex}.json"));
        fs::write(
            &bad_hex_build,
            json!({
                "schema": BUILD_SCHEMA,
                "firecracker_sha256": bad_hex,
                "patch_sha256": patch_sha,
                "source_sha256": source_sha,
            })
            .to_string(),
        )
        .unwrap();
        assert!(matches!(
            host_facts(&fc, &bad_hex_build, &lock),
            Err(OrchestratorError::MalformedArtifact { .. })
        ));
    }
}

#[test]
fn test_assemble_run_record_host_facts_missing_one_fails_closed() {
    let f = FixturePaths::new();
    // Remove pinned_lock.json while firecracker and firecracker_build.json exist
    fs::remove_file(f.path().join("pinned_lock.json")).unwrap();
    let err = assemble_run_record(f.path());
    assert!(matches!(
        err,
        Err(OrchestratorError::MissingArtifact("pinned_lock.json"))
    ));

    // Remove firecracker_build.json while firecracker exists
    fs::remove_file(f.path().join("firecracker_build.json")).unwrap();
    let err = assemble_run_record(f.path());
    assert!(matches!(
        err,
        Err(OrchestratorError::MissingArtifact("firecracker_build.json"))
    ));
}

#[test]
fn test_assemble_run_record_missing_all_host_facts_gives_faked_clock() {
    let f = FixturePaths::new();
    // Remove all 3 host fact artifacts
    fs::remove_file(f.path().join("firecracker")).unwrap();
    fs::remove_file(f.path().join("firecracker_build.json")).unwrap();
    fs::remove_file(f.path().join("pinned_lock.json")).unwrap();

    let record = assemble_run_record(f.path()).unwrap();
    assert_eq!(record.clock, ClockLevel::Faked);
}

// =========================================================================
// Defect 3: Invented values (spec_version and world_version)
// =========================================================================

#[test]
fn test_spec_version_mismatch_refused() {
    // The spec version is the code's own constant; refuse another version stated by manifest
    let f = FixturePaths::new();
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("world_manifest.json")).unwrap())
            .unwrap();
    manifest["spec_version"] = json!("v1.0");
    fs::write(f.path().join("world_manifest.json"), manifest.to_string()).unwrap();

    let err = assemble_run_record(f.path());
    assert!(matches!(
        err,
        Err(OrchestratorError::MalformedArtifact {
            artifact: "world_manifest.json",
            detail: "unsupported spec_version in world manifest"
        })
    ));
}

#[test]
fn test_spec_version_defaults_to_code_constant_when_omitted() {
    let f = FixturePaths::new();
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("world_manifest.json")).unwrap())
            .unwrap();
    manifest.as_object_mut().unwrap().remove("spec_version");
    fs::write(f.path().join("world_manifest.json"), manifest.to_string()).unwrap();

    let record = assemble_run_record(f.path()).expect("assemble record");
    assert_eq!(record.version_tuple.spec_version, RUN_SPEC_VERSION);
}

#[test]
fn test_world_version_required_no_fallback() {
    // world_version is required: missing = malformed artifact, no fallback to world_root
    let f = FixturePaths::new();
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("world_manifest.json")).unwrap())
            .unwrap();
    manifest.as_object_mut().unwrap().remove("world_version");
    fs::write(f.path().join("world_manifest.json"), manifest.to_string()).unwrap();

    let err = assemble_run_record(f.path());
    assert!(matches!(
        err,
        Err(OrchestratorError::Json {
            artifact: "world_manifest.json",
            ..
        })
    ));
}

// =========================================================================
// Defect 4: One canonical file name per artifact (no fallbacks)
// =========================================================================

#[test]
fn test_fallback_file_names_are_not_recognized() {
    // Fallback file names must be refused: if canonical file is missing,
    // presence of legacy/fallback names does not satisfy the requirement.

    // 1. gateway_date_sentinel.json vs date_sentinel.json
    let f = FixturePaths::new();
    fs::rename(
        f.path().join("date_sentinel.json"),
        f.path().join("gateway_date_sentinel.json"),
    )
    .unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::MissingArtifact("date_sentinel.json"))
    ));

    // 2. harness.json vs harness_summary.json
    let f = FixturePaths::new();
    fs::rename(
        f.path().join("harness_summary.json"),
        f.path().join("harness.json"),
    )
    .unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::MissingArtifact("harness_summary.json"))
    ));

    // 3. run.json vs verdict.json
    let f = FixturePaths::new();
    fs::rename(f.path().join("verdict.json"), f.path().join("run.json")).unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::MissingArtifact("verdict.json"))
    ));

    // 4. manifest.json vs world_manifest.json
    let f = FixturePaths::new();
    fs::rename(
        f.path().join("world_manifest.json"),
        f.path().join("manifest.json"),
    )
    .unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::MissingArtifact("world_manifest.json"))
    ));

    // 5. reboot-record.json vs boot_record.json
    let f = FixturePaths::new();
    fs::rename(
        f.path().join("boot_record.json"),
        f.path().join("reboot-record.json"),
    )
    .unwrap();
    assert!(matches!(
        assemble_run_record(f.path()),
        Err(OrchestratorError::MissingArtifact("boot_record.json"))
    ));
}

// =========================================================================
// Defect 5: resolve_submitted_work_digest fails closed (no silent skip)
// =========================================================================

#[test]
fn test_symlinked_patch_fails_closed() {
    let f = FixturePaths::new();
    // Remove submitted_work_digest from verdict.json so orchestrator resolves patch file
    let mut verdict: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("verdict.json")).unwrap()).unwrap();
    verdict
        .as_object_mut()
        .unwrap()
        .remove("submitted_work_digest");
    fs::write(f.path().join("verdict.json"), verdict.to_string()).unwrap();

    // Create a real patch and symlink submitted_work.patch to it
    let real_patch = f.path().join("patch.real");
    fs::write(&real_patch, b"diff --git a/foo b/foo\n").unwrap();
    symlink(&real_patch, f.path().join("submitted_work.patch")).unwrap();

    let err = assemble_run_record(f.path());
    assert!(
        matches!(
            err,
            Err(OrchestratorError::Fs {
                artifact: "submitted_work.patch",
                ..
            })
        ),
        "Symlinked patch must fail closed with Fs error, got {err:?}"
    );
}

#[test]
fn test_oversized_patch_fails_closed() {
    let f = FixturePaths::new();
    let mut verdict: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("verdict.json")).unwrap()).unwrap();
    verdict
        .as_object_mut()
        .unwrap()
        .remove("submitted_work_digest");
    fs::write(f.path().join("verdict.json"), verdict.to_string()).unwrap();

    // Write patch file exceeding MAX_SUBMITTED_WORK_BYTES
    let huge = vec![b'a'; MAX_SUBMITTED_WORK_BYTES + 1];
    fs::write(f.path().join("submitted_work.patch"), huge).unwrap();

    let err = assemble_run_record(f.path());
    assert!(
        matches!(
            err,
            Err(OrchestratorError::Fs {
                artifact: "submitted_work.patch",
                ..
            })
        ),
        "Oversized patch must fail closed with Fs error, got {err:?}"
    );
}

#[test]
fn test_valid_patch_file_resolves_digest() {
    let f = FixturePaths::new();
    let mut verdict: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("verdict.json")).unwrap()).unwrap();
    verdict
        .as_object_mut()
        .unwrap()
        .remove("submitted_work_digest");
    fs::write(f.path().join("verdict.json"), verdict.to_string()).unwrap();

    let patch_bytes = b"diff --git a/foo.rs b/foo.rs\n+fn test() {}\n";
    let expected_digest = Digest::from_sha256(patch_bytes);
    fs::write(f.path().join("submitted_work.patch"), patch_bytes).unwrap();

    let record = assemble_run_record(f.path()).expect("assemble record");
    assert_eq!(record.submitted_work_digest, expected_digest);
}

// =========================================================================
// Defect 6: Bare-boolean harness summary refused (require full SentinelSummary)
// =========================================================================

#[test]
fn test_bare_boolean_harness_summary_is_refused() {
    // The previous implementation had a fallback accepting `{"date_leak_observed": false}`
    // which synthesized scan_incomplete=false and bytes_scanned=0.
    // The fix requires the full SentinelSummary with deny_unknown_fields.
    let f = FixturePaths::new();
    let bare = json!({
        "date_leak_observed": false
    });
    fs::write(f.path().join("harness_summary.json"), bare.to_string()).unwrap();

    let err = assemble_run_record(f.path());
    assert!(
        matches!(
            err,
            Err(OrchestratorError::Json {
                artifact: "harness_summary.json",
                ..
            })
        ),
        "Bare boolean harness summary must be refused as malformed JSON, got {err:?}"
    );
}

// =========================================================================
// v1.0 and verification regression tests
// =========================================================================

#[test]
fn test_old_version_record_still_verifies() {
    let (key_bytes, signer, verifier) = generate_test_key();
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.p8");
    fs::write(&key_path, key_bytes).unwrap();

    // v1.0 record without boot_record
    let f = FixturePaths::new();
    let mut record = assemble_run_record(f.path()).unwrap();
    record.version_tuple.spec_version = "v1.0".to_string();
    record.boot_record = None;
    assert!(record.validate().is_ok());

    let statement = Statement::new_run_statement(record.clone()).unwrap();
    let envelope = DsseEnvelope::sign_statement(&statement, &signer).unwrap();
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    let mut guard = ReplayGuard::new();
    let binding = RunBinding {
        task_id: Some(record.task_id.clone()),
        world_root: Some(record.world_root.clone()),
        world_bundle: Some(record.world_root.clone()),
        sealcheck_report_digest: Some(record.sealcheck_report_digest.clone()),
        grader_image_digest: Some(record.version_tuple.grader_image_digest.clone()),
        boot_record: None,
    };

    let (verified, _digest) =
        verify_run_attestation(&envelope_json, &verifier, &binding, &mut guard).unwrap();
    assert_eq!(verified.predicate, record);
    assert!(verified.predicate.boot_record.is_none());
}

#[test]
fn test_tampered_boot_record_fails_verify() {
    let f = FixturePaths::new();
    let record = assemble_run_record(f.path()).unwrap();
    let (key_bytes, _signer, verifier) = generate_test_key();
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.p8");
    fs::write(&key_path, key_bytes).unwrap();

    let envelope = sign_run_record_with_key_path(&record, &key_path).unwrap();

    // 1. In-place tampering with envelope payload
    let mut payload: serde_json::Value = serde_json::from_slice(
        &hermetic_attest::base64::base64_decode(&envelope.payload, 1024 * 1024).unwrap(),
    )
    .unwrap();
    payload["predicate"]["boot_record"]["boot_path"] = json!("sealed_disk");
    let tampered_bytes = serde_json::to_vec(&payload).unwrap();

    let mut tampered_envelope = envelope.clone();
    tampered_envelope.payload = hermetic_attest::base64::base64_encode(&tampered_bytes);

    let mut guard = ReplayGuard::new();
    let binding = RunBinding::default();
    let tampered_json = serde_json::to_string(&tampered_envelope).unwrap();
    assert!(verify_run_attestation(&tampered_json, &verifier, &binding, &mut guard).is_err());

    // 2. Expected binding with different boot record fails verification
    let binding_mismatch = RunBinding {
        boot_record: Some(HostBootRecord::sealed_disk()),
        ..Default::default()
    };
    let mut guard = ReplayGuard::new();
    let envelope_json = serde_json::to_string(&envelope).unwrap();
    let err = verify_run_attestation(&envelope_json, &verifier, &binding_mismatch, &mut guard);
    assert_eq!(
        err.unwrap_err(),
        hermetic_attest::VerifyError::BindingMismatch("boot_record")
    );
}

#[test]
fn test_regression_coderabbit_hostile_parser_diagnostics_sanitized() {
    let hostile_token = "2026-11-17T12:34:56Z";

    // 1. Hostile unknown field in probe_output.jsonl
    let f = FixturePaths::new();
    let hostile_probe_line =
        format!(r#"{{"probe":"rdtsc","result":"blocked","{hostile_token}":true}}"#);
    fs::write(
        f.path().join("probe_output.jsonl"),
        format!("{hostile_probe_line}\n"),
    )
    .unwrap();

    let err = assemble_run_record(f.path()).expect_err("hostile probe line must fail");
    let err_msg = err.to_string();
    assert!(
        !err_msg.contains(hostile_token),
        "OrchestratorError display must not contain hostile text '{hostile_token}', got: {err_msg}"
    );
    if let OrchestratorError::Json { artifact, detail } = &err {
        assert_eq!(*artifact, "probe_output.jsonl");
        assert!(
            !detail.contains(hostile_token),
            "JSON error detail must not contain hostile text '{hostile_token}', got: {detail}"
        );
        assert!(
            detail.starts_with("parse error at line 1 column "),
            "Expected numeric location format, got: {detail}"
        );
    } else {
        panic!("Expected OrchestratorError::Json, got: {err:?}");
    }

    // 2. Hostile unknown field in date_sentinel.json
    let f = FixturePaths::new();
    let hostile_json = format!(
        r#"{{"date_leak_observed":false,"scan_incomplete":false,"hits":{{}},"incomplete":{{}},"bytes_scanned":1,"{hostile_token}":1}}"#
    );
    fs::write(f.path().join("date_sentinel.json"), hostile_json).unwrap();
    let err = assemble_run_record(f.path()).expect_err("hostile date_sentinel must fail");
    let err_msg = err.to_string();
    assert!(
        !err_msg.contains(hostile_token),
        "OrchestratorError display must not contain hostile text '{hostile_token}', got: {err_msg}"
    );
    if let OrchestratorError::Json { artifact, detail } = &err {
        assert_eq!(*artifact, "date_sentinel.json");
        assert!(
            !detail.contains(hostile_token),
            "JSON error detail must not contain hostile text '{hostile_token}', got: {detail}"
        );
        assert!(
            detail.starts_with("parse error at line 1 column "),
            "Expected numeric location format, got: {detail}"
        );
    } else {
        panic!("Expected OrchestratorError::Json, got: {err:?}");
    }

    // 3. Hostile unknown field in harness_summary.json
    let f = FixturePaths::new();
    let hostile_json = format!(
        r#"{{"date_leak_observed":false,"scan_incomplete":false,"hits":{{}},"incomplete":{{}},"bytes_scanned":1,"{hostile_token}":1}}"#
    );
    fs::write(f.path().join("harness_summary.json"), hostile_json).unwrap();
    let err = assemble_run_record(f.path()).expect_err("hostile harness_summary must fail");
    let err_msg = err.to_string();
    assert!(
        !err_msg.contains(hostile_token),
        "OrchestratorError display must not contain hostile text '{hostile_token}', got: {err_msg}"
    );
    if let OrchestratorError::Json { artifact, detail } = &err {
        assert_eq!(*artifact, "harness_summary.json");
        assert!(
            !detail.contains(hostile_token),
            "JSON error detail must not contain hostile text '{hostile_token}', got: {detail}"
        );
        assert!(
            detail.starts_with("parse error at line 1 column "),
            "Expected numeric location format, got: {detail}"
        );
    } else {
        panic!("Expected OrchestratorError::Json, got: {err:?}");
    }

    // 4. Hostile unknown field in boot_record.json
    let f = FixturePaths::new();
    let hostile_json = format!(r#"{{"boot_path":"sealed_disk","{hostile_token}":1}}"#);
    fs::write(f.path().join("boot_record.json"), hostile_json).unwrap();
    let err = assemble_run_record(f.path()).expect_err("hostile boot_record must fail");
    let err_msg = err.to_string();
    assert!(
        !err_msg.contains(hostile_token),
        "OrchestratorError display must not contain hostile text '{hostile_token}', got: {err_msg}"
    );
    if let OrchestratorError::Json { artifact, detail } = &err {
        assert_eq!(*artifact, "boot_record.json");
        assert!(
            !detail.contains(hostile_token),
            "JSON error detail must not contain hostile text '{hostile_token}', got: {detail}"
        );
        assert!(
            detail.starts_with("parse error at line 1 column "),
            "Expected numeric location format, got: {detail}"
        );
    } else {
        panic!("Expected OrchestratorError::Json, got: {err:?}");
    }

    // 5. Hostile unknown field in verdict.json
    let f = FixturePaths::new();
    let mut verdict_val: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("verdict.json")).unwrap()).unwrap();
    verdict_val[hostile_token] = json!("leak");
    fs::write(f.path().join("verdict.json"), verdict_val.to_string()).unwrap();
    let err = assemble_run_record(f.path()).expect_err("hostile verdict must fail");
    let err_msg = err.to_string();
    assert!(
        !err_msg.contains(hostile_token),
        "OrchestratorError display must not contain hostile text '{hostile_token}', got: {err_msg}"
    );
    if let OrchestratorError::Json { artifact, detail } = &err {
        assert_eq!(*artifact, "verdict.json");
        assert!(
            !detail.contains(hostile_token),
            "JSON error detail must not contain hostile text '{hostile_token}', got: {detail}"
        );
        assert!(
            detail.starts_with("parse error at line 1 column "),
            "Expected numeric location format, got: {detail}"
        );
    } else {
        panic!("Expected OrchestratorError::Json, got: {err:?}");
    }

    // 6. Hostile unknown field in world_manifest.json
    let f = FixturePaths::new();
    let mut manifest_val: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("world_manifest.json")).unwrap())
            .unwrap();
    manifest_val[hostile_token] = json!("leak");
    fs::write(
        f.path().join("world_manifest.json"),
        manifest_val.to_string(),
    )
    .unwrap();
    let err = assemble_run_record(f.path()).expect_err("hostile world_manifest must fail");
    let err_msg = err.to_string();
    assert!(
        !err_msg.contains(hostile_token),
        "OrchestratorError display must not contain hostile text '{hostile_token}', got: {err_msg}"
    );
    if let OrchestratorError::Json { artifact, detail } = &err {
        assert_eq!(*artifact, "world_manifest.json");
        assert!(
            !detail.contains(hostile_token),
            "JSON error detail must not contain hostile text '{hostile_token}', got: {detail}"
        );
        assert!(
            detail.starts_with("parse error at line 1 column "),
            "Expected numeric location format, got: {detail}"
        );
    } else {
        panic!("Expected OrchestratorError::Json, got: {err:?}");
    }
}

fn build_escape_probe_jsonl(
    f: impl Fn(&str) -> hermetic_escapeprobe::classify::EscapeResult,
) -> String {
    hermetic_escapeprobe::probes::expected_probe_names()
        .iter()
        .map(|n| {
            hermetic_escapeprobe::classify::EscapeRecord::new(n.clone(), f(n), "fixed detail")
                .to_json_line()
                + "\n"
        })
        .collect()
}

#[test]
fn test_escape_probe_jsonl_sealed_gives_passed_and_matching_digest() {
    let f = FixturePaths::new();
    let escape_content = build_escape_probe_jsonl(|n| {
        if n.starts_with("positive.") {
            hermetic_escapeprobe::classify::EscapeResult::Ok
        } else {
            hermetic_escapeprobe::classify::EscapeResult::Blocked
        }
    });
    let escape_bytes = escape_content.as_bytes();
    let expected_digest = Digest::from_sha256(escape_bytes);
    fs::write(f.path().join("escape_probe.jsonl"), escape_bytes).unwrap();

    let record = assemble_run_record(f.path()).expect("assemble with escape_probe.jsonl");
    assert_eq!(record.escape_probe_result, ProbeResult::Passed);
    assert_eq!(record.escape_probe_digest, expected_digest);
}

#[test]
fn test_escape_probe_jsonl_leak_gives_failed_and_triggers_date_leak() {
    let f = FixturePaths::new();
    let escape_content = build_escape_probe_jsonl(|n| {
        if n == "gateway.model_call_date" {
            hermetic_escapeprobe::classify::EscapeResult::Leak
        } else if n.starts_with("positive.") {
            hermetic_escapeprobe::classify::EscapeResult::Ok
        } else {
            hermetic_escapeprobe::classify::EscapeResult::Blocked
        }
    });
    fs::write(
        f.path().join("escape_probe.jsonl"),
        escape_content.as_bytes(),
    )
    .unwrap();

    let record = assemble_run_record(f.path()).expect("assemble with leaking escape_probe.jsonl");
    assert_eq!(record.escape_probe_result, ProbeResult::Failed);
    assert!(record.date_leak_observed);
    assert_eq!(record.clock, ClockLevel::Faked);
    assert_eq!(record.run_status, RunStatus::Review);
}

#[test]
fn test_escape_probe_jsonl_incomplete_gives_failed() {
    let f = FixturePaths::new();
    let escape_content = build_escape_probe_jsonl(|n| {
        if n == "gateway.quota" {
            hermetic_escapeprobe::classify::EscapeResult::Unavailable
        } else if n.starts_with("positive.") {
            hermetic_escapeprobe::classify::EscapeResult::Ok
        } else {
            hermetic_escapeprobe::classify::EscapeResult::Blocked
        }
    });
    fs::write(
        f.path().join("escape_probe.jsonl"),
        escape_content.as_bytes(),
    )
    .unwrap();

    let record = assemble_run_record(f.path()).expect("assemble with incomplete escape probe");
    assert_eq!(record.escape_probe_result, ProbeResult::Failed);
    assert!(!record.date_leak_observed);
}

#[test]
fn test_escape_probe_jsonl_malformed_fails_closed() {
    let f = FixturePaths::new();
    fs::write(
        f.path().join("escape_probe.jsonl"),
        b"not valid json lines\n",
    )
    .unwrap();

    let err = assemble_run_record(f.path()).expect_err("malformed escape_probe.jsonl must fail");
    assert!(matches!(
        err,
        OrchestratorError::MalformedArtifact {
            artifact: "escape_probe.jsonl",
            ..
        }
    ));
}

#[test]
fn test_escape_probe_jsonl_symlink_fails_closed() {
    let f = FixturePaths::new();
    let real = f.path().join("real_escape.jsonl");
    fs::write(&real, b"clean").unwrap();
    symlink(&real, f.path().join("escape_probe.jsonl")).unwrap();

    let err = assemble_run_record(f.path()).expect_err("symlinked escape_probe.jsonl must fail");
    assert!(matches!(
        err,
        OrchestratorError::Fs {
            artifact: "escape_probe.jsonl",
            ..
        }
    ));
}

#[test]
fn test_probe_sentinel_json_merged_into_date_leak_observed() {
    let f = FixturePaths::new();
    let probe_sentinel = json!({
        "date_leak_observed": true,
        "scan_incomplete": false,
        "hits": {"model_response:real_date": 1},
        "incomplete": {},
        "bytes_scanned": 100
    });
    fs::write(
        f.path().join("probe_sentinel.json"),
        probe_sentinel.to_string(),
    )
    .unwrap();

    let record = assemble_run_record(f.path()).expect("assemble with probe_sentinel.json");
    assert!(record.date_leak_observed);
    assert_eq!(record.clock, ClockLevel::Faked);
    assert_eq!(record.run_status, RunStatus::Review);
}

#[test]
fn test_probe_sentinel_json_malformed_fails_closed() {
    let f = FixturePaths::new();
    fs::write(f.path().join("probe_sentinel.json"), b"not valid json").unwrap();

    let err = assemble_run_record(f.path()).expect_err("malformed probe_sentinel.json must fail");
    assert!(matches!(
        err,
        OrchestratorError::Json {
            artifact: "probe_sentinel.json",
            ..
        }
    ));
}

#[test]
fn test_probe_sentinel_json_symlink_fails_closed() {
    let f = FixturePaths::new();
    let real = f.path().join("real_probe_sentinel.json");
    fs::write(&real, b"{}").unwrap();
    symlink(&real, f.path().join("probe_sentinel.json")).unwrap();

    let err = assemble_run_record(f.path()).expect_err("symlinked probe_sentinel.json must fail");
    assert!(matches!(
        err,
        OrchestratorError::Fs {
            artifact: "probe_sentinel.json",
            ..
        }
    ));
}

#[test]
fn test_assemble_and_sign_run_record_mode_g_records_agent_volume_digest() {
    let f = FixturePaths::new();

    // Mode G: replace world_manifest.json with agent_mode = "G"
    // and gateway log fields present, harness_command_log_head absent.
    let expected_agent_volume_digest =
        Digest::parse("sha256:8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
    let gateway_log_head =
        Digest::parse("sha256:d123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();

    let manifest = json!({
        "task_id": "pytest-dev__pytest-6202",
        "task_class": "patch",
        "seal_level": "strict",
        "agent_mode": "G",
        "substrate": "microvm",
        "grader_isolation": "clean",
        "deployment": "single_host",
        "t_world": "2020-01-01T00:00:00Z",
        "t_clock": "2020-01-01T00:00:00Z",
        "base_commit": "abcdef0123456789abcdef0123456789abcdef01",
        "spec_version": "v1.1",
        "world_version": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "sealcheck_version": "v1.0",
        "grader_image_digest": "sha256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "world_root": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "task_rootfs_digest": "sha256:2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "netvm_image_digest": "sha256:3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "guest_kernel_digest": "sha256:4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "vm_config_digest": "sha256:5123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "cpu_template_digest": "sha256:6123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "firecracker_build_digest": "sha256:7123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "agent_volume_digest": expected_agent_volume_digest.to_string(),
        "sealcheck_report_digest": "sha256:9123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "substrate_at_t": "full",
        "exemption_list": ["pkg-a", "pkg-b"],
        "world_server_log_head": "sha256:b123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "dedupe_index_digest": "sha256:c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "request_count": 42,
        "gateway_log_head": gateway_log_head.to_string(),
        "history_rewrite_count": 0,
        "gateway_adapter_version": "v1.0.0"
    });
    fs::write(
        f.path().join("world_manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let record = assemble_run_record(f.path()).expect("assemble Mode G run record");
    assert_eq!(record.agent_mode, AgentMode::G);
    assert_eq!(record.agent_volume_digest, expected_agent_volume_digest);
    assert!(record.harness_command_log_head.is_none());
    assert_eq!(record.gateway_log_head, Some(gateway_log_head));
    assert_eq!(record.history_rewrite_count, Some(0));
    assert_eq!(record.gateway_adapter_version.as_deref(), Some("v1.0.0"));

    let (key_bytes, _signer, verifier) = generate_test_key();
    let key_path = f.path().join("offline_key.p8");
    fs::write(&key_path, key_bytes).unwrap();

    let (assembled, envelope) =
        assemble_and_sign_run_record(f.path(), Some(&key_path)).expect("assemble and sign Mode G");
    assert_eq!(assembled, record);
    let env = envelope.unwrap();

    let mut guard = ReplayGuard::new();
    let binding = RunBinding {
        task_id: Some("pytest-dev__pytest-6202".to_string()),
        world_root: Some(record.world_root.clone()),
        world_bundle: Some(record.world_root.clone()),
        sealcheck_report_digest: Some(record.sealcheck_report_digest.clone()),
        grader_image_digest: Some(record.version_tuple.grader_image_digest.clone()),
        boot_record: record.boot_record.clone(),
    };
    let envelope_json = serde_json::to_string(&env).unwrap();
    let (statement, _digest) =
        verify_run_attestation(&envelope_json, &verifier, &binding, &mut guard)
            .expect("verify Mode G attestation");
    assert_eq!(statement.predicate.agent_mode, AgentMode::G);
    assert_eq!(
        statement.predicate.agent_volume_digest,
        expected_agent_volume_digest
    );
}

#[test]
fn test_mode_g_record_assembly_with_gateway_head_and_signing() {
    let f = FixturePaths::new();

    // Change agent_mode to G in world_manifest.json and remove Mode H harness_command_log_head
    let mut manifest_val: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("world_manifest.json")).unwrap())
            .unwrap();
    manifest_val["agent_mode"] = json!("G");
    manifest_val["harness_command_log_head"] = json!(null);
    fs::write(
        f.path().join("world_manifest.json"),
        manifest_val.to_string(),
    )
    .unwrap();

    // Mode G without gateway_head.json or manifest fields fails closed
    let err = assemble_run_record(f.path()).expect_err("Mode G without gateway head must fail");
    assert!(matches!(
        err,
        OrchestratorError::MissingArtifact("gateway_head.json")
            | OrchestratorError::Validation(RunValidationError::ModeGMissingGatewayFields)
    ));

    // Provide gateway_head.json
    let gw_head = json!({
        "records": 5,
        "head": "sha256:4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "history_rewrite_count": 2,
        "adapter_version": "2026-11-1"
    });
    fs::write(f.path().join("gateway_head.json"), gw_head.to_string()).unwrap();

    let record = assemble_run_record(f.path()).expect("Mode G assembly with gateway_head succeeds");
    assert_eq!(record.agent_mode, AgentMode::G);
    assert_eq!(
        record.gateway_log_head,
        Some(
            Digest::parse(
                "sha256:4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .unwrap()
        )
    );
    assert_eq!(record.history_rewrite_count, Some(2));
    assert_eq!(record.gateway_adapter_version.as_deref(), Some("2026-11-1"));

    // Verify signing and DSSE envelope
    let (_pkcs8, signer, verifier) = generate_test_key();
    let envelope = sign_run_record(&record, &signer).expect("signing succeeds");
    let mut guard = ReplayGuard::new();
    let binding = RunBinding {
        task_id: Some("pytest-dev__pytest-6202".to_string()),
        world_root: Some(record.world_root.clone()),
        world_bundle: Some(record.world_root.clone()),
        sealcheck_report_digest: Some(record.sealcheck_report_digest.clone()),
        grader_image_digest: Some(record.version_tuple.grader_image_digest.clone()),
        boot_record: record.boot_record.clone(),
    };
    let envelope_json = serde_json::to_string(&envelope).unwrap();
    let (statement, _) = verify_run_attestation(&envelope_json, &verifier, &binding, &mut guard)
        .expect("verification succeeds");
    assert_eq!(statement.predicate.agent_mode, AgentMode::G);
    assert_eq!(
        statement.predicate.gateway_log_head,
        record.gateway_log_head
    );
    assert_eq!(
        statement.predicate.history_rewrite_count,
        record.history_rewrite_count
    );
    assert_eq!(
        statement.predicate.gateway_adapter_version,
        record.gateway_adapter_version
    );
}

#[test]
fn test_mode_g_wires_gateway_history_into_run_record() {
    let f = FixturePaths::new();
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("world_manifest.json")).unwrap())
            .unwrap();
    manifest["agent_mode"] = json!("G");
    manifest
        .as_object_mut()
        .unwrap()
        .remove("harness_command_log_head");
    fs::write(f.path().join("world_manifest.json"), manifest.to_string()).unwrap();

    let gw_history = json!({
        "gateway_log_head": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "history_rewrite_count": 3,
        "gateway_adapter_version": "2026-11-1"
    });
    fs::write(
        f.path().join("gateway_history.json"),
        gw_history.to_string(),
    )
    .unwrap();

    let record = assemble_run_record(f.path()).expect("assemble record for Mode G");
    assert_eq!(record.agent_mode, AgentMode::G);
    assert_eq!(record.harness_command_log_head, None);
    assert_eq!(
        record.gateway_log_head,
        Some(
            Digest::parse(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            )
            .unwrap()
        )
    );
    assert_eq!(record.history_rewrite_count, Some(3));
    assert_eq!(
        record.gateway_adapter_version,
        Some("2026-11-1".to_string())
    );
}

#[test]
fn test_mode_g_missing_gateway_fields_fails_validation() {
    let f = FixturePaths::new();
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(f.path().join("world_manifest.json")).unwrap())
            .unwrap();
    manifest["agent_mode"] = json!("G");
    manifest
        .as_object_mut()
        .unwrap()
        .remove("harness_command_log_head");
    fs::write(f.path().join("world_manifest.json"), manifest.to_string()).unwrap();

    let err = assemble_run_record(f.path()).expect_err("Mode G without gateway fields must fail");
    assert_eq!(
        err,
        OrchestratorError::Validation(RunValidationError::ModeGMissingGatewayFields)
    );
}

#[test]
fn test_mode_g_symlinked_gateway_history_fails_closed() {
    let f = FixturePaths::new();
    let target = f.path().join("real_history.json");
    let gw_history = json!({
        "gateway_log_head": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "history_rewrite_count": 0,
        "gateway_adapter_version": "2026-11-1"
    });
    fs::write(&target, gw_history.to_string()).unwrap();
    std::os::unix::fs::symlink(&target, f.path().join("gateway_history.json")).unwrap();

    let err = assemble_run_record(f.path()).expect_err("symlinked gateway_history must fail");
    assert!(matches!(err, OrchestratorError::Fs { .. }));
}

#[test]
fn test_mode_g_oversized_gateway_history_fails_closed() {
    let f = FixturePaths::new();
    let huge = " ".repeat(MAX_GATEWAY_HISTORY_BYTES + 1);
    fs::write(f.path().join("gateway_history.json"), huge).unwrap();

    let err = assemble_run_record(f.path()).expect_err("oversized gateway_history must fail");
    assert!(matches!(err, OrchestratorError::Fs { .. }));
}

#[test]
fn test_mode_g_malformed_gateway_history_fails_closed() {
    let f = FixturePaths::new();
    fs::write(f.path().join("gateway_history.json"), "not valid json").unwrap();

    let err = assemble_run_record(f.path()).expect_err("malformed gateway_history must fail");
    assert!(matches!(err, OrchestratorError::Json { .. }));
}

#[test]
fn test_mode_g_symlinked_gateway_head_fails_closed() {
    let f = FixturePaths::new();
    let target = f.path().join("real_head.json");
    let gw_head = json!({
        "records": 5,
        "head": "sha256:4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "history_rewrite_count": 2,
        "adapter_version": "2026-11-1"
    });
    fs::write(&target, gw_head.to_string()).unwrap();
    std::os::unix::fs::symlink(&target, f.path().join("gateway_head.json")).unwrap();

    let err = assemble_run_record(f.path()).expect_err("symlinked gateway_head must fail");
    assert!(matches!(err, OrchestratorError::Fs { .. }));
}

#[test]
fn test_mode_g_oversized_gateway_head_fails_closed() {
    let f = FixturePaths::new();
    let huge = " ".repeat(MAX_GATEWAY_HEAD_BYTES + 1);
    fs::write(f.path().join("gateway_head.json"), huge).unwrap();

    let err = assemble_run_record(f.path()).expect_err("oversized gateway_head must fail");
    assert!(matches!(err, OrchestratorError::Fs { .. }));
}

#[test]
fn test_mode_g_malformed_gateway_head_fails_closed() {
    let f = FixturePaths::new();
    fs::write(f.path().join("gateway_head.json"), "not valid json").unwrap();

    let err = assemble_run_record(f.path()).expect_err("malformed gateway_head must fail");
    assert!(matches!(err, OrchestratorError::Json { .. }));
}
