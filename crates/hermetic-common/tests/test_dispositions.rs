use hermetic_common::world_manifest::{
    DispositionKind, ManifestCutoffs, PackagesRecord, Resources, RunSpec, SealLevel, SubstrateAtT,
    TaskClass, WorldManifest,
};
use hermetic_common::{
    redact_statement, TaskDispositionRecord, MAX_REDACTION_FRACTION, MIN_REMAINING_CHARS,
};
use std::collections::BTreeMap;

fn sample_manifest() -> WorldManifest {
    WorldManifest {
        spec_version: "hermetic-world/v1".to_string(),
        task_id: "test__task-001".to_string(),
        task_class: TaskClass::Dated,
        seal_level: SealLevel::Strict,
        cutoffs: ManifestCutoffs {
            t_world: "2024-01-15T00:00:00Z".to_string(),
            t_clock: "2024-01-15T00:00:00Z".to_string(),
            base_commit: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
            pkg_cutoff: "2024-01-15T00:00:00Z".to_string(),
        },
        repo_tree_digest: "blake3:0000000000000000000000000000000000000000000000000000000000000001"
            .to_string(),
        rootfs_digest: "blake3:0000000000000000000000000000000000000000000000000000000000000002"
            .to_string(),
        packages: PackagesRecord {
            closure_root: "blake3:0000000000000000000000000000000000000000000000000000000000000003"
                .to_string(),
            baseline_month: "2024-01".to_string(),
            baseline_root:
                "blake3:0000000000000000000000000000000000000000000000000000000000000004"
                    .to_string(),
        },
        web: None,
        substrate: Vec::new(),
        substrate_at_t: SubstrateAtT::Full,
        exemptions: Vec::new(),
        dns_table: Vec::new(),
        world_ca_cert_sha256:
            "blake3:0000000000000000000000000000000000000000000000000000000000000007".to_string(),
        trust_store_paths: Vec::new(),
        run_spec: RunSpec {
            env: BTreeMap::new(),
            workdir: "/testbed".to_string(),
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
        dispositions: Vec::new(),
    }
}

#[test]
fn test_threshold_constants() {
    assert_eq!(MAX_REDACTION_FRACTION, 0.50);
    assert_eq!(MIN_REMAINING_CHARS, 20);
}

#[test]
fn test_redact_statement_removes_leak_without_logging_text() {
    let stmt = "Bug report header.\nLeak snippet: SECRET_CODE_123\nMore information.";
    let leak = "SECRET_CODE_123";
    let start = stmt.find(leak).expect("find leak");
    let end = start + leak.len();

    let (redacted, spans) = redact_statement(stmt, vec![(start, end)]);
    assert!(!redacted.contains(leak));
    assert!(redacted.contains("[REDACTED]"));

    assert_eq!(spans.len(), 1);
    let span = &spans[0];
    assert_eq!(span.start, start);
    assert_eq!(span.end, end);
    assert!(span.hash.starts_with("blake3:"));

    let json_str = serde_json::to_string(&span).expect("serialize");
    assert!(!json_str.contains(leak));
}

#[test]
fn test_manifest_repaired_produces_new_world_version() {
    let mut manifest = sample_manifest();
    let initial_root = manifest.world_root().expect("initial root");

    // Add repaired disposition
    manifest.add_disposition(
        DispositionKind::Repaired,
        "D0",
        "problem_statement_redacted: 1 span",
    );

    let repaired_root = manifest.world_root().expect("repaired root");
    assert_ne!(
        initial_root, repaired_root,
        "Repaired disposition must yield new world version"
    );
}

#[test]
fn test_task_disposition_record_json_schema() {
    let record = TaskDispositionRecord {
        task_id: "test__task-001".to_string(),
        disposition: "clean".to_string(),
        detectors: vec![],
        reason: "gate passed".to_string(),
        world_version: Some("blake3:abcdef".to_string()),
    };

    let json_val = serde_json::to_value(&record).expect("serde_json::to_value");
    assert_eq!(json_val["task_id"], "test__task-001");
    assert_eq!(json_val["disposition"], "clean");
    assert_eq!(json_val["detectors"], serde_json::json!([]));
    assert_eq!(json_val["reason"], "gate passed");
    assert_eq!(json_val["world_version"], "blake3:abcdef");
}
