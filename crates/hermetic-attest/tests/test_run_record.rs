mod common;
use common::sample_run_record;
use hermetic_attest::{
    AgentMode, Digest, GraderIsolation, RunRecord, RunValidationError, SealLevel, TaskClass,
    MAX_RUN_RECORD_SIZE,
};

#[test]
fn review_resolved_requires_r0_passed() {
    use hermetic_attest::{GradingRunResult, RunStatus};
    let mut record = sample_run_record();
    record.run_status = RunStatus::Resolved;
    for result in [GradingRunResult::Failed, GradingRunResult::Skipped] {
        record.r0_result = result;
        assert!(record.validate().is_err(), "accepted {result:?}");
    }
    record.r0_result = GradingRunResult::Passed;
    record.validate().unwrap();
    record.run_status = RunStatus::Unresolved;
    record.r0_result = GradingRunResult::Failed;
    record.validate().unwrap();
}

#[test]
fn test_valid_fixture_parses_and_validates() {
    let record = sample_run_record();
    assert!(record.validate().is_ok());

    let json_str = serde_json::to_string(&record).expect("serialize");
    let parsed = RunRecord::from_json_str(&json_str).expect("parse json");
    assert_eq!(parsed, record);
}

#[test]
fn test_strict_parsing_denies_unknown_fields() {
    let record = sample_run_record();
    let mut val = serde_json::to_value(&record).unwrap();
    val.as_object_mut()
        .unwrap()
        .insert("host_name".to_string(), serde_json::json!("rogue-host"));

    let json_str = serde_json::to_string(&val).unwrap();
    let err = RunRecord::from_json_str(&json_str);
    assert!(err.is_err());
    let err_msg = err.unwrap_err().to_string();
    assert!(err_msg.contains("unknown field"));
}

#[test]
fn test_size_cap_exceeded_fails_without_panic() {
    let huge_str = " ".repeat(MAX_RUN_RECORD_SIZE + 10);
    let err = RunRecord::from_json_str(&huge_str);
    assert!(matches!(
        err,
        Err(RunValidationError::SizeCapExceeded { .. })
    ));
}

#[test]
fn test_mode_h_gateway_conflict() {
    let mut record = sample_run_record();
    assert_eq!(record.agent_mode, AgentMode::H);

    // Mode H carrying gateway fields must be rejected
    record.gateway_log_head = Some(
        Digest::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap(),
    );
    assert_eq!(
        record.validate(),
        Err(RunValidationError::ModeHHasGatewayFields)
    );

    // Mode H without harness command log head must be rejected
    record.gateway_log_head = None;
    record.harness_command_log_head = None;
    assert_eq!(
        record.validate(),
        Err(RunValidationError::ModeHMissingHarnessLog)
    );
}

#[test]
fn test_mode_g_harness_conflict() {
    let mut record = sample_run_record();
    record.agent_mode = AgentMode::G;
    record.harness_command_log_head = Some(
        Digest::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap(),
    );
    record.gateway_log_head = Some(
        Digest::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap(),
    );
    record.history_rewrite_count = Some(0);
    record.gateway_adapter_version = Some("anthropic-v1".to_string());

    // Mode G carrying harness log must be rejected
    assert_eq!(
        record.validate(),
        Err(RunValidationError::ModeGHasHarnessFields)
    );

    // Mode G missing gateway adapter version must be rejected
    record.harness_command_log_head = None;
    record.gateway_adapter_version = None;
    assert_eq!(
        record.validate(),
        Err(RunValidationError::ModeGMissingGatewayFields)
    );
}

#[test]
fn test_seal_level_strict_rejects_d5b_warnings() {
    let mut record = sample_run_record();
    assert_eq!(record.seal_level, SealLevel::Strict);

    record.d5b_warning_list = Some(vec!["package-foo==1.0".to_string()]);
    assert_eq!(
        record.validate(),
        Err(RunValidationError::StrictCarriesD5bWarning)
    );
}

#[test]
fn test_seal_level_repo_only_allows_d5b_warnings() {
    let mut record = sample_run_record();
    record.seal_level = SealLevel::RepoOnly;
    record.d5b_warning_list = Some(vec![
        "package-a==1.0".to_string(),
        "package-b==2.0".to_string(),
    ]);
    assert!(record.validate().is_ok());

    // But unsorted d5b warnings are rejected
    record.d5b_warning_list = Some(vec![
        "package-b==2.0".to_string(),
        "package-a==1.0".to_string(),
    ]);
    assert_eq!(
        record.validate(),
        Err(RunValidationError::UnsortedOrDuplicateD5bWarnings)
    );

    // Duplicate d5b warnings are rejected
    record.d5b_warning_list = Some(vec![
        "package-a==1.0".to_string(),
        "package-a==1.0".to_string(),
    ]);
    assert_eq!(
        record.validate(),
        Err(RunValidationError::UnsortedOrDuplicateD5bWarnings)
    );
}

#[test]
fn test_unsorted_and_duplicate_exemptions_rejected() {
    let mut record = sample_run_record();

    // Unsorted
    record.exemption_list = vec!["z-pkg".to_string(), "a-pkg".to_string()];
    assert_eq!(
        record.validate(),
        Err(RunValidationError::UnsortedOrDuplicateExemptions)
    );

    // Duplicate
    record.exemption_list = vec!["pkg-a".to_string(), "pkg-a".to_string()];
    assert_eq!(
        record.validate(),
        Err(RunValidationError::UnsortedOrDuplicateExemptions)
    );
}

#[test]
fn test_timestamp_validations() {
    let mut record = sample_run_record();

    // Non-UTC offset rejected
    record.t_world = "2020-01-01T00:00:00+02:00".to_string();
    assert!(matches!(
        record.validate(),
        Err(RunValidationError::InvalidTimestamp { .. })
    ));

    // Malformed timestamp rejected
    record.t_world = "not-a-timestamp".to_string();
    assert!(matches!(
        record.validate(),
        Err(RunValidationError::InvalidTimestamp { .. })
    ));

    // t_clock before t_world rejected
    record.t_world = "2020-05-01T00:00:00Z".to_string();
    record.t_clock = "2020-01-01T00:00:00Z".to_string();
    assert_eq!(
        record.validate(),
        Err(RunValidationError::ClockBeforeWorld {
            t_clock: "2020-01-01T00:00:00Z".into(),
            t_world: "2020-05-01T00:00:00Z".into(),
        })
    );

    // pkg_cutoff before t_world rejected
    record.t_world = "2020-05-01T00:00:00Z".to_string();
    record.t_clock = "2020-06-01T00:00:00Z".to_string();
    record.pkg_cutoff = Some("2020-04-01T00:00:00Z".to_string());
    assert_eq!(
        record.validate(),
        Err(RunValidationError::PkgCutoffBeforeWorld {
            pkg_cutoff: "2020-04-01T00:00:00Z".into(),
            t_world: "2020-05-01T00:00:00Z".into(),
        })
    );
}

#[test]
fn test_r1_coverage_per_mille_bound() {
    let mut record = sample_run_record();
    record.r1_coverage = Some(1001);
    assert_eq!(
        record.validate(),
        Err(RunValidationError::InvalidR1Coverage(1001))
    );

    record.r1_coverage = Some(1000);
    assert!(record.validate().is_ok());
}

#[test]
fn test_task_class_grader_isolation_consistency() {
    let mut record = sample_run_record();

    // Patch must use Clean
    record.task_class = TaskClass::Patch;
    record.grader_isolation = GraderIsolation::Shared;
    assert_eq!(
        record.validate(),
        Err(RunValidationError::TaskClassIsolationMismatch {
            task_class: TaskClass::Patch,
            grader_isolation: GraderIsolation::Shared,
        })
    );

    // State must use Shared
    record.task_class = TaskClass::State;
    record.grader_isolation = GraderIsolation::Clean;
    assert_eq!(
        record.validate(),
        Err(RunValidationError::TaskClassIsolationMismatch {
            task_class: TaskClass::State,
            grader_isolation: GraderIsolation::Clean,
        })
    );

    record.grader_isolation = GraderIsolation::Shared;
    assert!(record.validate().is_ok());
}

#[test]
fn test_task_id_and_base_commit_validation() {
    let mut record = sample_run_record();

    // Empty task_id
    record.task_id = "".to_string();
    assert_eq!(record.validate(), Err(RunValidationError::EmptyTaskId));

    // Control character in task_id
    record.task_id = "test\ntask".to_string();
    assert!(matches!(
        record.validate(),
        Err(RunValidationError::InvalidTaskId(_))
    ));

    // Empty base_commit
    record.task_id = "valid-id".to_string();
    record.base_commit = "".to_string();
    assert_eq!(record.validate(), Err(RunValidationError::EmptyBaseCommit));

    // Non-hex base_commit
    record.base_commit = "not-hex-commit!".to_string();
    assert!(matches!(
        record.validate(),
        Err(RunValidationError::InvalidBaseCommit(_))
    ));
}

#[test]
fn test_boot_record_version_gate() {
    let mut record = sample_run_record();
    assert_eq!(record.version_tuple.spec_version, "v1.1");
    assert!(record.boot_record.is_some());
    assert!(record.validate().is_ok());

    // v1.1 requires boot_record
    record.boot_record = None;
    assert_eq!(
        record.validate(),
        Err(RunValidationError::MissingBootRecord)
    );

    // v1.0 without boot_record validates
    record.version_tuple.spec_version = "v1.0".to_string();
    assert!(record.validate().is_ok());

    // v1.0 carrying boot_record is rejected
    record.boot_record = Some(hermetic_attest::HostBootRecord::sealed_disk());
    assert_eq!(
        record.validate(),
        Err(RunValidationError::BootRecordVersionMismatch)
    );
}

#[test]
fn test_boot_record_validation_and_tampering() {
    let mut record = sample_run_record();

    // Valid sealed_disk
    record.boot_record = Some(hermetic_attest::HostBootRecord::sealed_disk());
    assert!(record.validate().is_ok());

    // Tampered: unknown boot_path
    record.boot_record = Some(hermetic_attest::HostBootRecord {
        boot_path: "untrusted_network".to_string(),
        initrd_digest: None,
    });
    assert!(matches!(
        record.validate(),
        Err(RunValidationError::InvalidBootRecord(_))
    ));

    // Tampered: sealed_disk carrying an initrd_digest
    record.boot_record = Some(hermetic_attest::HostBootRecord {
        boot_path: "sealed_disk".to_string(),
        initrd_digest: Some(
            Digest::parse(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
        ),
    });
    assert!(matches!(
        record.validate(),
        Err(RunValidationError::InvalidBootRecord(_))
    ));

    // Tampered: trusted_initramfs missing initrd_digest
    record.boot_record = Some(hermetic_attest::HostBootRecord {
        boot_path: "trusted_initramfs".to_string(),
        initrd_digest: None,
    });
    assert!(matches!(
        record.validate(),
        Err(RunValidationError::InvalidBootRecord(_))
    ));
}
