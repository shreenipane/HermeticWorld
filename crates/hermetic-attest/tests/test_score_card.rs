mod common;
use common::sample_run_record;
use hermetic_attest::{
    generate_score_card, AgentMode, ClockLevel, Digest, ExcludedTask, RepairedTask, RunStatus,
    ScoreCardError, SealLevel, SubstrateAtT, TaskClass, MAX_SCORE_CARD_RECORDS,
};

#[test]
fn test_refuse_mixed_version_tuples() {
    let base = sample_run_record();
    let mut other = base.clone();

    // 1. Differing spec_version
    other.version_tuple.spec_version = "v2.0".to_string();
    let err = generate_score_card("SWE-bench", "v1", &[base.clone(), other], &[], &[]);
    assert!(matches!(
        err,
        Err(ScoreCardError::VersionTupleMismatch { index: 1, .. })
    ));

    // 2. Differing world_version
    let mut other2 = base.clone();
    other2.version_tuple.world_version =
        Digest::parse("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .unwrap();
    let err = generate_score_card("SWE-bench", "v1", &[base.clone(), other2], &[], &[]);
    assert!(matches!(
        err,
        Err(ScoreCardError::VersionTupleMismatch { index: 1, .. })
    ));

    // 3. Differing sealcheck_version
    let mut other3 = base.clone();
    other3.version_tuple.sealcheck_version = "v1.1".to_string();
    let err = generate_score_card("SWE-bench", "v1", &[base.clone(), other3], &[], &[]);
    assert!(matches!(
        err,
        Err(ScoreCardError::VersionTupleMismatch { index: 1, .. })
    ));

    // 4. Differing grader_image_digest
    let mut other4 = base.clone();
    other4.version_tuple.grader_image_digest =
        Digest::parse("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
            .unwrap();
    let err = generate_score_card("SWE-bench", "v1", &[base, other4], &[], &[]);
    assert!(matches!(
        err,
        Err(ScoreCardError::VersionTupleMismatch { index: 1, .. })
    ));
}

#[test]
fn test_refuse_mixed_seal_level_clock_and_agent_mode() {
    let base = sample_run_record();

    // Differing seal level
    let mut rec_repo_only = base.clone();
    rec_repo_only.seal_level = SealLevel::RepoOnly;
    let err = generate_score_card("Benchmark", "v1", &[base.clone(), rec_repo_only], &[], &[]);
    assert!(matches!(
        err,
        Err(ScoreCardError::SealLevelMismatch { index: 1, .. })
    ));

    // Differing clock level
    let mut rec_clock = base.clone();
    rec_clock.clock = ClockLevel::Real;
    let err = generate_score_card("Benchmark", "v1", &[base.clone(), rec_clock], &[], &[]);
    assert!(matches!(
        err,
        Err(ScoreCardError::ClockLevelMismatch { index: 1, .. })
    ));

    // Differing agent mode
    let mut rec_mode = base.clone();
    rec_mode.agent_mode = AgentMode::G;
    rec_mode.harness_command_log_head = None;
    rec_mode.gateway_log_head = Some(
        Digest::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap(),
    );
    rec_mode.history_rewrite_count = Some(0);
    rec_mode.gateway_adapter_version = Some("v1".to_string());
    let err = generate_score_card("Benchmark", "v1", &[base, rec_mode], &[], &[]);
    assert!(matches!(
        err,
        Err(ScoreCardError::AgentModeMismatch { index: 1, .. })
    ));
}

#[test]
fn test_score_card_empty_records_and_bounds() {
    let empty_err = generate_score_card("Bench", "1.0", &[], &[], &[]);
    assert_eq!(empty_err, Err(ScoreCardError::EmptyRecords));

    let record = sample_run_record();
    let excessive: Vec<_> = (0..=MAX_SCORE_CARD_RECORDS)
        .map(|_| record.clone())
        .collect();
    let bound_err = generate_score_card("Bench", "1.0", &excessive, &[], &[]);
    assert!(matches!(
        bound_err,
        Err(ScoreCardError::RecordCountExceeded { .. })
    ));
}

#[test]
fn test_score_card_counts_and_sorting() {
    let mut r1 = sample_run_record();
    r1.run_status = RunStatus::Resolved;
    r1.task_class = TaskClass::Patch;
    r1.substrate_at_t = SubstrateAtT::Full;

    let mut r2 = sample_run_record();
    r2.run_status = RunStatus::Unresolved;
    r2.task_class = TaskClass::Patch;
    r2.substrate_at_t = SubstrateAtT::Partial;

    let mut r3 = sample_run_record();
    r3.run_status = RunStatus::Tampered;
    r3.task_class = TaskClass::Artifact;
    r3.substrate_at_t = SubstrateAtT::None;

    let excluded = vec![
        ExcludedTask {
            task_id: "task-z".to_string(),
            detector: "D0".to_string(),
            reason: Some("Problem leak".to_string()),
        },
        ExcludedTask {
            task_id: "task-a".to_string(),
            detector: "D1".to_string(),
            reason: None,
        },
        ExcludedTask {
            task_id: "task-a".to_string(),
            detector: "D1".to_string(),
            reason: None,
        },
    ];

    let repaired = vec![
        RepairedTask {
            task_id: "task-r2".to_string(),
            detector: "D0".to_string(),
            detail: Some("Redacted".to_string()),
        },
        RepairedTask {
            task_id: "task-r1".to_string(),
            detector: "D2".to_string(),
            detail: None,
        },
    ];

    let card = generate_score_card(
        "SWE-bench Verified",
        "2024.1",
        &[r1, r2, r3],
        &excluded,
        &repaired,
    )
    .expect("generate card");

    assert_eq!(card.total_runs, 3);
    assert_eq!(card.status_counts.get("resolved"), Some(&1));
    assert_eq!(card.status_counts.get("unresolved"), Some(&1));
    assert_eq!(card.status_counts.get("tampered"), Some(&1));
    assert_eq!(card.status_counts.get("limit_exceeded"), Some(&0));
    assert_eq!(card.status_counts.get("review"), Some(&0));
    assert_eq!(card.status_counts.get("infra_error"), Some(&0));
    assert_eq!(card.status_counts.get("gate_blocked"), Some(&0));

    assert_eq!(card.task_class_counts.get("patch"), Some(&2));
    assert_eq!(card.task_class_counts.get("artifact"), Some(&1));
    assert_eq!(card.task_class_counts.get("state"), Some(&0));

    assert_eq!(card.grader_isolation_counts.get("clean"), Some(&3));
    assert_eq!(card.grader_isolation_counts.get("shared"), Some(&0));

    assert_eq!(card.substrate_at_t_spread.get("full"), Some(&1));
    assert_eq!(card.substrate_at_t_spread.get("partial"), Some(&1));
    assert_eq!(card.substrate_at_t_spread.get("none"), Some(&1));

    // Excluded tasks sorted and deduplicated (task-a before task-z, 2 items not 3)
    assert_eq!(card.excluded_tasks.len(), 2);
    assert_eq!(card.excluded_tasks[0].task_id, "task-a");
    assert_eq!(card.excluded_tasks[1].task_id, "task-z");

    // Repaired tasks sorted (task-r1 before task-r2)
    assert_eq!(card.repaired_tasks.len(), 2);
    assert_eq!(card.repaired_tasks[0].task_id, "task-r1");
    assert_eq!(card.repaired_tasks[1].task_id, "task-r2");

    // Deterministic JSON known answer
    let canonical_json = card.to_canonical_json().expect("canonical json");
    assert!(canonical_json.starts_with(r#"{"agent_mode":"H","benchmark":"SWE-bench Verified""#));
    assert!(!canonical_json.contains('\n'));
    assert!(!canonical_json.contains(" :"));
    assert!(!canonical_json.contains(": "));
    let card_digest = Digest::from_sha256(canonical_json.as_bytes());
    assert_eq!(
        card_digest.as_str(),
        "sha256:b2c8fb90aa4443323f365e05ed71255391b71b61c8ab2455481d18ac6b7da7ce"
    );
}
