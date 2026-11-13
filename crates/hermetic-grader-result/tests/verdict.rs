#![forbid(unsafe_code)]

use hermetic_grader_result::{
    verdict, write_disk, DiskError, GradingPlan, RunId, RunResult, SupervisorExit,
    SupervisorSummary, TamperReason, TestStatus, VerdictStatus,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

const VARIANT_SET_R0: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VARIANT_SET_R1: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const VARIANT_SET_R2: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const VARIANT_SET_R3: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn sample_plan() -> GradingPlan {
    let mut f2p = BTreeSet::new();
    f2p.insert("test_bugfix".to_string());

    let mut p2p = BTreeSet::new();
    p2p.insert("test_regression".to_string());

    let mut mutated = BTreeSet::new();
    mutated.insert("test_bugfix".to_string());

    let mut equivalents = BTreeMap::new();
    equivalents.insert("test_bugfix".to_string(), "equiv_bugfix".to_string());
    equivalents.insert(
        "test_regression".to_string(),
        "equiv_regression".to_string(),
    );

    GradingPlan {
        f2p,
        p2p,
        mutated,
        equivalents,
    }
}

fn clean_r0() -> RunResult {
    let mut tests = BTreeMap::new();
    tests.insert("test_bugfix".to_string(), TestStatus::Passed);
    tests.insert("test_regression".to_string(), TestStatus::Passed);
    RunResult {
        run: RunId::R0,
        variant_set: VARIANT_SET_R0.to_string(),
        tests,
        supervisor: SupervisorSummary {
            exit: SupervisorExit::Clean,
            tests_started: 2,
            tests_finished: 2,
        },
    }
}

fn clean_r1() -> RunResult {
    let mut tests = BTreeMap::new();
    tests.insert("test_bugfix".to_string(), TestStatus::Failed);
    tests.insert("test_regression".to_string(), TestStatus::Passed);
    RunResult {
        run: RunId::R1,
        variant_set: VARIANT_SET_R1.to_string(),
        tests,
        supervisor: SupervisorSummary {
            exit: SupervisorExit::Clean,
            tests_started: 2,
            tests_finished: 2,
        },
    }
}

fn clean_r2() -> RunResult {
    let mut tests = BTreeMap::new();
    tests.insert("equiv_bugfix".to_string(), TestStatus::Passed);
    tests.insert("equiv_regression".to_string(), TestStatus::Passed);
    RunResult {
        run: RunId::R2,
        variant_set: VARIANT_SET_R2.to_string(),
        tests,
        supervisor: SupervisorSummary {
            exit: SupervisorExit::Clean,
            tests_started: 2,
            tests_finished: 2,
        },
    }
}

fn clean_r3_failing_f2p() -> RunResult {
    let mut tests = BTreeMap::new();
    tests.insert("test_bugfix".to_string(), TestStatus::Failed);
    tests.insert("test_regression".to_string(), TestStatus::Passed);
    RunResult {
        run: RunId::R3,
        variant_set: VARIANT_SET_R3.to_string(),
        tests,
        supervisor: SupervisorSummary {
            exit: SupervisorExit::Clean,
            tests_started: 2,
            tests_finished: 2,
        },
    }
}

fn r3_passing_f2p() -> RunResult {
    let mut tests = BTreeMap::new();
    tests.insert("test_bugfix".to_string(), TestStatus::Passed);
    tests.insert("test_regression".to_string(), TestStatus::Passed);
    RunResult {
        run: RunId::R3,
        variant_set: VARIANT_SET_R3.to_string(),
        tests,
        supervisor: SupervisorSummary {
            exit: SupervisorExit::Clean,
            tests_started: 2,
            tests_finished: 2,
        },
    }
}

#[test]
fn verdict_resolved_when_all_checks_pass() {
    let plan = sample_plan();
    let v = verdict(
        Ok(clean_r0()),
        Ok(clean_r1()),
        Ok(clean_r2()),
        Some(Ok(clean_r3_failing_f2p())),
        &plan,
    );
    assert_eq!(v.status, VerdictStatus::Resolved);
    assert!(v.reasons.is_empty());
    assert_eq!(v.runs.len(), 4);
    for metrics in v.runs.values() {
        assert!(metrics.disk_sha256.is_some());
        assert_eq!(metrics.tests_total, 2);
    }

    // Deterministic serialization check
    let j1 = serde_json::to_string(&v).unwrap();
    let j2 = serde_json::to_string(&v).unwrap();
    assert_eq!(j1, j2);
}

#[test]
fn verdict_individual_rules() {
    let plan = sample_plan();

    // 1. DiskError::Tamper on any run -> tampered
    let v_tamper = verdict(
        Err(DiskError::Tamper(TamperReason::BadMagic)),
        Ok(clean_r1()),
        Ok(clean_r2()),
        None,
        &plan,
    );
    assert_eq!(v_tamper.status, VerdictStatus::Tampered);
    assert!(v_tamper.reasons.contains(&"disk_tamper".to_string()));

    // 2. R0 fails F2P -> unresolved
    let mut r0_f2p_fail = clean_r0();
    r0_f2p_fail
        .tests
        .insert("test_bugfix".to_string(), TestStatus::Failed);
    let mut r2_matching = clean_r2();
    r2_matching
        .tests
        .insert("equiv_bugfix".to_string(), TestStatus::Failed);
    let v_f2p = verdict(
        Ok(r0_f2p_fail),
        Ok(clean_r1()),
        Ok(r2_matching),
        None,
        &plan,
    );
    assert_eq!(v_f2p.status, VerdictStatus::Unresolved);
    assert_eq!(v_f2p.reasons, vec!["f2p_failed".to_string()]);

    // 3. R0 fails P2P -> unresolved
    let mut r0_p2p_fail = clean_r0();
    r0_p2p_fail
        .tests
        .insert("test_regression".to_string(), TestStatus::Failed);
    let mut r2_p2p_matching = clean_r2();
    r2_p2p_matching
        .tests
        .insert("equiv_regression".to_string(), TestStatus::Failed);
    let v_p2p = verdict(
        Ok(r0_p2p_fail),
        Ok(clean_r1()),
        Ok(r2_p2p_matching),
        None,
        &plan,
    );
    assert_eq!(v_p2p.status, VerdictStatus::Unresolved);
    assert_eq!(v_p2p.reasons, vec!["p2p_failed".to_string()]);

    // 4. R1 mutated test passes -> tampered with reason "mutant_passed"
    let mut r1_mutant_pass = clean_r1();
    r1_mutant_pass
        .tests
        .insert("test_bugfix".to_string(), TestStatus::Passed);
    let v_mutant = verdict(
        Ok(clean_r0()),
        Ok(r1_mutant_pass),
        Ok(clean_r2()),
        None,
        &plan,
    );
    assert_eq!(v_mutant.status, VerdictStatus::Tampered);
    assert_eq!(v_mutant.reasons, vec!["mutant_passed".to_string()]);

    // 5. R2 differs from R0 on paired equivalent -> tampered with reason "equivalence_mismatch"
    let mut r2_diff = clean_r2();
    r2_diff
        .tests
        .insert("equiv_bugfix".to_string(), TestStatus::Failed);
    let v_equiv = verdict(Ok(clean_r0()), Ok(clean_r1()), Ok(r2_diff), None, &plan);
    assert_eq!(v_equiv.status, VerdictStatus::Tampered);
    assert_eq!(v_equiv.reasons, vec!["equivalence_mismatch".to_string()]);

    // 6. R3 passes all F2P tests -> review with reason "fix_removal_passed"
    let v_review = verdict(
        Ok(clean_r0()),
        Ok(clean_r1()),
        Ok(clean_r2()),
        Some(Ok(r3_passing_f2p())),
        &plan,
    );
    assert_eq!(v_review.status, VerdictStatus::Review);
    assert_eq!(v_review.reasons, vec!["fix_removal_passed".to_string()]);

    // 7. Supervisor timeout or crash on R0 -> infra_error
    let mut r0_timeout = clean_r0();
    r0_timeout.supervisor.exit = SupervisorExit::Timeout;
    let v_timeout = verdict(Ok(r0_timeout), Ok(clean_r1()), Ok(clean_r2()), None, &plan);
    assert_eq!(v_timeout.status, VerdictStatus::InfraError);
    assert_eq!(v_timeout.reasons, vec!["supervisor_timeout".to_string()]);

    let mut r0_crash = clean_r0();
    r0_crash.supervisor.exit = SupervisorExit::Crash;
    let v_crash = verdict(Ok(r0_crash), Ok(clean_r1()), Ok(clean_r2()), None, &plan);
    assert_eq!(v_crash.status, VerdictStatus::InfraError);
    assert_eq!(v_crash.reasons, vec!["supervisor_crash".to_string()]);

    // 8. R1 mutated test skipped (not failing) -> tampered with reason "mutant_passed"
    let mut r1_mutant_skip = clean_r1();
    r1_mutant_skip
        .tests
        .insert("test_bugfix".to_string(), TestStatus::Skipped);
    let v_mutant_skip = verdict(
        Ok(clean_r0()),
        Ok(r1_mutant_skip),
        Ok(clean_r2()),
        None,
        &plan,
    );
    assert_eq!(v_mutant_skip.status, VerdictStatus::Tampered);
    assert_eq!(v_mutant_skip.reasons, vec!["mutant_passed".to_string()]);

    // 9. Run ID mismatch (R1 provided in R0 slot) -> tampered with reason "run_id_mismatch"
    let v_mismatch = verdict(Ok(clean_r1()), Ok(clean_r1()), Ok(clean_r2()), None, &plan);
    assert_eq!(v_mismatch.status, VerdictStatus::Tampered);
    assert!(v_mismatch.reasons.contains(&"run_id_mismatch".to_string()));

    // 10. Disk I/O error on run -> infra_error with reason "disk_io_error"
    let v_io = verdict(
        Err(DiskError::Io(std::io::ErrorKind::NotFound)),
        Ok(clean_r1()),
        Ok(clean_r2()),
        None,
        &plan,
    );
    assert_eq!(v_io.status, VerdictStatus::InfraError);
    assert!(v_io.reasons.contains(&"disk_io_error".to_string()));

    // 11. Invalid plan -> infra_error with reason "invalid_plan"
    let mut bad_plan = sample_plan();
    bad_plan.f2p.insert("invalid\x01id".to_string());
    let v_bad_plan = verdict(
        Ok(clean_r0()),
        Ok(clean_r1()),
        Ok(clean_r2()),
        None,
        &bad_plan,
    );
    assert_eq!(v_bad_plan.status, VerdictStatus::InfraError);
    assert!(v_bad_plan.reasons.contains(&"invalid_plan".to_string()));
}

#[test]
fn verdict_resolved_without_r3() {
    let plan = sample_plan();
    let v = verdict(Ok(clean_r0()), Ok(clean_r1()), Ok(clean_r2()), None, &plan);
    assert_eq!(v.status, VerdictStatus::Resolved);
    assert!(v.reasons.is_empty());
    assert_eq!(v.runs.len(), 3);
    assert!(v.runs.contains_key(&RunId::R0));
    assert!(v.runs.contains_key(&RunId::R1));
    assert!(v.runs.contains_key(&RunId::R2));
    assert!(!v.runs.contains_key(&RunId::R3));
}

#[test]
fn table_driven_precedence_conflicts() {
    let plan = sample_plan();

    struct PrecedenceCase {
        name: &'static str,
        tamper_r1: bool,
        infra_r0: bool,
        unresolved_r0: bool,
        review_r3: bool,
        expected_status: VerdictStatus,
        expected_reason: &'static str,
    }

    let cases = [
        PrecedenceCase {
            name: "tampered_beats_infra_error",
            tamper_r1: true,
            infra_r0: true,
            unresolved_r0: false,
            review_r3: false,
            expected_status: VerdictStatus::Tampered,
            expected_reason: "mutant_passed",
        },
        PrecedenceCase {
            name: "tampered_beats_unresolved",
            tamper_r1: true,
            infra_r0: false,
            unresolved_r0: true,
            review_r3: false,
            expected_status: VerdictStatus::Tampered,
            expected_reason: "mutant_passed",
        },
        PrecedenceCase {
            name: "tampered_beats_review",
            tamper_r1: true,
            infra_r0: false,
            unresolved_r0: false,
            review_r3: true,
            expected_status: VerdictStatus::Tampered,
            expected_reason: "mutant_passed",
        },
        PrecedenceCase {
            name: "infra_error_beats_unresolved",
            tamper_r1: false,
            infra_r0: true,
            unresolved_r0: true,
            review_r3: false,
            expected_status: VerdictStatus::InfraError,
            expected_reason: "supervisor_timeout",
        },
        PrecedenceCase {
            name: "infra_error_beats_review",
            tamper_r1: false,
            infra_r0: true,
            unresolved_r0: false,
            review_r3: true,
            expected_status: VerdictStatus::InfraError,
            expected_reason: "supervisor_timeout",
        },
        PrecedenceCase {
            name: "unresolved_beats_review",
            tamper_r1: false,
            infra_r0: false,
            unresolved_r0: true,
            review_r3: true,
            expected_status: VerdictStatus::Unresolved,
            expected_reason: "f2p_failed",
        },
        PrecedenceCase {
            name: "all_four_active_tampered_wins",
            tamper_r1: true,
            infra_r0: true,
            unresolved_r0: true,
            review_r3: true,
            expected_status: VerdictStatus::Tampered,
            expected_reason: "mutant_passed",
        },
    ];

    for case in &cases {
        let mut r0 = clean_r0();
        let mut r1 = clean_r1();
        let mut r2 = clean_r2();

        if case.unresolved_r0 {
            r0.tests
                .insert("test_bugfix".to_string(), TestStatus::Failed);
            r2.tests
                .insert("equiv_bugfix".to_string(), TestStatus::Failed);
        }
        if case.infra_r0 {
            r0.supervisor.exit = SupervisorExit::Timeout;
        }
        if case.tamper_r1 {
            r1.tests
                .insert("test_bugfix".to_string(), TestStatus::Passed);
        }
        let r3 = if case.review_r3 {
            Some(Ok(r3_passing_f2p()))
        } else {
            Some(Ok(clean_r3_failing_f2p()))
        };

        let out = verdict(Ok(r0), Ok(r1), Ok(r2), r3, &plan);
        assert_eq!(out.status, case.expected_status, "case {}", case.name);
        assert!(
            out.reasons.contains(&case.expected_reason.to_string()),
            "case {} missing reason {}",
            case.name,
            case.expected_reason
        );
    }
}

#[test]
fn cli_binary_exit_codes_and_output() {
    let bin = env!("CARGO_BIN_EXE_hermetic-grader-verdict");
    let dir = tempdir().unwrap();

    let r0_path = dir.path().join("r0.hgrd");
    let r1_path = dir.path().join("r1.hgrd");
    let r2_path = dir.path().join("r2.hgrd");
    let r3_path = dir.path().join("r3.hgrd");
    let plan_path = dir.path().join("plan.json");

    write_disk(&clean_r0(), &r0_path).unwrap();
    write_disk(&clean_r1(), &r1_path).unwrap();
    write_disk(&clean_r2(), &r2_path).unwrap();
    write_disk(&clean_r3_failing_f2p(), &r3_path).unwrap();
    fs::write(&plan_path, serde_json::to_vec(&sample_plan()).unwrap()).unwrap();

    // Resolved -> exit 0
    let out_ok = Command::new(bin)
        .args([
            "--r0",
            r0_path.to_str().unwrap(),
            "--r1",
            r1_path.to_str().unwrap(),
            "--r2",
            r2_path.to_str().unwrap(),
            "--r3",
            r3_path.to_str().unwrap(),
            "--plan",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out_ok.status.code(), Some(0));
    let parsed_ok: hermetic_grader_result::Verdict =
        serde_json::from_slice(&out_ok.stdout).unwrap();
    assert_eq!(parsed_ok.status, VerdictStatus::Resolved);
    assert_eq!(parsed_ok.runs.len(), 4);

    // Resolved without --r3 -> exit 0
    let out_no_r3 = Command::new(bin)
        .args([
            "--r0",
            r0_path.to_str().unwrap(),
            "--r1",
            r1_path.to_str().unwrap(),
            "--r2",
            r2_path.to_str().unwrap(),
            "--plan",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out_no_r3.status.code(), Some(0));
    let parsed_no_r3: hermetic_grader_result::Verdict =
        serde_json::from_slice(&out_no_r3.stdout).unwrap();
    assert_eq!(parsed_no_r3.status, VerdictStatus::Resolved);
    assert_eq!(parsed_no_r3.runs.len(), 3);

    // Non-resolved (review when R3 passes F2P) -> exit 2
    write_disk(&r3_passing_f2p(), &r3_path).unwrap();
    let out_review = Command::new(bin)
        .args([
            "--r0",
            r0_path.to_str().unwrap(),
            "--r1",
            r1_path.to_str().unwrap(),
            "--r2",
            r2_path.to_str().unwrap(),
            "--r3",
            r3_path.to_str().unwrap(),
            "--plan",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out_review.status.code(), Some(2));
    let parsed_review: hermetic_grader_result::Verdict =
        serde_json::from_slice(&out_review.stdout).unwrap();
    assert_eq!(parsed_review.status, VerdictStatus::Review);

    // Tampered disk file -> exit 2 with status "tampered"
    fs::write(&r1_path, b"corrupt").unwrap();
    let out_tamper = Command::new(bin)
        .args([
            "--r0",
            r0_path.to_str().unwrap(),
            "--r1",
            r1_path.to_str().unwrap(),
            "--r2",
            r2_path.to_str().unwrap(),
            "--plan",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out_tamper.status.code(), Some(2));
    let parsed_tamper: hermetic_grader_result::Verdict =
        serde_json::from_slice(&out_tamper.stdout).unwrap();
    assert_eq!(parsed_tamper.status, VerdictStatus::Tampered);

    // Usage error -> exit 1
    let out_usage = Command::new(bin).arg("--invalid").output().unwrap();
    assert_eq!(out_usage.status.code(), Some(1));

    // Missing file I/O error -> exit 1
    let missing_path = dir.path().join("does_not_exist.hgrd");
    let out_io = Command::new(bin)
        .args([
            "--r0",
            missing_path.to_str().unwrap(),
            "--r1",
            r1_path.to_str().unwrap(),
            "--r2",
            r2_path.to_str().unwrap(),
            "--plan",
            plan_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out_io.status.code(), Some(1));
}
