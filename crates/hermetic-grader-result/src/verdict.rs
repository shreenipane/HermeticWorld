#![forbid(unsafe_code)]

use crate::disk::{
    encode_disk, is_valid_node_id, sha256_hex, DiskError, RunId, RunResult, SupervisorExit,
    TestStatus, MAX_TESTS,
};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MAX_PLAN_BYTES: usize = 1_048_576;
pub const MAX_PLAN_TESTS: usize = 100_000;
pub const MAX_EQUIVALENT_PAIRS: usize = 100_000;

/// Differential verdict status ordered by precedence:
///
/// Precedence from highest to lowest:
/// 1. `Tampered` ("tampered") - beats `InfraError`, `Unresolved`, `Review`, and `Resolved`.
/// 2. `InfraError` ("infra_error") - beats `Unresolved`, `Review`, and `Resolved`.
/// 3. `Unresolved` ("unresolved") - beats `Review` and `Resolved`.
/// 4. `Review` ("review") - beats `Resolved`.
/// 5. `Resolved` ("resolved") - lowest precedence; returned only when no higher condition holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    Resolved,
    Review,
    Unresolved,
    InfraError,
    Tampered,
}

impl VerdictStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Review => "review",
            Self::Unresolved => "unresolved",
            Self::InfraError => "infra_error",
            Self::Tampered => "tampered",
        }
    }
}

impl fmt::Display for VerdictStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GradingPlan {
    #[serde(deserialize_with = "deserialize_test_set")]
    pub f2p: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_test_set")]
    pub p2p: BTreeSet<String>,
    #[serde(alias = "r1_mutated", alias = "mutated_tests")]
    #[serde(deserialize_with = "deserialize_test_set")]
    pub mutated: BTreeSet<String>,
    #[serde(alias = "paired_equivalents", alias = "r2_equivalents")]
    #[serde(deserialize_with = "deserialize_equivalents")]
    pub equivalents: BTreeMap<String, String>,
}

fn deserialize_test_set<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeSet<String>, D::Error> {
    struct TestSetVisitor;
    impl<'de> Visitor<'de> for TestSetVisitor {
        type Value = BTreeSet<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a bounded list of distinct test IDs")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
            let mut tests = BTreeSet::new();
            for _ in 0..MAX_PLAN_TESTS {
                let Some(id) = access.next_element::<String>()? else {
                    return Ok(tests);
                };
                if !is_valid_node_id(&id) || !tests.insert(id) {
                    return Err(serde::de::Error::custom("invalid or duplicate plan test"));
                }
            }
            if access.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("plan test cap exceeded"));
            }
            Ok(tests)
        }
    }
    deserializer.deserialize_seq(TestSetVisitor)
}

fn deserialize_equivalents<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct EquivalentsVisitor;
    impl<'de> Visitor<'de> for EquivalentsVisitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a bounded map of distinct equivalent test pairs")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
            let mut pairs = BTreeMap::new();
            for _ in 0..MAX_EQUIVALENT_PAIRS {
                let Some((original, equivalent)) = access.next_entry::<String, String>()? else {
                    return Ok(pairs);
                };
                if !is_valid_node_id(&original)
                    || !is_valid_node_id(&equivalent)
                    || pairs.insert(original, equivalent).is_some()
                {
                    return Err(serde::de::Error::custom(
                        "invalid or duplicate equivalent pair",
                    ));
                }
            }
            if access.next_key::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("equivalent pair cap exceeded"));
            }
            Ok(pairs)
        }
    }
    deserializer.deserialize_map(EquivalentsVisitor)
}

impl GradingPlan {
    pub fn is_valid(&self) -> bool {
        if self.f2p.len() > MAX_PLAN_TESTS
            || self.p2p.len() > MAX_PLAN_TESTS
            || self.mutated.len() > MAX_PLAN_TESTS
            || self.equivalents.len() > MAX_EQUIVALENT_PAIRS
        {
            return false;
        }
        let f2p_ok = self
            .f2p
            .iter()
            .take(MAX_PLAN_TESTS)
            .all(|s| is_valid_node_id(s));
        let p2p_ok = self
            .p2p
            .iter()
            .take(MAX_PLAN_TESTS)
            .all(|s| is_valid_node_id(s));
        let mutated_ok = self
            .mutated
            .iter()
            .take(MAX_PLAN_TESTS)
            .all(|s| is_valid_node_id(s));
        let eq_ok = self
            .equivalents
            .iter()
            .take(MAX_EQUIVALENT_PAIRS)
            .all(|(k, v)| is_valid_node_id(k) && is_valid_node_id(v));

        f2p_ok && p2p_ok && mutated_ok && eq_ok
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunMetrics {
    pub disk_sha256: Option<String>,
    pub tests_total: u32,
    pub tests_started: u32,
    pub tests_finished: u32,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub error: u32,
    pub missing: u32,
}

impl RunMetrics {
    pub fn empty() -> Self {
        Self {
            disk_sha256: None,
            tests_total: 0,
            tests_started: 0,
            tests_finished: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            error: 0,
            missing: 0,
        }
    }

    pub fn from_run_result(run: &RunResult) -> Result<Self, DiskError> {
        let (_, digest) = encode_disk(run)?;
        let mut passed: u32 = 0;
        let mut failed: u32 = 0;
        let mut skipped: u32 = 0;
        let mut error: u32 = 0;
        let mut missing: u32 = 0;

        for status in run.tests.values().take(MAX_TESTS) {
            match status {
                TestStatus::Passed => passed = passed.saturating_add(1),
                TestStatus::Failed => failed = failed.saturating_add(1),
                TestStatus::Skipped => skipped = skipped.saturating_add(1),
                TestStatus::Error => error = error.saturating_add(1),
                TestStatus::Missing => missing = missing.saturating_add(1),
            }
        }

        let tests_total = u32::try_from(run.tests.len()).unwrap_or(u32::MAX);
        Ok(Self {
            disk_sha256: Some(sha256_hex(&digest)),
            tests_total,
            tests_started: run.supervisor.tests_started,
            tests_finished: run.supervisor.tests_finished,
            passed,
            failed,
            skipped,
            error,
            missing,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub status: VerdictStatus,
    pub reasons: Vec<String>,
    pub runs: BTreeMap<RunId, RunMetrics>,
}

fn promote_status(current: &mut VerdictStatus, candidate: VerdictStatus) {
    if candidate > *current {
        *current = candidate;
    }
}

fn inspect_run_slot(
    slot: RunId,
    run_res: &Result<RunResult, DiskError>,
    status: &mut VerdictStatus,
    reasons: &mut BTreeSet<String>,
    runs_out: &mut BTreeMap<RunId, RunMetrics>,
) -> Option<RunResult> {
    match run_res {
        Ok(run) => {
            if run.run != slot {
                promote_status(status, VerdictStatus::Tampered);
                reasons.insert("run_id_mismatch".to_string());
                runs_out.insert(slot, RunMetrics::empty());
                return None;
            }
            match RunMetrics::from_run_result(run) {
                Ok(metrics) => {
                    runs_out.insert(slot, metrics);
                    Some(run.clone())
                }
                Err(DiskError::Tamper(_)) | Err(DiskError::NotRegularFile(_)) => {
                    promote_status(status, VerdictStatus::Tampered);
                    reasons.insert("disk_tamper".to_string());
                    runs_out.insert(slot, RunMetrics::empty());
                    None
                }
                Err(_) => {
                    promote_status(status, VerdictStatus::InfraError);
                    reasons.insert("disk_io_error".to_string());
                    runs_out.insert(slot, RunMetrics::empty());
                    None
                }
            }
        }
        Err(DiskError::Tamper(_)) | Err(DiskError::NotRegularFile(_)) => {
            promote_status(status, VerdictStatus::Tampered);
            reasons.insert("disk_tamper".to_string());
            runs_out.insert(slot, RunMetrics::empty());
            None
        }
        Err(DiskError::Io(_)) => {
            promote_status(status, VerdictStatus::InfraError);
            reasons.insert("disk_io_error".to_string());
            runs_out.insert(slot, RunMetrics::empty());
            None
        }
    }
}

/// Computes the differential verdict across R0, R1, R2, and optional R3 runs.
///
/// Status precedence (highest to lowest):
/// `Tampered` > `InfraError` > `Unresolved` > `Review` > `Resolved`.
pub fn verdict(
    r0: Result<RunResult, DiskError>,
    r1: Result<RunResult, DiskError>,
    r2: Result<RunResult, DiskError>,
    r3: Option<Result<RunResult, DiskError>>,
    plan: &GradingPlan,
) -> Verdict {
    let mut status = VerdictStatus::Resolved;
    let mut reasons = BTreeSet::new();
    let mut runs_out = BTreeMap::new();

    if !plan.is_valid() {
        promote_status(&mut status, VerdictStatus::InfraError);
        reasons.insert("invalid_plan".to_string());
    }

    let valid_r0 = inspect_run_slot(RunId::R0, &r0, &mut status, &mut reasons, &mut runs_out);
    let valid_r1 = inspect_run_slot(RunId::R1, &r1, &mut status, &mut reasons, &mut runs_out);
    let valid_r2 = inspect_run_slot(RunId::R2, &r2, &mut status, &mut reasons, &mut runs_out);
    let valid_r3 = match r3 {
        Some(ref r3_res) => {
            inspect_run_slot(RunId::R3, r3_res, &mut status, &mut reasons, &mut runs_out)
        }
        None => None,
    };

    if let Some(ref r1_run) = valid_r1 {
        let mut mutant_not_failed = false;
        for mutated_id in plan.mutated.iter().take(MAX_PLAN_TESTS) {
            match r1_run.tests.get(mutated_id) {
                Some(TestStatus::Failed) => {}
                _ => {
                    mutant_not_failed = true;
                    break;
                }
            }
        }
        if mutant_not_failed {
            promote_status(&mut status, VerdictStatus::Tampered);
            reasons.insert("mutant_passed".to_string());
        }
    }

    if let (Some(ref r0_run), Some(ref r2_run)) = (&valid_r0, &valid_r2) {
        let mut mismatch = false;
        for (r0_id, r2_id) in plan.equivalents.iter().take(MAX_EQUIVALENT_PAIRS) {
            let s0 = r0_run.tests.get(r0_id);
            let s2 = r2_run.tests.get(r2_id);
            if s0.is_none() || s2.is_none() || s0 != s2 {
                mismatch = true;
                break;
            }
        }
        if mismatch {
            promote_status(&mut status, VerdictStatus::Tampered);
            reasons.insert("equivalence_mismatch".to_string());
        }
    }

    if let Some(ref r0_run) = valid_r0 {
        match r0_run.supervisor.exit {
            SupervisorExit::Clean => {}
            SupervisorExit::Timeout => {
                promote_status(&mut status, VerdictStatus::InfraError);
                reasons.insert("supervisor_timeout".to_string());
            }
            SupervisorExit::Crash => {
                promote_status(&mut status, VerdictStatus::InfraError);
                reasons.insert("supervisor_crash".to_string());
            }
        }

        let mut f2p_failed = false;
        for test_id in plan.f2p.iter().take(MAX_PLAN_TESTS) {
            if r0_run.tests.get(test_id) != Some(&TestStatus::Passed) {
                f2p_failed = true;
                break;
            }
        }
        if f2p_failed {
            promote_status(&mut status, VerdictStatus::Unresolved);
            reasons.insert("f2p_failed".to_string());
        }

        let mut p2p_failed = false;
        for test_id in plan.p2p.iter().take(MAX_PLAN_TESTS) {
            if r0_run.tests.get(test_id) != Some(&TestStatus::Passed) {
                p2p_failed = true;
                break;
            }
        }
        if p2p_failed {
            promote_status(&mut status, VerdictStatus::Unresolved);
            reasons.insert("p2p_failed".to_string());
        }
    }

    if let Some(ref r3_run) = valid_r3 {
        let all_f2p_passed = plan
            .f2p
            .iter()
            .take(MAX_PLAN_TESTS)
            .all(|test_id| r3_run.tests.get(test_id) == Some(&TestStatus::Passed));
        if all_f2p_passed {
            promote_status(&mut status, VerdictStatus::Review);
            reasons.insert("fix_removal_passed".to_string());
        }
    }

    let ordered_reasons: Vec<String> = reasons.into_iter().collect();
    Verdict {
        status,
        reasons: ordered_reasons,
        runs: runs_out,
    }
}
