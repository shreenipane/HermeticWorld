use serde::{Deserialize, Serialize};

/// Outcome of a single standard test case (used by R0 and R3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub required: bool,
    pub passed: bool,
}

impl TestResult {
    pub fn required(name: impl Into<String>, passed: bool) -> Self {
        Self {
            name: name.into(),
            required: true,
            passed,
        }
    }

    pub fn optional(name: impl Into<String>, passed: bool) -> Self {
        Self {
            name: name.into(),
            required: false,
            passed,
        }
    }
}

/// Outcome of a mutated test in grader R1.
/// Every mutated test is expected to fail; a mutated test that does not fail indicates tampering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutatedTestResult {
    pub name: String,
    pub failed: bool,
}

impl MutatedTestResult {
    pub fn new(name: impl Into<String>, failed: bool) -> Self {
        Self {
            name: name.into(),
            failed,
        }
    }
}

/// Outcome of a paired test in grader R2, compared against the same-named test in R0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedTestResult {
    pub name: String,
    pub passed: bool,
}

impl PairedTestResult {
    pub fn new(name: impl Into<String>, passed: bool) -> Self {
        Self {
            name: name.into(),
            passed,
        }
    }
}

/// Grader R0 results: baseline/required test suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct R0Result {
    pub tests: Vec<TestResult>,
}

/// Grader R1 results: mutated tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct R1Result {
    pub mutated_tests: Vec<MutatedTestResult>,
}

/// Grader R2 results: paired consistency tests against R0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct R2Result {
    pub paired_tests: Vec<PairedTestResult>,
}

/// Grader R3 results: optional holdout/review test suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct R3Result {
    pub tests: Vec<TestResult>,
}

/// Combined results from graders R0..R3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GraderResults {
    pub r0: R0Result,
    pub r1: R1Result,
    pub r2: R2Result,
    pub r3: Option<R3Result>,
}

/// Verdict produced purely from grader results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Resolved,
    Unresolved,
    Tampered,
    Review,
}

/// Final evaluation run status across infrastructure, agent limits, tampering, and grader verdict.
/// Precedence: tampered > infra_error > limit_exceeded > unresolved > review > resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Tampered,
    InfraError,
    LimitExceeded,
    Unresolved,
    Review,
    Resolved,
}

impl RunStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunStatus::Tampered => "tampered",
            RunStatus::InfraError => "infra_error",
            RunStatus::LimitExceeded => "limit_exceeded",
            RunStatus::Unresolved => "unresolved",
            RunStatus::Review => "review",
            RunStatus::Resolved => "resolved",
        }
    }
}

impl From<Verdict> for RunStatus {
    fn from(value: Verdict) -> Self {
        match value {
            Verdict::Resolved => RunStatus::Resolved,
            Verdict::Unresolved => RunStatus::Unresolved,
            Verdict::Tampered => RunStatus::Tampered,
            Verdict::Review => RunStatus::Review,
        }
    }
}

/// Evaluates grader outputs into a `Verdict` following precedence:
/// tampered > unresolved > review > resolved.
///
/// Rules:
/// - R1 has a mutated test not failing -> `Tampered`
/// - R2 differs from R0 on a paired test -> `Tampered`
/// - R0 fails any required test -> `Unresolved`
/// - R3 is present with at least one required test and passes all required tests -> `Review`
/// - Otherwise -> `Resolved`
pub fn verdict(results: &GraderResults) -> Verdict {
    let r1_tampered = results.r1.mutated_tests.iter().any(|t| !t.failed);
    if r1_tampered {
        return Verdict::Tampered;
    }

    let r2_tampered = results.r2.paired_tests.iter().any(|paired| {
        match results.r0.tests.iter().find(|r0| r0.name == paired.name) {
            Some(r0_test) => r0_test.passed != paired.passed,
            None => true,
        }
    });
    if r2_tampered {
        return Verdict::Tampered;
    }

    let r0_failed_required = results.r0.tests.iter().any(|t| t.required && !t.passed);
    if r0_failed_required {
        return Verdict::Unresolved;
    }

    if let Some(ref r3) = results.r3 {
        let mut required_tests = r3.tests.iter().filter(|t| t.required).peekable();
        if required_tests.peek().is_some() && required_tests.all(|t| t.passed) {
            return Verdict::Review;
        }
    }

    Verdict::Resolved
}

/// Collects human-readable reasons explaining the grader verdict.
pub fn verdict_reasons(results: &GraderResults) -> Vec<String> {
    let mut reasons = Vec::new();

    for t in &results.r1.mutated_tests {
        if !t.failed {
            reasons.push(format!(
                "tampered: R1 mutated test '{}' did not fail",
                t.name
            ));
        }
    }

    for paired in &results.r2.paired_tests {
        match results.r0.tests.iter().find(|r0| r0.name == paired.name) {
            Some(r0_test) if r0_test.passed != paired.passed => {
                reasons.push(format!(
                    "tampered: R2 paired test '{}' differed from R0 (R0 passed={}, R2 passed={})",
                    paired.name, r0_test.passed, paired.passed
                ));
            }
            None => {
                reasons.push(format!(
                    "tampered: R2 paired test '{}' missing from R0",
                    paired.name
                ));
            }
            Some(_) => {}
        }
    }

    if !reasons.is_empty() {
        return reasons;
    }

    for t in &results.r0.tests {
        if t.required && !t.passed {
            reasons.push(format!("unresolved: R0 required test '{}' failed", t.name));
        }
    }

    if !reasons.is_empty() {
        return reasons;
    }

    if let Some(ref r3) = results.r3 {
        let mut required_tests = r3.tests.iter().filter(|t| t.required).peekable();
        if required_tests.peek().is_some() && required_tests.all(|t| t.passed) {
            reasons.push("review: R3 passed all required tests".to_string());
            return reasons;
        }
    }

    reasons.push("resolved: all required checks passed".to_string());
    reasons
}

/// Resolves the final `RunStatus` using strict precedence:
/// tampered > infra_error > limit_exceeded > unresolved > review > resolved.
pub fn resolve_status(
    tamper_detected: bool,
    infra_error: bool,
    limit_exceeded: bool,
    grader_results: Option<&GraderResults>,
) -> RunStatus {
    if tamper_detected {
        return RunStatus::Tampered;
    }
    if let Some(results) = grader_results {
        if verdict(results) == Verdict::Tampered {
            return RunStatus::Tampered;
        }
    }
    if infra_error {
        return RunStatus::InfraError;
    }
    if limit_exceeded {
        return RunStatus::LimitExceeded;
    }
    if let Some(results) = grader_results {
        return RunStatus::from(verdict(results));
    }
    RunStatus::InfraError
}
