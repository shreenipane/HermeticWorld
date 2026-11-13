#![forbid(unsafe_code)]

//! Regression: the guest supervisor wrote the result disk header little-endian while the
//! host parser (hermetic-grader-result) reads it big-endian, so every real result disk
//! was classified as tampered on the host.

use std::collections::BTreeMap;

use hermetic_grader_result::{
    encode_disk, parse_disk_bytes, RunId, RunResult, SupervisorExit as HostExit,
    SupervisorSummary as HostSummary, TestStatus,
};
use hermetic_grader_supervisor::{
    encode_result_disk, FinalTestOutcome, ResultPayload, RunName, SupervisorExit, SupervisorSummary,
};

const VARIANT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn supervisor_result_disk_is_accepted_by_host_parser() {
    let mut tests = BTreeMap::new();
    tests.insert("t.py::test_a".to_string(), FinalTestOutcome::Passed);
    tests.insert("t.py::test_b".to_string(), FinalTestOutcome::Failed);
    let payload = ResultPayload {
        run: RunName::R0,
        variant_set: VARIANT.to_string(),
        tests,
        supervisor: SupervisorSummary {
            exit: SupervisorExit::Clean,
            tests_started: 2,
            tests_finished: 2,
        },
    };
    let image = encode_result_disk(&payload).expect("supervisor encode");
    let parsed = parse_disk_bytes(&image).expect("host parser accepts supervisor disk");

    let mut host_tests = BTreeMap::new();
    host_tests.insert("t.py::test_a".to_string(), TestStatus::Passed);
    host_tests.insert("t.py::test_b".to_string(), TestStatus::Failed);
    let expected = RunResult {
        run: RunId::R0,
        variant_set: VARIANT.to_string(),
        tests: host_tests,
        supervisor: HostSummary {
            exit: HostExit::Clean,
            tests_started: 2,
            tests_finished: 2,
        },
    };
    assert_eq!(parsed, expected);
    let (host_image, _) = encode_disk(&expected).expect("host encode");
    assert_eq!(
        image, host_image,
        "guest and host images must be byte-identical"
    );
}
