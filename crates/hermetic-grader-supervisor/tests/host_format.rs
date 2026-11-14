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

#[test]
fn recovery_replaces_clean_results_with_host_infra_error_without_spawning_tests() {
    use hermetic_grader_result::{verdict, GradingPlan, VerdictStatus};
    use hermetic_grader_supervisor::{write_infra_error, FakeOs, OsEvent, RunConfig};
    use std::path::Path;

    let mut recovered = Vec::new();
    for run in [RunName::R0, RunName::R1, RunName::R2] {
        let config = RunConfig {
            argv: vec!["pytest".into()],
            env: BTreeMap::new(),
            cwd: "/work/repo".into(),
            sandbox: Default::default(),
            deadline_seconds: 120,
            expected_test_ids: vec!["t.py::test_a".into()],
            variant_set: VARIANT.into(),
        };
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config");
        let disk_path = tmp.path().join("result");
        std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let clean = ResultPayload {
            run,
            variant_set: VARIANT.into(),
            tests: BTreeMap::from([("t.py::test_a".into(), FinalTestOutcome::Passed)]),
            supervisor: SupervisorSummary {
                exit: SupervisorExit::Clean,
                tests_started: 1,
                tests_finished: 1,
            },
        };
        std::fs::write(&disk_path, encode_result_disk(&clean).unwrap()).unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_hermetic-grader-supervisor"))
            .arg("--infra-error")
            .arg("--config")
            .arg(&config_path)
            .arg("--result-disk")
            .arg(&disk_path)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr,
            b"grader-supervisor phase infra-error-write\ngrader-supervisor phase infra-error-synced\n");
        let bytes = std::fs::read(&disk_path).unwrap();
        let parsed = parse_disk_bytes(&bytes).unwrap();
        assert_eq!(parsed.supervisor.exit, HostExit::Crash);
        assert_eq!(parsed.tests["t.py::test_a"], TestStatus::Missing);
        recovered.push(Ok(parsed));

        let mut fake = FakeOs::new();
        fake.insert_file("config", serde_json::to_vec(&config).unwrap());
        fake.insert_file("disk", encode_result_disk(&clean).unwrap());
        write_infra_error(&mut fake, Path::new("config"), Path::new("disk")).unwrap();
        assert_eq!(fake.written_file(Path::new("disk")).unwrap(), bytes);
        assert!(!fake.events().iter().any(|e| matches!(e, OsEvent::Spawn(_))));
        fake.insert_file("config", b"{}".to_vec());
        let before = fake.events().len();
        assert!(write_infra_error(&mut fake, Path::new("config"), Path::new("untouched")).is_err());
        assert!(fake.written_file(Path::new("untouched")).is_none());
        assert_eq!(fake.events().len(), before + 1);
    }
    let plan = GradingPlan {
        f2p: ["t.py::test_a".into()].into(),
        p2p: Default::default(),
        mutated: Default::default(),
        equivalents: Default::default(),
    };
    let r2 = recovered.pop().unwrap();
    let r1 = recovered.pop().unwrap();
    let r0 = recovered.pop().unwrap();
    assert_eq!(
        verdict(r0, r1, r2, None, &plan).status,
        VerdictStatus::InfraError
    );
}
