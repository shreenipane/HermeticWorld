#![forbid(unsafe_code)]

use hermetic_grader_result::{
    encode_disk, parse_disk_bytes, read_bounded_regular_file, read_disk, sha256_bytes, sha256_hex,
    verdict, write_disk, DiskError, GradingPlan, InvalidFileType, RunId, RunResult, SupervisorExit,
    SupervisorSummary, TamperReason, TestStatus, VerdictStatus, DISK_BYTES, HEADER_BYTES,
    MAX_NODE_ID_BYTES, PAYLOAD_CAP,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn run(id: RunId, status: TestStatus) -> RunResult {
    RunResult {
        run: id,
        variant_set: "a".repeat(64),
        tests: BTreeMap::from([("test".into(), status)]),
        supervisor: SupervisorSummary {
            exit: SupervisorExit::Clean,
            tests_started: 1,
            tests_finished: 1,
        },
    }
}

fn plan() -> GradingPlan {
    GradingPlan {
        f2p: BTreeSet::from(["test".into()]),
        p2p: BTreeSet::new(),
        mutated: BTreeSet::from(["test".into()]),
        equivalents: BTreeMap::from([("test".into(), "test".into())]),
    }
}

fn raw_disk(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= PAYLOAD_CAP);
    let mut image = vec![0; DISK_BYTES];
    image[..4].copy_from_slice(b"HGRD");
    image[4..6].copy_from_slice(&1u16.to_be_bytes());
    image[8..12].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    image[12..HEADER_BYTES].copy_from_slice(&sha256_bytes(payload));
    image[HEADER_BYTES..HEADER_BYTES + payload.len()].copy_from_slice(payload);
    image
}

#[test]
fn serializer_stops_at_payload_cap_before_touching_destination() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("result");
    fs::write(&path, b"existing result").unwrap();
    let mut result = run(RunId::R0, TestStatus::Passed);
    result.tests = (0..2_000)
        .map(|i| (format!("{i:04}{}", "x".repeat(1_020)), TestStatus::Passed))
        .collect();
    result.supervisor.tests_started = 2_000;
    result.supervisor.tests_finished = 2_000;
    // The sentinel means serialization stopped at the limit rather than first
    // constructing the complete, oversized payload to learn its length.
    let expected = Err(DiskError::Tamper(TamperReason::PayloadLengthExceedsCap {
        len: PAYLOAD_CAP as u32 + 1,
    }));
    assert_eq!(write_disk(&result, &path), expected);
    assert_eq!(fs::read(&path).unwrap(), b"existing result");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn generic_reader_cannot_disable_the_named_file_cap() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("oversized");
    fs::File::create(&path)
        .unwrap()
        .set_len(DISK_BYTES as u64 + 1)
        .unwrap();
    assert_eq!(
        read_bounded_regular_file(&path, usize::MAX),
        Err(DiskError::Io(io::ErrorKind::InvalidInput))
    );
    assert_eq!(
        read_bounded_regular_file(&path, DISK_BYTES),
        Err(DiskError::Io(io::ErrorKind::InvalidData))
    );
}

#[cfg(unix)]
#[test]
fn result_files_are_private_on_creation_and_replacement() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let path = dir.path().join("result");
    for _ in 0..2 {
        write_disk(&run(RunId::R0, TestStatus::Passed), &path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }
}

#[test]
fn json_error_classification_cannot_be_spoofed_by_field_names_or_values() {
    for marker in [
        "HERMETIC_ERR_DUPLICATE_KEY",
        "HERMETIC_ERR_TOO_MANY_TESTS",
        "HERMETIC_ERR_INVALID_NODE_ID",
        "duplicate field",
    ] {
        let mut value = serde_json::to_value(run(RunId::R0, TestStatus::Passed)).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert(marker.into(), 0.into());
        assert_eq!(
            parse_disk_bytes(&raw_disk(&serde_json::to_vec(&value).unwrap())),
            Err(DiskError::Tamper(TamperReason::InvalidJson))
        );
        value.as_object_mut().unwrap().remove(marker);
        value["run"] = marker.into();
        assert_eq!(
            parse_disk_bytes(&raw_disk(&serde_json::to_vec(&value).unwrap())),
            Err(DiskError::Tamper(TamperReason::InvalidJson))
        );
    }
}

#[test]
fn non_regular_disk_errors_are_tamper_in_every_verdict_slot() {
    for kind in [
        InvalidFileType::Symlink,
        InvalidFileType::Fifo,
        InvalidFileType::Device,
        InvalidFileType::Socket,
        InvalidFileType::Directory,
        InvalidFileType::Other,
    ] {
        for slot in 0..4 {
            let mut results = [
                Ok(run(RunId::R0, TestStatus::Passed)),
                Ok(run(RunId::R1, TestStatus::Failed)),
                Ok(run(RunId::R2, TestStatus::Passed)),
                Ok(run(RunId::R3, TestStatus::Passed)),
            ];
            // Make infra_error, unresolved and review active as well.
            let r0 = results[0].as_mut().unwrap();
            r0.supervisor.exit = SupervisorExit::Timeout;
            r0.tests.insert("test".into(), TestStatus::Failed);
            results[2]
                .as_mut()
                .unwrap()
                .tests
                .insert("test".into(), TestStatus::Failed);
            results[slot] = Err(DiskError::NotRegularFile(kind));
            let [r0, r1, r2, r3] = results;
            let out = verdict(r0, r1, r2, Some(r3), &plan());
            assert_eq!(out.status, VerdictStatus::Tampered, "{kind:?}, slot {slot}");
            assert!(out.reasons.iter().any(|reason| reason == "disk_tamper"));
        }
    }
}

#[cfg(unix)]
#[test]
fn socket_disk_is_reported_as_tampering() {
    use std::os::unix::net::UnixListener;
    let dir = tempdir().unwrap();
    let path = dir.path().join("socket");
    let _listener = UnixListener::bind(&path).unwrap();
    assert!(matches!(read_disk(&path), Err(DiskError::Tamper(_))));
}

#[test]
fn ambiguous_plan_collections_are_rejected() {
    for json in [
        r#"{"f2p":[],"p2p":[],"mutated":[],"equivalents":{"test":"failing","test":"passing"}}"#,
        r#"{"f2p":["test","test"],"p2p":[],"mutated":[],"equivalents":{}}"#,
        r#"{"f2p":[],"p2p":["test","test"],"mutated":[],"equivalents":{}}"#,
        r#"{"f2p":[],"p2p":[],"mutated":["test","test"],"equivalents":{}}"#,
        r#"{"f2p":[],"p2p":[],"mutated":[],"equivalents":{"test":"first","te\u0073t":"second"}}"#,
    ] {
        assert!(serde_json::from_str::<GradingPlan>(json).is_err(), "{json}");
    }
}

#[test]
fn plan_collection_limits_apply_during_deserialization() {
    use hermetic_grader_result::{MAX_EQUIVALENT_PAIRS, MAX_PLAN_TESTS};
    for field in ["f2p", "p2p", "mutated"] {
        let mut value = serde_json::to_value(plan()).unwrap();
        value[field] = (0..=MAX_PLAN_TESTS)
            .map(|i| format!("t{i}"))
            .collect::<Vec<_>>()
            .into();
        assert!(
            serde_json::from_value::<GradingPlan>(value).is_err(),
            "{field}"
        );
    }
    let mut value = serde_json::to_value(plan()).unwrap();
    value["equivalents"] = serde_json::to_value(
        (0..=MAX_EQUIVALENT_PAIRS)
            .map(|i| (format!("t{i}"), "equivalent"))
            .collect::<BTreeMap<_, _>>(),
    )
    .unwrap();
    assert!(serde_json::from_value::<GradingPlan>(value).is_err());
}

#[test]
fn r3_all_f2p_rule_includes_an_empty_f2p_set() {
    let mut plan = plan();
    plan.f2p.clear();
    let out = verdict(
        Ok(run(RunId::R0, TestStatus::Passed)),
        Ok(run(RunId::R1, TestStatus::Failed)),
        Ok(run(RunId::R2, TestStatus::Passed)),
        Some(Ok(run(RunId::R3, TestStatus::Failed))),
        &plan,
    );
    assert_eq!(out.status, VerdictStatus::Review);
    assert_eq!(out.reasons, ["fix_removal_passed"]);
}

#[test]
fn cli_closed_stdout_returns_io_exit_without_panicking() {
    let dir = tempdir().unwrap();
    let r0 = dir.path().join("r0");
    let r1 = dir.path().join("r1");
    let r2 = dir.path().join("r2");
    let plan_path = dir.path().join("plan");
    write_disk(&run(RunId::R0, TestStatus::Passed), &r0).unwrap();
    write_disk(&run(RunId::R1, TestStatus::Failed), &r1).unwrap();
    write_disk(&run(RunId::R2, TestStatus::Passed), &r2).unwrap();
    fs::write(&plan_path, serde_json::to_vec(&plan()).unwrap()).unwrap();
    // Block the child on stdin until its stdout read end has been closed.
    // The shell's read command is only a synchronization barrier.
    use std::io::Write;
    let mut child = Command::new("sh")
        .args(["-c", "read barrier; exec \"$@\"", "barrier"])
        .arg(env!("CARGO_BIN_EXE_hermetic-grader-verdict"))
        .arg("--r0")
        .arg(&r0)
        .arg("--r1")
        .arg(&r1)
        .arg("--r2")
        .arg(&r2)
        .arg("--plan")
        .arg(&plan_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take().unwrap());
    child.stdin.take().unwrap().write_all(b"go\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stderr, b"error: grading input or output failure\n");
}

#[test]
fn cli_closed_stderr_returns_usage_exit_without_panicking() {
    use std::io::Write;
    let mut child = Command::new("sh")
        .args(["-c", "read barrier; exec \"$@\"", "barrier"])
        .arg(env!("CARGO_BIN_EXE_hermetic-grader-verdict"))
        .arg("--invalid")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stderr.take().unwrap());
    child.stdin.take().unwrap().write_all(b"go\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

#[test]
fn cli_rejects_oversized_path_arguments_as_usage_before_file_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_hermetic-grader-verdict"))
        .arg("--r0")
        .arg("x".repeat(4_097))
        .args(["--r1", "missing", "--r2", "missing", "--plan", "missing"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"usage: hermetic-grader-verdict --r0 F --r1 F --r2 F [--r3 F] --plan F\n"
    );
}

#[test]
fn actual_hgrd_image_has_a_literal_known_answer_digest() {
    let mut result = run(RunId::R0, TestStatus::Passed);
    result.variant_set = "0123456789abcdef".repeat(4);
    result.tests = BTreeMap::from([("test_alpha".into(), TestStatus::Passed)]);
    let (bytes, digest) = encode_disk(&result).unwrap();
    assert_eq!(sha256_bytes(&bytes), digest);
    assert_eq!(
        sha256_hex(&digest),
        "ff9d96204a8b6db5cd649a63fcde25ea786775859f8607d93090439d2f075f93"
    );
}

#[test]
fn reader_checks_node_id_length_and_nested_schema_rules() {
    for id in ["x".repeat(MAX_NODE_ID_BYTES + 1), "non_ascii_é".into()] {
        let mut result = run(RunId::R0, TestStatus::Passed);
        result.tests = BTreeMap::from([(id, TestStatus::Passed)]);
        assert_eq!(
            parse_disk_bytes(&raw_disk(&serde_json::to_vec(&result).unwrap())),
            Err(DiskError::Tamper(TamperReason::InvalidNodeId))
        );
    }
    let mut value = serde_json::to_value(run(RunId::R0, TestStatus::Passed)).unwrap();
    value["supervisor"]["extra"] = true.into();
    assert_eq!(
        parse_disk_bytes(&raw_disk(&serde_json::to_vec(&value).unwrap())),
        Err(DiskError::Tamper(TamperReason::InvalidJson))
    );
    for payload in [b"{".as_slice(), b"[]", b"null", b"", b"{}{}"] {
        assert!(matches!(
            parse_disk_bytes(&raw_disk(payload)),
            Err(DiskError::Tamper(_))
        ));
    }
}

#[test]
fn every_nonpassing_or_absent_required_test_is_rejected() {
    for status in [
        TestStatus::Failed,
        TestStatus::Skipped,
        TestStatus::Error,
        TestStatus::Missing,
    ] {
        for field in ["f2p", "p2p"] {
            let mut plan = plan();
            if field == "p2p" {
                plan.p2p = std::mem::take(&mut plan.f2p);
            }
            let output = verdict(
                Ok(run(RunId::R0, status)),
                Ok(run(RunId::R1, TestStatus::Failed)),
                Ok(run(RunId::R2, status)),
                None,
                &plan,
            );
            assert_eq!(output.status, VerdictStatus::Unresolved);
            assert_eq!(output.reasons, [format!("{field}_failed")]);
        }
    }
    for status in [
        Some(TestStatus::Passed),
        Some(TestStatus::Skipped),
        Some(TestStatus::Error),
        Some(TestStatus::Missing),
        None,
    ] {
        let mut r1 = run(RunId::R1, status.unwrap_or(TestStatus::Missing));
        if status.is_none() {
            r1.tests.clear();
            r1.supervisor.tests_started = 0;
            r1.supervisor.tests_finished = 0;
        }
        let output = verdict(
            Ok(run(RunId::R0, TestStatus::Passed)),
            Ok(r1),
            Ok(run(RunId::R2, TestStatus::Passed)),
            None,
            &plan(),
        );
        assert_eq!(output.status, VerdictStatus::Tampered);
        assert_eq!(output.reasons, ["mutant_passed"]);
    }
    let mut r0 = run(RunId::R0, TestStatus::Missing);
    r0.tests.clear();
    r0.supervisor.tests_started = 0;
    r0.supervisor.tests_finished = 0;
    let mut r2 = r0.clone();
    r2.run = RunId::R2;
    let output = verdict(
        Ok(r0),
        Ok(run(RunId::R1, TestStatus::Failed)),
        Ok(r2),
        None,
        &plan(),
    );
    assert_eq!(output.status, VerdictStatus::Tampered);
    assert_eq!(output.reasons, ["equivalence_mismatch", "f2p_failed"]);
}

#[test]
fn verdict_json_has_literal_hashes_counts_and_slot_order() {
    let out = verdict(
        Ok(run(RunId::R0, TestStatus::Passed)),
        Ok(run(RunId::R1, TestStatus::Failed)),
        Ok(run(RunId::R2, TestStatus::Passed)),
        None,
        &plan(),
    );
    let expected = r#"{"status":"resolved","reasons":[],"runs":{"R0":{"disk_sha256":"7b2653c4fb4dd8747fa054a82f0781247a0ba63cff6c9fdb04fb6b89940c8e8b","tests_total":1,"tests_started":1,"tests_finished":1,"passed":1,"failed":0,"skipped":0,"error":0,"missing":0},"R1":{"disk_sha256":"51faf5b4c720f75f36fa84227f9a2d3addf1ccf55e225a15c4647f18361f992a","tests_total":1,"tests_started":1,"tests_finished":1,"passed":0,"failed":1,"skipped":0,"error":0,"missing":0},"R2":{"disk_sha256":"f5484105e6b2b781457b4a58dd8b87b2840dbeaefe800077bbd53ecbcb5b820b","tests_total":1,"tests_started":1,"tests_finished":1,"passed":1,"failed":0,"skipped":0,"error":0,"missing":0}}}"#;
    assert_eq!(serde_json::to_string(&out).unwrap(), expected);
}
