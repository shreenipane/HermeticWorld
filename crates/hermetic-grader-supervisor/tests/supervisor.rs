#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use hermetic_grader_supervisor::{
    canonical_payload_json, decode_result_disk, encode_result_disk, run_supervisor, DecodedRecord,
    DiskError, EndRecord, ExitKind, FakeChildScript, FakeOs, FakeStep, FinalTestOutcome,
    FinishRecord, Os, OsEvent, RealOs, RecordEncoder, RecordOutcome, ResultPayload, RunConfig,
    RunName, SpawnSpec, StartRecord, SupervisorExit, SupervisorSummary, TreeStatus,
    MAX_RECORD_PAYLOAD_BYTES, RESULT_DISK_BYTES, RESULT_DISK_HEADER_BYTES, RESULT_DISK_MAGIC,
};
use sha2::{Digest, Sha256};

const SAMPLE_VARIANT_SHA256: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn make_config_json(deadline_seconds: u64, expected: &[&str], run: RunName) -> Vec<u8> {
    let mut env = BTreeMap::new();
    env.insert("PYTHONDONTWRITEBYTECODE".to_string(), "1".to_string());
    let cfg = RunConfig {
        argv: vec!["pytest".to_string(), "-q".to_string()],
        env,
        cwd: "/workspace".to_string(),
        deadline_seconds,
        expected_test_ids: expected.iter().map(|s| (*s).to_string()).collect(),
        run,
        variant_set: SAMPLE_VARIANT_SHA256.to_string(),
    };
    serde_json::to_vec(&cfg).expect("serialize RunConfig")
}

fn encode_records(records: &[DecodedRecord]) -> Vec<u8> {
    let mut stream = Vec::new();
    stream.extend_from_slice(&RecordEncoder::stream_header());
    for rec in records {
        let frame = RecordEncoder::encode_record(rec).expect("encode record");
        stream.extend_from_slice(&frame);
    }
    stream
}

/// Requirement 1 & 6: Verifies `Os` trait abstraction (`SpawnSpec` forwarding argv, env, cwd)
/// and real `RealOs` file/process execution offline using `tempfile`.
#[test]
fn test_os_trait_and_real_os_offline() {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let config_path = tmp.path().join("run_config.json");
    let disk_path = tmp.path().join("result_disk.img");

    let mut real_os = RealOs::new();
    let sample_bytes = b"{\"hello\":\"hermetic\"}";
    real_os
        .write_file_atomic(&config_path, sample_bytes)
        .expect("atomic write");
    let read_back = real_os
        .read_file(&config_path, 1024)
        .expect("read file back");
    assert_eq!(read_back, sample_bytes);

    // Exercise RealOs::spawn + read_pipe + wait_tree with a minimal offline executable if available.
    #[cfg(unix)]
    if Path::new("/bin/sh").exists() {
        let mut env = BTreeMap::new();
        env.insert("HERMETIC_TEST".to_string(), "ok".to_string());
        let spec = SpawnSpec {
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf 'HGR1' >&2".to_string(),
            ],
            env,
            cwd: tmp.path().to_path_buf(),
        };
        let mut child = real_os.spawn(&spec).expect("spawn /bin/sh");
        let mut collected = Vec::new();
        for _ in 0..200 {
            match real_os
                .read_pipe(&mut child, 64, Duration::from_millis(20))
                .expect("read pipe")
            {
                hermetic_grader_supervisor::PipeRead::Data(d) => collected.extend_from_slice(&d),
                hermetic_grader_supervisor::PipeRead::WouldBlock => {}
                hermetic_grader_supervisor::PipeRead::Eof => break,
            }
        }
        for _ in 0..200 {
            if let TreeStatus::Exited(kind) = real_os
                .wait_tree(&mut child, Duration::from_millis(20))
                .expect("wait tree")
            {
                assert_eq!(kind, ExitKind::Clean);
                break;
            }
        }
        assert_eq!(collected, b"HGR1");
    }

    // Exercise the compiled binary CLI (`--config FILE --result-disk FILE`) error path offline.
    let bin = env!("CARGO_BIN_EXE_hermetic-grader-supervisor");
    let output = Command::new(bin)
        .arg("--config")
        .arg(&config_path)
        .arg("--result-disk")
        .arg(&disk_path)
        .output()
        .expect("run binary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid run config JSON"));
}

/// Requirement 2, 3, 4, 5: Normal run with passed, failed, skipped, and error outcomes.
/// Also verifies that stdout/exit codes are ignored (only pipe records determine outcomes).
#[test]
fn test_normal_run() {
    let mut os = FakeOs::new();
    let cfg_path = Path::new("/etc/hermetic/run.json");
    let disk_path = Path::new("/dev/vdb");

    os.insert_file(
        cfg_path,
        make_config_json(
            30,
            &["test_alpha", "test_beta", "test_gamma", "test_delta"],
            RunName::R1,
        ),
    );

    let stream = encode_records(&[
        DecodedRecord::Start(StartRecord {
            seq: 1,
            nodeid: "test_alpha".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 2,
            nodeid: "test_alpha".to_string(),
            outcome: RecordOutcome::Passed,
            duration_ms: 12,
        }),
        DecodedRecord::Start(StartRecord {
            seq: 3,
            nodeid: "test_beta".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 4,
            nodeid: "test_beta".to_string(),
            outcome: RecordOutcome::Failed,
            duration_ms: 45,
        }),
        DecodedRecord::Start(StartRecord {
            seq: 5,
            nodeid: "test_gamma".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 6,
            nodeid: "test_gamma".to_string(),
            outcome: RecordOutcome::Skipped,
            duration_ms: 1,
        }),
        DecodedRecord::Start(StartRecord {
            seq: 7,
            nodeid: "test_delta".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 8,
            nodeid: "test_delta".to_string(),
            outcome: RecordOutcome::Error,
            duration_ms: 9,
        }),
        DecodedRecord::End(EndRecord { count: 4 }),
    ]);

    // Split across small chunks to verify incremental framing across arbitrary chunk boundaries.
    let mid = stream.len() / 2;
    os.push_child_script(FakeChildScript::new(vec![
        FakeStep::EmitBytes(stream[..mid].to_vec()),
        FakeStep::Sleep(Duration::from_millis(50)),
        FakeStep::EmitBytes(stream[mid..].to_vec()),
        FakeStep::ExitTree(ExitKind::Clean),
    ]));

    let report = run_supervisor(&mut os, cfg_path, disk_path).expect("supervisor run");
    assert_eq!(report.unexpected_ids, 0);
    assert!(report.stream_error.is_none());
    assert_eq!(report.payload.run, RunName::R1);
    assert_eq!(report.payload.supervisor.exit, SupervisorExit::Clean);
    assert_eq!(report.payload.supervisor.tests_started, 4);
    assert_eq!(report.payload.supervisor.tests_finished, 4);
    assert_eq!(
        report.payload.tests.get("test_alpha"),
        Some(&FinalTestOutcome::Passed)
    );
    assert_eq!(
        report.payload.tests.get("test_beta"),
        Some(&FinalTestOutcome::Failed)
    );
    assert_eq!(
        report.payload.tests.get("test_gamma"),
        Some(&FinalTestOutcome::Skipped)
    );
    assert_eq!(
        report.payload.tests.get("test_delta"),
        Some(&FinalTestOutcome::Error)
    );

    let disk_bytes = os.written_file(disk_path).expect("result disk written");
    assert_eq!(disk_bytes.len(), RESULT_DISK_BYTES);
    let decoded = decode_result_disk(disk_bytes).expect("decode result disk");
    assert_eq!(decoded, report.payload);
}

/// Requirement 4 & 5: A test that calls `os._exit` after `START` never emits `FINISH` or `END`.
/// The started-but-unfinished test becomes `"failed"`, unstarted tests become `"missing"`,
/// and `supervisor.exit` becomes `"crash"`.
#[test]
fn test_os_exit_simulation_never_finishes() {
    let mut os = FakeOs::new();
    let cfg_path = Path::new("/run/config.json");
    let disk_path = Path::new("/run/result.disk");

    os.insert_file(
        cfg_path,
        make_config_json(30, &["test_1", "test_2", "test_3"], RunName::R0),
    );

    // Emit START+FINISH for test_1, START for test_2, then abruptly close pipe and exit (os._exit).
    let partial_stream = encode_records(&[
        DecodedRecord::Start(StartRecord {
            seq: 1,
            nodeid: "test_1".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 2,
            nodeid: "test_1".to_string(),
            outcome: RecordOutcome::Passed,
            duration_ms: 5,
        }),
        DecodedRecord::Start(StartRecord {
            seq: 3,
            nodeid: "test_2".to_string(),
        }),
    ]);

    os.push_child_script(FakeChildScript::new(vec![
        FakeStep::EmitBytes(partial_stream),
        FakeStep::ExitTree(ExitKind::Clean),
    ]));

    let report = run_supervisor(&mut os, cfg_path, disk_path).expect("supervisor run");
    assert_eq!(report.payload.supervisor.exit, SupervisorExit::Crash);
    assert_eq!(report.payload.supervisor.tests_started, 2);
    assert_eq!(report.payload.supervisor.tests_finished, 1);
    assert_eq!(
        report.payload.tests.get("test_1"),
        Some(&FinalTestOutcome::Passed)
    );
    assert_eq!(
        report.payload.tests.get("test_2"),
        Some(&FinalTestOutcome::Failed)
    );
    assert_eq!(
        report.payload.tests.get("test_3"),
        Some(&FinalTestOutcome::Missing)
    );
}

/// Requirement 2 & 5: Deadline expiry kills the whole process group and marks exit `"timeout"`.
#[test]
fn test_deadline_expiry_kills_and_marks_timeout() {
    let mut os = FakeOs::new();
    let cfg_path = Path::new("/run/config.json");
    let disk_path = Path::new("/run/result.disk");

    os.insert_file(
        cfg_path,
        make_config_json(2, &["test_fast", "test_hang", "test_later"], RunName::R2),
    );

    let prefix = encode_records(&[
        DecodedRecord::Start(StartRecord {
            seq: 1,
            nodeid: "test_fast".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 2,
            nodeid: "test_fast".to_string(),
            outcome: RecordOutcome::Passed,
            duration_ms: 3,
        }),
        DecodedRecord::Start(StartRecord {
            seq: 3,
            nodeid: "test_hang".to_string(),
        }),
    ]);

    os.push_child_script(
        FakeChildScript::new(vec![FakeStep::EmitBytes(prefix), FakeStep::HangForever])
            .with_post_kill_running_polls(2),
    );

    let report = run_supervisor(&mut os, cfg_path, disk_path).expect("supervisor run");
    assert_eq!(os.kill_count(), 1);
    assert_eq!(report.payload.supervisor.exit, SupervisorExit::Timeout);
    assert_eq!(
        report.payload.tests.get("test_fast"),
        Some(&FinalTestOutcome::Passed)
    );
    assert_eq!(
        report.payload.tests.get("test_hang"),
        Some(&FinalTestOutcome::Failed)
    );
    assert_eq!(
        report.payload.tests.get("test_later"),
        Some(&FinalTestOutcome::Missing)
    );
}

/// Requirement 3: Garbage on the pipe keeps the valid prefix and marks the rest failed.
#[test]
fn test_garbage_on_pipe_keeps_valid_prefix_marks_rest_failed() {
    let mut os = FakeOs::new();
    let cfg_path = Path::new("/run/config.json");
    let disk_path = Path::new("/run/result.disk");

    os.insert_file(
        cfg_path,
        make_config_json(10, &["test_ok", "test_mid", "test_unreached"], RunName::R3),
    );

    let mut corrupted = encode_records(&[
        DecodedRecord::Start(StartRecord {
            seq: 1,
            nodeid: "test_ok".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 2,
            nodeid: "test_ok".to_string(),
            outcome: RecordOutcome::Passed,
            duration_ms: 4,
        }),
        DecodedRecord::Start(StartRecord {
            seq: 3,
            nodeid: "test_mid".to_string(),
        }),
    ]);
    // Inject invalid record type 0xFF and random garbage bytes.
    corrupted.extend_from_slice(b"\xff\x05\x00\x00\x00garb!");

    os.push_child_script(FakeChildScript::new(vec![
        FakeStep::EmitBytes(corrupted),
        FakeStep::ExitTree(ExitKind::Clean),
    ]));

    let report = run_supervisor(&mut os, cfg_path, disk_path).expect("supervisor run");
    assert!(report.stream_error.is_some());
    assert_eq!(report.payload.supervisor.exit, SupervisorExit::Crash);
    assert_eq!(
        report.payload.tests.get("test_ok"),
        Some(&FinalTestOutcome::Passed)
    );
    assert_eq!(
        report.payload.tests.get("test_mid"),
        Some(&FinalTestOutcome::Failed)
    );
    assert_eq!(
        report.payload.tests.get("test_unreached"),
        Some(&FinalTestOutcome::Failed)
    );
}

/// Requirement 3: Records exceeding the 64 KiB cap are strictly rejected without OOM,
/// keeping the valid prefix and marking the rest failed.
#[test]
fn test_oversized_record_rejected_and_marks_rest_failed() {
    let mut os = FakeOs::new();
    let cfg_path = Path::new("/run/config.json");
    let disk_path = Path::new("/run/result.disk");

    os.insert_file(
        cfg_path,
        make_config_json(10, &["test_first", "test_second"], RunName::R0),
    );

    let mut stream = encode_records(&[
        DecodedRecord::Start(StartRecord {
            seq: 1,
            nodeid: "test_first".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 2,
            nodeid: "test_first".to_string(),
            outcome: RecordOutcome::Passed,
            duration_ms: 8,
        }),
    ]);

    // Header claiming payload length = MAX_RECORD_PAYLOAD_BYTES + 1 (65,537 bytes).
    let oversized_len = (MAX_RECORD_PAYLOAD_BYTES as u32) + 1;
    stream.push(1u8); // START
    stream.extend_from_slice(&oversized_len.to_le_bytes());
    stream.extend_from_slice(b"{\"seq\":3");

    os.push_child_script(FakeChildScript::new(vec![
        FakeStep::EmitBytes(stream),
        FakeStep::ExitTree(ExitKind::Clean),
    ]));

    let report = run_supervisor(&mut os, cfg_path, disk_path).expect("supervisor run");
    assert!(report.stream_error.is_some());
    assert_eq!(report.payload.supervisor.exit, SupervisorExit::Crash);
    assert_eq!(
        report.payload.tests.get("test_first"),
        Some(&FinalTestOutcome::Passed)
    );
    assert_eq!(
        report.payload.tests.get("test_second"),
        Some(&FinalTestOutcome::Failed)
    );
}

/// Requirement 4: Unexpected test IDs are ignored in the result disk `tests` map and counted.
#[test]
fn test_unexpected_ids_ignored_and_counted() {
    let mut os = FakeOs::new();
    let cfg_path = Path::new("/run/config.json");
    let disk_path = Path::new("/run/result.disk");

    os.insert_file(
        cfg_path,
        make_config_json(10, &["expected_a", "expected_b"], RunName::R1),
    );

    let stream = encode_records(&[
        DecodedRecord::Start(StartRecord {
            seq: 1,
            nodeid: "expected_a".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 2,
            nodeid: "expected_a".to_string(),
            outcome: RecordOutcome::Passed,
            duration_ms: 2,
        }),
        DecodedRecord::Start(StartRecord {
            seq: 3,
            nodeid: "rogue_injected_test_1".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 4,
            nodeid: "rogue_injected_test_1".to_string(),
            outcome: RecordOutcome::Passed,
            duration_ms: 1,
        }),
        DecodedRecord::Start(StartRecord {
            seq: 5,
            nodeid: "rogue_injected_test_2".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 6,
            nodeid: "rogue_injected_test_2".to_string(),
            outcome: RecordOutcome::Failed,
            duration_ms: 1,
        }),
        DecodedRecord::Start(StartRecord {
            seq: 7,
            nodeid: "expected_b".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 8,
            nodeid: "expected_b".to_string(),
            outcome: RecordOutcome::Passed,
            duration_ms: 2,
        }),
        DecodedRecord::End(EndRecord { count: 4 }),
    ]);

    os.push_child_script(FakeChildScript::new(vec![
        FakeStep::EmitBytes(stream),
        FakeStep::ExitTree(ExitKind::Clean),
    ]));

    let report = run_supervisor(&mut os, cfg_path, disk_path).expect("supervisor run");
    assert_eq!(report.unexpected_ids, 2);
    assert_eq!(report.payload.tests.len(), 2);
    assert!(!report.payload.tests.contains_key("rogue_injected_test_1"));
    assert!(!report.payload.tests.contains_key("rogue_injected_test_2"));
    assert_eq!(
        report.payload.tests.get("expected_a"),
        Some(&FinalTestOutcome::Passed)
    );
    assert_eq!(
        report.payload.tests.get("expected_b"),
        Some(&FinalTestOutcome::Passed)
    );
    assert_eq!(report.payload.supervisor.exit, SupervisorExit::Clean);
}

/// Requirement 5: Known-answer test verifying the exact 1 MiB result disk layout,
/// canonical JSON bytes, SHA-256 header digest, zero padding, and full-image SHA-256 hash.
#[test]
fn test_result_disk_known_answer_bytes_and_hash() {
    let mut tests = BTreeMap::new();
    tests.insert("test_b".to_string(), FinalTestOutcome::Failed);
    tests.insert("test_a".to_string(), FinalTestOutcome::Passed);

    let payload = ResultPayload {
        run: RunName::R0,
        variant_set: SAMPLE_VARIANT_SHA256.to_string(),
        tests,
        supervisor: SupervisorSummary {
            exit: SupervisorExit::Clean,
            tests_started: 2,
            tests_finished: 2,
        },
    };

    let canonical = canonical_payload_json(&payload).expect("canonical json");
    let expected_json = concat!(
        r#"{"run":"R0","supervisor":{"exit":"clean","tests_finished":2,"tests_started":2},"#,
        r#""tests":{"test_a":"passed","test_b":"failed"},"#,
        r#""variant_set":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#,
    );
    assert_eq!(
        std::str::from_utf8(&canonical).expect("utf8"),
        expected_json
    );

    let disk = encode_result_disk(&payload).expect("encode disk");
    assert_eq!(disk.len(), 1_048_576);
    assert_eq!(&disk[0..4], RESULT_DISK_MAGIC);
    assert_eq!(u16::from_le_bytes([disk[4], disk[5]]), 1);
    assert_eq!(u16::from_le_bytes([disk[6], disk[7]]), 0);
    assert_eq!(
        u32::from_le_bytes([disk[8], disk[9], disk[10], disk[11]]) as usize,
        expected_json.len()
    );

    let expected_payload_sha = Sha256::digest(expected_json.as_bytes());
    assert_eq!(&disk[12..44], expected_payload_sha.as_slice());

    let payload_end = RESULT_DISK_HEADER_BYTES + expected_json.len();
    assert_eq!(
        &disk[RESULT_DISK_HEADER_BYTES..payload_end],
        expected_json.as_bytes()
    );
    assert!(disk[payload_end..].iter().all(|&b| b == 0));

    // Known-answer SHA-256 of the entire 1 MiB result disk image.
    let full_disk_sha_hex = format!("{:x}", Sha256::digest(&disk));
    assert_eq!(
        full_disk_sha_hex,
        "a85313efa7901069b4df7d05ff1dcfc8998bd539ba4b47df3e126888bf3b8ef0"
    );

    // Tampering with a single byte must fail SHA-256 verification.
    let mut tampered = disk.clone();
    tampered[RESULT_DISK_HEADER_BYTES] ^= 0x01;
    assert_eq!(
        decode_result_disk(&tampered),
        Err(DiskError::DigestMismatch)
    );
}

/// Requirement 2 & 5: Verifies that the result disk is NEVER written before the entire
/// test process tree has ended (even after the main runner sends `END` and closes the pipe).
#[test]
fn test_disk_not_written_before_tree_ends() {
    let mut os = FakeOs::new();
    let cfg_path = Path::new("/run/config.json");
    let disk_path = Path::new("/run/result.disk");

    os.insert_file(cfg_path, make_config_json(10, &["test_only"], RunName::R0));

    let stream = encode_records(&[
        DecodedRecord::Start(StartRecord {
            seq: 1,
            nodeid: "test_only".to_string(),
        }),
        DecodedRecord::Finish(FinishRecord {
            seq: 2,
            nodeid: "test_only".to_string(),
            outcome: RecordOutcome::Passed,
            duration_ms: 1,
        }),
        DecodedRecord::End(EndRecord { count: 1 }),
    ]);

    // Main test runner finishes and closes pipe, while a background child process in the tree
    // stays alive for 4 `wait_tree` polls before exiting.
    os.push_child_script(FakeChildScript::new(vec![
        FakeStep::EmitBytes(stream),
        FakeStep::ClosePipe,
        FakeStep::TreeRunningPolls(4),
        FakeStep::ExitTree(ExitKind::Clean),
    ]));

    let report = run_supervisor(&mut os, cfg_path, disk_path).expect("supervisor run");
    assert_eq!(report.payload.supervisor.exit, SupervisorExit::Clean);

    let events = os.events();
    let running_count = events
        .iter()
        .filter(|e| matches!(e, OsEvent::WaitTree(TreeStatus::Running)))
        .count();
    assert_eq!(running_count, 4);

    let exited_pos = events
        .iter()
        .position(|e| matches!(e, OsEvent::WaitTree(TreeStatus::Exited(_))))
        .expect("WaitTree(Exited) must occur");
    let write_pos = events
        .iter()
        .position(|e| matches!(e, OsEvent::WriteFileAtomic { .. }))
        .expect("WriteFileAtomic must occur");

    assert!(
        write_pos > exited_pos,
        "result disk was written at event {} before tree exited at event {}",
        write_pos,
        exited_pos
    );
}

/// Runs `script` under `/bin/sh` through `RealOs` and `run_supervisor` on a worker thread,
/// returning `None` if the supervisor did not return within `limit`.
#[cfg(unix)]
fn run_real_shell(
    script: &str,
    deadline_seconds: u64,
    limit: Duration,
) -> Option<Result<hermetic_grader_supervisor::RunReport, String>> {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    let cfg = RunConfig {
        argv: vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()],
        env,
        cwd: tmp.path().to_string_lossy().into_owned(),
        deadline_seconds,
        expected_test_ids: vec!["test_a".to_string()],
        run: RunName::R0,
        variant_set: SAMPLE_VARIANT_SHA256.to_string(),
    };
    let cfg_path = tmp.path().join("config.json");
    let disk_path = tmp.path().join("result.disk");
    std::fs::write(&cfg_path, serde_json::to_vec(&cfg).expect("config json")).expect("config");

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut os = RealOs::new();
        let res = run_supervisor(&mut os, &cfg_path, &disk_path).map_err(|e| e.to_string());
        let _ = tx.send(res);
        drop(tmp);
    });
    rx.recv_timeout(limit).ok()
}

#[cfg(unix)]
#[test]
fn regression_real_os_descendant_holding_pipe_cannot_stall_past_deadline() {
    if !Path::new("/bin/sh").exists() {
        return;
    }
    // The leader exits at once; a background child keeps the result pipe (fd 2) open past the
    // 1 s deadline. The deadline must still be enforced and classified as a timeout.
    let res = run_real_shell("sleep 4 & exit 0", 1, Duration::from_secs(25))
        .expect("supervisor must return");
    let report = res.expect("supervisor run");
    assert_eq!(report.payload.supervisor.exit, SupervisorExit::Timeout);
    assert_eq!(
        report.payload.tests.get("test_a"),
        Some(&FinalTestOutcome::Missing)
    );
}

#[cfg(unix)]
#[test]
fn regression_real_os_large_garbage_on_pipe_does_not_deadlock() {
    if !Path::new("/bin/sh").exists() {
        return;
    }
    // Far more garbage than the reader channel plus the pipe buffer can hold: after the stream
    // error the supervisor must keep draining so the writer finishes and the tree ends.
    let res = run_real_shell("head -c 4000000 /dev/zero >&2", 60, Duration::from_secs(25))
        .expect("supervisor must not deadlock");
    let report = res.expect("supervisor run");
    assert!(report.stream_error.is_some());
    assert_eq!(report.payload.supervisor.exit, SupervisorExit::Crash);
    assert_eq!(
        report.payload.tests.get("test_a"),
        Some(&FinalTestOutcome::Failed)
    );
}

#[cfg(unix)]
#[test]
fn regression_real_os_atomic_write_never_follows_planted_temp_symlink() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"keep me").expect("victim");
    let disk = tmp.path().join("disk");
    std::os::unix::fs::symlink(&victim, tmp.path().join(".disk.tmp")).expect("plant symlink");

    let mut os = RealOs::new();
    assert!(os.write_file_atomic(&disk, b"result bytes").is_err());
    assert_eq!(std::fs::read(&victim).expect("victim"), b"keep me");
    assert!(!disk.exists());

    // A symlink at the result path itself is refused as well.
    let link = tmp.path().join("link_disk");
    std::os::unix::fs::symlink(&victim, &link).expect("plant symlink");
    assert!(os.write_file_atomic(&link, b"result bytes").is_err());
    assert_eq!(std::fs::read(&victim).expect("victim"), b"keep me");
}
