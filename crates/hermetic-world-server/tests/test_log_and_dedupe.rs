#![forbid(unsafe_code)]

use hermetic_world_server::{verify_log, DedupeEntry, LogEventParams, LogManager};
use std::collections::BTreeMap;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_hash_chain_verification_and_tampering() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");
    let mut lm = LogManager::new(&log_dir).expect("create log manager");

    for i in 1..=5 {
        lm.log_event(&LogEventParams {
            elapsed_ms: i * 10,
            request_id: i,
            method: "GET",
            authority: "pypi.org",
            path_and_query: &format!("/package/{i}"),
            range: None,
            status: "200",
            bytes: 100 * i,
        })
        .expect("log event");
    }
    lm.finish().expect("finish log");

    let log_path = log_dir.join("requests.log");

    // 1. Valid log verifies
    let count = verify_log(&log_path).expect("valid log should verify");
    assert_eq!(count, 5);

    // Read lines for tampering tests
    let original_content = fs::read_to_string(&log_path).expect("read log");
    let lines: Vec<&str> = original_content.lines().collect();
    assert_eq!(lines.len(), 5);

    // 2. Editing a line is detected
    let mut edited_lines = lines.clone();
    // Tamper with bytes field in line 3
    let tampered_line = edited_lines[2].replace("\"bytes\":300", "\"bytes\":999");
    edited_lines[2] = &tampered_line;
    let edited_content = edited_lines.join("\n") + "\n";
    let edited_log = temp.path().join("edited_requests.log");
    fs::write(&edited_log, edited_content).expect("write edited log");
    let edit_res = verify_log(&edited_log);
    assert!(edit_res.is_err(), "Edited line must fail verification");
    let err = edit_res.unwrap_err();
    assert!(
        err.to_string().contains("Bad line 3: hash mismatch"),
        "Unexpected error: {err}"
    );

    // 3. Deleting a line is detected
    let mut deleted_lines = lines.clone();
    deleted_lines.remove(1); // remove line 2 (seq 2)
    let deleted_content = deleted_lines.join("\n") + "\n";
    let deleted_log = temp.path().join("deleted_requests.log");
    fs::write(&deleted_log, deleted_content).expect("write deleted log");
    let del_res = verify_log(&deleted_log);
    assert!(del_res.is_err(), "Deleted line must fail verification");
    let err = del_res.unwrap_err();
    assert!(
        err.to_string().contains("Bad line 2: seq mismatch"),
        "Unexpected error: {err}"
    );

    // 4. Reordering lines is detected
    let mut reordered_lines = lines.clone();
    reordered_lines.swap(1, 2); // swap lines 2 and 3
    let reordered_content = reordered_lines.join("\n") + "\n";
    let reordered_log = temp.path().join("reordered_requests.log");
    fs::write(&reordered_log, reordered_content).expect("write reordered log");
    let reorder_res = verify_log(&reordered_log);
    assert!(
        reorder_res.is_err(),
        "Reordered lines must fail verification"
    );
}

#[test]
fn test_dedupe_index_counts_repeated_requests() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");
    let mut lm = LogManager::new(&log_dir).expect("create log manager");

    // Log 3 identical requests for /simple/requests/ (200)
    for _ in 0..3 {
        lm.log_event(&LogEventParams {
            elapsed_ms: 10,
            request_id: 1,
            method: "GET",
            authority: "pypi.org",
            path_and_query: "/simple/requests/",
            range: None,
            status: "200",
            bytes: 50,
        })
        .expect("log event");
    }

    // Log 2 identical requests for /simple/pip/ (200)
    for _ in 0..2 {
        lm.log_event(&LogEventParams {
            elapsed_ms: 20,
            request_id: 2,
            method: "GET",
            authority: "pypi.org",
            path_and_query: "/simple/pip/",
            range: None,
            status: "200",
            bytes: 60,
        })
        .expect("log event");
    }

    // Log 1 request for /simple/requests/ (404)
    lm.log_event(&LogEventParams {
        elapsed_ms: 30,
        request_id: 3,
        method: "GET",
        authority: "pypi.org",
        path_and_query: "/simple/requests/",
        range: None,
        status: "404",
        bytes: 10,
    })
    .expect("log event");

    lm.finish().expect("finish");

    // Read dedupe.json
    let dedupe_path = log_dir.join("dedupe.json");
    assert!(dedupe_path.is_file(), "dedupe.json must exist");
    let content = fs::read_to_string(&dedupe_path).expect("read dedupe.json");
    let map: BTreeMap<String, DedupeEntry> =
        serde_json::from_str(&content).expect("parse dedupe.json");

    let req_entry = map
        .get("pypi.org /simple/requests/ 200")
        .expect("entry for requests 200");
    assert_eq!(req_entry.count, 3);
    assert_eq!(req_entry.first_seen_seq, 1);
    assert_eq!(req_entry.last_seen_seq, 3);

    let pip_entry = map
        .get("pypi.org /simple/pip/ 200")
        .expect("entry for pip 200");
    assert_eq!(pip_entry.count, 2);
    assert_eq!(pip_entry.first_seen_seq, 4);
    assert_eq!(pip_entry.last_seen_seq, 5);

    let notfound_entry = map
        .get("pypi.org /simple/requests/ 404")
        .expect("entry for requests 404");
    assert_eq!(notfound_entry.count, 1);
    assert_eq!(notfound_entry.first_seen_seq, 6);
    assert_eq!(notfound_entry.last_seen_seq, 6);
}

struct FailingWriter;
impl std::io::Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("disk write failure"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("disk flush failure"))
    }
}
impl hermetic_world_server::LogWriter for FailingWriter {}

#[test]
fn test_fix3_log_write_failure_chain_integrity() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");
    fs::create_dir_all(&log_dir).expect("create log dir");

    let mut lm = LogManager::new_with_writer(&log_dir, FailingWriter);
    assert_eq!(lm.current_seq(), 0);
    assert_eq!(lm.prev_hash(), hermetic_world_server::INITIAL_PREV_HASH);

    let res = lm.log_event(&LogEventParams {
        elapsed_ms: 10,
        request_id: 1,
        method: "GET",
        authority: "example.com",
        path_and_query: "/",
        range: None,
        status: "200",
        bytes: 100,
    });

    // Error propagates
    assert!(res.is_err(), "Write failure must propagate error");

    // Chain state did not advance
    assert_eq!(lm.current_seq(), 0, "seq must not advance on write failure");
    assert_eq!(
        lm.prev_hash(),
        hermetic_world_server::INITIAL_PREV_HASH,
        "prev_hash must not advance on write failure"
    );
}

#[test]
fn test_fix7_tail_truncation_detection() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");
    let mut lm = LogManager::new(&log_dir).expect("create log manager");

    for i in 1..=5 {
        lm.log_event(&LogEventParams {
            elapsed_ms: i * 10,
            request_id: i,
            method: "GET",
            authority: "example.com",
            path_and_query: &format!("/{i}"),
            range: None,
            status: "200",
            bytes: 100 * i,
        })
        .expect("log event");
    }
    lm.finish().expect("finish");

    let log_path = log_dir.join("requests.log");
    let head_path = log_dir.join("requests.log.head");
    assert!(
        head_path.is_file(),
        "requests.log.head must be created at finish"
    );

    // Baseline: valid log verifies
    let count = verify_log(&log_path).expect("valid anchored log should verify");
    assert_eq!(count, 5);

    let original_content = fs::read_to_string(&log_path).expect("read log");
    let lines: Vec<&str> = original_content.lines().collect();
    assert_eq!(lines.len(), 5);

    // 1. Deleting the last line is detected
    let last_1_deleted = lines[..4].join("\n") + "\n";
    let log_dir_del1 = temp.path().join("log_del1");
    fs::create_dir_all(&log_dir_del1).expect("create dir");
    fs::write(log_dir_del1.join("requests.log"), &last_1_deleted).expect("write log");
    fs::copy(&head_path, log_dir_del1.join("requests.log.head")).expect("copy head");

    let del1_res = verify_log(log_dir_del1.join("requests.log"));
    assert!(
        del1_res.is_err(),
        "Deleting last line must fail verification"
    );
    let err = del1_res.unwrap_err();
    assert!(
        matches!(err, hermetic_world_server::VerifyError::HeadMismatch { .. }),
        "Expected HeadMismatch on deleting last line, got: {err:?}"
    );

    // 2. Deleting the last 3 lines is detected
    let last_3_deleted = lines[..2].join("\n") + "\n";
    let log_dir_del3 = temp.path().join("log_del3");
    fs::create_dir_all(&log_dir_del3).expect("create dir");
    fs::write(log_dir_del3.join("requests.log"), &last_3_deleted).expect("write log");
    fs::copy(&head_path, log_dir_del3.join("requests.log.head")).expect("copy head");

    let del3_res = verify_log(log_dir_del3.join("requests.log"));
    assert!(
        del3_res.is_err(),
        "Deleting last 3 lines must fail verification"
    );
    let err3 = del3_res.unwrap_err();
    assert!(
        matches!(
            err3,
            hermetic_world_server::VerifyError::HeadMismatch { .. }
        ),
        "Expected HeadMismatch on deleting last 3 lines, got: {err3:?}"
    );

    // 3. Missing head file is reported as unanchored
    let log_dir_nohead = temp.path().join("log_nohead");
    fs::create_dir_all(&log_dir_nohead).expect("create dir");
    fs::write(log_dir_nohead.join("requests.log"), &original_content).expect("write log");

    let nohead_res = verify_log(log_dir_nohead.join("requests.log"));
    assert!(
        nohead_res.is_err(),
        "Missing head file must fail anchored verify"
    );
    let err_nohead = nohead_res.unwrap_err();
    assert_eq!(
        err_nohead,
        hermetic_world_server::VerifyError::Unanchored,
        "Expected Unanchored error"
    );
    assert_eq!(err_nohead.to_string(), "unanchored (no head file)");

    // With allow_unanchored: true, it succeeds
    let unanchored_ok =
        hermetic_world_server::verify_log_ext(log_dir_nohead.join("requests.log"), true)
            .expect("allow_unanchored must succeed");
    assert_eq!(unanchored_ok, 5);
}

#[test]
fn test_fix8_resume_log_and_dedupe_accumulation() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");

    // First run: log 3 events
    {
        let mut lm1 = LogManager::new(&log_dir).expect("create log manager");
        lm1.log_event(&LogEventParams {
            elapsed_ms: 10,
            request_id: 1,
            method: "GET",
            authority: "pypi.org",
            path_and_query: "/item1",
            range: None,
            status: "200",
            bytes: 50,
        })
        .expect("log event");

        lm1.log_event(&LogEventParams {
            elapsed_ms: 20,
            request_id: 2,
            method: "GET",
            authority: "pypi.org",
            path_and_query: "/item1",
            range: None,
            status: "200",
            bytes: 50,
        })
        .expect("log event");

        lm1.log_event(&LogEventParams {
            elapsed_ms: 30,
            request_id: 3,
            method: "GET",
            authority: "pypi.org",
            path_and_query: "/item2",
            range: None,
            status: "200",
            bytes: 60,
        })
        .expect("log event");

        lm1.finish().expect("finish");
    }

    let log_path = log_dir.join("requests.log");
    let original_log = fs::read_to_string(&log_path).expect("read original log");

    // Second run without --resume-log: refuses to start (StartupFailed), leaves log untouched
    let second_run_no_resume = LogManager::new_opts(&log_dir, false);
    assert!(
        second_run_no_resume.is_err(),
        "Second run without resume_log must fail to start"
    );
    let log_after_failed_second_run = fs::read_to_string(&log_path).expect("read log");
    assert_eq!(
        original_log, log_after_failed_second_run,
        "requests.log must remain untouched when startup fails"
    );

    // Third run with --resume-log: continues and accumulates dedupe
    {
        let mut lm_resume = LogManager::new_opts(&log_dir, true).expect("resume log manager");
        assert_eq!(lm_resume.current_seq(), 3, "Resumed seq must be 3");

        // Log 1 more for /item1 (now total 3), and 1 for /item3
        lm_resume
            .log_event(&LogEventParams {
                elapsed_ms: 40,
                request_id: 4,
                method: "GET",
                authority: "pypi.org",
                path_and_query: "/item1",
                range: None,
                status: "200",
                bytes: 50,
            })
            .expect("log event");

        lm_resume
            .log_event(&LogEventParams {
                elapsed_ms: 50,
                request_id: 5,
                method: "GET",
                authority: "pypi.org",
                path_and_query: "/item3",
                range: None,
                status: "200",
                bytes: 70,
            })
            .expect("log event");

        lm_resume.finish().expect("finish");
    }

    // Verify combined log: all 5 records verify
    let count = verify_log(&log_path).expect("combined log must verify");
    assert_eq!(count, 5);

    // Verify dedupe counts accumulated
    let dedupe_path = log_dir.join("dedupe.json");
    let dedupe_content = fs::read_to_string(&dedupe_path).expect("read dedupe.json");
    let map: BTreeMap<String, DedupeEntry> =
        serde_json::from_str(&dedupe_content).expect("parse dedupe.json");

    let item1_entry = map.get("pypi.org /item1 200").expect("item1 entry");
    assert_eq!(item1_entry.count, 3, "item1 count must accumulate to 3");
    assert_eq!(item1_entry.first_seen_seq, 1);
    assert_eq!(item1_entry.last_seen_seq, 4);

    let item2_entry = map.get("pypi.org /item2 200").expect("item2 entry");
    assert_eq!(item2_entry.count, 1);
    assert_eq!(item2_entry.first_seen_seq, 3);
    assert_eq!(item2_entry.last_seen_seq, 3);

    let item3_entry = map.get("pypi.org /item3 200").expect("item3 entry");
    assert_eq!(item3_entry.count, 1);
    assert_eq!(item3_entry.first_seen_seq, 5);
    assert_eq!(item3_entry.last_seen_seq, 5);
}

#[test]
fn test_fix3_resume_missing_dedupe_rebuild() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");

    // First run: log 2 requests for the same path
    {
        let mut lm = LogManager::new(&log_dir).expect("create log manager");
        for i in 1..=2 {
            lm.log_event(&LogEventParams {
                elapsed_ms: i * 10,
                request_id: i,
                method: "GET",
                authority: "pypi.org",
                path_and_query: "/simple/requests/",
                range: None,
                status: "200",
                bytes: 100,
            })
            .expect("log event");
        }
        lm.finish().expect("finish");
    }

    let dedupe_path = log_dir.join("dedupe.json");
    assert!(dedupe_path.is_file(), "dedupe.json must exist after finish");
    // Delete dedupe.json between runs
    fs::remove_file(&dedupe_path).expect("delete dedupe.json");
    assert!(!dedupe_path.exists());

    // Second run with --resume-log
    {
        let mut lm2 = LogManager::new_opts(&log_dir, true).expect("resume log manager");
        assert_eq!(lm2.current_seq(), 2);

        // Log a 3rd request for the same path
        lm2.log_event(&LogEventParams {
            elapsed_ms: 30,
            request_id: 3,
            method: "GET",
            authority: "pypi.org",
            path_and_query: "/simple/requests/",
            range: None,
            status: "200",
            bytes: 100,
        })
        .expect("log event");

        lm2.finish().expect("finish");
    }

    // Verify counts include the first run's requests
    assert!(dedupe_path.is_file());
    let dedupe_content = fs::read_to_string(&dedupe_path).expect("read dedupe.json");
    let map: BTreeMap<String, DedupeEntry> =
        serde_json::from_str(&dedupe_content).expect("parse dedupe.json");
    let entry = map
        .get("pypi.org /simple/requests/ 200")
        .expect("entry for requests 200");
    assert_eq!(
        entry.count, 3,
        "Dedupe count must accumulate to 3 even when dedupe.json was deleted"
    );
    assert_eq!(entry.first_seen_seq, 1);
    assert_eq!(entry.last_seen_seq, 3);
}

struct FailingSyncWriter {
    inner: Vec<u8>,
}

impl std::io::Write for FailingSyncWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("disk flush failed on finish"))
    }
}

impl hermetic_world_server::LogWriter for FailingSyncWriter {
    fn sync_all(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("disk sync failed on finish"))
    }
}

#[test]
fn test_fix4_finish_failure_prevents_head_anchor() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");
    fs::create_dir_all(&log_dir).expect("create log dir");

    let writer = FailingSyncWriter { inner: Vec::new() };
    let mut lm = LogManager::new_with_writer(&log_dir, writer);

    // finish() should fail on flush/sync
    let res = lm.finish();
    assert!(
        res.is_err(),
        "finish() must return error on flush/sync failure"
    );

    // Head file MUST NOT be written
    let head_path = log_dir.join("requests.log.head");
    assert!(
        !head_path.exists(),
        "requests.log.head must not be written if sync/flush fails"
    );
}

#[test]
fn test_fix5_crash_recovery() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");

    // Write records and simulate a crash (no finish)
    {
        let mut lm = LogManager::new(&log_dir).expect("create log manager");
        for i in 1..=4 {
            lm.log_event(&LogEventParams {
                elapsed_ms: i * 10,
                request_id: i,
                method: "GET",
                authority: "example.com",
                path_and_query: &format!("/page/{i}"),
                range: None,
                status: "200",
                bytes: 100 * i,
            })
            .expect("log event");
        }
        // Crash: do NOT call finish()!
        // Head file is missing.
    }

    let log_path = log_dir.join("requests.log");
    let head_path = log_dir.join("requests.log.head");
    assert!(
        !head_path.exists(),
        "Head file must not exist before finish"
    );

    // Without --recover, verify_log and resume fail
    let verify_res = verify_log(&log_path);
    assert!(
        verify_res.is_err(),
        "verify_log without --recover must fail on unanchored crash"
    );

    let resume_fail = LogManager::new_opts(&log_dir, true);
    assert!(
        resume_fail.is_err(),
        "Resume without --recover must fail when head is missing"
    );

    // With --recover, verify_log_recover and resume succeed
    let mut lm_recovered = LogManager::new_opts_recover(&log_dir, true, true)
        .expect("Resume with --recover must succeed");
    assert_eq!(lm_recovered.current_seq(), 4);
    assert!(
        head_path.is_file(),
        "Head file must be re-anchored by recovery"
    );

    // Resume writing
    lm_recovered
        .log_event(&LogEventParams {
            elapsed_ms: 50,
            request_id: 5,
            method: "GET",
            authority: "example.com",
            path_and_query: "/page/5",
            range: None,
            status: "200",
            bytes: 500,
        })
        .expect("log event");
    lm_recovered.finish().expect("finish");

    let count = verify_log(&log_path).expect("Final log must verify");
    assert_eq!(count, 5);

    // Test trailing partial line truncation during recovery:
    // Append partial unclosed JSON without trailing newline
    use std::io::Write;
    {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("open log");
        file.write_all(b"{\"seq\":6,\"incomplete\":\"data")
            .expect("write partial line");
    }

    // Now resume with --recover truncates the partial line and recovers
    let mut lm_partial_recovered = LogManager::new_opts_recover(&log_dir, true, true)
        .expect("Resume with --recover must truncate partial line and succeed");
    assert_eq!(lm_partial_recovered.current_seq(), 5);

    lm_partial_recovered.finish().expect("finish");
    let count2 = verify_log(&log_path).expect("Verified count after partial line truncation");
    assert_eq!(count2, 5);
}

#[test]
fn test_finding_preserve_native_path_bytes_head_path() {
    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let temp = tempdir().expect("tempdir");
        let non_utf8_dir = temp
            .path()
            .join(OsStr::from_bytes(b"non_utf8_\xff\xfe_log_dir"));
        fs::create_dir_all(&non_utf8_dir).expect("create non-utf8 dir");

        let mut lm = LogManager::new(&non_utf8_dir).expect("create log manager");
        lm.log_event(&LogEventParams {
            elapsed_ms: 10,
            request_id: 1,
            method: "GET",
            authority: "example.com",
            path_and_query: "/test",
            range: None,
            status: "200",
            bytes: 50,
        })
        .expect("log event");
        lm.finish().expect("finish");

        let log_path = non_utf8_dir.join("requests.log");
        let count = verify_log(&log_path).expect("verify non-utf8 log");
        assert_eq!(count, 1);

        let lm_resumed = LogManager::new_opts(&non_utf8_dir, true).expect("resume non-utf8 log");
        assert_eq!(lm_resumed.current_seq(), 1);
    }
}

#[test]
fn test_finding_verify_existing_checkpoint_when_log_empty() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");

    // 1. Create a log with 2 records and finish it
    {
        let mut lm = LogManager::new(&log_dir).expect("create log manager");
        for i in 1..=2 {
            lm.log_event(&LogEventParams {
                elapsed_ms: i * 10,
                request_id: i,
                method: "GET",
                authority: "example.com",
                path_and_query: "/item",
                range: None,
                status: "200",
                bytes: 100,
            })
            .expect("log event");
        }
        lm.finish().expect("finish");
    }

    let log_path = log_dir.join("requests.log");
    let head_path = log_dir.join("requests.log.head");
    assert!(head_path.is_file());

    // Truncate requests.log to zero bytes
    fs::write(&log_path, b"").expect("truncate log");
    assert_eq!(fs::metadata(&log_path).expect("meta").len(), 0);

    // Resuming without recovery must reject empty log with nonzero checkpoint
    let resume_res = LogManager::new_opts(&log_dir, true);
    assert!(
        resume_res.is_err(),
        "Empty log with nonzero head checkpoint must be rejected on resume"
    );
    let err = match resume_res {
        Err(e) => e,
        Ok(_) => panic!("Expected resume to fail"),
    };
    assert!(
        matches!(err, hermetic_world_server::LogError::ResumeVerification(_)),
        "Expected ResumeVerification error, got {err:?}"
    );

    // Resuming with recovery must also reject missing records
    let recover_res = LogManager::new_opts_recover(&log_dir, true, true);
    assert!(
        recover_res.is_err(),
        "Recovery must not wipe out a nonzero checkpoint when log is empty"
    );

    // Verify head file was not overwritten
    let head_content = fs::read_to_string(&head_path).expect("read head");
    let head: hermetic_world_server::LogHead =
        serde_json::from_str(&head_content).expect("parse head");
    assert_eq!(head.seq, 2);

    // 2. Empty log with seq 0 checkpoint must be accepted
    let temp2 = tempdir().expect("tempdir");
    let log_dir2 = temp2.path().join("log2");
    fs::create_dir_all(&log_dir2).expect("create dir");
    let log_path2 = log_dir2.join("requests.log");
    fs::write(&log_path2, b"").expect("write empty log");
    let head_path2 = log_dir2.join("requests.log.head");
    let seq0_head = hermetic_world_server::LogHead {
        seq: 0,
        hash: hermetic_world_server::INITIAL_PREV_HASH.to_string(),
    };
    fs::write(
        &head_path2,
        serde_json::to_string_pretty(&seq0_head).expect("json"),
    )
    .expect("write seq 0 head");

    let lm_empty_ok =
        LogManager::new_opts(&log_dir2, true).expect("empty log with seq 0 head should succeed");
    assert_eq!(lm_empty_ok.current_seq(), 0);
}

#[test]
fn test_finding_sync_recovered_log_before_publishing_head() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");

    {
        let mut lm = LogManager::new(&log_dir).expect("create log manager");
        for i in 1..=3 {
            lm.log_event(&LogEventParams {
                elapsed_ms: i * 10,
                request_id: i,
                method: "GET",
                authority: "example.com",
                path_and_query: "/sync-test",
                range: None,
                status: "200",
                bytes: 100,
            })
            .expect("log event");
        }
        lm.finish().expect("finish");
    }

    let log_path = log_dir.join("requests.log");
    // Simulate crash after writing 4th record and partial 5th line before finish
    use std::io::Write;
    {
        let (h4, line4) = hermetic_world_server::LogManager::compute_hash(
            &fs::read_to_string(&log_path)
                .expect("read")
                .lines()
                .last()
                .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .and_then(|v| {
                    v.get("hash")
                        .and_then(|h| h.as_str().map(|s| s.to_string()))
                })
                .expect("hash"),
            4,
            &LogEventParams {
                elapsed_ms: 40,
                request_id: 4,
                method: "GET",
                authority: "example.com",
                path_and_query: "/sync-test-4",
                range: None,
                status: "200",
                bytes: 100,
            },
        )
        .expect("hash");
        let _ = h4;
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("open");
        writeln!(f, "{line4}").expect("write line 4");
        // write partial 5th line
        write!(f, "{{\"seq\":5,\"corrupt").expect("write partial");
    }

    // Recover log: should truncate partial line, sync requests.log, and publish new head
    let recovered_lines = hermetic_world_server::verify_log_recover(&log_path, false, true)
        .expect("recovery should succeed");
    assert_eq!(recovered_lines, 4);

    let head_path = log_dir.join("requests.log.head");
    let head: hermetic_world_server::LogHead =
        serde_json::from_str(&fs::read_to_string(&head_path).expect("read head")).expect("parse");
    assert_eq!(head.seq, 4);
}

#[test]
fn test_finding_atomic_head_replacement() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");

    let mut lm = LogManager::new(&log_dir).expect("create log manager");
    lm.log_event(&LogEventParams {
        elapsed_ms: 10,
        request_id: 1,
        method: "GET",
        authority: "example.com",
        path_and_query: "/atomic",
        range: None,
        status: "200",
        bytes: 50,
    })
    .expect("log event");
    lm.finish().expect("finish");

    let head_path = log_dir.join("requests.log.head");
    assert!(head_path.is_file());

    // Check that no temporary files remain in log_dir
    let entries = fs::read_dir(&log_dir).expect("read dir");
    for entry in entries {
        let entry = entry.expect("entry");
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        assert!(
            !name_str.starts_with(".head.tmp"),
            "Temporary head file was not cleaned up: {name_str}"
        );
    }

    // Head content must be valid JSON
    let head_data = fs::read_to_string(&head_path).expect("read head");
    let head: hermetic_world_server::LogHead =
        serde_json::from_str(&head_data).expect("valid json");
    assert_eq!(head.seq, 1);
}

#[test]
fn test_finding_reconcile_dedupe_snapshot_with_recovered_log() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");

    // Run 1: log 3 requests for /item1, and finish
    {
        let mut lm = LogManager::new(&log_dir).expect("create log manager");
        for i in 1..=3 {
            lm.log_event(&LogEventParams {
                elapsed_ms: i * 10,
                request_id: i,
                method: "GET",
                authority: "pypi.org",
                path_and_query: "/item1",
                range: None,
                status: "200",
                bytes: 100,
            })
            .expect("log event");
        }
        lm.finish().expect("finish");
    }

    let dedupe_path = log_dir.join("dedupe.json");
    let dedupe_before = fs::read_to_string(&dedupe_path).expect("read dedupe");
    let map_before: BTreeMap<String, DedupeEntry> =
        serde_json::from_str(&dedupe_before).expect("parse");
    assert_eq!(
        map_before.get("pypi.org /item1 200").expect("entry").count,
        3
    );

    // Run 2: resume and log 2 more events for /item1 (seq 4 and 5), but crash before finish
    {
        let mut lm2 = LogManager::new_opts(&log_dir, true).expect("resume");
        for i in 4..=5 {
            lm2.log_event(&LogEventParams {
                elapsed_ms: i * 10,
                request_id: i,
                method: "GET",
                authority: "pypi.org",
                path_and_query: "/item1",
                range: None,
                status: "200",
                bytes: 100,
            })
            .expect("log event");
        }
        // CRASH: do NOT call finish()
    }

    // Notice dedupe.json on disk still has count 3
    let dedupe_stale = fs::read_to_string(&dedupe_path).expect("read dedupe");
    let map_stale: BTreeMap<String, DedupeEntry> =
        serde_json::from_str(&dedupe_stale).expect("parse");
    assert_eq!(
        map_stale.get("pypi.org /item1 200").expect("entry").count,
        3
    );

    // Run 3: resume with recover=true
    {
        let mut lm3 = LogManager::new_opts_recover(&log_dir, true, true)
            .expect("recovery resume should reconcile dedupe");
        assert_eq!(lm3.current_seq(), 5);

        // Log 1 more event (seq 6) and finish
        lm3.log_event(&LogEventParams {
            elapsed_ms: 60,
            request_id: 6,
            method: "GET",
            authority: "pypi.org",
            path_and_query: "/item1",
            range: None,
            status: "200",
            bytes: 100,
        })
        .expect("log event");
        lm3.finish().expect("finish");
    }

    // Dedupe index must now have count 6 (3 from run 1 + 2 from crash run + 1 from run 3)
    let dedupe_after = fs::read_to_string(&dedupe_path).expect("read dedupe");
    let map_after: BTreeMap<String, DedupeEntry> =
        serde_json::from_str(&dedupe_after).expect("parse");
    let entry = map_after.get("pypi.org /item1 200").expect("entry");
    assert_eq!(
        entry.count, 6,
        "Dedupe count must reconcile all 6 records across recovery"
    );
    assert_eq!(entry.first_seen_seq, 1);
    assert_eq!(entry.last_seen_seq, 6);
}

#[test]
fn test_finding_validate_checkpoint_hash_before_reanchoring() {
    let temp = tempdir().expect("tempdir");
    let genuine_dir = temp.path().join("genuine");
    let fake_dir = temp.path().join("fake");

    // 1. Create genuine log with 3 events
    {
        let mut lm = LogManager::new(&genuine_dir).expect("create genuine");
        for i in 1..=3 {
            lm.log_event(&LogEventParams {
                elapsed_ms: i * 10,
                request_id: i,
                method: "GET",
                authority: "genuine.org",
                path_and_query: "/genuine",
                range: None,
                status: "200",
                bytes: 100,
            })
            .expect("log event");
        }
        lm.finish().expect("finish");
    }

    let genuine_head_path = genuine_dir.join("requests.log.head");
    let genuine_head_content = fs::read_to_string(&genuine_head_path).expect("read genuine head");

    // 2. Create fake log with 5 events (different chain)
    {
        let mut lm = LogManager::new(&fake_dir).expect("create fake");
        for i in 1..=5 {
            lm.log_event(&LogEventParams {
                elapsed_ms: i * 10,
                request_id: i,
                method: "POST", // different method => completely different hashes
                authority: "attacker.com",
                path_and_query: "/fake",
                range: None,
                status: "500",
                bytes: 200,
            })
            .expect("log event");
        }
        // Do not finish; instead, place the genuine head (seq 3) into fake_dir
    }

    let fake_head_path = fake_dir.join("requests.log.head");
    fs::write(&fake_head_path, &genuine_head_content).expect("overwrite with genuine head");

    let fake_log_path = fake_dir.join("requests.log");

    // Recovery must reject because fake log record 3 has a different hash than genuine head
    let recover_res = hermetic_world_server::verify_log_recover(&fake_log_path, false, true);
    assert!(
        recover_res.is_err(),
        "Recovery must reject re-anchoring when log record at head.seq has different hash"
    );
    let err = recover_res.expect_err("err");
    assert!(
        matches!(err, hermetic_world_server::VerifyError::HeadMismatch { .. }),
        "Expected HeadMismatch error, got {err:?}"
    );

    // Also test: fake log has 3 events (same seq as genuine head), trailing partial line,
    // but different hashes
    let temp_partial = tempdir().expect("tempdir");
    let partial_dir = temp_partial.path().join("partial");
    {
        let mut lm = LogManager::new(&partial_dir).expect("create partial");
        for i in 1..=3 {
            lm.log_event(&LogEventParams {
                elapsed_ms: i * 10,
                request_id: i,
                method: "PUT",
                authority: "attacker.com",
                path_and_query: "/partial",
                range: None,
                status: "403",
                bytes: 300,
            })
            .expect("log event");
        }
    }
    let partial_head = partial_dir.join("requests.log.head");
    fs::write(&partial_head, &genuine_head_content).expect("write genuine head");
    let partial_log = partial_dir.join("requests.log");
    use std::io::Write;
    {
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&partial_log)
            .expect("open");
        write!(f, "{{\"seq\":4,\"trailing").expect("write trailing");
    }

    let recover_partial_res = hermetic_world_server::verify_log_recover(&partial_log, false, true);
    assert!(
        recover_partial_res.is_err(),
        "Recovery must reject even when had_partial_line is true and seq matches, if hashes differ"
    );
}
