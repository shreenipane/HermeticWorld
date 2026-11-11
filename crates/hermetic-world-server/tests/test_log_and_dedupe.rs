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
