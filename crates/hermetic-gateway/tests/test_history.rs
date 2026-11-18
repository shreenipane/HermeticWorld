mod common;

use common::TestEnv;
use hermetic_gateway::history::HistoryLog;
use hermetic_gateway::quota::QuotasConfig;
use std::thread;
use std::time::Duration;
use tiny_http::Response;

#[test]
fn test_history_unit_logic() {
    let history = HistoryLog::new();
    let sys = b"\"system prompt\"";

    let m0 = b"{\"role\":\"user\",\"content\":\"first\"}".to_vec();
    let m1 = b"{\"role\":\"assistant\",\"content\":\"reply 1\"}".to_vec();
    let m2 = b"{\"role\":\"user\",\"content\":\"second\"}".to_vec();

    // 1. First message starts new conversation -> not a rewrite
    let (is_rw1, total1) = history.check_and_record(sys, std::slice::from_ref(&m0));
    assert!(!is_rw1);
    assert_eq!(total1, 0);

    // 2. Extending conversation with [m0, m1, m2] -> not a rewrite
    let (is_rw2, total2) = history.check_and_record(sys, &[m0.clone(), m1.clone(), m2.clone()]);
    assert!(!is_rw2);
    assert_eq!(total2, 0);

    // 3. Extending further with [m0, m1, m2, m3, m4]
    let m3 = b"{\"role\":\"assistant\",\"content\":\"reply 2\"}".to_vec();
    let m4 = b"{\"role\":\"user\",\"content\":\"third\"}".to_vec();
    let (is_rw3, total3) = history.check_and_record(
        sys,
        &[m0.clone(), m1.clone(), m2.clone(), m3.clone(), m4.clone()],
    );
    assert!(!is_rw3);
    assert_eq!(total3, 0);

    // 4. Edit an earlier message: change m2 to m2_edited
    let m2_edited = b"{\"role\":\"user\",\"content\":\"second EDIT\"}".to_vec();
    let (is_rw4, total4) = history.check_and_record(sys, &[m0, m1, m2_edited, m3, m4]);
    assert!(
        is_rw4,
        "Editing an earlier message must be recorded as a rewrite"
    );
    assert_eq!(total4, 1);
}

#[test]
fn test_history_rewrites_logged_and_never_rejected_via_gateway() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        for _ in 0..3 {
            let req = common::recv_upstream(&mock);
            req.respond(Response::from_string(r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#)).unwrap();
        }
    });

    let client = common::test_client();

    // Turn 1: 1 message -> starts conversation
    let body1 = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Question 1"}]
    }"#;
    let res1 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body1)
        .expect("turn 1 ok");
    assert_eq!(res1.status(), 200);

    // Turn 2: 3 messages, extends Turn 1
    let body2 = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {"role": "user", "content": "Question 1"},
            {"role": "assistant", "content": "Answer 1"},
            {"role": "user", "content": "Question 2"}
        ]
    }"#;
    let res2 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body2)
        .expect("turn 2 ok");
    assert_eq!(res2.status(), 200);

    // Turn 3: 3 messages, but earlier message "Question 1" was edited to "Question 1 edited"
    let body3 = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {"role": "user", "content": "Question 1 edited"},
            {"role": "assistant", "content": "Answer 1"},
            {"role": "user", "content": "Question 2"}
        ]
    }"#;
    let res3 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body3)
        .expect("turn 3 ok (rewrites are NEVER rejected)");
    assert_eq!(res3.status(), 200);

    common::join_within(mock_handle);

    // Check host logs
    let logs = env.read_host_logs();
    assert_eq!(logs.len(), 3);
    assert_eq!(logs[0]["history_rewrite"], false);
    assert_eq!(logs[1]["history_rewrite"], false);
    assert_eq!(logs[2]["history_rewrite"], true);
    assert_eq!(logs[2]["history_rewrites_total"], 1);

    // Check persisted gateway_history.json
    let history_file = env
        .temp_dir
        .path()
        .join("logs")
        .join("gateway_history.json");
    assert!(history_file.is_file());
    let history_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&history_file).unwrap()).unwrap();
    assert_eq!(history_json["history_rewrite_count"], 1);
    assert_eq!(history_json["gateway_adapter_version"], "2026-11-1");
    let head = history_json["gateway_log_head"].as_str().unwrap();
    assert!(head.starts_with("sha256:"));
    assert_eq!(head.len(), 71); // "sha256:" + 64 hex chars
    assert_eq!(head, env.gateway_server.history().head_digest());
}

#[test]
fn test_history_hash_chain_head_progression() {
    let history = HistoryLog::new();
    let initial_head = history.head();
    assert_eq!(
        initial_head,
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        history.head_digest(),
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(history.rewrites_total(), 0);

    let sys = b"\"system prompt\"";
    let m0 = b"{\"role\":\"user\",\"content\":\"q1\"}".to_vec();
    let m1 = b"{\"role\":\"assistant\",\"content\":\"a1\"}".to_vec();
    let m2 = b"{\"role\":\"user\",\"content\":\"q2\"}".to_vec();

    // Turn 1
    let (is_rw1, total1) = history.check_and_record(sys, std::slice::from_ref(&m0));
    assert!(!is_rw1);
    assert_eq!(total1, 0);
    let head1 = history.head();
    assert_ne!(head1, initial_head);

    // Turn 2
    let (is_rw2, total2) = history.check_and_record(sys, &[m0.clone(), m1.clone(), m2.clone()]);
    assert!(!is_rw2);
    assert_eq!(total2, 0);
    let head2 = history.head();
    assert_ne!(head2, head1);

    // Turn 3 (rewrite)
    let m0_edited = b"{\"role\":\"user\",\"content\":\"q1_edited\"}".to_vec();
    let (is_rw3, total3) = history.check_and_record(sys, &[m0_edited, m1, m2]);
    assert!(is_rw3);
    assert_eq!(total3, 1);
    let head3 = history.head();
    assert_ne!(head3, head2);
    assert_eq!(history.rewrites_total(), 1);
}

#[test]
fn test_history_snapshot_atomic_head_and_rewrites() {
    let history = HistoryLog::new();
    let sys = b"\"system prompt\"";
    let m0 = b"{\"role\":\"user\",\"content\":\"q1\"}".to_vec();
    let (head0, rw0) = history.snapshot();
    assert_eq!(
        head0,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(rw0, 0);

    history.check_and_record(sys, &[m0]);
    let (head1, rw1) = history.snapshot();
    assert_ne!(head1, head0);
    assert_eq!(rw1, 0);
}

#[test]
fn test_concurrent_history_persistence_serializes_snapshot_and_publication() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );
    let server = env.gateway_server.clone();
    let history_file = env
        .temp_dir
        .path()
        .join("logs")
        .join("gateway_history.json");

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    let server1 = server.clone();
    let t1 = thread::spawn(move || {
        server1.persist_history_with_writer(|bytes| {
            entered_tx.send(()).unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("release signal");
            let dir = hermetic_gateway::fsutil::open_dir_nofollow_create(&server1.config().log_dir)
                .unwrap();
            hermetic_gateway::fsutil::write_state_file(
                &dir,
                hermetic_gateway::server::GATEWAY_HISTORY_FILE,
                bytes,
            )
            .is_ok()
        })
    });

    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("entered lock");

    // Intervening rewrite
    let sys = b"\"system prompt\"";
    let m0 = b"{\"role\":\"user\",\"content\":\"q1\"}".to_vec();
    let m1 = b"{\"role\":\"assistant\",\"content\":\"a1\"}".to_vec();
    let m0_edited = b"{\"role\":\"user\",\"content\":\"q1_edited\"}".to_vec();
    server
        .history()
        .check_and_record(sys, std::slice::from_ref(&m0));
    server.history().check_and_record(sys, &[m0, m1.clone()]);
    server.history().check_and_record(sys, &[m0_edited, m1]);
    assert_eq!(server.history().rewrites_total(), 1);

    let server2 = server.clone();
    let t2 = thread::spawn(move || {
        let res = server2.persist_history();
        done_tx.send(()).unwrap();
        res
    });

    let premature = done_rx.recv_timeout(Duration::from_millis(50)).is_ok();
    assert!(
        !premature,
        "newer snapshot was published ahead of an older writer"
    );

    release_tx.send(()).unwrap();

    assert!(t1.join().unwrap());
    assert!(t2.join().unwrap());

    let history_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&history_file).unwrap()).unwrap();
    assert_eq!(history_json["history_rewrite_count"], 1);
}

#[test]
fn test_history_persistence_failure_latched_and_removes_stale_artifact() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );
    let history_file = env
        .temp_dir
        .path()
        .join("logs")
        .join("gateway_history.json");
    assert!(history_file.is_file());

    env.gateway_server.simulate_history_persist_failure();
    assert!(env.gateway_server.history_persist_failed());
    assert!(
        !history_file.exists(),
        "gateway_history.json must be removed on failure"
    );

    assert!(!env.gateway_server.persist_history());
    assert!(!history_file.exists());
}

#[test]
fn test_constructor_fails_if_initial_history_persist_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let key_path = temp_dir.path().join("key.txt");
    std::fs::write(&key_path, "secret").unwrap();

    let bad_log_dir = temp_dir.path().join("not_a_dir");
    std::fs::write(&bad_log_dir, "blocking file").unwrap();

    let config = hermetic_gateway::config::GatewayConfig::from_raw(
        "http://127.0.0.1:1234".to_string(),
        "2023-06-01".to_string(),
        vec![],
        vec!["claude-3-5-sonnet-20241022".to_string()],
        QuotasConfig::default(),
        bad_log_dir,
        key_path,
        "secret".to_string(),
    );
    let t_clock = time::OffsetDateTime::parse(
        "2026-11-11T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let err = hermetic_gateway::server::GatewayServer::new(config, t_clock);
    assert!(err.is_err());
}
