mod common;

use common::TestEnv;
use hermetic_gateway::history::HistoryLog;
use hermetic_gateway::quota::QuotasConfig;
use std::thread;
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
            let req = mock.recv().unwrap();
            req.respond(Response::from_string(r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#)).unwrap();
        }
    });

    let client = ureq::AgentBuilder::new().build();

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

    mock_handle.join().unwrap();

    // Check host logs
    let logs = env.read_host_logs();
    assert_eq!(logs.len(), 3);
    assert_eq!(logs[0]["history_rewrite"], false);
    assert_eq!(logs[1]["history_rewrite"], false);
    assert_eq!(logs[2]["history_rewrite"], true);
    assert_eq!(logs[2]["history_rewrites_total"], 1);
}
