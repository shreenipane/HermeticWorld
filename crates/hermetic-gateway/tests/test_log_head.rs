#![forbid(unsafe_code)]

mod common;

use common::TestEnv;
use hermetic_common::hash::HashChain;
use hermetic_gateway::log::{
    GatewayHeadSummary, HostLogEntry, HostLogger, GATEWAY_HEAD_FILE, GATEWAY_LOG_HEAD_FILE,
};
use hermetic_gateway::quota::{QuotaSnapshot, QuotasConfig};
use std::collections::BTreeMap;
use std::fs;
use std::thread;
use tempfile::tempdir;
use tiny_http::Response;

#[test]
fn test_logger_hash_chain_vectors_and_head_persistence() {
    let temp = tempdir().expect("tempdir");
    let log_dir = temp.path().join("log");
    let logger = HostLogger::new(&log_dir).expect("create logger");

    // Initially 0 records and head is 64 zeros
    assert_eq!(logger.records_count(), 0);
    assert_eq!(
        logger.head_hex(),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        logger.head_digest(),
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    );

    let dummy_entry = HostLogEntry {
        timestamp: "2026-11-18T00:00:00Z".to_string(),
        adapter_version: "2026-11-1".to_string(),
        endpoint: "/v1/messages".to_string(),
        model: Some("model-1".to_string()),
        stream: false,
        client_status: 200,
        upstream_status: Some(200),
        dropped_headers: BTreeMap::new(),
        original_error_body: None,
        history_rewrite: false,
        history_rewrites_total: 0,
        quotas: QuotaSnapshot {
            requests: 1,
            input_tokens: 10,
            output_tokens: 5,
            concurrent_requests: 1,
            limit_exceeded: false,
            limit_exceeded_reason: None,
        },
    };

    assert!(logger.log(&dummy_entry));
    assert_eq!(logger.records_count(), 1);
    let head1 = logger.head_hex();
    assert_ne!(
        head1,
        "0000000000000000000000000000000000000000000000000000000000000000"
    );

    logger
        .persist_head(&log_dir, 0, "2026-11-1")
        .expect("persist head");

    let head_path = log_dir.join(GATEWAY_HEAD_FILE);
    assert!(head_path.exists());
    let log_head_path = log_dir.join(GATEWAY_LOG_HEAD_FILE);
    assert!(log_head_path.exists());

    let raw = fs::read_to_string(&head_path).expect("read head file");
    let summary: GatewayHeadSummary = serde_json::from_str(&raw).expect("parse summary");
    assert_eq!(summary.records, 1);
    assert_eq!(summary.head, format!("sha256:{head1}"));
    assert_eq!(summary.history_rewrite_count, 0);
    assert_eq!(summary.adapter_version, "2026-11-1");

    // Verify log lines independently against HashChain
    let log_file = log_dir.join("gateway.jsonl");
    let log_content = fs::read(&log_file).expect("read log");
    let verified_head =
        HashChain::verify_records([log_content.as_slice()], &head1).expect("verify records");
    assert_eq!(verified_head, head1);
}

#[test]
fn test_gateway_server_persists_log_head_after_model_call() {
    let env = TestEnv::new(vec!["model-1".to_string()], vec![], QuotasConfig::default());

    let mock_server = env.mock_server.clone();
    let upstream_thread = thread::spawn(move || {
        let req = mock_server.recv().expect("mock receives request");
        let body = r#"{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"response"}],"model":"model-1","usage":{"input_tokens":10,"output_tokens":5}}"#;
        let response = Response::from_string(body)
            .with_status_code(200)
            .with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap(),
            );
        req.respond(response).expect("mock responds");
    });

    let client_req = serde_json::json!({
        "model": "model-1",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hello"}]
    });

    let resp = ureq::post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(&client_req.to_string())
        .expect("gateway call succeeds");
    assert_eq!(resp.status(), 200);

    upstream_thread.join().expect("join mock thread");

    let head_path = env.temp_dir.path().join("logs").join(GATEWAY_HEAD_FILE);
    let deadline = std::time::Instant::now() + common::TEST_WAIT;
    let summary = loop {
        if let Ok(raw) = fs::read_to_string(&head_path) {
            if let Ok(s) = serde_json::from_str::<GatewayHeadSummary>(&raw) {
                if s.records >= 1 {
                    break s;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for head persistence with records >= 1");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };

    assert_eq!(summary.records, 1);
    assert!(summary.head.starts_with("sha256:"));
    assert_eq!(summary.head.len(), 71);
    assert_eq!(summary.history_rewrite_count, 0);
    assert_eq!(summary.adapter_version, "2026-11-1");
}
