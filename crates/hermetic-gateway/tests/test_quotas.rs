mod common;

use common::TestEnv;
use hermetic_gateway::quota::QuotasConfig;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tiny_http::Response;

#[test]
fn test_request_quota_triggers_limit_exceeded() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig {
            max_requests: Some(1),
            ..Default::default()
        },
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        req.respond(Response::from_string(r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#)).unwrap();
    });

    let client = common::test_client();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    // First request should succeed
    let res1 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("first request ok");
    assert_eq!(res1.status(), 200);
    common::join_within(mock_handle);

    // Second request breaches quota
    let err2 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .unwrap_err();

    if let ureq::Error::Status(429, resp) = err2 {
        let b = resp.into_string().unwrap();
        assert!(b.contains("rate_limit_error"));
    } else {
        panic!("Expected 429 for second request");
    }

    // Third request refused due to terminal limit_exceeded
    let err3 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .unwrap_err();

    if let ureq::Error::Status(429, resp) = err3 {
        let b = resp.into_string().unwrap();
        assert!(b.contains("rate_limit_error"));
    } else {
        panic!("Expected 429 for third request");
    }

    assert!(env.gateway_server.quota().snapshot().limit_exceeded);
}

#[test]
fn test_output_token_quota_triggers_limit_exceeded() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig {
            max_output_tokens: Some(10),
            ..Default::default()
        },
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        // Return 15 output tokens, which breaches limit of 10
        req.respond(Response::from_string(r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":15}}"#)).unwrap();
    });

    let client = common::test_client();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    // The breaching response itself is not delivered: a standard 429 replaces it.
    let err1 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .unwrap_err();
    match err1 {
        ureq::Error::Status(429, resp) => {
            let b = resp.into_string().unwrap();
            assert!(b.contains("rate_limit_error"), "{b}");
            assert!(!b.contains("\"usage\""), "breaching body leaked: {b}");
        }
        other => panic!("Expected 429 for the breaching response, got {other:?}"),
    }
    common::join_within(mock_handle);

    // Now gateway is in limit_exceeded state
    assert!(env.gateway_server.quota().snapshot().limit_exceeded);

    // Later request must be refused
    let err2 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .unwrap_err();

    if let ureq::Error::Status(429, resp) = err2 {
        let b = resp.into_string().unwrap();
        assert!(b.contains("rate_limit_error"));
    } else {
        panic!("Expected 429 for request after token cap breach");
    }
}

#[test]
fn test_input_token_quota_triggers_limit_exceeded() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig {
            max_input_tokens: Some(20),
            ..Default::default()
        },
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        // Return 25 input tokens, breaching cap of 20
        req.respond(Response::from_string(r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":25,"output_tokens":1}}"#)).unwrap();
    });

    let client = common::test_client();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    // The breaching response itself is not delivered: a standard 429 replaces it.
    let err1 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .unwrap_err();
    match err1 {
        ureq::Error::Status(429, resp) => {
            let b = resp.into_string().unwrap();
            assert!(b.contains("rate_limit_error"), "{b}");
            assert!(!b.contains("\"usage\""), "breaching body leaked: {b}");
        }
        other => panic!("Expected 429 for the breaching response, got {other:?}"),
    }
    common::join_within(mock_handle);

    assert!(env.gateway_server.quota().snapshot().limit_exceeded);

    let err2 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .unwrap_err();

    if let ureq::Error::Status(429, _) = err2 {
        // Ok
    } else {
        panic!("Expected 429");
    }
}

#[test]
fn test_concurrency_quota_triggers_limit_exceeded() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig {
            max_concurrent_requests: Some(1),
            ..Default::default()
        },
    );

    let (req1_started_tx, req1_started_rx) = mpsc::channel();
    let (release_req1_tx, release_req1_rx) = mpsc::channel();

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = common::recv_upstream(&mock);
        req1_started_tx.send(()).unwrap();
        release_req1_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap();
        req.respond(Response::from_string(r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#)).unwrap();
    });

    let gw_url1 = env.gateway_url.clone();
    let client1 = common::test_client();
    let req1_handle = thread::spawn(move || {
        let body =
            r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;
        client1
            .post(&format!("{}/v1/messages", gw_url1))
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_string(body)
            .map(|r| r.status())
            .map_err(|e| e.to_string())
    });

    // Wait until req1 is active and held in mock
    req1_started_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap();

    // Now send req2 while req1 is still active
    let client2 = common::test_client();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;
    let err2 = client2
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .unwrap_err();

    match err2 {
        ureq::Error::Status(429, resp) => {
            let b = resp.into_string().unwrap();
            assert!(b.contains("rate_limit_error"));
        }
        other => panic!("Expected 429 for concurrent request breach, got {other:?}"),
    }

    // Release req1
    release_req1_tx.send(()).unwrap();
    let _ = common::join_within(req1_handle);
    common::join_within(mock_handle);

    // Terminal limit_exceeded must now reject all later requests
    assert!(env.gateway_server.quota().snapshot().limit_exceeded);
}

#[test]
fn test_wall_time_quota_triggers_limit_exceeded() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig {
            max_wall_time_seconds: Some(1),
            ..Default::default()
        },
    );

    // Sleep past the 1s wall time cap
    thread::sleep(Duration::from_millis(1100));

    let client = common::test_client();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .unwrap_err();

    match err {
        ureq::Error::Status(429, resp) => {
            let b = resp.into_string().unwrap();
            assert!(b.contains("rate_limit_error"));
        }
        other => panic!("Expected 429 for wall time breach, got {other:?}"),
    }

    assert!(env.gateway_server.quota().snapshot().limit_exceeded);
}
