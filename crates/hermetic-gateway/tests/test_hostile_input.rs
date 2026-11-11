mod common;

use common::TestEnv;
use hermetic_gateway::quota::QuotasConfig;
use std::io::Cursor;
use std::thread;
use tiny_http::{Header, Response};

#[test]
fn test_huge_body_rejected_with_413() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();

    // Declared content-length exceeds 32 MiB
    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .set("content-length", "34000000") // ~32.4 MiB
        .send(Cursor::new(vec![b'A'; 100]))
        .unwrap_err();

    match err {
        ureq::Error::Status(413, resp) => {
            let b = resp.into_string().unwrap();
            let json: serde_json::Value = serde_json::from_str(&b).unwrap();
            assert_eq!(json["type"], "error");
            assert_eq!(json["error"]["type"], "request_too_large");
        }
        other => panic!("Expected 413 for huge body, got {other:?}"),
    }

    assert!(env.mock_server.try_recv().unwrap().is_none());
}

#[test]
fn test_deeply_nested_json_rejected() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();

    // Create 100-deep nested array
    let mut nested = String::new();
    for _ in 0..100 {
        nested.push('[');
    }
    for _ in 0..100 {
        nested.push(']');
    }

    let body = format!(
        r#"{{"model":"claude-3-5-sonnet-20241022","messages":[{{"role":"user","content":{nested}}}]}}"#
    );

    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(&body)
        .unwrap_err();

    match err {
        ureq::Error::Status(400, resp) => {
            let b = resp.into_string().unwrap();
            let json: serde_json::Value = serde_json::from_str(&b).unwrap();
            assert_eq!(json["error"]["type"], "invalid_request_error");
            assert!(json["error"]["message"].as_str().unwrap().contains("depth"));
        }
        other => panic!("Expected 400 for deep nesting, got {other:?}"),
    }

    assert!(env.mock_server.try_recv().unwrap().is_none());
}

#[test]
fn test_invalid_utf8_rejected_without_panic() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();

    // Send invalid UTF-8 bytes (0xFF, 0xFE)
    let invalid_bytes: &[u8] = b"{\"model\":\"claude-3-5-sonnet-20241022\", \xff\xfe: 123}";

    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_bytes(invalid_bytes)
        .unwrap_err();

    match err {
        ureq::Error::Status(400, resp) => {
            let b = resp.into_string().unwrap();
            let json: serde_json::Value = serde_json::from_str(&b).unwrap();
            assert_eq!(json["error"]["type"], "invalid_request_error");
            assert!(json["error"]["message"].as_str().unwrap().contains("UTF-8"));
        }
        other => panic!("Expected 400 for invalid UTF-8, got {other:?}"),
    }

    assert!(env.mock_server.try_recv().unwrap().is_none());
}

#[test]
fn test_malformed_sse_from_mock_does_not_panic() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = mock.recv().unwrap();

        // Malformed SSE: random non-JSON data lines, broken events, truncated fields
        let sse_garbage = "garbage_line_without_colon\n\
event: unknown_event\n\
data: not a valid json at all {{{{}}}}}} [[[\n\n\
:this is an sse comment line\n\
event: message_delta\n\
data: {broken json\n\n\
event: message_stop\n\
data: {}\n\n";

        let resp = Response::new(
            200.into(),
            vec![Header::from_bytes(&b"Content-Type"[..], &b"text/event-stream"[..]).unwrap()],
            Cursor::new(sse_garbage.as_bytes().to_vec()),
            Some(sse_garbage.len()),
            None,
        );

        req.respond(resp).unwrap();
    });

    let client = ureq::AgentBuilder::new().build();
    let body = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hi"}],
        "stream": true
    }"#;

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("send stream ok");

    assert_eq!(res.status(), 200);

    let mut body_out = String::new();
    let mut reader = res.into_reader();
    let _ = reader.read_to_string(&mut body_out);

    mock_handle.join().unwrap();

    // Verify server survived and stream completed without panic
    assert!(body_out.contains("event: message_stop"));
}
