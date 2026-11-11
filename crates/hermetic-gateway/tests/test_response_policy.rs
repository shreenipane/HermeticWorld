mod common;

use common::TestEnv;
use hermetic_gateway::quota::QuotasConfig;
use std::thread;
use std::time::Duration;
use tiny_http::{Header, Response};

#[test]
fn test_response_headers_filtered_and_date_replaced() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");

        let mut resp = Response::from_string(r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#)
            .with_status_code(200);

        // Add headers from upstream mock:
        resp.add_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"Date"[..], &b"Sun, 06 Nov 1994 08:49:37 GMT"[..]).unwrap(),
        );
        resp.add_header(Header::from_bytes(&b"cf-ray"[..], &b"8f123456789abcde"[..]).unwrap());
        resp.add_header(Header::from_bytes(&b"x-request-id"[..], &b"req_xyz_123"[..]).unwrap());
        resp.add_header(
            Header::from_bytes(&b"anthropic-ratelimit-requests-limit"[..], &b"1000"[..]).unwrap(),
        );

        req.respond(resp).unwrap();
    });

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("send ok");

    assert_eq!(res.status(), 200);

    // Dropped headers must NOT reach the agent
    assert!(res.header("cf-ray").is_none());
    assert!(res.header("x-request-id").is_none());
    assert!(res.header("anthropic-ratelimit-requests-limit").is_none());

    // Date must be replaced with guest time (2026-11-11...)
    let date_hdr = res.header("date").expect("Date header present");
    assert!(
        date_hdr.contains("2026"),
        "Date header '{date_hdr}' should be guest time in 2026"
    );

    mock_handle.join().unwrap();

    // Verify dropped headers were written to host log
    let logs = env.read_host_logs();
    assert!(!logs.is_empty());
    let last_log = logs.last().unwrap();
    let dropped = &last_log["dropped_headers"];
    assert_eq!(dropped["cf-ray"], "8f123456789abcde");
    assert_eq!(dropped["x-request-id"], "req_xyz_123");
    assert_eq!(dropped["anthropic-ratelimit-requests-limit"], "1000");
}

#[test]
fn test_retry_after_seconds_input() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let mut resp = Response::from_string(
            r#"{"type":"error","error":{"type":"rate_limit_error","message":"Slow down"}}"#,
        )
        .with_status_code(429);
        resp.add_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
        resp.add_header(Header::from_bytes(&b"Retry-After"[..], &b"120"[..]).unwrap());
        req.respond(resp).unwrap();
    });

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body);

    h.join().unwrap();

    match res {
        Err(ureq::Error::Status(429, resp)) => {
            assert_eq!(
                resp.header("retry-after"),
                Some("120"),
                "Headers: {:?}",
                resp.headers_names()
            );
        }
        other => panic!("Expected 429 status, got {other:?}"),
    }
}

#[test]
fn test_retry_after_http_date_input() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let mut resp = Response::from_string(
            r#"{"type":"error","error":{"type":"rate_limit_error","message":"Wait"}}"#,
        )
        .with_status_code(429);
        resp.add_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"Date"[..], &b"Wed, 11 Nov 2026 12:00:00 GMT"[..]).unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"Retry-After"[..], &b"Wed, 11 Nov 2026 12:01:30 GMT"[..]).unwrap(),
        );
        req.respond(resp).unwrap();
    });

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body);

    h.join().unwrap();

    match res {
        Err(ureq::Error::Status(429, resp)) => {
            assert_eq!(
                resp.header("retry-after"),
                Some("90"),
                "Headers: {:?}",
                resp.headers_names()
            );
        }
        other => panic!("Expected 429 status, got {other:?}"),
    }
}

#[test]
fn test_retry_after_rfc3339_input() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let mut resp = Response::from_string(
            r#"{"type":"error","error":{"type":"rate_limit_error","message":"Wait"}}"#,
        )
        .with_status_code(429);
        resp.add_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"Date"[..], &b"Wed, 11 Nov 2026 12:00:00 GMT"[..]).unwrap(),
        );
        resp.add_header(
            Header::from_bytes(&b"Retry-After"[..], &b"2026-11-11T12:02:15Z"[..]).unwrap(),
        );
        req.respond(resp).unwrap();
    });

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body);

    h.join().unwrap();

    match res {
        Err(ureq::Error::Status(429, resp)) => {
            assert_eq!(
                resp.header("retry-after"),
                Some("135"),
                "Headers: {:?}",
                resp.headers_names()
            );
        }
        other => panic!("Expected 429 status, got {other:?}"),
    }
}

#[test]
fn test_body_timestamp_rewrites_in_json() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let h = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let resp_json = r#"{
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "created": 1700000000,
            "created_at": 1700000001,
            "updated_at": "2024-01-01T00:00:00Z",
            "expires_at": "2024-01-02T00:00:00Z",
            "content": [{"type": "text", "text": "Hello"}],
            "nested": {
                "created_at": 1700000002,
                "other_field": 123
            },
            "usage": {"input_tokens": 10, "output_tokens": 5}
        }"#;

        let resp = Response::from_string(resp_json)
            .with_status_code(200)
            .with_header(
                Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
            );
        req.respond(resp).unwrap();
    });

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("success");

    let resp_str = res.into_string().unwrap();
    let val: serde_json::Value = serde_json::from_str(&resp_str).unwrap();

    let guest_unix = env.t_clock.unix_timestamp();

    // Verify numbers rewritten to guest unix seconds
    assert_eq!(val["created"].as_i64(), Some(guest_unix));
    assert_eq!(val["created_at"].as_i64(), Some(guest_unix));
    assert_eq!(val["nested"]["created_at"].as_i64(), Some(guest_unix));
    assert_eq!(val["nested"]["other_field"].as_i64(), Some(123)); // untouched

    // Verify RFC 3339 strings rewritten to guest RFC 3339
    assert_eq!(val["updated_at"].as_str(), Some("2026-11-11T12:00:00Z"));
    assert_eq!(val["expires_at"].as_str(), Some("2026-11-11T12:00:00Z"));

    h.join().unwrap();
}

#[test]
fn test_non_2xx_bodies_recognised_type_replaced_with_standard_error() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();
    let req_body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    // Upstream 529 Overloaded with leak in message
    let mock = env.mock_server.clone();
    let h1 = thread::spawn(move || {
        let req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let resp = Response::from_string(r#"{"type":"error","error":{"type":"overloaded_error","message":"Server overloaded at host cluster dc4-2026-11-11T20:30:00Z"}}"#)
            .with_status_code(529)
            .with_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());
        req.respond(resp).unwrap();
    });

    let err1 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(req_body)
        .unwrap_err();

    if let ureq::Error::Status(529, resp) = err1 {
        let b = resp.into_string().unwrap();
        let val: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(val["type"], "error");
        assert_eq!(val["error"]["type"], "overloaded_error");
        // Message must be replaced with standard text
        assert_eq!(val["error"]["message"], "Overloaded");
    } else {
        panic!("Expected 529");
    }
    h1.join().unwrap();
}

#[test]
fn test_non_2xx_bodies_unrecognised_type_html_replaced_with_api_error() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = ureq::AgentBuilder::new().build();
    let req_body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    let mock2 = env.mock_server.clone();
    let h2 = thread::spawn(move || {
        let req = mock2
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req received");
        let resp = Response::from_string(
            "<html><body>502 Bad Gateway - Cloudflare host node 42</body></html>",
        )
        .with_status_code(502)
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"text/html"[..]).unwrap());
        req.respond(resp).unwrap();
    });

    let err2 = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(req_body)
        .unwrap_err();

    if let ureq::Error::Status(502, resp) = err2 {
        let b = resp.into_string().unwrap();
        let val: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(val["type"], "error");
        // Unrecognised becomes api_error
        assert_eq!(val["error"]["type"], "api_error");
        assert_eq!(val["error"]["message"], "Upstream API error");
    } else {
        panic!("Expected 502");
    }
    h2.join().unwrap();

    // Verify original error bodies are in host log
    let logs = env.read_host_logs();
    assert!(logs.iter().any(|l| {
        l["original_error_body"]
            .as_str()
            .map(|s| s.contains("Cloudflare host node 42"))
            .unwrap_or(false)
    }));
}
