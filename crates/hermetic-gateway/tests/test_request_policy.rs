mod common;

use common::TestEnv;
use hermetic_gateway::quota::QuotasConfig;
use std::thread;
use std::time::Duration;

#[test]
fn test_allowed_request_rebuilt_and_verified_at_mock() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec!["prompt-caching-2024-07-31".to_string()],
        QuotasConfig::default(),
    );

    let mock = env.mock_server.clone();
    let expected_key = env.api_key.clone();

    let mock_handle = thread::spawn(move || {
        let mut req = mock
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("request received at mock");

        // Verify headers received at mock
        let mut received_api_key = None;
        let mut received_anthropic_version = None;
        let mut received_anthropic_beta = None;
        let mut received_agent_auth = None;

        for h in req.headers() {
            let name = h.field.as_str().as_str();
            let val = h.value.as_str();
            if name.eq_ignore_ascii_case("x-api-key") {
                received_api_key = Some(val.to_string());
            } else if name.eq_ignore_ascii_case("anthropic-version") {
                received_anthropic_version = Some(val.to_string());
            } else if name.eq_ignore_ascii_case("anthropic-beta") {
                received_anthropic_beta = Some(val.to_string());
            } else if name.eq_ignore_ascii_case("authorization") {
                received_agent_auth = Some(val.to_string());
            }
        }

        assert_eq!(received_api_key.as_deref(), Some(expected_key.as_str()));
        assert_eq!(received_anthropic_version.as_deref(), Some("2023-06-01"));
        assert_eq!(
            received_anthropic_beta.as_deref(),
            Some("prompt-caching-2024-07-31")
        );
        assert!(received_agent_auth.is_none());

        let mut body = String::new();
        req.as_reader()
            .read_to_string(&mut body)
            .expect("read body");

        // Verify that the body was rebuilt and starts with "model" field
        assert!(body.starts_with(r#"{"model":"claude-3-5-sonnet-20241022""#));

        // Verify system prompt was injected with run nonce
        assert!(body.contains("[run-nonce "));

        let resp_body = r#"{
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello, world!"}],
            "model": "claude-3-5-sonnet-20241022",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        }"#;

        let response = tiny_http::Response::from_string(resp_body)
            .with_status_code(200)
            .with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap(),
            );
        req.respond(response).expect("respond");
    });

    let client = common::test_client();
    let agent_request_body = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": "Hi"
            }
        ],
        "max_tokens": 100
    }"#;

    let res = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("anthropic-beta", "prompt-caching-2024-07-31")
        .set("content-type", "application/json")
        .set("x-api-key", "agent-hostile-stolen-key")
        .set("authorization", "Bearer agent-stolen-token")
        .send_string(agent_request_body)
        .expect("agent request success");

    assert_eq!(res.status(), 200);
    common::join_within(mock_handle);
}

#[test]
fn test_unknown_field_rejected_before_mock() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = common::test_client();
    let hostile_body = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hi"}],
        "max_tokens": 100,
        "unexpected_field": "hostile"
    }"#;

    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(hostile_body)
        .unwrap_err();

    match err {
        ureq::Error::Status(400, resp) => {
            let body = resp.into_string().unwrap();
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["type"], "error");
            assert_eq!(json["error"]["type"], "invalid_request_error");
            assert!(json["error"]["message"]
                .as_str()
                .unwrap()
                .contains("unexpected_field"));
        }
        other => panic!("Expected 400 error, got {other:?}"),
    }

    // Mock received nothing
    assert!(env.mock_server.try_recv().unwrap().is_none());
}

#[test]
fn test_server_tool_rejected_before_mock() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = common::test_client();
    let body_with_server_tool = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hi"}],
        "max_tokens": 100,
        "tools": [
            {
                "type": "web_search_20250101",
                "name": "web_search"
            }
        ]
    }"#;

    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body_with_server_tool)
        .unwrap_err();

    match err {
        ureq::Error::Status(400, resp) => {
            let body = resp.into_string().unwrap();
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["type"], "error");
            assert_eq!(json["error"]["type"], "invalid_request_error");
            let msg = json["error"]["message"].as_str().unwrap().to_lowercase();
            assert!(msg.contains("server tool") || msg.contains("type"));
        }
        other => panic!("Expected 400 error, got {other:?}"),
    }

    assert!(env.mock_server.try_recv().unwrap().is_none());
}

#[test]
fn test_url_image_source_rejected_before_mock() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = common::test_client();
    let body_url_image = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "url",
                            "url": "https://attacker.com/evil.png"
                        }
                    }
                ]
            }
        ],
        "max_tokens": 100
    }"#;

    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body_url_image)
        .unwrap_err();

    match err {
        ureq::Error::Status(400, resp) => {
            let body = resp.into_string().unwrap();
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["error"]["type"], "invalid_request_error");
            assert!(json["error"]["message"].as_str().unwrap().contains("URL"));
        }
        other => panic!("Expected 400 error, got {other:?}"),
    }

    assert!(env.mock_server.try_recv().unwrap().is_none());
}

#[test]
fn test_file_id_document_rejected_before_mock() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = common::test_client();
    let body_file_id = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {
                            "type": "file_id",
                            "file_id": "file_12345"
                        }
                    }
                ]
            }
        ],
        "max_tokens": 100
    }"#;

    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body_file_id)
        .unwrap_err();

    match err {
        ureq::Error::Status(400, resp) => {
            let body = resp.into_string().unwrap();
            let json: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(json["error"]["type"], "invalid_request_error");
            assert!(json["error"]["message"]
                .as_str()
                .unwrap()
                .contains("File-ID"));
        }
        other => panic!("Expected 400 error, got {other:?}"),
    }

    assert!(env.mock_server.try_recv().unwrap().is_none());
}

#[test]
fn test_unlisted_beta_flag_rejected() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec!["prompt-caching-2024-07-31".to_string()], // only this beta is allowed
        QuotasConfig::default(),
    );

    let client = common::test_client();
    let body = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hi"}],
        "max_tokens": 100
    }"#;

    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("anthropic-beta", "computer-use-2024-10-22")
        .set("content-type", "application/json")
        .send_string(body)
        .unwrap_err();

    match err {
        ureq::Error::Status(400, resp) => {
            let b = resp.into_string().unwrap();
            let json: serde_json::Value = serde_json::from_str(&b).unwrap();
            assert_eq!(json["error"]["type"], "invalid_request_error");
            assert!(json["error"]["message"]
                .as_str()
                .unwrap()
                .contains("computer-use-2024-10-22"));
        }
        other => panic!("Expected 400 error, got {other:?}"),
    }

    assert!(env.mock_server.try_recv().unwrap().is_none());
}

#[test]
fn test_unpinned_model_rejected() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = common::test_client();
    let body = r#"{
        "model": "claude-3-opus-20240229",
        "messages": [{"role": "user", "content": "Hi"}],
        "max_tokens": 100
    }"#;

    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .unwrap_err();

    match err {
        ureq::Error::Status(400, resp) => {
            let b = resp.into_string().unwrap();
            let json: serde_json::Value = serde_json::from_str(&b).unwrap();
            assert_eq!(json["error"]["type"], "invalid_request_error");
            assert!(json["error"]["message"]
                .as_str()
                .unwrap()
                .contains("claude-3-opus-20240229"));
        }
        other => panic!("Expected 400 error, got {other:?}"),
    }

    assert!(env.mock_server.try_recv().unwrap().is_none());
}

#[test]
fn test_wrong_endpoint_rejected_with_404() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = common::test_client();
    let err = client
        .post(&format!("{}/v1/complete", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(r#"{"model":"claude-3-5-sonnet-20241022"}"#)
        .unwrap_err();

    match err {
        ureq::Error::Status(404, resp) => {
            let b = resp.into_string().unwrap();
            let json: serde_json::Value = serde_json::from_str(&b).unwrap();
            assert_eq!(json["type"], "error");
            assert_eq!(json["error"]["type"], "not_found_error");
        }
        other => panic!("Expected 404 error, got {other:?}"),
    }

    assert!(env.mock_server.try_recv().unwrap().is_none());
}

#[test]
fn test_forbidden_fields_mcp_servers_and_container() {
    let env = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    let client = common::test_client();

    // Test mcp_servers
    let body_mcp = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hi"}],
        "mcp_servers": ["server1"]
    }"#;
    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body_mcp)
        .unwrap_err();
    match err {
        ureq::Error::Status(400, resp) => {
            let b = resp.into_string().unwrap();
            assert!(b.contains("mcp_servers"));
        }
        other => panic!("Expected 400, got {other:?}"),
    }

    // Test container
    let body_container = r#"{
        "model": "claude-3-5-sonnet-20241022",
        "messages": [{"role": "user", "content": "Hi"}],
        "container": {"image": "ubuntu"}
    }"#;
    let err = client
        .post(&format!("{}/v1/messages", env.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body_container)
        .unwrap_err();
    match err {
        ureq::Error::Status(400, resp) => {
            let b = resp.into_string().unwrap();
            assert!(b.contains("container"));
        }
        other => panic!("Expected 400, got {other:?}"),
    }
}
