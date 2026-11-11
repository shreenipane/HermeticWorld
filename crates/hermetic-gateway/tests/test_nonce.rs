mod common;

use common::TestEnv;
use hermetic_gateway::anthropic::{AnthropicRequest, SystemPrompt, TextBlock};
use hermetic_gateway::nonce::RunNonce;
use hermetic_gateway::quota::QuotasConfig;
use std::thread;
use std::time::Duration;

#[test]
fn test_nonce_generation_properties() {
    let nonce1 = RunNonce::generate().expect("generate nonce1");
    let nonce2 = RunNonce::generate().expect("generate nonce2");

    assert_eq!(nonce1.hex().len(), 32);
    assert_eq!(nonce2.hex().len(), 32);

    // Verify all hex characters
    assert!(nonce1.hex().chars().all(|c| c.is_ascii_hexdigit()));
    assert!(nonce2.hex().chars().all(|c| c.is_ascii_hexdigit()));

    // Different across instances
    assert_ne!(nonce1.hex(), nonce2.hex());

    assert_eq!(
        nonce1.system_prefix(),
        format!("[run-nonce {}]\n", nonce1.hex())
    );
}

#[test]
fn test_nonce_injection_shapes() {
    let nonce = RunNonce::from_hex("0123456789abcdef0123456789abcdef".to_string());

    // 1. System absent -> created
    let mut req1 = AnthropicRequest {
        model: "claude-3-5-sonnet-20241022".to_string(),
        messages: vec![],
        system: None,
        max_tokens: Some(10),
        temperature: None,
        top_p: None,
        top_k: None,
        stop_sequences: None,
        stream: None,
        metadata: None,
        tools: None,
        tool_choice: None,
        thinking: None,
    };
    req1.inject_nonce(&nonce);
    match req1.system {
        Some(SystemPrompt::String(ref s)) => {
            assert_eq!(s, "[run-nonce 0123456789abcdef0123456789abcdef]\n");
        }
        other => panic!("Expected SystemPrompt::String, got {other:?}"),
    }

    // 2. System is a string -> prepended
    let mut req2 = req1.clone();
    req2.system = Some(SystemPrompt::String("Act as a coder.".to_string()));
    req2.inject_nonce(&nonce);
    match req2.system {
        Some(SystemPrompt::String(ref s)) => {
            assert_eq!(
                s,
                "[run-nonce 0123456789abcdef0123456789abcdef]\nAct as a coder."
            );
        }
        other => panic!("Expected SystemPrompt::String, got {other:?}"),
    }

    // 3. System is an array of blocks -> inserted as new first text block
    let mut req3 = req1.clone();
    req3.system = Some(SystemPrompt::Blocks(vec![TextBlock {
        r#type: "text".to_string(),
        text: "Existing block".to_string(),
        cache_control: None,
    }]));
    req3.inject_nonce(&nonce);
    match req3.system {
        Some(SystemPrompt::Blocks(blocks)) => {
            assert_eq!(blocks.len(), 2);
            assert_eq!(
                blocks[0].text,
                "[run-nonce 0123456789abcdef0123456789abcdef]\n"
            );
            assert_eq!(blocks[1].text, "Existing block");
        }
        other => panic!("Expected SystemPrompt::Blocks, got {other:?}"),
    }
}

#[test]
fn test_nonce_across_requests_and_instances() {
    let env1 = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );
    let env2 = TestEnv::new(
        vec!["claude-3-5-sonnet-20241022".to_string()],
        vec![],
        QuotasConfig::default(),
    );

    // Nonces must differ across two gateway instances
    assert_ne!(
        env1.gateway_server.nonce().hex(),
        env2.gateway_server.nonce().hex()
    );

    let mock1 = env1.mock_server.clone();
    let mock_handle = thread::spawn(move || {
        // Request 1
        let mut req1 = mock1
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req1 received");
        let mut body1 = String::new();
        req1.as_reader().read_to_string(&mut body1).unwrap();
        req1.respond(tiny_http::Response::from_string(r#"{"id":"1","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#)).unwrap();

        // Request 2
        let mut req2 = mock1
            .recv_timeout(Duration::from_secs(3))
            .expect("recv")
            .expect("req2 received");
        let mut body2 = String::new();
        req2.as_reader().read_to_string(&mut body2).unwrap();
        req2.respond(tiny_http::Response::from_string(r#"{"id":"2","type":"message","role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":1}}"#)).unwrap();

        (body1, body2)
    });

    let client = ureq::AgentBuilder::new().build();
    let body =
        r#"{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hi"}]}"#;

    client
        .post(&format!("{}/v1/messages", env1.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("req1 ok");

    client
        .post(&format!("{}/v1/messages", env1.gateway_url))
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .send_string(body)
        .expect("req2 ok");

    let (body1, body2) = mock_handle.join().expect("mock finished");

    let expected_nonce_str = format!("[run-nonce {}]", env1.gateway_server.nonce().hex());
    assert!(body1.contains(&expected_nonce_str));
    assert!(body2.contains(&expected_nonce_str));
}
