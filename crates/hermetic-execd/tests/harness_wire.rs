//! Shared known-answer vectors are also consumed by the Python harness tests.
use hermetic_execd::rpc::{write_frame, ExecReply, Reply, Request};

#[test]
fn harness_wire_known_answers_match_rust_encoder() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../python/hermetic_agent/wire-vectors.json"
    ))
    .unwrap();
    let request = Request::Exec {
        argv: vec!["/bin/bash".into(), "-c".into(), "printf hi".into()],
        tty: false,
        timeout_ms: 1000,
    };
    let reply = Reply::Exec(ExecReply {
        code: Some(0),
        output: b"hi".to_vec(),
        truncated: false,
        timed_out: false,
    });
    let mut encoded = Vec::new();
    write_frame(&request, &mut encoded).unwrap();
    assert_eq!(
        encoded,
        vectors["request_bytes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect::<Vec<_>>()
    );
    encoded.clear();
    write_frame(&reply, &mut encoded).unwrap();
    assert_eq!(
        encoded,
        vectors["reply_bytes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect::<Vec<_>>()
    );
}
