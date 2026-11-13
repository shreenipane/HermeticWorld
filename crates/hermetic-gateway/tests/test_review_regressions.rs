use hermetic_gateway::history::HistoryLog;
use hermetic_gateway::log::{HostLogEntry, HostLogger, MAX_LOGGED_FIELD_BYTES, REDACTED};
use hermetic_gateway::quota::{QuotaTracker, QuotasConfig};
use std::collections::BTreeMap;

#[test]
fn reinserted_history_tip_survives_stale_queue_entry() {
    let history = HistoryLog::with_capacity(2);
    let a = b"A".to_vec();
    let b = b"B".to_vec();
    let c = b"C".to_vec();
    let d = b"D".to_vec();
    for messages in [
        vec![a.clone()],
        vec![a.clone(), b],
        vec![a.clone()],
        vec![c],
    ] {
        assert_eq!(history.check_and_record(b"system", &messages), (false, 0));
    }
    assert_eq!(history.tip_count(), 2);
    assert_eq!(history.check_and_record(b"system", &[a, d]), (false, 0));
}

#[test]
fn secrets_crossing_field_truncation_boundary_are_redacted() {
    let dir = tempfile::tempdir().unwrap();
    // Include JSON escapes and a multibyte character as well as an ordinary API key.
    for secret in ["sk-private-credential", "sk-\"private\\credentialé"] {
        let logger = HostLogger::open(dir.path(), vec![secret.to_string()], 1024 * 1024).unwrap();
        let prefix = "p".repeat(MAX_LOGGED_FIELD_BYTES - secret.len() + 1);
        let value = format!("{prefix}{secret}suffix");
        let entry = HostLogEntry {
            timestamp: "frozen".into(),
            adapter_version: "test".into(),
            endpoint: "/v1/messages".into(),
            model: None,
            stream: false,
            client_status: 400,
            upstream_status: Some(400),
            dropped_headers: BTreeMap::from([("x-echo".into(), value.clone())]),
            original_error_body: Some(value),
            history_rewrite: false,
            history_rewrites_total: 0,
            quotas: QuotaTracker::new(QuotasConfig::default()).snapshot(),
        };
        assert!(logger.log(&entry));
        let text = std::fs::read_to_string(logger.path()).unwrap();
        let saved: HostLogEntry = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        for value in [
            saved.original_error_body.unwrap(),
            saved.dropped_headers["x-echo"].clone(),
        ] {
            let partial_secret: String = secret.chars().take(secret.chars().count() - 1).collect();
            assert!(!value.contains(&partial_secret), "credential prefix leaked");
            assert!(value.starts_with(&prefix));
            assert_eq!(value, format!("{prefix}{REDACTED}suffix"));
        }
    }
}
