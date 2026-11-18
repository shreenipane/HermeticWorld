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

#[test]
fn test_bind_unix_socket_preserves_live_sockets_and_regular_files_and_cleans_stale() {
    let dir = tempfile::tempdir().unwrap();

    // 1. Fresh path binds successfully
    let sock1 = dir.path().join("sock1.sock");
    let l1 = hermetic_gateway::fsutil::bind_unix_socket(&sock1).unwrap();
    assert!(sock1.exists());

    // 2. Existing regular file: bind fails, file is NOT removed
    let reg_file = dir.path().join("regular.txt");
    std::fs::write(&reg_file, b"important data").unwrap();
    let err = hermetic_gateway::fsutil::bind_unix_socket(&reg_file).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(reg_file.exists());
    assert_eq!(std::fs::read(&reg_file).unwrap(), b"important data");

    // 3. Existing live socket: bind fails with AddrInUse, existing listener still works
    let err = hermetic_gateway::fsutil::bind_unix_socket(&sock1).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    drop(l1);

    // 4. Stale socket: l1 was dropped, so sock1 exists on disk without an active listener.
    // Binding detects stale socket, unlinks it, and binds successfully.
    let l2 = hermetic_gateway::fsutil::bind_unix_socket(&sock1).unwrap();
    drop(l2);

    // 5. Symlink to regular file or socket: refused without deleting target
    let target = dir.path().join("symlink_target.txt");
    std::fs::write(&target, b"target data").unwrap();
    let sym = dir.path().join("symlink.sock");
    std::os::unix::fs::symlink(&target, &sym).unwrap();
    let err = hermetic_gateway::fsutil::bind_unix_socket(&sym).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(target.exists());
    assert_eq!(std::fs::read(&target).unwrap(), b"target data");
}
