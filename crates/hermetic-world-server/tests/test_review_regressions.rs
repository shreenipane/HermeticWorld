#![forbid(unsafe_code)]

use hermetic_world_server::log::{MAX_CHECKPOINT_BYTES, MAX_DEDUPE_ENTRIES, MAX_LOG_LINE_BYTES};
use hermetic_world_server::{
    filter_headers, verify_log_recover, LogEventParams, LogManager, ServerConfig, WorldServer,
};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use tempfile::tempdir;
use time::macros::datetime;

fn event(path: &str) -> LogEventParams<'_> {
    LogEventParams {
        elapsed_ms: 100,
        request_id: 1,
        method: "GET",
        authority: "example.org",
        path_and_query: path,
        range: None,
        status: "200",
        bytes: 3,
    }
}

fn finalized(dir: &Path) {
    let mut log = LogManager::new(dir).unwrap();
    log.log_event(&event("/test")).unwrap();
    log.finish().unwrap();
}

#[test]
fn blank_record_recovery_twice_preserves_checkpoint() {
    let temp = tempdir().unwrap();
    finalized(temp.path());
    let log = temp.path().join("requests.log");
    let head = temp.path().join("requests.log.head");
    fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    let original = fs::read(&log).unwrap();
    let checkpoint = fs::read(&head).unwrap();
    for _ in 0..2 {
        assert!(verify_log_recover(&log, false, true).is_err());
        assert_eq!(fs::read(&log).unwrap(), original);
        assert_eq!(fs::read(&head).unwrap(), checkpoint);
    }
}

#[test]
fn invalid_recovery_never_changes_evidence() {
    for damage in ["missing_newline", "invalid_checkpoint", "checkpoint_hash"] {
        let temp = tempdir().unwrap();
        finalized(temp.path());
        let log = temp.path().join("requests.log");
        let head = temp.path().join("requests.log.head");
        match damage {
            "missing_newline" => {
                let mut bytes = fs::read(&log).unwrap();
                bytes.pop();
                fs::write(&log, bytes).unwrap();
            }
            "invalid_checkpoint" => {
                fs::write(&head, b"{").unwrap();
                fs::OpenOptions::new()
                    .append(true)
                    .open(&log)
                    .unwrap()
                    .write_all(b"partial")
                    .unwrap();
            }
            _ => {
                let mut checkpoint: hermetic_world_server::LogHead =
                    serde_json::from_slice(&fs::read(&head).unwrap()).unwrap();
                checkpoint.hash = "f".repeat(64);
                fs::write(&head, serde_json::to_vec(&checkpoint).unwrap()).unwrap();
                fs::OpenOptions::new()
                    .append(true)
                    .open(&log)
                    .unwrap()
                    .write_all(b"partial")
                    .unwrap();
            }
        }
        let inputs: Vec<_> = ["requests.log", "requests.log.head", "dedupe.json"]
            .iter()
            .map(|name| {
                (
                    temp.path().join(name),
                    fs::read(temp.path().join(name)).unwrap(),
                )
            })
            .collect();
        assert!(verify_log_recover(&log, false, true).is_err());
        for (path, original) in inputs {
            assert_eq!(fs::read(path).unwrap(), original);
        }
    }
}

#[test]
fn fresh_start_rejects_empty_or_deleted_checkpointed_logs() {
    for delete in [false, true] {
        let temp = tempdir().unwrap();
        finalized(temp.path());
        let log = temp.path().join("requests.log");
        let head = temp.path().join("requests.log.head");
        let checkpoint = fs::read(&head).unwrap();
        if delete {
            fs::remove_file(&log).unwrap();
        } else {
            fs::write(&log, b"").unwrap();
        }
        assert!(LogManager::new(temp.path()).is_err());
        assert_eq!(fs::read(&head).unwrap(), checkpoint);
        assert_eq!(log.exists(), !delete);
    }
}

#[test]
fn audit_symlinks_fifos_and_temporary_entries_are_rejected() {
    for name in [
        "requests.log",
        "requests.log.head",
        ".head.tmp",
        ".dedupe.json.tmp",
    ] {
        for fifo in [false, true] {
            let temp = tempdir().unwrap();
            let dir = temp.path().join("log");
            fs::create_dir(&dir).unwrap();
            let outside = temp.path().join("outside");
            fs::write(&outside, b"").unwrap();
            let target = dir.join(name);
            let mut log = if name == "requests.log" {
                None
            } else {
                Some(LogManager::new(&dir).unwrap())
            };
            if fifo {
                assert!(std::process::Command::new("mkfifo")
                    .arg(&target)
                    .status()
                    .unwrap()
                    .success());
            } else {
                symlink(&outside, &target).unwrap();
            }
            let result = if let Some(log) = &mut log {
                log.finish()
            } else {
                LogManager::new(&dir).map(|_| ())
            };
            assert!(result.is_err(), "{name}");
            assert_eq!(fs::read(&outside).unwrap(), b"");
            assert!(fs::symlink_metadata(&target).is_ok());
        }
    }
    let temp = tempdir().unwrap();
    finalized(temp.path());
    for name in ["requests.log", "requests.log.head", "dedupe.json"] {
        assert_eq!(
            fs::metadata(temp.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn audit_line_checkpoint_and_unique_request_budgets() {
    let temp = tempdir().unwrap();
    finalized(temp.path());
    let log = temp.path().join("requests.log");
    fs::write(&log, vec![b'x'; (MAX_LOG_LINE_BYTES + 1) as usize]).unwrap();
    let original = fs::read(&log).unwrap();
    assert!(verify_log_recover(&log, false, true).is_err());
    assert_eq!(fs::read(&log).unwrap(), original);
    fs::write(
        temp.path().join("requests.log.head"),
        vec![b' '; (MAX_CHECKPOINT_BYTES + 1) as usize],
    )
    .unwrap();
    assert!(verify_log_recover(&log, false, true).is_err());
    let flood = temp.path().join("flood");
    let mut manager = LogManager::new(&flood).unwrap();
    for i in 0..MAX_DEDUPE_ENTRIES {
        manager.log_event(&event(&format!("/{i}"))).unwrap();
    }
    let before = fs::metadata(flood.join("requests.log")).unwrap().len();
    assert!(manager.log_event(&event("/over-budget")).is_err());
    assert_eq!(
        fs::metadata(flood.join("requests.log")).unwrap().len(),
        before
    );
    assert!(before <= hermetic_world_server::log::MAX_LOG_BYTES);
}

fn config(root: &Path) -> ServerConfig {
    ServerConfig {
        store_dir: root.join("store"),
        socket_path: root.join("socket"),
        log_dir: root.join("log"),
        t_clock: datetime!(2024-03-01 12:00:00 UTC),
        rate_rps: None,
        burst: None,
        max_requests: None,
        max_bytes: None,
        allow_no_landlock: true,
        no_sandbox: true,
        resume_log: false,
        recover: false,
    }
}

#[test]
fn invalid_and_extreme_rates_fail_before_creating_artifacts() {
    for (rate, burst) in [
        (0.0, 1.0),
        (-1.0, 1.0),
        (f64::NAN, 1.0),
        (f64::INFINITY, 1.0),
        (1e-300, 1.0),
        (1e300, 1.0),
        (1.0, 0.0),
        (1.0, f64::NAN),
        (1.0, f64::INFINITY),
        (1.0, 1e300),
    ] {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("store")).unwrap();
        let mut cfg = config(temp.path());
        cfg.rate_rps = Some(rate);
        cfg.burst = Some(burst);
        assert!(WorldServer::new(cfg).is_err());
        assert!(!temp.path().join("log").exists());
        assert!(!temp.path().join("socket").exists());
        let mut limits = hermetic_world_server::Limits::new(Some(rate), Some(burst), None, None);
        assert!(limits.acquire_token().is_err());
    }
}

#[test]
fn upper_guest_clock_boundary_returns_error_without_artifacts() {
    let temp = tempdir().unwrap();
    fs::create_dir(temp.path().join("store")).unwrap();
    let upper = datetime!(9999-12-31 23:59:59 UTC);
    let mut cfg = config(temp.path());
    cfg.t_clock = upper;
    assert!(WorldServer::new(cfg).is_err());
    assert!(!temp.path().join("log").exists());
    assert!(hermetic_world_server::server::guest_clock(upper, 1000).is_err());
    assert!(hermetic_world_server::server::guest_clock(upper, u64::MAX).is_err());
}

#[test]
fn unknown_and_transport_headers_are_excluded() {
    let headers = filter_headers(
        vec![
            ("transfer-encoding".into(), "chunked".into()),
            ("x-secret".into(), "host".into()),
            ("connection".into(), "keep-alive".into()),
            ("ETag".into(), "abc".into()),
            ("Cache-Control".into(), "public".into()),
        ],
        Some("text/plain"),
        3,
        "Fri, 01 Mar 2024 12:00:00 GMT",
        None,
    );
    assert!(headers.iter().any(|h| h.name == "etag" && h.value == "abc"));
    assert!(headers
        .iter()
        .any(|h| h.name == "cache-control" && h.value == "public"));
    assert!(headers
        .iter()
        .all(|h| !["transfer-encoding", "x-secret", "connection"].contains(&h.name.as_str())));
}

#[test]
fn socket_regular_files_and_symlinks_survive_startup() {
    for link in [false, true] {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("store")).unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, b"keep").unwrap();
        let socket = temp.path().join("socket");
        if link {
            symlink(&outside, &socket).unwrap();
        } else {
            fs::write(&socket, b"keep").unwrap();
        }
        let result = WorldServer::new(config(temp.path()));
        let rejected = match result {
            Err(_) => true,
            Ok(server) => server.run().is_err(),
        };
        assert!(rejected);
        assert_eq!(fs::read(&socket).unwrap(), b"keep");
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
        assert_eq!(
            fs::symlink_metadata(&socket)
                .unwrap()
                .file_type()
                .is_symlink(),
            link
        );
    }
}
