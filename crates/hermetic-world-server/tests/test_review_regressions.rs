#![forbid(unsafe_code)]

mod support;

use hermetic_common::{Method, RequestFrame, ResponseFrame};
use hermetic_world_server::log::{MAX_CHECKPOINT_BYTES, MAX_DEDUPE_ENTRIES, MAX_LOG_LINE_BYTES};
use hermetic_world_server::{
    filter_headers, format_imf_fixdate, server::guest_clock, verify_log_recover, LogEventParams,
    LogManager, ServerConfig, ServerExit, WorldServer,
};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use support::private_tempdir as tempdir;
use support::BoundedChild as AuditChild;
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
            support::create_private_dir(&dir).unwrap();
            let outside = temp.path().join("outside");
            fs::write(&outside, b"").unwrap();
            let target = dir.join(name);
            let mut log = if name == "requests.log" {
                None
            } else {
                Some(LogManager::new(&dir).unwrap())
            };
            if fifo {
                assert!(
                    AuditChild::spawn(std::process::Command::new("mkfifo").arg(&target))
                        .wait_status()
                        .success()
                );
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
        frame_deadline: None,
        transmission_deadline: None,
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
        support::create_private_dir(temp.path().join("store")).unwrap();
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
    support::create_private_dir(temp.path().join("store")).unwrap();
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
        support::create_private_dir(temp.path().join("store")).unwrap();
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

#[test]
fn defect1_guest_clock_non_utc_overflow_rejected() {
    let temp = tempdir().unwrap();
    support::create_private_dir(temp.path().join("store")).unwrap();

    let offset = time::UtcOffset::from_hms(-23, -59, 0).unwrap();
    let dt = time::Date::from_calendar_date(9999, time::Month::December, 30)
        .unwrap()
        .with_hms(23, 59, 59)
        .unwrap()
        .assume_offset(offset);

    let mut cfg = config(temp.path());
    cfg.t_clock = dt;
    let new_res = WorldServer::new(cfg);
    assert!(
        new_res.is_err(),
        "Must reject clock that overflows year 9999 in run interval"
    );
    assert!(
        !temp.path().join("log").exists(),
        "Must create no artifacts"
    );
    assert!(
        !temp.path().join("socket").exists(),
        "Must create no artifacts"
    );

    let clock_res = guest_clock(dt, 61_000);
    assert!(clock_res.is_err());

    let fmt_res = format_imf_fixdate(dt);
    let _ = fmt_res;
}

#[test]
fn defect2_sidecar_internal_metadata_retrieval_rejected() {
    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let obj_dir = store_dir.join("example.org");
    support::create_private_dir_all(&obj_dir).unwrap();

    let canary = "CANARY_SECRET_METADATA_DISCLOSURE_98765";
    fs::write(obj_dir.join("index.html"), b"Hello Public World").unwrap();
    fs::write(
        obj_dir.join("index.html.headers.json"),
        format!(
            r#"{{"content_type": "text/html", "headers": {{"x-archive-canary": "{canary}", "memento-datetime": "{canary}"}}}}"#
        ),
    )
    .unwrap();
    fs::write(
        obj_dir.join(".404.json"),
        format!(r#"{{"content_type": "text/plain", "body": "Custom 404 with canary {canary}"}}"#),
    )
    .unwrap();

    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    let mut cfg = config(temp.path());
    cfg.store_dir = store_dir;
    cfg.log_dir = log_dir;
    cfg.socket_path = socket_path.clone();

    let server = WorldServer::new(cfg).unwrap();
    let thread_handle = support::spawn_bounded(move || {
        let _ = server.run();
    });

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let send_req = |path_and_query: &str| -> ResponseFrame {
        let mut client = support::connect(&socket_path).unwrap();
        let req = RequestFrame {
            method: Method::Get,
            request_id: 1,
            authority: "example.org".into(),
            path_and_query: path_and_query.into(),
            range: None,
        };
        client.write_all(&req.encode().unwrap()).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        ResponseFrame::read_from(&mut client, 1024 * 1024).unwrap()
    };

    let resp = send_req("/index.html");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"Hello Public World");

    let resp = send_req("/index.html.headers.json");
    assert_eq!(resp.status, 404);
    assert!(!String::from_utf8_lossy(&resp.body).contains(canary));
    for h in &resp.headers {
        assert!(!h.value.contains(canary));
    }

    let resp = send_req("/index.html%2eheaders%2ejson");
    assert_eq!(resp.status, 404);
    assert!(!String::from_utf8_lossy(&resp.body).contains(canary));
    for h in &resp.headers {
        assert!(!h.value.contains(canary));
    }

    let resp = send_req("/.404.json");
    assert_eq!(resp.status, 404);
    assert!(!String::from_utf8_lossy(&resp.body).contains(canary));

    let resp = send_req("/%2e404%2ejson");
    assert_eq!(resp.status, 404);
    assert!(!String::from_utf8_lossy(&resp.body).contains(canary));

    drop(thread_handle);
}

#[test]
fn defect3_overlapping_store_and_log_roots_rejected() {
    {
        let temp = tempdir().unwrap();
        let store = temp.path().join("store");
        support::create_private_dir_all(store.join("example.org")).unwrap();
        let log = store.join("example.org");
        let mut cfg = config(temp.path());
        cfg.store_dir = store.clone();
        cfg.log_dir = log.clone();
        assert!(WorldServer::new(cfg).is_err());
        assert!(!log.join("requests.log").exists());
    }

    {
        let temp = tempdir().unwrap();
        let log = temp.path().join("log");
        support::create_private_dir_all(&log).unwrap();
        let store = log.join("store");
        support::create_private_dir_all(&store).unwrap();
        let mut cfg = config(temp.path());
        cfg.store_dir = store.clone();
        cfg.log_dir = log.clone();
        assert!(WorldServer::new(cfg).is_err());
        assert!(!log.join("requests.log").exists());
    }

    {
        let temp = tempdir().unwrap();
        let root = temp.path().join("same_dir");
        support::create_private_dir_all(&root).unwrap();
        let mut cfg = config(temp.path());
        cfg.store_dir = root.clone();
        cfg.log_dir = root.clone();
        assert!(WorldServer::new(cfg).is_err());
        assert!(!root.join("requests.log").exists());
    }
}

#[test]
fn defect4_recovery_retains_verified_descriptor_across_pathname_replacement() {
    let temp = tempdir().unwrap();
    let log_dir = temp.path().join("log");
    support::create_private_dir_all(&log_dir).unwrap();

    {
        let mut log = LogManager::new(&log_dir).unwrap();
        log.log_event(&event("/first")).unwrap();
        log.log_event(&event("/second")).unwrap();
        log.finish().unwrap();
    }

    let mut log_mgr = LogManager::new_opts_recover(&log_dir, true, true).unwrap();

    let log_path = log_dir.join("requests.log");
    let backup_path = log_dir.join("requests.log.bak");
    fs::rename(&log_path, &backup_path).unwrap();
    fs::write(&log_path, b"malicious unverified file contents\n").unwrap();

    log_mgr.log_event(&event("/third")).unwrap();
    log_mgr.finish().unwrap();

    assert_eq!(
        fs::read(&log_path).unwrap(),
        b"malicious unverified file contents\n"
    );

    let verified = verify_log_recover(&backup_path, false, false).unwrap();
    assert_eq!(verified, 3);
}

#[test]
fn defect5_crash_recovery_endpoint_reuse() {
    use std::process::Command;

    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    support::create_private_dir_all(store_dir.join("example.org")).unwrap();
    fs::write(
        store_dir.join("example.org/test.txt"),
        b"crash recovery data",
    )
    .unwrap();

    let exe = env!("CARGO_BIN_EXE_hermetic-world-server");

    let mut child = AuditChild::spawn(
        Command::new(exe)
            .arg("--store")
            .arg(&store_dir)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--log")
            .arg(&log_dir)
            .arg("--t-clock")
            .arg("2024-03-01T12:00:00Z")
            .arg("--no-sandbox"),
    );

    let mut connected = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if socket_path.exists() {
            if let Ok(mut s) = support::connect(&socket_path) {
                let req = RequestFrame {
                    method: Method::Get,
                    request_id: 1,
                    authority: "example.org".into(),
                    path_and_query: "/test.txt".into(),
                    range: None,
                };
                let _ = s.write_all(&req.encode().unwrap());
                let _ = s.shutdown(std::net::Shutdown::Write);
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf);
                connected = true;
                break;
            }
        }
    }
    assert!(connected, "Server should have answered request");

    let live_conflict = support::output_bounded(
        Command::new(exe)
            .arg("--store")
            .arg(&store_dir)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--log")
            .arg(&log_dir)
            .arg("--t-clock")
            .arg("2024-03-01T12:00:00Z")
            .arg("--no-sandbox")
            // Valid recovery inputs, so the refusal comes from the endpoint ownership
            // check and not from argument validation (T2.1 review).
            .arg("--resume-log")
            .arg("--recover"),
    );
    assert_eq!(
        live_conflict.status.code(),
        Some(1),
        "Live endpoint must be protected"
    );
    // The original listener still owns the endpoint and still serves.
    {
        let mut s = support::connect(&socket_path).expect("original listener still accepts");
        let req = RequestFrame {
            method: Method::Get,
            request_id: 7,
            authority: "example.org".into(),
            path_and_query: "/test.txt".into(),
            range: None,
        };
        s.write_all(&req.encode().unwrap()).unwrap();
        s.shutdown(std::net::Shutdown::Write).unwrap();
        let resp = ResponseFrame::read_from(&mut s, 1024 * 1024).unwrap();
        assert_eq!(resp.status, 200, "original listener stopped serving");
    }

    child.kill();

    assert!(
        socket_path.exists(),
        "Socket file should remain after SIGKILL"
    );

    let mut resumed = AuditChild::spawn(
        Command::new(exe)
            .arg("--store")
            .arg(&store_dir)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--log")
            .arg(&log_dir)
            .arg("--t-clock")
            .arg("2024-03-01T12:00:00Z")
            .arg("--no-sandbox")
            .arg("--resume-log")
            .arg("--recover"),
    );

    let mut resumed_connected = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if let Ok(mut s) = support::connect(&socket_path) {
            let req = RequestFrame {
                method: Method::Get,
                request_id: 2,
                authority: "example.org".into(),
                path_and_query: "/test.txt".into(),
                range: None,
            };
            if s.write_all(&req.encode().unwrap()).is_ok() {
                let _ = s.shutdown(std::net::Shutdown::Write);
                let resp = ResponseFrame::read_from(&mut s, 1024 * 1024).unwrap();
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body, b"crash recovery data");
                resumed_connected = true;
                break;
            }
        }
    }
    assert!(
        resumed_connected,
        "Resumed server should reuse endpoint and serve requests"
    );
    resumed.kill();
}

#[test]
fn defect6_socket_deadlines_terminate_stalled_reader_and_writer() {
    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    support::create_private_dir_all(store_dir.join("example.org")).unwrap();
    fs::write(
        store_dir.join("example.org/large.txt"),
        vec![b'X'; 512 * 1024],
    )
    .unwrap();

    let mut cfg = config(temp.path());
    cfg.store_dir = store_dir;
    cfg.log_dir = log_dir.clone();
    cfg.socket_path = socket_path.clone();
    cfg.frame_deadline = Some(std::time::Duration::from_millis(100));
    cfg.transmission_deadline = Some(std::time::Duration::from_millis(100));

    let server = WorldServer::new(cfg).unwrap();
    let handle = support::spawn_bounded(move || {
        let _ = server.run();
    });

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    {
        let mut client = support::connect(&socket_path).unwrap();
        client.write_all(b"HW").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(250));
        let mut buf = [0u8; 16];
        let res = client.read(&mut buf);
        assert!(matches!(res, Ok(0) | Err(_)));
    }

    {
        let mut client = support::connect(&socket_path).unwrap();
        let req = RequestFrame {
            method: Method::Get,
            request_id: 10,
            authority: "example.org".into(),
            path_and_query: "/large.txt".into(),
            range: None,
        };
        client.write_all(&req.encode().unwrap()).unwrap();
        let mut buf = [0u8; 16];
        client.read_exact(&mut buf).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    drop(handle);

    let log_content = fs::read_to_string(log_dir.join("requests.log")).unwrap();
    assert!(
        log_content.contains("\"status\":\"frame_timeout\""),
        "Must contain frame_timeout audit record"
    );
    assert!(
        log_content.contains("\"status\":\"write_error\""),
        "Must contain write_error audit record"
    );
}

#[test]
fn defect7_audit_capacity_and_terminal_reservation() {
    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    support::create_private_dir_all(store_dir.join("example.org")).unwrap();
    fs::write(store_dir.join("example.org/item"), b"content").unwrap();

    let mut cfg = config(temp.path());
    cfg.store_dir = store_dir;
    cfg.log_dir = log_dir.clone();
    cfg.socket_path = socket_path.clone();
    cfg.max_requests = Some(2050);

    let server = WorldServer::new(cfg).unwrap();
    let handle = support::spawn_bounded(move || server.run());

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut client = support::connect(&socket_path).unwrap();
    for i in 0..2050 {
        let req = RequestFrame {
            method: Method::Get,
            request_id: i + 1,
            authority: "example.org".into(),
            path_and_query: format!("/item?q={i}"),
            range: None,
        };
        client.write_all(&req.encode().unwrap()).unwrap();
        let resp = ResponseFrame::read_from(&mut client, 1024 * 1024).unwrap();
        assert_eq!(resp.status, 404);
    }

    let req_over = RequestFrame {
        method: Method::Get,
        request_id: 2051,
        authority: "example.org".into(),
        path_and_query: "/item?q=overflow".into(),
        range: None,
    };
    let _ = client.write_all(&req_over.encode().unwrap());

    let exit_result = handle.join().unwrap();
    assert_eq!(exit_result, Err(ServerExit::LimitExceeded));

    let log_content = fs::read_to_string(log_dir.join("requests.log")).unwrap();
    assert!(log_content.contains("\"status\":\"limit_exceeded\""));
}

#[test]
fn defect8_stream_object_larger_than_16mib() {
    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    support::create_private_dir_all(store_dir.join("example.org")).unwrap();

    let size = 17 * 1024 * 1024usize;
    let file_path = store_dir.join("example.org/large.bin");
    {
        let mut f = fs::File::create(&file_path).unwrap();
        let chunk = [0x5au8; 64 * 1024];
        let mut written = 0;
        while written < size {
            let to_write = (size - written).min(chunk.len());
            f.write_all(&chunk[..to_write]).unwrap();
            written += to_write;
        }
        f.sync_all().unwrap();
    }

    let mut cfg = config(temp.path());
    cfg.store_dir = store_dir;
    cfg.log_dir = log_dir;
    cfg.socket_path = socket_path.clone();
    cfg.max_bytes = Some(50 * 1024 * 1024);

    let server = WorldServer::new(cfg).unwrap();
    let handle = support::spawn_bounded(move || {
        let _ = server.run();
    });

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut client = support::connect(&socket_path).unwrap();
    let req = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "example.org".into(),
        path_and_query: "/large.bin".into(),
        range: None,
    };
    client.write_all(&req.encode().unwrap()).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();

    let resp = ResponseFrame::read_from(&mut client, 50 * 1024 * 1024).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body.len(), size);
    assert!(resp.body.iter().all(|&b| b == 0x5a));

    drop(handle);
}

#[test]
fn defect9_sidecar_conflicting_headers_excluded() {
    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    let obj_dir = store_dir.join("example.org");
    support::create_private_dir_all(&obj_dir).unwrap();

    fs::write(obj_dir.join("item.txt"), b"0123456789").unwrap();
    fs::write(
        obj_dir.join("item.txt.headers.json"),
        r#"{
            "content_type": "text/plain",
            "headers": {
                "Content-Range": "bytes 99-100/200",
                "content-range": "bytes 5-10/20",
                "Accept-Ranges": "none",
                "ACCEPT-RANGES": "foobar",
                "Content-Length": "99999",
                "content-length": "88888",
                "Date": "Wed, 01 Jan 2000 00:00:00 GMT"
            }
        }"#,
    )
    .unwrap();

    let mut cfg = config(temp.path());
    cfg.store_dir = store_dir;
    cfg.log_dir = log_dir;
    cfg.socket_path = socket_path.clone();

    let server = WorldServer::new(cfg).unwrap();
    let handle = support::spawn_bounded(move || {
        let _ = server.run();
    });

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let send = |method, range| -> ResponseFrame {
        let mut client = support::connect(&socket_path).unwrap();
        let req = RequestFrame {
            method,
            request_id: 1,
            authority: "example.org".into(),
            path_and_query: "/item.txt".into(),
            range,
        };
        client.write_all(&req.encode().unwrap()).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        ResponseFrame::read_from(&mut client, 1024 * 1024).unwrap()
    };

    let resp = send(Method::Get, None);
    assert_eq!(resp.status, 200);
    let accept_ranges: Vec<_> = resp
        .headers
        .iter()
        .filter(|h| h.name == "accept-ranges")
        .collect();
    assert_eq!(accept_ranges.len(), 1);
    assert_eq!(accept_ranges[0].value, "bytes");
    let content_ranges: Vec<_> = resp
        .headers
        .iter()
        .filter(|h| h.name == "content-range")
        .collect();
    assert_eq!(content_ranges.len(), 0);
    let content_lengths: Vec<_> = resp
        .headers
        .iter()
        .filter(|h| h.name == "content-length")
        .collect();
    assert_eq!(content_lengths.len(), 1);
    assert_eq!(content_lengths[0].value, "10");

    let resp = send(Method::Head, None);
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers
            .iter()
            .filter(|h| h.name == "accept-ranges")
            .count(),
        1
    );
    assert_eq!(
        resp.headers
            .iter()
            .filter(|h| h.name == "content-range")
            .count(),
        0
    );

    let resp = send(Method::Get, Some((0, 4)));
    assert_eq!(resp.status, 206);
    let cr: Vec<_> = resp
        .headers
        .iter()
        .filter(|h| h.name == "content-range")
        .collect();
    assert_eq!(cr.len(), 1);
    assert_eq!(cr[0].value, "bytes 0-4/10");
    assert_eq!(
        resp.headers
            .iter()
            .filter(|h| h.name == "accept-ranges")
            .count(),
        1
    );

    let resp = send(Method::Get, Some((50, 100)));
    assert_eq!(resp.status, 416);
    let cr: Vec<_> = resp
        .headers
        .iter()
        .filter(|h| h.name == "content-range")
        .collect();
    assert_eq!(cr.len(), 1);
    assert_eq!(cr[0].value, "bytes */10");
    assert_eq!(
        resp.headers
            .iter()
            .filter(|h| h.name == "accept-ranges")
            .count(),
        1
    );

    drop(handle);
}

#[test]
fn defect10_retained_header_presence_and_deterministic_order() {
    let headers_ordered = [
        ("vary", "val-vary"),
        ("last-modified", "val-lm"),
        ("expires", "val-exp"),
        ("etag", "val-etag"),
        ("cache-control", "val-cc"),
        ("access-control-allow-origin", "*"),
    ];

    let mut reversed = headers_ordered.to_vec();
    reversed.reverse();

    let out1 = filter_headers(
        headers_ordered
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        Some("text/plain"),
        10,
        "Fri, 01 Mar 2024 12:00:00 GMT",
        None,
    );

    let out2 = filter_headers(
        reversed
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        Some("text/plain"),
        10,
        "Fri, 01 Mar 2024 12:00:00 GMT",
        None,
    );

    assert_eq!(
        out1, out2,
        "Different input orders must produce identical filtered output"
    );

    let names: Vec<&str> = out1.iter().map(|h| h.name.as_str()).collect();
    for (k, _) in headers_ordered {
        assert!(names.contains(&k), "Retained header {k} must be present");
    }

    let extra_names: Vec<&str> = out1
        .iter()
        .map(|h| h.name.as_str())
        .filter(|n| !["date", "content-length", "accept-ranges", "content-type"].contains(n))
        .collect();
    let mut sorted_extra = extra_names.clone();
    sorted_extra.sort();
    assert_eq!(
        extra_names, sorted_extra,
        "Extra headers must appear in alphabetical order"
    );
}

/// The Landlock failure injection is process-global; it runs only in a child
/// process so other tests in this binary never start a server with it set.
#[test]
fn defect11_unavailable_landlock_startup_regression() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "defect11_unavailable_landlock_startup_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("HERMETIC_DEFECT11_CHILD", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(status.status.success(), "{stdout}");
    // The child really ran its body (not just the early return).
    assert!(stdout.contains("defect11 child completed"), "{stdout}");
}

#[test]
fn defect11_unavailable_landlock_startup_child() {
    if std::env::var_os("HERMETIC_DEFECT11_CHILD").is_none() {
        return;
    }
    hermetic_world_server::sandbox::set_inject_landlock_unavailable(true);

    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    support::create_private_dir_all(store_dir.join("example.org")).unwrap();
    fs::write(store_dir.join("example.org/index.html"), b"hello").unwrap();

    let mut cfg = config(temp.path());
    cfg.store_dir = store_dir;
    cfg.log_dir = log_dir.clone();
    cfg.socket_path = socket_path.clone();
    cfg.no_sandbox = false;
    cfg.allow_no_landlock = true;

    let server = WorldServer::new(cfg).unwrap();
    let handle = support::spawn_bounded(move || server.run());

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    {
        let client = support::connect(&socket_path).unwrap();
        client.shutdown(std::net::Shutdown::Both).unwrap();
    }

    let run_res = handle.join().unwrap();
    assert_eq!(run_res, Ok(()));

    hermetic_world_server::sandbox::set_inject_landlock_unavailable(false);

    let log_path = log_dir.join("requests.log");
    let lines = fs::read_to_string(&log_path).unwrap();
    let mut entries = lines.lines();
    let line1 = entries.next().unwrap();
    assert!(line1.contains("\"status\":\"run_config\""));
    let line2 = entries.next().unwrap();
    assert!(
        line2.contains("\"status\":\"sandbox_landlock_not_enforced\""),
        "Degraded-sandbox event must be durably chained on startup: {line2}"
    );

    let count = verify_log_recover(&log_path, false, false).unwrap();
    assert_eq!(count, 2);
    println!("defect11 child completed");
}

#[test]
fn review_defect1_capacity_exhaustion_escaped_paths_and_malformed_input() {
    // 1. Flood maximum-length distinct paths (8 KiB)
    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    support::create_private_dir_all(store_dir.join("example.org")).unwrap();
    fs::write(store_dir.join("example.org/item"), b"data").unwrap();

    let mut cfg = config(temp.path());
    cfg.store_dir = store_dir;
    cfg.log_dir = log_dir.clone();
    cfg.socket_path = socket_path.clone();

    let server = WorldServer::new(cfg).unwrap();
    let handle = support::spawn_bounded(move || server.run());

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut client = support::connect(&socket_path).unwrap();
    // Path of length exactly 8192 bytes. The flood runs until the server ends
    // the run itself; its own count and wall-clock bounds keep the test from
    // depending on where exactly the audit capacity is exhausted.
    let pad = "a".repeat(8178);
    let flood_deadline = std::time::Instant::now() + support::WAIT_TIMEOUT;
    let mut capacity_reached = false;
    for i in 0..99_999u64 {
        if std::time::Instant::now() >= flood_deadline {
            break;
        }
        let pq = format!("/item?q={i:0>5}_{pad}");
        assert_eq!(pq.len(), 8192);
        let req = RequestFrame {
            method: Method::Get,
            request_id: i + 1,
            authority: "example.org".into(),
            path_and_query: pq,
            range: None,
        };
        if client.write_all(&req.encode().unwrap()).is_err() {
            capacity_reached = true;
            break;
        }
        match ResponseFrame::read_from(&mut client, 1024 * 1024) {
            Ok(resp) => {
                assert_eq!(resp.status, 404);
            }
            Err(_) => {
                capacity_reached = true;
                break;
            }
        }
    }
    drop(client);
    assert!(
        capacity_reached,
        "distinct-path flood must exhaust audit capacity and end the run"
    );

    let run_res = handle.join().unwrap();
    assert_eq!(run_res, Err(ServerExit::LimitExceeded));

    let log_path = log_dir.join("requests.log");
    let log_content = fs::read_to_string(&log_path).unwrap();
    assert!(log_content.contains("\"status\":\"limit_exceeded\""));
    let verified_count = verify_log_recover(&log_path, false, false).unwrap();
    assert!(verified_count > 0);

    // 2. Flood repeated escaped paths
    let temp2 = tempdir().unwrap();
    let store_dir2 = temp2.path().join("store");
    let log_dir2 = temp2.path().join("log");
    let socket_path2 = temp2.path().join("server.sock");
    support::create_private_dir_all(store_dir2.join("example.org")).unwrap();
    fs::write(store_dir2.join("example.org/item"), b"data").unwrap();

    let mut cfg2 = config(temp2.path());
    cfg2.store_dir = store_dir2.clone();
    cfg2.log_dir = log_dir2.clone();
    cfg2.socket_path = socket_path2.clone();
    cfg2.max_requests = Some(20);

    let server2 = WorldServer::new(cfg2).unwrap();
    let handle2 = support::spawn_bounded(move || server2.run());

    for _ in 0..50 {
        if socket_path2.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut client2 = support::connect(&socket_path2).unwrap();
    let escaped_query = "/item?q=\\\"escaped\\\\string\\\"";
    for i in 0..20 {
        let req = RequestFrame {
            method: Method::Get,
            request_id: i + 1,
            authority: "example.org".into(),
            path_and_query: escaped_query.to_string(),
            range: None,
        };
        client2.write_all(&req.encode().unwrap()).unwrap();
        let resp = ResponseFrame::read_from(&mut client2, 1024 * 1024).unwrap();
        assert_eq!(resp.status, 404);
    }
    let req_over = RequestFrame {
        method: Method::Get,
        request_id: 21,
        authority: "example.org".into(),
        path_and_query: escaped_query.to_string(),
        range: None,
    };
    let _ = client2.write_all(&req_over.encode().unwrap());

    let run_res2 = handle2.join().unwrap();
    assert_eq!(run_res2, Err(ServerExit::LimitExceeded));

    let log_path2 = log_dir2.join("requests.log");
    let verified_count2 = verify_log_recover(&log_path2, false, false).unwrap();
    assert_eq!(verified_count2, 43);

    // 3. Test malformed input -> exit code 3 (Tampered) and chain verifies
    let temp3 = tempdir().unwrap();
    let store_dir3 = temp3.path().join("store");
    let log_dir3 = temp3.path().join("log");
    let socket_path3 = temp3.path().join("server.sock");
    support::create_private_dir_all(store_dir3.join("example.org")).unwrap();

    let mut cfg3 = config(temp3.path());
    cfg3.store_dir = store_dir3;
    cfg3.log_dir = log_dir3.clone();
    cfg3.socket_path = socket_path3.clone();

    let server3 = WorldServer::new(cfg3).unwrap();
    let handle3 = support::spawn_bounded(move || server3.run());

    for _ in 0..50 {
        if socket_path3.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut client3 = support::connect(&socket_path3).unwrap();
    client3
        .write_all(b"INVALID_HEADER_GARBAGE_BYTES_1234")
        .unwrap();

    let run_res3 = handle3.join().unwrap();
    assert_eq!(run_res3, Err(ServerExit::Tampered));

    let log_path3 = log_dir3.join("requests.log");
    let log_content3 = fs::read_to_string(&log_path3).unwrap();
    assert!(log_content3.contains("\"status\":\"tampered\""));
    let verified_count3 = verify_log_recover(&log_path3, false, false).unwrap();
    assert!(verified_count3 >= 2);
}

#[test]
fn review_defect2_exclusive_audit_ownership_and_init_pathname_replacement() {
    let temp = tempdir().unwrap();
    let log_dir = temp.path().join("log");
    support::create_private_dir_all(&log_dir).unwrap();

    // 1. Active writer blocks second writer and recovery without changing evidence
    let mut writer1 = LogManager::new(&log_dir).unwrap();
    writer1.log_event(&event("/first")).unwrap();

    // Second writer must fail
    let writer2_res = LogManager::new_opts(&log_dir, true);
    assert!(
        writer2_res.is_err(),
        "Second writer must be rejected while first is active"
    );

    // Second recovery process must fail
    let log_path = log_dir.join("requests.log");
    let recover_res = verify_log_recover(&log_path, false, true);
    assert!(
        recover_res.is_err(),
        "Recovery process must fail while writer is active"
    );

    // Writer1 continues and finishes
    writer1.log_event(&event("/second")).unwrap();
    writer1.finish().unwrap();

    // Now recovery succeeds
    let count = verify_log_recover(&log_path, false, false).unwrap();
    assert_eq!(count, 2);

    // 2. Replace pathname during initialization: descriptor is retained
    let temp2 = tempdir().unwrap();
    let log_dir2 = temp2.path().join("log");
    support::create_private_dir_all(&log_dir2).unwrap();
    {
        let mut lm = LogManager::new(&log_dir2).unwrap();
        lm.log_event(&event("/r1")).unwrap();
        lm.log_event(&event("/r2")).unwrap();
        lm.finish().unwrap();
    }

    let log_path2 = log_dir2.join("requests.log");
    let bak_path2 = log_dir2.join("requests.log.bak");

    let mut resumed = LogManager::new_opts_recover(&log_dir2, true, true).unwrap();
    // Replace pathname
    fs::rename(&log_path2, &bak_path2).unwrap();
    fs::write(&log_path2, b"malicious content inserted at path\n").unwrap();

    resumed.log_event(&event("/r3")).unwrap();
    resumed.finish().unwrap();

    // The fake file at path was never modified
    assert_eq!(
        fs::read(&log_path2).unwrap(),
        b"malicious content inserted at path\n"
    );
    // The genuine descriptor in bak_path has all 3 records and verifies
    let count2 = verify_log_recover(&bak_path2, false, false).unwrap();
    assert_eq!(count2, 3);
}

#[test]
fn review_defect3_root_separation_ancestor_replacement_retained_descriptors() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let store_dir = root.join("store");
    let log_parent = root.join("log_parent");
    let log_dir = log_parent.join("example.org");
    let socket_path = root.join("server.sock");

    support::create_private_dir_all(store_dir.join("example.org")).unwrap();
    fs::write(store_dir.join("example.org/item.txt"), b"genuine content").unwrap();
    support::create_private_dir_all(&log_dir).unwrap();

    let mut cfg = config(root);
    cfg.store_dir = store_dir.clone();
    cfg.log_dir = log_dir.clone();
    cfg.socket_path = socket_path.clone();
    // This fixture joins after EOF, so use the one-connection lifecycle.
    cfg.no_sandbox = false;

    // Initialize WorldServer which validates and retains open directory descriptors
    let server = WorldServer::new(cfg).unwrap();

    // Deterministically perform ancestor replacement between validation/creation and running
    let log_parent_aside = root.join("log_parent_aside");
    fs::rename(&log_parent, &log_parent_aside).unwrap();
    // Recreate log_parent as symlink to store_dir
    symlink(&store_dir, &log_parent).unwrap();

    let handle = support::spawn_bounded(move || server.run());

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut client = support::connect(&socket_path).unwrap();
    // Attempt to retrieve /requests.log from store
    let req = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "example.org".into(),
        path_and_query: "/requests.log".into(),
        range: None,
    };
    client.write_all(&req.encode().unwrap()).unwrap();
    let resp = ResponseFrame::read_from(&mut client, 1024 * 1024).unwrap();
    // Must NOT serve requests.log from the store
    assert_eq!(resp.status, 404);

    // Retrieve normal item
    let req_ok = RequestFrame {
        method: Method::Get,
        request_id: 2,
        authority: "example.org".into(),
        path_and_query: "/item.txt".into(),
        range: None,
    };
    client.write_all(&req_ok.encode().unwrap()).unwrap();
    let resp_ok = ResponseFrame::read_from(&mut client, 1024 * 1024).unwrap();
    assert_eq!(resp_ok.status, 200);
    assert_eq!(resp_ok.body, b"genuine content");

    client.shutdown(std::net::Shutdown::Both).unwrap();
    let run_res = handle.join().unwrap();
    assert_eq!(run_res, Ok(()));

    // Audit content was safely written to the original separated descriptor in log_parent_aside
    let real_log = log_parent_aside.join("example.org/requests.log");
    assert!(real_log.exists());
    let count = verify_log_recover(&real_log, false, false).unwrap();
    assert!(count >= 3);
}

#[test]
fn review_defect4_live_sandboxed_server_survives_recovery_attempt() {
    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    support::create_private_dir_all(store_dir.join("example.org")).unwrap();
    fs::write(store_dir.join("example.org/item.txt"), b"payload").unwrap();

    let mut cfg = config(temp.path());
    cfg.store_dir = store_dir.clone();
    cfg.log_dir = log_dir.clone();
    cfg.socket_path = socket_path.clone();
    cfg.no_sandbox = false;
    cfg.allow_no_landlock = true;

    let server = WorldServer::new(cfg).unwrap();
    let handle = support::spawn_bounded(move || server.run());

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Attempt recovery startup with both --resume-log and --recover
    let mut competing_cfg = config(temp.path());
    competing_cfg.store_dir = store_dir.clone();
    competing_cfg.log_dir = log_dir.clone();
    competing_cfg.socket_path = socket_path.clone();
    competing_cfg.no_sandbox = false;
    competing_cfg.allow_no_landlock = true;
    competing_cfg.resume_log = true;
    competing_cfg.recover = true;

    // Competing server startup/run must fail and must not kill original server
    let competing_res = WorldServer::new(competing_cfg).and_then(|s| s.run());
    assert!(
        competing_res.is_err(),
        "Competing recovery startup must fail on live endpoint"
    );

    // Verify original sandboxed server is still alive and serves requests
    let mut client = support::connect(&socket_path).unwrap();
    let req = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "example.org".into(),
        path_and_query: "/item.txt".into(),
        range: None,
    };
    client.write_all(&req.encode().unwrap()).unwrap();
    let resp = ResponseFrame::read_from(&mut client, 1024 * 1024).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"payload");

    client.shutdown(std::net::Shutdown::Both).unwrap();
    let run_res = handle.join().unwrap();
    assert_eq!(run_res, Ok(()));
}

#[test]
fn review_defect5_unowned_endpoint_survives_failed_startup_and_destruction() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    support::create_private_dir_all(root.join("store")).unwrap();

    // 1. Regular sentinel file inserted between new() and run()
    let socket1 = root.join("sentinel.sock");
    let mut cfg1 = config(root);
    cfg1.socket_path = socket1.clone();
    let server1 = WorldServer::new(cfg1).unwrap();

    // Insert sentinel file
    fs::write(&socket1, b"sentinel content").unwrap();

    let run_res1 = server1.run();
    assert_eq!(run_res1, Err(ServerExit::StartupFailed));
    let _ = run_res1;

    // Sentinel file must survive failed startup and drop
    assert!(
        socket1.exists(),
        "Sentinel file must survive failed startup"
    );
    assert_eq!(fs::read(&socket1).unwrap(), b"sentinel content");

    // 2. Competing socket inserted between new() and run()
    let socket2 = root.join("competing.sock");
    let mut cfg2 = config(root);
    cfg2.log_dir = root.join("log2");
    cfg2.socket_path = socket2.clone();
    let server2 = WorldServer::new(cfg2).unwrap();

    // Bind competing listener
    let competing_listener = std::os::unix::net::UnixListener::bind(&socket2).unwrap();

    let run_res2 = server2.run();
    assert_eq!(run_res2, Err(ServerExit::StartupFailed));
    let _ = run_res2;

    // Competing socket must survive failed startup and drop
    assert!(
        socket2.exists(),
        "Competing socket must survive failed startup"
    );
    drop(competing_listener);
}

#[test]
fn review_defect6_absolute_run_deadline_idle_listener_and_token_exhaustion() {
    // 1. Idle listener: server exits at run deadline
    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    support::create_private_dir_all(store_dir.join("example.org")).unwrap();

    // Create a prior log whose elapsed_ms is near MAX_RUN_ELAPSED_MS
    let near_deadline_ms = hermetic_world_server::server::MAX_RUN_ELAPSED_MS - 50;
    let mut cfg = config(temp.path());
    cfg.store_dir = store_dir.clone();
    cfg.log_dir = log_dir.clone();
    cfg.socket_path = socket_path.clone();

    // Create initial server to generate run_config binding in requests.log
    {
        let mut init_cfg = config(temp.path());
        init_cfg.store_dir = store_dir.clone();
        init_cfg.log_dir = log_dir.clone();
        init_cfg.socket_path = socket_path.clone();
        let init_server = WorldServer::new(init_cfg).unwrap();
        init_server.finish().unwrap();
        let mut lm = LogManager::new_opts(&log_dir, true).unwrap();
        lm.log_event(&LogEventParams {
            elapsed_ms: near_deadline_ms,
            request_id: 1,
            method: "GET",
            authority: "example.org",
            path_and_query: "/init",
            range: None,
            status: "200",
            bytes: 10,
        })
        .unwrap();
        lm.finish().unwrap();
    }

    cfg.resume_log = true;
    cfg.recover = true;

    let server = WorldServer::new(cfg).unwrap();
    let start = std::time::Instant::now();
    let run_res = server.run();
    let elapsed = start.elapsed();
    assert_eq!(run_res, Err(ServerExit::LimitExceeded));
    assert!(
        elapsed.as_millis() < 5000,
        "Idle listener must exit promptly at deadline"
    );

    let log_content = fs::read_to_string(log_dir.join("requests.log")).unwrap();
    assert!(log_content.contains("\"status\":\"clock_exhausted\""));

    // 2. Token exhaustion beyond run deadline
    let temp2 = tempdir().unwrap();
    let store_dir2 = temp2.path().join("store");
    let log_dir2 = temp2.path().join("log");
    let socket_path2 = temp2.path().join("server.sock");
    support::create_private_dir_all(store_dir2.join("example.org")).unwrap();
    fs::write(store_dir2.join("example.org/item"), b"content").unwrap();

    let mut cfg2 = config(temp2.path());
    cfg2.store_dir = store_dir2.clone();
    cfg2.log_dir = log_dir2.clone();
    cfg2.socket_path = socket_path2.clone();
    cfg2.rate_rps = Some(0.001);
    cfg2.burst = Some(1.0);

    {
        let mut init_cfg2 = config(temp2.path());
        init_cfg2.store_dir = store_dir2.clone();
        init_cfg2.log_dir = log_dir2.clone();
        init_cfg2.socket_path = socket_path2.clone();
        init_cfg2.rate_rps = Some(0.001);
        init_cfg2.burst = Some(1.0);
        let init_server = WorldServer::new(init_cfg2).unwrap();
        init_server.finish().unwrap();
        let mut lm = LogManager::new_opts(&log_dir2, true).unwrap();
        lm.log_event(&LogEventParams {
            elapsed_ms: near_deadline_ms,
            request_id: 1,
            method: "GET",
            authority: "example.org",
            path_and_query: "/init",
            range: None,
            status: "200",
            bytes: 10,
        })
        .unwrap();
        lm.finish().unwrap();
    }

    cfg2.resume_log = true;
    cfg2.recover = true;

    let server2 = WorldServer::new(cfg2).unwrap();
    let handle2 = support::spawn_bounded(move || server2.run());

    for _ in 0..50 {
        if socket_path2.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut client = support::connect(&socket_path2).unwrap();
    // First request consumes token
    let req1 = RequestFrame {
        method: Method::Get,
        request_id: 2,
        authority: "example.org".into(),
        path_and_query: "/item".into(),
        range: None,
    };
    client.write_all(&req1.encode().unwrap()).unwrap();
    let _ = ResponseFrame::read_from(&mut client, 1024);

    // Second request requires waiting 1000s, exceeding deadline
    let req2 = RequestFrame {
        method: Method::Get,
        request_id: 3,
        authority: "example.org".into(),
        path_and_query: "/item".into(),
        range: None,
    };
    let _ = client.write_all(&req2.encode().unwrap());

    let run_res2 = handle2.join().unwrap();
    assert_eq!(run_res2, Err(ServerExit::LimitExceeded));

    let log_content2 = fs::read_to_string(log_dir2.join("requests.log")).unwrap();
    assert!(log_content2.contains("\"status\":\"clock_exhausted\""));
}

#[test]
fn review_defect7_crash_leftovers_atomic_publication_recovery() {
    let temp = tempdir().unwrap();
    let log_dir = temp.path().join("log");
    support::create_private_dir_all(&log_dir).unwrap();

    {
        let mut lm = LogManager::new(&log_dir).unwrap();
        lm.log_event(&event("/first")).unwrap();
        lm.finish().unwrap();
    }

    // Simulate crash leftovers: abandoned .head.tmp and .dedupe.json.tmp
    let head_tmp = log_dir.join(".head.tmp");
    let dedupe_tmp = log_dir.join(".dedupe.json.tmp");
    fs::write(&head_tmp, b"leftover head tmp data from crashed process").unwrap();
    fs::write(
        &dedupe_tmp,
        b"leftover dedupe tmp data from crashed process",
    )
    .unwrap();

    // Resume with --recover; should safely replace leftovers and publish new head/dedupe
    let mut resumed = LogManager::new_opts_recover(&log_dir, true, true).unwrap();
    resumed.log_event(&event("/second")).unwrap();
    resumed.finish().unwrap();

    let count = verify_log_recover(log_dir.join("requests.log"), false, false).unwrap();
    assert_eq!(count, 2);

    // Verify head file is valid JSON and seq is 2
    let head_content = fs::read_to_string(log_dir.join("requests.log.head")).unwrap();
    assert!(head_content.contains("\"seq\": 2"));

    // Verify dedupe file is valid JSON
    let dedupe_content = fs::read_to_string(log_dir.join("dedupe.json")).unwrap();
    assert!(dedupe_content.contains("\"count\": 1"));

    // Verify symlink temp files are rejected fail-closed
    let temp_sym = tempdir().unwrap();
    let log_dir_sym = temp_sym.path().join("log");
    support::create_private_dir_all(&log_dir_sym).unwrap();
    {
        let mut lm = LogManager::new(&log_dir_sym).unwrap();
        lm.log_event(&event("/one")).unwrap();
        lm.finish().unwrap();
    }
    symlink("/etc/passwd", log_dir_sym.join(".head.tmp")).unwrap();
    let mut resumed_sym = LogManager::new_opts_recover(&log_dir_sym, true, true).unwrap();
    resumed_sym.log_event(&event("/two")).unwrap();
    // finish() must fail because .head.tmp is a symlink
    assert!(resumed_sym.finish().is_err());
}

#[test]
fn review_defect8_missing_query_specific_object_returns_404() {
    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let socket_path = temp.path().join("server.sock");
    let obj_dir = store_dir.join("example.org");
    support::create_private_dir_all(&obj_dir).unwrap();

    // Queryless object
    fs::write(obj_dir.join("search"), b"queryless response").unwrap();
    // Query-specific object for ?q=target
    fs::write(obj_dir.join("search%3Fq=target"), b"query target response").unwrap();

    let mut cfg = config(temp.path());
    cfg.store_dir = store_dir;
    cfg.socket_path = socket_path.clone();
    // This fixture joins after EOF, so use the one-connection lifecycle.
    cfg.no_sandbox = false;

    let server = WorldServer::new(cfg).unwrap();
    let handle = support::spawn_bounded(move || server.run());

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut client = support::connect(&socket_path).unwrap();

    // 1. Queryless request returns queryless body
    let req1 = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "example.org".into(),
        path_and_query: "/search".into(),
        range: None,
    };
    client.write_all(&req1.encode().unwrap()).unwrap();
    let resp1 = ResponseFrame::read_from(&mut client, 1024).unwrap();
    assert_eq!(resp1.status, 200);
    assert_eq!(resp1.body, b"queryless response");

    // 2. Query ?q=target returns query target response
    let req2 = RequestFrame {
        method: Method::Get,
        request_id: 2,
        authority: "example.org".into(),
        path_and_query: "/search?q=target".into(),
        range: None,
    };
    client.write_all(&req2.encode().unwrap()).unwrap();
    let resp2 = ResponseFrame::read_from(&mut client, 1024).unwrap();
    assert_eq!(resp2.status, 200);
    assert_eq!(resp2.body, b"query target response");

    // 3. Query ?q=missing must NOT fall through to queryless object; returns 404
    let req3 = RequestFrame {
        method: Method::Get,
        request_id: 3,
        authority: "example.org".into(),
        path_and_query: "/search?q=missing".into(),
        range: None,
    };
    client.write_all(&req3.encode().unwrap()).unwrap();
    let resp3 = ResponseFrame::read_from(&mut client, 1024).unwrap();
    assert_eq!(resp3.status, 404);

    client.shutdown(std::net::Shutdown::Both).unwrap();
    let _ = handle.join();
}

#[test]
fn review_defect9_empty_and_partial_first_record_recovery_rejected() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    // Reach binding verification rather than failing because the store is absent.
    support::create_private_dir(root.join("store")).unwrap();

    // 1. Server recovery on empty requests.log must be rejected
    let log_dir1 = root.join("log1");
    support::create_private_dir_all(&log_dir1).unwrap();
    let log_file1 = log_dir1.join("requests.log");
    fs::write(&log_file1, b"").unwrap();

    let mut cfg1 = config(root);
    cfg1.log_dir = log_dir1.clone();
    cfg1.resume_log = true;
    cfg1.recover = true;

    let res1 = WorldServer::new(cfg1);
    assert_eq!(res1.err(), Some(ServerExit::StartupFailed));
    assert_eq!(fs::read(&log_file1).unwrap().len(), 0);
    assert!(!log_dir1.join("requests.log.head").exists());

    // 2. Server recovery on partial first record must be rejected with artifacts unchanged
    let log_dir2 = root.join("log2");
    support::create_private_dir_all(&log_dir2).unwrap();
    let log_file2 = log_dir2.join("requests.log");
    let partial_record = b"{\"seq\":1,\"run_config\":{\"incomplete\":\"truncated";
    fs::write(&log_file2, partial_record).unwrap();

    let mut cfg2 = config(root);
    cfg2.log_dir = log_dir2.clone();
    cfg2.resume_log = true;
    cfg2.recover = true;

    let res2 = WorldServer::new(cfg2);
    assert_eq!(res2.err(), Some(ServerExit::StartupFailed));
    // Verify file content is unchanged: not truncated to 0, no head created
    assert_eq!(fs::read(&log_file2).unwrap(), partial_record);
    assert!(!log_dir2.join("requests.log.head").exists());
}

const AUDIT_CHILD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn audit_command(root: &Path, socket: &str) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_hermetic-world-server"));
    command
        .arg("--store")
        .arg(root.join("store"))
        .arg("--log")
        .arg(root.join("log"))
        .arg("--socket")
        .arg(root.join(socket))
        .args([
            "--t-clock",
            "2024-03-01T12:00:00Z",
            "--no-sandbox",
            "--max-requests",
            "4096",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command
}

fn audit_connect(root: &Path, child: &mut AuditChild) -> UnixStream {
    let deadline = std::time::Instant::now() + AUDIT_CHILD_TIMEOUT;
    loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "audit server exited before connect"
        );
        if let Ok(stream) = support::connect(root.join("socket")) {
            stream.set_read_timeout(Some(AUDIT_CHILD_TIMEOUT)).unwrap();
            stream.set_write_timeout(Some(AUDIT_CHILD_TIMEOUT)).unwrap();
            return stream;
        }
        assert!(std::time::Instant::now() < deadline, "audit socket timeout");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn frame_timeout_reconnection_retains_ownership_and_finalizes_verified_evidence() {
    const RESPONSE_CAP: u64 = 1024;
    let root = tempdir().unwrap();
    support::create_private_dir_all(root.path().join("store/example.org")).unwrap();
    fs::write(root.path().join("store/example.org/item"), b"payload").unwrap();
    let mut child = AuditChild(
        audit_command(root.path(), "socket")
            .args(["--frame-deadline-ms", "1000"])
            .spawn()
            .unwrap(),
    );
    let path = root.path().join("log/requests.log");
    let read_artifact = |name: &str, cap: u64| {
        let path = root.path().join("log").join(name);
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert!(metadata.len() <= cap);
        let mut data = Vec::new();
        fs::File::open(path)
            .unwrap()
            .take(cap + 1)
            .read_to_end(&mut data)
            .unwrap();
        assert!(data.len() as u64 <= cap);
        data
    };

    let mut stalled = audit_connect(root.path(), &mut child);
    stalled.write_all(b"HW").unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(stalled.read(&mut byte).unwrap(), 0);
    let before = read_artifact("requests.log", hermetic_world_server::log::MAX_LOG_BYTES);
    let records: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&before)
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert_eq!(records.len(), 3);
    assert_eq!(records[2]["status"], "frame_timeout");
    assert!(LogManager::new_opts_recover(root.path().join("log"), true, true).is_err());
    assert!(verify_log_recover(&path, false, true).is_err());
    assert_eq!(
        read_artifact("requests.log", hermetic_world_server::log::MAX_LOG_BYTES),
        before
    );

    let mut reconnected = audit_connect(root.path(), &mut child);
    let request = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "example.org".into(),
        path_and_query: "/item".into(),
        range: None,
    };
    reconnected.write_all(&request.encode().unwrap()).unwrap();
    let response = ResponseFrame::read_from(&mut reconnected, RESPONSE_CAP).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"payload");
    reconnected.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(LogManager::new_opts_recover(root.path().join("log"), true, true).is_err());
    assert!(verify_log_recover(&path, false, true).is_err());
    let mut terminal = audit_connect(root.path(), &mut child);
    terminal
        .write_all(b"INVALID_HEADER_GARBAGE_BYTES_1234")
        .unwrap();
    assert_eq!(child.wait_code(), 3);

    assert_eq!(verify_log_recover(&path, false, false).unwrap(), 6);
    let records: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&read_artifact(
        "requests.log",
        hermetic_world_server::log::MAX_LOG_BYTES,
    ))
    .into_iter()
    .map(Result::unwrap)
    .collect();
    let statuses: Vec<_> = records
        .iter()
        .map(|record| record["status"].as_str().unwrap())
        .collect();
    assert_eq!(
        statuses,
        [
            "run_config",
            "sandbox_disabled",
            "frame_timeout",
            "transmission_intent",
            "200",
            "tampered"
        ]
    );
    let head: hermetic_world_server::LogHead =
        serde_json::from_slice(&read_artifact("requests.log.head", MAX_CHECKPOINT_BYTES)).unwrap();
    assert_eq!(head.seq, 6);
    assert_eq!(head.hash, records[5]["hash"].as_str().unwrap());
    let index: std::collections::BTreeMap<String, hermetic_world_server::DedupeEntry> =
        serde_json::from_slice(&read_artifact(
            "dedupe.json",
            hermetic_world_server::log::MAX_DEDUPE_BYTES as u64,
        ))
        .unwrap();
    let rebuilt = LogManager::rebuild_dedupe_from_log(&path).unwrap();
    assert_eq!(
        index.values().collect::<Vec<_>>(),
        rebuilt.values().collect::<Vec<_>>()
    );
    let mut resumed = LogManager::new_opts_recover(root.path().join("log"), true, true).unwrap();
    assert_eq!(resumed.run_state().requests, 1);
    assert_eq!(resumed.run_state().bytes, 7);
    assert_eq!(resumed.run_state().incomplete_transmissions, 0);
    resumed.finish().unwrap();
    assert_eq!(verify_log_recover(&path, false, false).unwrap(), 6);
}

#[test]
fn sandboxed_accept_finalizes_evidence_and_releases_audit_ownership() {
    let root = tempdir().unwrap();
    support::create_private_dir_all(root.path().join("store/example.org")).unwrap();
    fs::write(root.path().join("store/example.org/item"), b"payload").unwrap();
    let mut child = AuditChild(
        std::process::Command::new(env!("CARGO_BIN_EXE_hermetic-world-server"))
            .arg("--store")
            .arg(root.path().join("store"))
            .arg("--log")
            .arg(root.path().join("log"))
            .arg("--socket")
            .arg(root.path().join("socket"))
            .args(["--t-clock", "2024-03-01T12:00:00Z", "--allow-no-landlock"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut stream = audit_connect(root.path(), &mut child);
    let request = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "example.org".into(),
        path_and_query: "/item".into(),
        range: None,
    };
    stream.write_all(&request.encode().unwrap()).unwrap();
    let response = ResponseFrame::read_from(&mut stream, 1024).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"payload");
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(child.wait_code(), 0);

    let path = root.path().join("log/requests.log");
    assert_eq!(verify_log_recover(&path, false, false).unwrap(), 4);
    let records: Vec<serde_json::Value> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records[0]["status"], "run_config");
    assert!(matches!(
        records[1]["status"].as_str(),
        Some("sandbox_landlock_enforced" | "sandbox_landlock_not_enforced")
    ));
    assert_eq!(records[2]["status"], "transmission_intent");
    assert_eq!(records[3]["status"], "200");
    let head: hermetic_world_server::LogHead =
        serde_json::from_slice(&fs::read(root.path().join("log/requests.log.head")).unwrap())
            .unwrap();
    assert_eq!(head.seq, 4);
    assert_eq!(head.hash, records[3]["hash"].as_str().unwrap());
    let index: std::collections::BTreeMap<String, hermetic_world_server::DedupeEntry> =
        serde_json::from_slice(&fs::read(root.path().join("log/dedupe.json")).unwrap()).unwrap();
    let rebuilt = LogManager::rebuild_dedupe_from_log(&path).unwrap();
    assert_eq!(
        index.values().collect::<Vec<_>>(),
        rebuilt.values().collect::<Vec<_>>()
    );
    let mut resumed = LogManager::new_opts_recover(root.path().join("log"), true, true).unwrap();
    assert_eq!(resumed.run_state().requests, 1);
    resumed.finish().unwrap();
    assert_eq!(verify_log_recover(&path, false, false).unwrap(), 4);
}

fn assert_audit_chain(root: &Path, status: &str, requests: u64) {
    let path = root.join("log/requests.log");
    let data = fs::read_to_string(&path).unwrap();
    let records: Vec<serde_json::Value> = data
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.last().unwrap()["status"], status);
    assert_eq!(
        verify_log_recover(&path, false, false).unwrap(),
        usize::try_from(requests * 2 + 3).unwrap()
    );
    assert!(fs::metadata(path).unwrap().len() <= hermetic_world_server::log::MAX_LOG_BYTES);
    let index: std::collections::BTreeMap<String, hermetic_world_server::DedupeEntry> =
        serde_json::from_slice(&fs::read(root.join("log/dedupe.json")).unwrap()).unwrap();
    let rebuilt = LogManager::rebuild_dedupe_from_log(&root.join("log/requests.log")).unwrap();
    assert_eq!(
        index.values().collect::<Vec<_>>(),
        rebuilt.values().collect::<Vec<_>>()
    );
}

#[test]
fn review_1_process_exit_codes_and_maximum_path_byte_budgets() {
    for scenario in ["distinct", "escaped", "quota", "malformed"] {
        let temp = tempdir().unwrap();
        support::create_private_dir_all(temp.path().join("store/example.org")).unwrap();
        let mut child = AuditChild(audit_command(temp.path(), "socket").spawn().unwrap());
        let mut stream = audit_connect(temp.path(), &mut child);
        let mut accepted = 0;
        if scenario == "malformed" {
            // Keep the write half open: bad magic must be rejected immediately.
            stream
                .write_all(b"INVALID_HEADER_GARBAGE_BYTES_1234")
                .unwrap();
            assert_eq!(child.wait_code(), 3);
            assert_audit_chain(temp.path(), "tampered", 0);
            continue;
        }
        for request_id in 1..=4097 {
            let path = match scenario {
                "distinct" => format!("/item?q={request_id:05}_{}", "a".repeat(8178)),
                "escaped" => format!("/item?{}", "\"".repeat(8186)),
                _ => "/missing".to_owned(),
            };
            if scenario != "quota" {
                assert_eq!(path.len(), hermetic_common::MAX_PATH_LEN);
            }
            let request = RequestFrame {
                method: Method::Get,
                request_id,
                authority: "example.org".into(),
                path_and_query: path,
                range: None,
            };
            stream.write_all(&request.encode().unwrap()).unwrap();
            match ResponseFrame::read_from(&mut stream, 1024 * 1024) {
                Ok(response) => {
                    assert_eq!(response.status, 404);
                    accepted += 1;
                }
                Err(_) => break,
            }
        }
        assert_eq!(child.wait_code(), 4, "{scenario}");
        if scenario == "quota" {
            assert_eq!(accepted, 4096);
        } else {
            assert!(accepted > 100 && accepted < 4096, "{scenario}: {accepted}");
        }
        assert_audit_chain(temp.path(), "limit_exceeded", accepted);
    }
}

#[test]
fn review_2_competing_processes_cannot_recover_or_spend_restored_quota() {
    let temp = tempdir().unwrap();
    support::create_private_dir_all(temp.path().join("store/example.org")).unwrap();
    let mut child = AuditChild(audit_command(temp.path(), "socket").spawn().unwrap());
    let mut stream = audit_connect(temp.path(), &mut child);
    let request = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "example.org".into(),
        path_and_query: "/missing".into(),
        range: None,
    };
    stream.write_all(&request.encode().unwrap()).unwrap();
    assert_eq!(
        ResponseFrame::read_from(&mut stream, 1024 * 1024)
            .unwrap()
            .status,
        404
    );
    stream
        .write_all(b"INVALID_HEADER_GARBAGE_BYTES_1234")
        .unwrap();
    assert_eq!(child.wait_code(), 3);
    let mut resumed = AuditChild(
        audit_command(temp.path(), "resumed_socket")
            .args(["--resume-log", "--recover"])
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + AUDIT_CHILD_TIMEOUT;
    while !temp.path().join("resumed_socket").exists() {
        assert!(resumed.0.try_wait().unwrap().is_none());
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    // Binding the socket precedes the startup audit record. Snapshot only after it.
    loop {
        let data = fs::read_to_string(temp.path().join("log/requests.log")).unwrap();
        let last = data
            .lines()
            .last()
            .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok());
        if data.ends_with('\n')
            && last
                .as_ref()
                .is_some_and(|record| record["seq"] == 6 && record["status"] == "sandbox_disabled")
        {
            break;
        }
        assert!(resumed.0.try_wait().unwrap().is_none());
        assert!(
            std::time::Instant::now() < deadline,
            "resumed startup audit timeout"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let original = fs::read(temp.path().join("log/requests.log")).unwrap();
    let checkpoint = fs::read(temp.path().join("log/requests.log.head")).unwrap();
    let dedupe = fs::read(temp.path().join("log/dedupe.json")).unwrap();
    // More attempts than a socket probe backlog: ownership checks must never block.
    for _ in 0..16 {
        let mut contender = AuditChild(
            audit_command(temp.path(), "different_socket")
                .args(["--resume-log", "--recover"])
                .spawn()
                .unwrap(),
        );
        assert_eq!(contender.wait_code(), 1);
        let mut recovery = AuditChild(
            std::process::Command::new(env!("CARGO_BIN_EXE_hermetic-world-server"))
                .arg("verify-log")
                .arg(temp.path().join("log/requests.log"))
                .arg("--recover")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        assert_eq!(recovery.wait_code(), 1);
        assert_eq!(
            fs::read(temp.path().join("log/requests.log")).unwrap(),
            original
        );
        assert_eq!(
            fs::read(temp.path().join("log/requests.log.head")).unwrap(),
            checkpoint
        );
        assert_eq!(
            fs::read(temp.path().join("log/dedupe.json")).unwrap(),
            dedupe
        );
        assert!(!temp.path().join("different_socket").exists());
    }
    let mut stream = support::connect(temp.path().join("resumed_socket")).unwrap();
    stream.set_write_timeout(Some(AUDIT_CHILD_TIMEOUT)).unwrap();
    stream
        .write_all(b"INVALID_HEADER_GARBAGE_BYTES_1234")
        .unwrap();
    assert_eq!(resumed.wait_code(), 3);
    assert_eq!(
        verify_log_recover(temp.path().join("log/requests.log"), false, false).unwrap(),
        7
    );
}

#[test]
fn review_9_unbound_recovery_rejects_before_changing_any_artifact() {
    for content in [
        b"".as_slice(),
        b"{\"status\":\"run_config\",\"path_and_query\":\"partial".as_slice(),
    ] {
        for checkpoint in [false, true] {
            let root = tempdir().unwrap();
            support::create_private_dir(root.path().join("store")).unwrap();
            support::create_private_dir(root.path().join("log")).unwrap();
            fs::write(root.path().join("log/requests.log"), content).unwrap();
            fs::write(root.path().join("log/dedupe.json"), b"{}").unwrap();
            fs::write(root.path().join("log/.head.tmp"), b"abandoned").unwrap();
            fs::write(root.path().join("log/.dedupe.json.tmp"), b"abandoned").unwrap();
            if checkpoint {
                let head = hermetic_world_server::LogHead {
                    seq: 0,
                    hash: hermetic_world_server::log::INITIAL_PREV_HASH.into(),
                };
                fs::write(
                    root.path().join("log/requests.log.head"),
                    serde_json::to_vec(&head).unwrap(),
                )
                .unwrap();
            }
            let paths = [
                "requests.log",
                "requests.log.head",
                "dedupe.json",
                ".head.tmp",
                ".dedupe.json.tmp",
            ];
            let snapshot: Vec<_> = paths
                .iter()
                .map(|name| fs::read(root.path().join("log").join(name)).ok())
                .collect();
            let mut cfg = config(root.path());
            cfg.resume_log = true;
            cfg.recover = true;
            assert_eq!(WorldServer::new(cfg).err(), Some(ServerExit::StartupFailed));
            for (name, before) in paths.iter().zip(snapshot) {
                assert_eq!(fs::read(root.path().join("log").join(name)).ok(), before);
            }
            assert!(!root.path().join("socket").exists());
        }
    }
}

#[test]
fn review_root_separation_rename_during_validation_rejected_no_disclosure() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let store_dir = root.join("store");
    let log_dir = store_dir.join("example.org");
    let socket_path = root.join("server.sock");

    support::create_private_dir_all(&log_dir).unwrap();
    fs::write(log_dir.join("item.txt"), b"genuine content").unwrap();

    let mut cfg = config(root);
    cfg.store_dir = store_dir.clone();
    cfg.log_dir = log_dir.clone();
    cfg.socket_path = socket_path.clone();
    cfg.no_sandbox = false;

    let store_for_rename = store_dir.clone();
    let renamed_store = root.join("store_renamed");
    let renamed_store_clone = renamed_store.clone();

    hermetic_world_server::server::set_validation_rename_hook(move || {
        fs::rename(&store_for_rename, &renamed_store_clone).unwrap();
    });

    let res = WorldServer::new(cfg);
    assert_eq!(res.err(), Some(ServerExit::StartupFailed));

    // Assert no audit disclosure: requests.log was never written to store or log
    assert!(!renamed_store.join("example.org/requests.log").exists());
    assert!(!store_dir.join("example.org/requests.log").exists());

    use hermetic_world_server::Store;
    let store = hermetic_world_server::DirStore::new(&renamed_store);
    assert!(store.get("example.org", "/requests.log").is_none());
}

#[test]
fn review_startup_validates_endpoint_and_proposed_log_before_creating_artifacts() {
    fn tree_snapshot(root: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
        let mut tree = std::collections::BTreeMap::new();
        fn walk(
            dir: &Path,
            base: &Path,
            tree: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
        ) {
            if let Ok(entries) = fs::read_dir(dir) {
                let mut paths: Vec<_> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
                paths.sort();
                for p in paths {
                    let rel = p.strip_prefix(base).unwrap().to_path_buf();
                    if p.is_dir() {
                        tree.insert(rel.clone(), Vec::new());
                        walk(&p, base, tree);
                    } else if let Ok(data) = fs::read(&p) {
                        tree.insert(rel, data);
                    }
                }
            }
        }
        walk(root, root, &mut tree);
        tree
    }

    // 1. Overlapping nonexistent log paths
    for overlap in ["nonexistent_log", "example.org/nonexistent_child"] {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let store = root.join("store");
        support::create_private_dir_all(store.join("example.org")).unwrap();
        fs::write(store.join("example.org/item.txt"), b"item").unwrap();

        let mut cfg = config(root);
        cfg.store_dir = store.clone();
        cfg.log_dir = store.join(overlap);
        cfg.socket_path = root.join("server.sock");

        let before = tree_snapshot(root);
        let res = WorldServer::new(cfg);
        assert_eq!(res.err(), Some(ServerExit::StartupFailed));
        assert_eq!(tree_snapshot(root), before);
        assert!(!store.join(overlap).exists());
    }

    // 2. Invalid endpoints with nonexistent log directory
    {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let store = root.join("store");
        support::create_private_dir_all(store.join("example.org")).unwrap();
        fs::write(store.join("example.org/item.txt"), b"item").unwrap();

        // Nonexistent socket parent
        let mut cfg = config(root);
        cfg.store_dir = store.clone();
        cfg.log_dir = root.join("nonexistent_log");
        cfg.socket_path = root.join("nonexistent_parent/server.sock");
        let before = tree_snapshot(root);
        assert_eq!(WorldServer::new(cfg).err(), Some(ServerExit::StartupFailed));
        assert_eq!(tree_snapshot(root), before);
        assert!(!root.join("nonexistent_log").exists());

        // Regular file as socket
        let reg_sock = root.join("reg.sock");
        fs::write(&reg_sock, b"regular file").unwrap();
        let mut cfg = config(root);
        cfg.store_dir = store.clone();
        cfg.log_dir = root.join("nonexistent_log");
        cfg.socket_path = reg_sock;
        let before = tree_snapshot(root);
        assert_eq!(WorldServer::new(cfg).err(), Some(ServerExit::StartupFailed));
        assert_eq!(tree_snapshot(root), before);
        assert!(!root.join("nonexistent_log").exists());

        // Symlink as socket
        let sym_sock = root.join("sym.sock");
        symlink(&store, &sym_sock).unwrap();
        let mut cfg = config(root);
        cfg.store_dir = store.clone();
        cfg.log_dir = root.join("nonexistent_log");
        cfg.socket_path = sym_sock;
        let before = tree_snapshot(root);
        assert_eq!(WorldServer::new(cfg).err(), Some(ServerExit::StartupFailed));
        assert_eq!(tree_snapshot(root), before);
        assert!(!root.join("nonexistent_log").exists());

        // Socket name too long
        let long_sock = root.join(format!("{}.sock", "a".repeat(300)));
        let mut cfg = config(root);
        cfg.store_dir = store.clone();
        cfg.log_dir = root.join("nonexistent_log");
        cfg.socket_path = long_sock;
        let before = tree_snapshot(root);
        assert_eq!(WorldServer::new(cfg).err(), Some(ServerExit::StartupFailed));
        assert_eq!(tree_snapshot(root), before);
        assert!(!root.join("nonexistent_log").exists());

        // Existing socket when recover is false
        let exist_sock = root.join("exist.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&exist_sock).unwrap();
        let mut cfg = config(root);
        cfg.store_dir = store.clone();
        cfg.log_dir = root.join("nonexistent_log");
        cfg.socket_path = exist_sock;
        cfg.recover = false;
        let before = tree_snapshot(root);
        assert_eq!(WorldServer::new(cfg).err(), Some(ServerExit::StartupFailed));
        assert_eq!(tree_snapshot(root), before);
        assert!(!root.join("nonexistent_log").exists());
    }
}

#[test]
fn rereview_1_invalid_fixed_header_without_payload_is_tampering() {
    // (header byte, value): version, method (two values), flags, reserved.
    for (offset, value) in [(4usize, 2u8), (5, 0), (5, 3), (6, 0x02), (7, 1)] {
        let temp = tempdir().unwrap();
        support::create_private_dir_all(temp.path().join("store/example.org")).unwrap();
        let mut child = AuditChild(
            audit_command(temp.path(), "socket")
                .args(["--frame-deadline-ms", "1000"])
                .spawn()
                .unwrap(),
        );
        let mut stream = audit_connect(temp.path(), &mut child);
        let request = RequestFrame {
            method: Method::Get,
            request_id: 1,
            authority: "example.org".into(),
            path_and_query: "/item".into(),
            range: None,
        };
        let mut header = request.encode().unwrap();
        header.truncate(hermetic_common::REQUEST_HEADER_SIZE);
        header[offset] = value;
        // Send only the fixed header and keep the write half open: the
        // declared payload is withheld, so only header validation can end it.
        stream.write_all(&header).unwrap();
        assert_eq!(child.wait_code(), 3, "header byte {offset} = {value}");
        assert_audit_chain(temp.path(), "tampered", 0);
        drop(stream);
    }
}

#[test]
fn priorcheck_3_stale_endpoint_in_group_writable_directory_is_not_reclaimed() {
    // The 0700 case is covered by the reclaim unit tests in server.rs.
    for mode in [0o770, 0o775, 0o720] {
        let temp = tempdir().unwrap();
        support::create_private_dir_all(temp.path().join("store")).unwrap();
        finalized(&temp.path().join("log"));
        let socket = temp.path().join("socket");
        let lock = temp.path().join(".socket.lock");
        // Stale endpoint: both sockets exist but nothing listens on them.
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        drop(std::os::unix::net::UnixListener::bind(&lock).unwrap());
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(mode)).unwrap();
        let output = support::output_bounded(
            audit_command(temp.path(), "socket").args(["--resume-log", "--recover"]),
        );
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{mode:o}: {stderr}");
        assert!(
            stderr.contains("not removed") && stderr.contains("remove the stale socket"),
            "{mode:o}: {stderr}"
        );
        for entry in [&socket, &lock] {
            assert!(
                fs::symlink_metadata(entry).is_ok(),
                "{mode:o}: {} was removed",
                entry.display()
            );
        }
        let names: Vec<_> = fs::read_dir(temp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|name| !name.contains("reclaim")),
            "{names:?}"
        );
    }
}

#[test]
fn test_sandboxed_server_endpoint_cleanup_on_drop() {
    let root = tempdir().unwrap();
    let store_dir = root.path().join("store");
    let log_dir = root.path().join("log");
    let socket_dir = root.path().join("endpoint");
    support::create_private_dir(&store_dir).unwrap();
    support::create_private_dir(&log_dir).unwrap();
    support::create_private_dir(&socket_dir).unwrap();
    support::create_private_dir_all(store_dir.join("example.org")).unwrap();
    fs::write(store_dir.join("example.org/item"), b"payload").unwrap();

    let socket_path = socket_dir.join("server.sock");
    let lock_path = socket_dir.join(".server.sock.lock");

    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_hermetic-world-server"));
    command
        .arg("--store")
        .arg(&store_dir)
        .arg("--log")
        .arg(&log_dir)
        .arg("--socket")
        .arg(&socket_path)
        .args([
            "--t-clock",
            "2024-03-01T12:00:00Z",
            "--allow-no-landlock",
            "--max-requests",
            "1",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = AuditChild(command.spawn().unwrap());

    // Connect to server socket
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut stream = loop {
        if socket_path.exists() {
            if let Ok(s) = support::connect(&socket_path) {
                break s;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timeout connecting to sandboxed server"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };

    // Send a valid request
    let req = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "example.org".into(),
        path_and_query: "/item".into(),
        range: None,
    };
    stream.write_all(&req.encode().unwrap()).unwrap();
    let resp = ResponseFrame::read_from(&mut stream, 1024).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"payload");
    drop(stream);

    // Wait for the sandboxed server to complete and exit
    let status = child.wait_status();
    assert!(status.success(), "sandboxed server failed: {status:?}");

    // The endpoint socket and its lock must be removed on drop
    assert!(
        !socket_path.exists(),
        "socket {} was not removed on drop",
        socket_path.display()
    );
    assert!(
        !lock_path.exists(),
        "lock {} was not removed on drop",
        lock_path.display()
    );

    // A second server on the same socket path must succeed to start without --recover
    let log_dir2 = root.path().join("log2");
    support::create_private_dir(&log_dir2).unwrap();
    let mut second_cmd = std::process::Command::new(env!("CARGO_BIN_EXE_hermetic-world-server"));
    second_cmd
        .arg("--store")
        .arg(&store_dir)
        .arg("--log")
        .arg(&log_dir2)
        .arg("--socket")
        .arg(&socket_path)
        .args([
            "--t-clock",
            "2024-03-01T12:00:00Z",
            "--allow-no-landlock",
            "--max-requests",
            "1",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut second_child = AuditChild(second_cmd.spawn().unwrap());
    let deadline2 = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let stream2 = loop {
        if socket_path.exists() {
            if let Ok(s) = support::connect(&socket_path) {
                break s;
            }
        }
        assert!(
            std::time::Instant::now() < deadline2,
            "timeout connecting to second server"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    drop(stream2);
    let _ = second_child.wait_status();
}
