#![forbid(unsafe_code)]

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

#[test]
fn defect1_guest_clock_non_utc_overflow_rejected() {
    let temp = tempdir().unwrap();
    fs::create_dir(temp.path().join("store")).unwrap();

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
    fs::create_dir_all(&obj_dir).unwrap();

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
    let thread_handle = std::thread::spawn(move || {
        let _ = server.run();
    });

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let send_req = |path_and_query: &str| -> ResponseFrame {
        let mut client = UnixStream::connect(&socket_path).unwrap();
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
        fs::create_dir_all(store.join("example.org")).unwrap();
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
        fs::create_dir_all(&log).unwrap();
        let store = log.join("store");
        fs::create_dir_all(&store).unwrap();
        let mut cfg = config(temp.path());
        cfg.store_dir = store.clone();
        cfg.log_dir = log.clone();
        assert!(WorldServer::new(cfg).is_err());
        assert!(!log.join("requests.log").exists());
    }

    {
        let temp = tempdir().unwrap();
        let root = temp.path().join("same_dir");
        fs::create_dir_all(&root).unwrap();
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
    fs::create_dir_all(&log_dir).unwrap();

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
    fs::create_dir_all(store_dir.join("example.org")).unwrap();
    fs::write(
        store_dir.join("example.org/test.txt"),
        b"crash recovery data",
    )
    .unwrap();

    let exe = env!("CARGO_BIN_EXE_hermetic-world-server");

    let mut child = Command::new(exe)
        .arg("--store")
        .arg(&store_dir)
        .arg("--socket")
        .arg(&socket_path)
        .arg("--log")
        .arg(&log_dir)
        .arg("--t-clock")
        .arg("2024-03-01T12:00:00Z")
        .arg("--no-sandbox")
        .spawn()
        .unwrap();

    let mut connected = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if socket_path.exists() {
            if let Ok(mut s) = UnixStream::connect(&socket_path) {
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

    let live_conflict = Command::new(exe)
        .arg("--store")
        .arg(&store_dir)
        .arg("--socket")
        .arg(&socket_path)
        .arg("--log")
        .arg(temp.path().join("other_log"))
        .arg("--t-clock")
        .arg("2024-03-01T12:00:00Z")
        .arg("--no-sandbox")
        .arg("--recover")
        .output()
        .unwrap();
    assert_eq!(
        live_conflict.status.code(),
        Some(1),
        "Live endpoint must be protected"
    );

    child.kill().unwrap();
    let _ = child.wait();

    assert!(
        socket_path.exists(),
        "Socket file should remain after SIGKILL"
    );

    let mut resumed = Command::new(exe)
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
        .arg("--recover")
        .spawn()
        .unwrap();

    let mut resumed_connected = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if let Ok(mut s) = UnixStream::connect(&socket_path) {
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
    resumed.kill().unwrap();
    let _ = resumed.wait();
}

#[test]
fn defect6_socket_deadlines_terminate_stalled_reader_and_writer() {
    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    fs::create_dir_all(store_dir.join("example.org")).unwrap();
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
    let handle = std::thread::spawn(move || {
        let _ = server.run();
    });

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    {
        let mut client = UnixStream::connect(&socket_path).unwrap();
        client.write_all(b"HW").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(250));
        let mut buf = [0u8; 16];
        let res = client.read(&mut buf);
        assert!(matches!(res, Ok(0) | Err(_)));
    }

    {
        let mut client = UnixStream::connect(&socket_path).unwrap();
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
    fs::create_dir_all(store_dir.join("example.org")).unwrap();
    fs::write(store_dir.join("example.org/item"), b"content").unwrap();

    let mut cfg = config(temp.path());
    cfg.store_dir = store_dir;
    cfg.log_dir = log_dir.clone();
    cfg.socket_path = socket_path.clone();
    cfg.max_requests = Some(2050);

    let server = WorldServer::new(cfg).unwrap();
    let handle = std::thread::spawn(move || server.run());

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut client = UnixStream::connect(&socket_path).unwrap();
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
        assert_eq!(resp.status, 200);
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
    fs::create_dir_all(store_dir.join("example.org")).unwrap();

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
    let handle = std::thread::spawn(move || {
        let _ = server.run();
    });

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let mut client = UnixStream::connect(&socket_path).unwrap();
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
    fs::create_dir_all(&obj_dir).unwrap();

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
    let handle = std::thread::spawn(move || {
        let _ = server.run();
    });

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let send = |method, range| -> ResponseFrame {
        let mut client = UnixStream::connect(&socket_path).unwrap();
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

#[test]
fn defect11_unavailable_landlock_startup_regression() {
    hermetic_world_server::sandbox::set_inject_landlock_unavailable(true);

    let temp = tempdir().unwrap();
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    fs::create_dir_all(store_dir.join("example.org")).unwrap();
    fs::write(store_dir.join("example.org/index.html"), b"hello").unwrap();

    let mut cfg = config(temp.path());
    cfg.store_dir = store_dir;
    cfg.log_dir = log_dir.clone();
    cfg.socket_path = socket_path.clone();
    cfg.no_sandbox = false;
    cfg.allow_no_landlock = true;

    let server = WorldServer::new(cfg).unwrap();
    let handle = std::thread::spawn(move || server.run());

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    {
        let client = UnixStream::connect(&socket_path).unwrap();
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
}
