#![forbid(unsafe_code)]

mod support;

use hermetic_common::{Method, RequestFrame, ResponseFrame};
use hermetic_world_server::{ServerConfig, WorldServer};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use support::private_tempdir as tempdir;
use support::BoundedChild;
use time::macros::datetime;

fn send_req(socket: &Path, req: &RequestFrame) -> ResponseFrame {
    let mut stream = support::connect(socket).expect("connect to socket");
    let encoded = req.encode().expect("encode req");
    stream.write_all(&encoded).expect("write req");
    ResponseFrame::read_from(&mut stream, 10 * 1024 * 1024).expect("read response")
}

#[test]
fn test_token_bucket_delays_requests() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");
    let t_clock = datetime!(2024-03-01 12:00:00 UTC);

    support::create_private_dir_all(store_dir.join("pypi.org")).expect("create store");
    fs::write(store_dir.join("pypi.org").join("test.txt"), b"ok").expect("write test file");

    let config = ServerConfig {
        store_dir,
        socket_path: socket_path.clone(),
        log_dir,
        t_clock,
        rate_rps: Some(5.0), // 5 requests per second = 200ms per request
        burst: Some(1.0),    // burst of 1 token
        max_requests: None,
        max_bytes: None,
        allow_no_landlock: true,
        no_sandbox: true,
        resume_log: false,
        recover: false,
        frame_deadline: None,
        transmission_deadline: None,
    };

    let server = WorldServer::new(config).expect("create server");
    thread::spawn(move || {
        let _ = server.run();
    });

    for _ in 0..100 {
        if socket_path.exists() {
            thread::sleep(Duration::from_millis(20));
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let req = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "pypi.org".into(),
        path_and_query: "/test.txt".into(),
        range: None,
    };

    let start = Instant::now();
    for i in 1..=3 {
        let mut r = req.clone();
        r.request_id = i;
        let resp = send_req(&socket_path, &r);
        assert_eq!(resp.status, 200);
    }
    let elapsed = start.elapsed();
    // 3 requests with rate 5 rps and burst 1:
    // Req 1: 0ms (uses burst token)
    // Req 2: ~200ms delay
    // Req 3: ~200ms delay
    // Total should be around 400ms. Bounds: >= 300ms, <= 3000ms.
    assert!(
        elapsed >= Duration::from_millis(300),
        "Elapsed {elapsed:?} should be >= 300ms due to rate limit delays"
    );
    assert!(
        elapsed <= Duration::from_millis(3000),
        "Elapsed {elapsed:?} should be <= 3000ms"
    );
}

fn bin_path() -> PathBuf {
    // Cargo builds the package's binaries for its integration tests and names
    // the exact path; no search through target-directory layouts.
    PathBuf::from(env!("CARGO_BIN_EXE_hermetic-world-server"))
}

#[test]
fn test_request_cap_exceeded_exit_code_4() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");

    support::create_private_dir_all(store_dir.join("pypi.org")).expect("create store");
    fs::write(store_dir.join("pypi.org").join("test.txt"), b"ok").expect("write test file");

    let bin = bin_path();
    let mut child = BoundedChild(
        Command::new(&bin)
            .arg("--store")
            .arg(&store_dir)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--log")
            .arg(&log_dir)
            .arg("--t-clock")
            .arg("2024-03-01T12:00:00Z")
            .arg("--max-requests")
            .arg("2")
            .arg("--no-sandbox")
            .spawn()
            .expect("spawn server"),
    );

    for _ in 0..100 {
        if socket_path.exists() {
            thread::sleep(Duration::from_millis(20));
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let req = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "pypi.org".into(),
        path_and_query: "/test.txt".into(),
        range: None,
    };

    // Request 1: OK
    let resp1 = send_req(&socket_path, &req);
    assert_eq!(resp1.status, 200);

    // Request 2: OK
    let resp2 = send_req(&socket_path, &req);
    assert_eq!(resp2.status, 200);

    // Request 3: Exceeds max-requests (2)!
    let mut stream = support::connect(&socket_path).expect("connect for req 3");
    let encoded = req.encode().expect("encode");
    let _ = stream.write_all(&encoded);

    let status = child.wait_status();
    assert_eq!(
        status.code(),
        Some(4),
        "Exceeding request cap must exit with code 4"
    );

    // Verify requests.log has limit_exceeded
    let log_content = fs::read_to_string(log_dir.join("requests.log")).expect("read log");
    assert!(log_content.contains("\"limit_exceeded\""));
}

#[test]
fn test_byte_cap_exceeded_exit_code_4() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");

    support::create_private_dir_all(store_dir.join("pypi.org")).expect("create store");
    // Write 50-byte file
    let data = vec![b'a'; 50];
    fs::write(store_dir.join("pypi.org").join("test.txt"), &data).expect("write file");

    let bin = bin_path();
    let mut child = BoundedChild(
        Command::new(&bin)
            .arg("--store")
            .arg(&store_dir)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--log")
            .arg(&log_dir)
            .arg("--t-clock")
            .arg("2024-03-01T12:00:00Z")
            .arg("--max-bytes")
            .arg("80") // First request serves 50 bytes, second would exceed (100 > 80)
            .arg("--no-sandbox")
            .spawn()
            .expect("spawn server"),
    );

    for _ in 0..100 {
        if socket_path.exists() {
            thread::sleep(Duration::from_millis(20));
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let req = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "pypi.org".into(),
        path_and_query: "/test.txt".into(),
        range: None,
    };

    // Request 1: 50 bytes <= 80 -> OK
    let resp1 = send_req(&socket_path, &req);
    assert_eq!(resp1.status, 200);

    // Request 2: would be 100 bytes > 80 -> Limit exceeded!
    let mut stream = support::connect(&socket_path).expect("connect for req 2");
    let encoded = req.encode().expect("encode");
    let _ = stream.write_all(&encoded);

    let status = child.wait_status();
    assert_eq!(
        status.code(),
        Some(4),
        "Exceeding byte cap must exit with code 4"
    );

    let log_content = fs::read_to_string(log_dir.join("requests.log")).expect("read log");
    assert!(log_content.contains("\"limit_exceeded\""));
}

#[test]
fn test_malformed_frame_exit_code_3() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");

    support::create_private_dir_all(store_dir.join("pypi.org")).expect("create store");

    let bin = bin_path();
    let mut child = BoundedChild(
        Command::new(&bin)
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
            .expect("spawn server"),
    );

    for _ in 0..100 {
        if socket_path.exists() {
            thread::sleep(Duration::from_millis(20));
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    // Send malformed bytes (bad magic and corrupted header)
    let mut stream = support::connect(&socket_path).expect("connect");
    let bad_bytes = b"BAD_MAGIC_BYTES_AND_CORRUPTED_FRAME_PAYLOAD_HERE!!";
    let _ = stream.write_all(bad_bytes);

    let status = child.wait_status();
    assert_eq!(
        status.code(),
        Some(3),
        "Malformed frame must exit with code 3"
    );

    let log_content = fs::read_to_string(log_dir.join("requests.log")).expect("read log");
    assert!(
        log_content.contains("\"tampered\""),
        "Log must record status tampered"
    );
}

#[test]
fn test_fix2_startup_failed_socket_nonexistent_dir() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    support::create_private_dir_all(&store_dir).expect("create store");
    support::create_private_dir_all(&log_dir).expect("create log");

    let bad_socket = temp.path().join("nonexistent_subdir").join("server.sock");
    let bin = bin_path();
    let status = BoundedChild(
        Command::new(&bin)
            .arg("--store")
            .arg(&store_dir)
            .arg("--socket")
            .arg(&bad_socket)
            .arg("--log")
            .arg(&log_dir)
            .arg("--t-clock")
            .arg("2024-03-01T12:00:00Z")
            .arg("--no-sandbox")
            .spawn()
            .expect("run binary"),
    )
    .wait_status();

    // FIX 2: bind failure exits code 1 (ServerExit::StartupFailed)
    assert_eq!(
        status.code(),
        Some(1),
        "Server startup failure (bind error) must exit with code 1"
    );
}

#[test]
fn test_fix5_client_early_close_logs_write_error_and_chain_verifies() {
    let temp = tempdir().expect("tempdir");
    let store_dir = temp.path().join("store");
    let log_dir = temp.path().join("log");
    let socket_path = temp.path().join("server.sock");

    let auth_dir = store_dir.join("example.com");
    support::create_private_dir_all(&auth_dir).expect("create auth dir");
    // Write 500 KB file so server writing to dropped client will encounter broken pipe
    let big_body = vec![b'w'; 500 * 1024];
    fs::write(auth_dir.join("large.dat"), &big_body).expect("write large file");

    let bin = bin_path();
    let mut child = BoundedChild(
        Command::new(&bin)
            .arg("--store")
            .arg(&store_dir)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--log")
            .arg(&log_dir)
            .arg("--t-clock")
            .arg("2024-03-01T12:00:00Z")
            .arg("--max-requests")
            .arg("1")
            .arg("--no-sandbox")
            .spawn()
            .expect("spawn server"),
    );

    for _ in 0..100 {
        if socket_path.exists() {
            thread::sleep(Duration::from_millis(20));
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let req = RequestFrame {
        method: Method::Get,
        request_id: 1,
        authority: "example.com".into(),
        path_and_query: "/large.dat".into(),
        range: None,
    };
    let encoded = req.encode().expect("encode");

    // Connect, send frame, immediately drop stream
    let mut stream = support::connect(&socket_path).expect("connect");
    stream.write_all(&encoded).expect("write request");
    drop(stream);

    thread::sleep(Duration::from_millis(50));

    // Send a 2nd request to cleanly trigger max-requests (limit_exceeded) exit
    let req2 = RequestFrame {
        method: Method::Get,
        request_id: 2,
        authority: "example.com".into(),
        path_and_query: "/large.dat".into(),
        range: None,
    };
    if let Ok(mut s2) = support::connect(&socket_path) {
        let _ = s2.write_all(&req2.encode().expect("encode req2"));
    }

    let status = child.wait_status();
    assert_eq!(status.code(), Some(4));

    let log_file = log_dir.join("requests.log");
    assert!(log_file.exists(), "requests.log must exist");

    // FIX 5: chain still verifies
    let count = hermetic_world_server::verify_log(&log_file).expect("chain must verify");
    assert!(count >= 1, "at least one record must be verified");

    let log_content = fs::read_to_string(&log_file).expect("read log");
    assert!(
        log_content.contains("\"status\":\"write_error\""),
        "Log must contain write_error record: {log_content}"
    );
}
