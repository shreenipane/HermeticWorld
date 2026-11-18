//! The vsock upstream against an in-process WorldServer and against hostile fakes.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hermetic_common::wire::{RequestFrame, ResponseFrame, ResponseHeader};
use hermetic_netvm_core::http::{HttpRuntimeConfig, Upstream, UpstreamError};
use hermetic_netvm_core::runtime::{WorldDns, WorldFilter};
use hermetic_netvm_core::upstream::VsockUpstream;
use hermetic_netvm_core::{RunningNetvm, VecLogSink};
use hermetic_netvm_dns::DnsTable;
use hermetic_world_server::{ServerConfig, WorldServer};

const BODY: &[u8] = b"hello from the frozen world\n";

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn world(temp: &Path) -> PathBuf {
    let store = temp.join("store");
    private_dir(&store.join("files.example"));
    std::fs::write(store.join("files.example").join("hello.txt"), BODY).unwrap();
    private_dir(&temp.join("log"));
    let socket = temp.join("world.sock");
    let server = WorldServer::new(ServerConfig {
        store_dir: store,
        socket_path: socket.clone(),
        log_dir: temp.join("log"),
        t_clock: time::macros::datetime!(2023-11-14 22:13:20 UTC),
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
        search_index_dir: None,
        replay_index_path: None,
    })
    .unwrap();
    std::thread::spawn(move || {
        let _ = server.run();
    });
    let end = Instant::now() + Duration::from_secs(10);
    while std::os::unix::net::UnixStream::connect(&socket).is_err() {
        assert!(Instant::now() < end, "world server did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    socket
}

fn descriptor(method: &str, path: &str, range: Option<(u64, u64)>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "method": method, "authority": "files.example", "path": path, "range": range
    }))
    .unwrap()
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn body(r: hermetic_netvm_core::http::UpstreamResponse) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut b = r.body;
    b.read_to_end(&mut out)?;
    Ok(out)
}

#[test]
fn fetches_from_world_server_over_wire_frames() {
    let temp = tempfile::tempdir().unwrap();
    let socket = world(temp.path());
    let up = VsockUpstream::unix(&socket);
    let r = up
        .fetch(&descriptor("GET", "/hello.txt", None), soon())
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(body(r).unwrap(), BODY);
    let r = up
        .fetch(&descriptor("GET", "/hello.txt", Some((0, 4))), soon())
        .unwrap();
    assert_eq!(r.status, 206);
    assert_eq!(body(r).unwrap(), b"hello");
    let r = up
        .fetch(&descriptor("HEAD", "/hello.txt", None), soon())
        .unwrap();
    assert_eq!(body(r).unwrap(), b"");
    let r = up
        .fetch(&descriptor("GET", "/missing", None), soon())
        .unwrap();
    assert_eq!(r.status, 404);
}

#[test]
fn http_through_filter_reaches_world_and_post_is_405() {
    let temp = tempfile::tempdir().unwrap();
    let socket = world(temp.path());
    let table = DnsTable::test_fixture([(
        "files.example",
        vec!["127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()],
    )]);
    let server = RunningNetvm::start(
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
        HttpRuntimeConfig::bounded(8, 2000, 1000, 5000, 1_700_000_000),
        Arc::new(WorldDns(table.clone())),
        Arc::new(WorldFilter::new(&table)),
        Arc::new(VsockUpstream::unix(&socket)),
        Arc::new(VecLogSink::new()),
    )
    .unwrap();
    let ask = |req: &[u8]| {
        let mut s = TcpStream::connect(server.http_addr()).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(req).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    };
    let ok = ask(b"GET /hello.txt HTTP/1.1\r\nHost: files.example\r\nConnection: close\r\n\r\n");
    assert!(ok.starts_with(b"HTTP/1.1 200"), "{ok:?}");
    assert!(ok.ends_with(BODY));
    let post = ask(b"POST /hello.txt HTTP/1.1\r\nHost: files.example\r\nContent-Length: 0\r\n\r\n");
    assert!(post.starts_with(b"HTTP/1.1 405"), "{post:?}");
    let other = ask(b"GET / HTTP/1.1\r\nHost: elsewhere.example\r\n\r\n");
    assert!(!other.starts_with(b"HTTP/1.1 2"), "{other:?}");
    server.stop();
}

/// A fake world endpoint that reads one request frame and replies with `reply`.
fn fake(temp: &Path, reply: Vec<u8>, hold: Duration) -> PathBuf {
    let path = temp.join("fake.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = RequestFrame::read_from(&mut s);
            let _ = s.write_all(&reply);
            std::thread::sleep(hold);
        }
    });
    path
}

fn response(id: u64, status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    ResponseFrame {
        request_id: id,
        status,
        headers: headers
            .iter()
            .map(|(n, v)| ResponseHeader {
                name: (*n).into(),
                value: (*v).into(),
            })
            .collect(),
        body: body.to_vec(),
    }
    .encode(1 << 20)
    .unwrap()
}

#[test]
fn hostile_world_replies_are_refused() {
    let get = descriptor("GET", "/x", None);
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (response(7, 200, &[], b"x"), "wrong request id"),
        (response(1, 99, &[], b""), "status out of range"),
        (response(1, 204, &[], b"x"), "204 with body"),
        (
            response(1, 200, &[("content-length", "5")], b"x"),
            "content-length mismatch",
        ),
        (
            response(
                1,
                200,
                &[("content-length", "1"), ("content-length", "1")],
                b"x",
            ),
            "duplicate content-length",
        ),
        (b"garbage".to_vec(), "malformed frame"),
    ];
    for (reply, why) in cases {
        let temp = tempfile::tempdir().unwrap();
        let up = VsockUpstream::unix(fake(temp.path(), reply, Duration::ZERO));
        assert!(up.fetch(&get, soon()).is_err(), "{why}");
    }
}

#[test]
fn truncated_body_is_an_error_not_a_short_success() {
    let temp = tempfile::tempdir().unwrap();
    let mut reply = response(1, 200, &[], b"0123456789");
    reply.truncate(reply.len() - 4);
    let up = VsockUpstream::unix(fake(temp.path(), reply, Duration::ZERO));
    let r = up.fetch(&descriptor("GET", "/x", None), soon()).unwrap();
    assert!(body(r).is_err());
}

#[test]
fn silent_world_times_out_at_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let up = VsockUpstream::unix(fake(temp.path(), Vec::new(), Duration::from_secs(5)));
    let start = Instant::now();
    let r = up.fetch(
        &descriptor("GET", "/x", None),
        Instant::now() + Duration::from_millis(200),
    );
    assert!(matches!(r, Err(UpstreamError::Timeout)), "{r:?}");
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn bad_descriptors_never_open_the_endpoint() {
    let temp = tempfile::tempdir().unwrap();
    // No listener: a connection attempt would be an Io error, not BadRequest.
    let up = VsockUpstream::unix(temp.path().join("absent.sock"));
    for d in [
        descriptor("POST", "/x", None),
        b"{".to_vec(),
        serde_json::to_vec(
            &serde_json::json!({"method":"GET","authority":"a","path":"/","range":null,"x":1}),
        )
        .unwrap(),
        vec![b' '; 1 << 20],
    ] {
        assert!(matches!(
            up.fetch(&d, soon()),
            Err(UpstreamError::BadRequest(_))
        ));
    }
}

#[test]
fn world_socket_path_must_not_be_a_symlink() {
    let temp = tempfile::tempdir().unwrap();
    let real = fake(temp.path(), response(1, 200, &[], b""), Duration::ZERO);
    let link = temp.path().join("link.sock");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let up = VsockUpstream::unix(&link);
    assert!(matches!(
        up.fetch(&descriptor("GET", "/x", None), soon()),
        Err(UpstreamError::Io(_))
    ));
}

/// Regression: a sandboxed WorldServer accepts exactly one connection per run.
/// Every request, including one whose body the client abandons, must reuse that
/// connection with increasing request ids.
#[test]
fn requests_share_one_connection_with_increasing_ids() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("one.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut ids = Vec::new();
        while let Ok(frame) = RequestFrame::read_from(&mut s) {
            ids.push(frame.request_id);
            let body = vec![b'z'; 100_000];
            s.write_all(&response(frame.request_id, 200, &[], &body))
                .unwrap();
        }
        ids
    });
    let up = Arc::new(VsockUpstream::unix(&path));
    // Abandon the first body after a few bytes: the rest must be drained.
    let mut r = up.fetch(&descriptor("GET", "/a", None), soon()).unwrap();
    let mut few = [0u8; 10];
    r.body.read_exact(&mut few).unwrap();
    drop(r);
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let up = Arc::clone(&up);
            std::thread::spawn(move || {
                let r = up.fetch(&descriptor("GET", "/b", None), soon()).unwrap();
                body(r).unwrap().len()
            })
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().unwrap(), 100_000);
    }
    drop(up);
    assert_eq!(server.join().unwrap(), vec![1, 2, 3, 4, 5]);
}

#[test]
fn non_pid1_serve_preserves_direct_http_for_allowed_host() {
    let temp = tempfile::tempdir().unwrap();
    let socket = world(temp.path());

    let config_path = temp.path().join("netvm.json");
    std::fs::write(&config_path, b"{\"t_clock\":1700000000}").unwrap();

    let dns_path = temp.path().join("dns.json");
    std::fs::write(
        &dns_path,
        b"{\"records\":[{\"name\":\"files.example\",\"a\":[\"10.9.0.1\"],\"aaaa\":[]}]}",
    )
    .unwrap();

    let dns_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dns_addr = dns_socket.local_addr().unwrap();
    drop(dns_socket);

    let http_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    drop(http_listener);

    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let child = std::process::Command::new(env!("CARGO_BIN_EXE_hermetic-netvm"))
        .args([
            "serve",
            "--config",
            config_path.to_str().unwrap(),
            "--dns-table",
            dns_path.to_str().unwrap(),
            "--world-socket",
            socket.to_str().unwrap(),
            "--dns",
            &dns_addr.to_string(),
            "--http",
            &http_addr.to_string(),
        ])
        .spawn()
        .unwrap();
    let _guard = ChildGuard(child);

    let start = Instant::now();
    let mut stream = loop {
        match TcpStream::connect(http_addr) {
            Ok(s) => break s,
            Err(_) if start.elapsed() < Duration::from_secs(3) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("failed to connect to netvm serve http port: {e}"),
        }
    };

    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(b"GET /hello.txt HTTP/1.1\r\nHost: files.example\r\nConnection: close\r\n\r\n")
        .unwrap();

    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);

    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "expected 200 response, got: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(response.ends_with(BODY));
}
