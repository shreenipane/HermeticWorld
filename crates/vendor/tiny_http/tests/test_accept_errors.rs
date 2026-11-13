use std::io::{Error, ErrorKind, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;
use tiny_http::{inject_accept_error_once, is_recoverable_accept_error, Response, Server};

static TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_recoverable_accept_error_classification() {
    // EINTR
    assert!(is_recoverable_accept_error(&Error::from(
        ErrorKind::Interrupted
    )));
    assert!(is_recoverable_accept_error(&Error::from_raw_os_error(4)));

    // ECONNABORTED
    assert!(is_recoverable_accept_error(&Error::from(
        ErrorKind::ConnectionAborted
    )));
    assert!(is_recoverable_accept_error(&Error::from_raw_os_error(103)));

    // EMFILE
    assert!(is_recoverable_accept_error(&Error::from_raw_os_error(24)));

    // ENFILE
    assert!(is_recoverable_accept_error(&Error::from_raw_os_error(23)));

    // Non-recoverable persistent errors
    assert!(!is_recoverable_accept_error(&Error::from_raw_os_error(9))); // EBADF
    assert!(!is_recoverable_accept_error(&Error::from_raw_os_error(22))); // EINVAL
    assert!(!is_recoverable_accept_error(&Error::from_raw_os_error(88))); // ENOTSOCK
    assert!(!is_recoverable_accept_error(&Error::from(
        ErrorKind::PermissionDenied
    )));
}

#[test]
fn test_server_continues_accepting_after_emfile() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let server = Server::http("127.0.0.1:0").expect("start server");
    let addr = server.server_addr().to_ip().expect("ip addr");

    // Inject EMFILE (24) on accept
    inject_accept_error_once(24);

    // Trigger accept failure
    let _trigger = TcpStream::connect(addr);

    // Wait briefly so the accept loop processes the error and recovers
    std::thread::sleep(Duration::from_millis(50));

    // Send a normal request; the accept loop must still be active and accept it
    let mut client = TcpStream::connect(addr).expect("client connect");
    client
        .write_all(b"GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");

    let rq = server
        .recv_timeout(Duration::from_secs(3))
        .expect("recv result")
        .expect("request received after recoverable accept error");

    assert_eq!(rq.url(), "/test");
    rq.respond(Response::from_string("ok")).expect("respond");
}

#[test]
fn test_server_continues_accepting_after_eintr_and_econnaborted() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let server = Server::http("127.0.0.1:0").expect("start server");
    let addr = server.server_addr().to_ip().expect("ip addr");

    // Inject ECONNABORTED (103)
    inject_accept_error_once(103);
    let _trigger1 = TcpStream::connect(addr);
    std::thread::sleep(Duration::from_millis(50));

    // Inject EINTR (4)
    inject_accept_error_once(4);
    let _trigger2 = TcpStream::connect(addr);
    std::thread::sleep(Duration::from_millis(50));

    let mut client = TcpStream::connect(addr).expect("client connect");
    client
        .write_all(b"GET /retry HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");

    let rq = server
        .recv_timeout(Duration::from_secs(3))
        .expect("recv result")
        .expect("request received after EINTR and ECONNABORTED");

    assert_eq!(rq.url(), "/retry");
    rq.respond(Response::from_string("ok")).expect("respond");
}

#[test]
fn test_server_breaks_accept_loop_on_persistent_error() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let server = Server::http("127.0.0.1:0").expect("start server");
    let addr = server.server_addr().to_ip().expect("ip addr");

    // Inject non-recoverable error EBADF (9)
    inject_accept_error_once(9);
    let _trigger = TcpStream::connect(addr);
    std::thread::sleep(Duration::from_millis(50));

    // The accept loop must have broken and queued the error
    let res = server.recv_timeout(Duration::from_secs(1));
    assert!(
        res.is_err(),
        "persistent error must break accept loop and return Err"
    );
}
