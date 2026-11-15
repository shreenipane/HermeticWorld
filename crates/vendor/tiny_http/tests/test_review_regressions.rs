use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tiny_http::{Response, Server, StatusCode, MAX_CONNECTIONS, MAX_IDENTITY_BUFFER_BYTES};

const WAIT: Duration = Duration::from_secs(5);

#[test]
fn failed_identity_response_closes_before_pipelined_response() {
    let server = Server::http("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(server.server_addr().to_ip().unwrap()).unwrap();
    client.set_read_timeout(Some(WAIT)).unwrap();
    client.write_all(b"GET /first HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET /second HTTP/1.0\r\nConnection: close\r\n\r\n").unwrap();
    let first = server.recv_timeout(WAIT).unwrap().unwrap();
    let second = server.recv_timeout(WAIT).unwrap().unwrap();
    let response = Response::new(StatusCode(200), vec![], io::repeat(b'x').take(MAX_IDENTITY_BUFFER_BYTES as u64 + 1), None, None);
    assert!(first.respond(response).is_err());
    let _ = second.respond(Response::from_string("must not replace first response"));
    let mut bytes = Vec::new();
    match client.take(1024).read_to_end(&mut bytes) {
        Ok(_) => (),
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => (),
        Err(e) => panic!("connection did not close: {}", e),
    }
    assert!(bytes.is_empty(), "later response replaced failed response: {:?}", bytes);
}

#[test]
fn outstanding_requests_and_extracted_writers_hold_connection_slots() {
    let server = Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    let mut clients = Vec::new();
    let mut requests = Vec::new();
    let mut writers = Vec::new();
    for i in 0..MAX_CONNECTIONS {
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
        let request = server.recv_timeout(WAIT).unwrap().expect("slot available");
        if i % 2 == 0 {
            requests.push(request);
        } else {
            writers.push(request.into_writer());
        }
        clients.push(client);
    }
    let mut overflow = TcpStream::connect(addr).unwrap();
    overflow.set_read_timeout(Some(WAIT)).unwrap();
    overflow.write_all(b"GET /overflow HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
    match overflow.read(&mut [0; 1]) {
        Ok(0) => (),
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => (),
        other => panic!("connection cap did not refuse excess connection: {:?}", other),
    }
    drop(requests);
    drop(writers);
    drop(clients);
    let mut recovered = TcpStream::connect(addr).unwrap();
    recovered.write_all(b"GET /recovered HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
    let request = server.recv_timeout(WAIT).unwrap().expect("slots released");
    assert_eq!(request.url(), "/recovered");
    request.close_without_response();
}

/// Gateway startup race (2026-11-14): a connection accepted before the
/// application installs deadlines was read with none, forever. Deadlines given
/// at construction apply to the very first connection.
#[test]
fn deadlines_given_at_construction_bound_the_first_connection() {
    use std::time::Instant;
    use tiny_http::RequestDeadlines;
    let deadlines = RequestDeadlines {
        head: Some(Duration::from_millis(50)),
        body: Some(Duration::from_millis(50)),
    };
    let server = Server::http_with_deadlines("127.0.0.1:0", deadlines).unwrap();
    let mut client = TcpStream::connect(server.server_addr().to_ip().unwrap()).unwrap();
    client.set_read_timeout(Some(WAIT)).unwrap();
    // Incomplete request line, sent before anything calls set_request_deadlines.
    client.write_all(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\n").unwrap();
    let start = Instant::now();
    let mut buf = [0u8; 64];
    let n = client.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "connection must be closed without a response");
    assert!(start.elapsed() < Duration::from_secs(3), "head deadline was not in force");
    assert!(server.try_recv().unwrap().is_none());
}

/// Deadlines installed after a connection began waiting for its request head
/// must still bound that request's body (the gateway installs them in its loop).
#[test]
fn body_deadline_installed_while_head_is_pending_still_applies() {
    use tiny_http::RequestDeadlines;
    let server = Server::http("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(server.server_addr().to_ip().unwrap()).unwrap();
    client.write_all(b"POST / HTTP/1.1\r\n").unwrap();
    // Give the connection thread time to start reading the head with no deadlines.
    std::thread::sleep(Duration::from_millis(300));
    server.set_request_deadlines(RequestDeadlines {
        head: None,
        body: Some(Duration::from_millis(200)),
    });
    client
        .write_all(b"Host: x\r\nContent-Length: 5000\r\n\r\n{")
        .unwrap();
    let mut request = server.recv_timeout(WAIT).unwrap().expect("request");
    // Read on a helper thread so a missing deadline fails the test, not hangs it.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut body = Vec::new();
        let _ = tx.send(request.as_reader().read_to_end(&mut body).is_err());
    });
    match rx.recv_timeout(Duration::from_secs(3)) {
        Ok(failed) => assert!(failed, "stalled body read did not fail"),
        Err(_) => panic!("body read outlived its deadline"),
    }
    drop(client);
}
