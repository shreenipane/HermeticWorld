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
