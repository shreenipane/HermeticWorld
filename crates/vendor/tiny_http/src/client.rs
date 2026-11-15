use ascii::AsciiString;

use std::io::Error as IoError;
use std::io::Result as IoResult;
use std::io::{BufReader, BufWriter, ErrorKind, Read};

use std::net::SocketAddr;
use std::str::FromStr;

use crate::common::{HTTPVersion, Method};
use crate::connection::Connection;
use crate::util::refined_tcp_stream::DeadlineCell;
use crate::util::RefinedTcpStream;
use crate::RequestDeadlines;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use crate::util::{SequentialReader, SequentialReaderBuilder, SequentialWriterBuilder};
use crate::Request;

/// A ClientConnection is an object that will store a socket to a client
/// and return Request objects.
pub struct ClientConnection {
    // address of the client
    remote_addr: IoResult<Option<SocketAddr>>,

    // sequence of Readers to the stream, so that the data is not read in
    //  the wrong order
    source: SequentialReaderBuilder<BufReader<RefinedTcpStream>>,

    // sequence of Writers to the stream, to avoid writing response #2 before
    //  response #1
    sink: SequentialWriterBuilder<BufWriter<RefinedTcpStream>>,

    // Reader to read the next header from
    next_header_source: SequentialReader<BufReader<RefinedTcpStream>>,

    // set to true if we know that the previous request is the last one
    no_more_requests: bool,

    // true if the connection goes through SSL
    secure: bool,

    // HERMETIC PATCH: a duplicate handle on the client socket, handed to each `Request` so
    // the application can watch for a client disconnect and so an unanswered request can
    // close the connection instead of writing a self-generated reply.
    probe: Option<Connection>,

    // HERMETIC PATCH: the connection's absolute read deadline, and where its values come from.
    read_deadline: DeadlineCell,
    write_deadline: DeadlineCell,
    deadlines: Arc<Mutex<RequestDeadlines>>,
}

/// HERMETIC PATCH: longest request line or header line accepted (bytes, without CRLF).
/// Longer lines close the connection, so a client cannot grow the buffer without bound.
pub(crate) const MAX_HEADER_LINE_BYTES: usize = 16 * 1024;

/// HERMETIC PATCH: most header lines accepted in one request; more closes the connection.
pub(crate) const MAX_HEADER_COUNT: usize = 128;

/// Error that can happen when reading a request.
#[derive(Debug)]
enum ReadError {
    WrongRequestLine,
    WrongHeader(HTTPVersion),
    /// the client sent an unrecognized `Expect` header
    ExpectationFailed(HTTPVersion),
    ReadIoError(IoError),
}

impl ClientConnection {
    /// Creates a new `ClientConnection` that takes ownership of the `TcpStream`.
    pub fn new(
        mut write_socket: RefinedTcpStream,
        mut read_socket: RefinedTcpStream,
        probe: Option<Connection>,
        deadlines: Arc<Mutex<RequestDeadlines>>,
    ) -> ClientConnection {
        let remote_addr = read_socket.peer_addr();
        let secure = read_socket.secure();
        let read_deadline: DeadlineCell = Arc::new(Mutex::new(None));
        read_socket.set_deadline_cell(read_deadline.clone());
        let write_deadline: DeadlineCell = Arc::new(Mutex::new(None));
        write_socket.set_write_deadline_cell(write_deadline.clone());

        let mut source = SequentialReaderBuilder::new(BufReader::with_capacity(1024, read_socket));
        let first_header = source.next().unwrap();

        ClientConnection {
            source,
            sink: SequentialWriterBuilder::new(BufWriter::with_capacity(1024, write_socket)),
            remote_addr,
            next_header_source: first_header,
            no_more_requests: false,
            secure,
            probe,
            read_deadline,
            write_deadline,
            deadlines,
        }
    }

    /// true if the connection is HTTPS
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// Reads the next line from self.next_header_source.
    ///
    /// Reads until `CRLF` is reached. The next read will start
    ///  at the first byte of the new line.
    fn read_next_line(&mut self) -> IoResult<AsciiString> {
        let mut buf = Vec::new();
        let mut prev_byte_was_cr = false;

        loop {
            let byte = self.next_header_source.by_ref().bytes().next();

            let byte = match byte {
                Some(b) => b?,
                None => return Err(IoError::new(ErrorKind::ConnectionAborted, "Unexpected EOF")),
            };

            if byte == b'\n' && prev_byte_was_cr {
                buf.pop(); // removing the '\r'
                return AsciiString::from_ascii(buf)
                    .map_err(|_| IoError::new(ErrorKind::InvalidInput, "Header is not in ASCII"));
            }

            prev_byte_was_cr = byte == b'\r';

            buf.push(byte);

            // HERMETIC PATCH: bound the line length (upstream grew `buf` without limit).
            if buf.len() > MAX_HEADER_LINE_BYTES + 1 {
                return Err(IoError::new(ErrorKind::InvalidData, "Header line too long"));
            }
        }
    }

    /// Reads a request from the stream.
    /// Blocks until the header has been read.
    fn current_deadlines(&self) -> RequestDeadlines {
        match self.deadlines.lock() {
            Ok(g) => *g,
            Err(p) => *p.into_inner(),
        }
    }

    fn set_read_deadline(&self, after: Option<std::time::Duration>) {
        let value = after.map(|d| Instant::now() + d);
        match self.read_deadline.lock() {
            Ok(mut g) => *g = value,
            Err(p) => *p.into_inner() = value,
        }
    }

    fn prepare_head_deadline(&mut self, after: Option<std::time::Duration>) {
        // Each request gets its own cell: a retained Request may still change its body
        // deadline after the stream has already moved on to the next header reader.
        self.read_deadline = Arc::new(Mutex::new(None));
        let cell = self.read_deadline.clone();
        // The previous request can still own the body reader. Arm the next header
        // deadline only when the existing sequential hand-off grants us the stream.
        self.next_header_source.on_start(move |reader| {
            let value = after.map(|d| Instant::now() + d);
            match cell.lock() {
                Ok(mut g) => *g = value,
                Err(p) => *p.into_inner() = value,
            }
            reader.get_mut().set_deadline_cell(cell);
        });
    }

    fn read(&mut self) -> Result<Request, ReadError> {
        // HERMETIC PATCH: the request line and headers (including any idle wait before them)
        // must arrive within `head`.
        let deadlines = self.current_deadlines();
        self.prepare_head_deadline(deadlines.head);
        let (method, path, version, headers) = {
            // reading the request line
            let (method, path, version) = {
                let line = self.read_next_line().map_err(ReadError::ReadIoError)?;

                parse_request_line(
                    line.as_str().trim(), // TODO: remove this conversion
                )?
            };

            // getting all headers
            let headers = {
                let mut headers = Vec::new();
                loop {
                    let line = self.read_next_line().map_err(ReadError::ReadIoError)?;

                    if line.is_empty() {
                        break;
                    };
                    // HERMETIC PATCH: bound the number of header lines.
                    if headers.len() >= MAX_HEADER_COUNT {
                        return Err(ReadError::WrongHeader(version));
                    }
                    headers.push(match FromStr::from_str(line.as_str().trim()) {
                        // TODO: remove this conversion
                        Ok(h) => h,
                        _ => return Err(ReadError::WrongHeader(version)),
                    });
                }

                headers
            };

            (method, path, version, headers)
        };

        // HERMETIC PATCH: the body (and any discarding of an unread body) within `body`.
        // Re-read the configuration: deadlines installed while this connection was
        // already waiting for its request head must still bound the body.
        self.set_read_deadline(self.current_deadlines().body);

        // building the writer for the request
        let writer = self.sink.next().unwrap();

        // follow-up for next potential request
        let mut data_source = self.source.next().unwrap();
        std::mem::swap(&mut self.next_header_source, &mut data_source);

        // building the next reader
        let request = crate::request::new_request(
            self.secure,
            method,
            path,
            version.clone(),
            headers,
            // HERMETIC PATCH: upstream unwrapped here; a client that resets the connection
            // before `peer_addr` succeeds made that panic.
            self.remote_addr.as_ref().ok().copied().flatten(),
            data_source,
            writer,
        )
        .map_err(|e| {
            use crate::request;
            match e {
                request::RequestCreationError::CreationIoError(e) => ReadError::ReadIoError(e),
                request::RequestCreationError::ExpectationFailed => {
                    ReadError::ExpectationFailed(version)
                }
            }
        })?;

        // HERMETIC PATCH: attach a duplicate socket handle (see `probe`).
        let request = request
            .with_peer_probe(self.probe.as_ref().and_then(|c| c.try_clone().ok()))
            .with_read_deadline_cell(self.read_deadline.clone())
            .with_write_deadline_cell(self.write_deadline.clone());

        // return the request
        Ok(request)
    }
}

impl Iterator for ClientConnection {
    type Item = Request;

    /// Blocks until the next Request is available.
    /// Returns None when no new Requests will come from the client.
    fn next(&mut self) -> Option<Request> {
        // the client sent a "connection: close" header in this previous request
        //  or is using HTTP 1.0, meaning that no new request will come
        if self.no_more_requests {
            return None;
        }

        // HERMETIC PATCH: upstream answered a malformed request line or header (400), a read
        // timeout (408), an unknown `Expect` (417) and HTTP versions above 1.1 (505) itself,
        // through `Response::raw_print`, which stamped them with the host's `Date` and a
        // `Server` header. The application never saw those requests, so it could not control
        // the reply. Each of these cases now closes the connection without writing anything:
        // returning `None` drops this `ClientConnection` and with it the socket.
        {
            let rq = match self.read() {
                Err(ReadError::WrongRequestLine) => return None,
                Err(ReadError::WrongHeader(_)) => return None,
                Err(ReadError::ExpectationFailed(_)) => return None,
                Err(ReadError::ReadIoError(_)) => return None,
                Ok(rq) => rq,
            };

            // checking HTTP version (HERMETIC PATCH: close instead of a 505 reply)
            if *rq.http_version() > (1, 1) {
                rq.close_without_response();
                return None;
            }

            // updating the status of the connection
            let connection_header = rq
                .headers()
                .iter()
                .find(|h| h.field.equiv("Connection"))
                .map(|h| h.value.as_str());

            let lowercase = connection_header.map(|h| h.to_ascii_lowercase());

            match lowercase {
                Some(ref val) if val.contains("close") => self.no_more_requests = true,
                Some(ref val) if val.contains("upgrade") => self.no_more_requests = true,
                Some(ref val)
                    if !val.contains("keep-alive") && *rq.http_version() == HTTPVersion(1, 0) =>
                {
                    self.no_more_requests = true
                }
                None if *rq.http_version() == HTTPVersion(1, 0) => self.no_more_requests = true,
                _ => (),
            };

            // returning the request
            Some(rq)
        }
    }
}

/// Parses a "HTTP/1.1" string.
fn parse_http_version(version: &str) -> Result<HTTPVersion, ReadError> {
    let (major, minor) = match version {
        "HTTP/0.9" => (0, 9),
        "HTTP/1.0" => (1, 0),
        "HTTP/1.1" => (1, 1),
        "HTTP/2.0" => (2, 0),
        "HTTP/3.0" => (3, 0),
        _ => return Err(ReadError::WrongRequestLine),
    };

    Ok(HTTPVersion(major, minor))
}

/// Parses the request line of the request.
/// eg. GET / HTTP/1.1
fn parse_request_line(line: &str) -> Result<(Method, String, HTTPVersion), ReadError> {
    let mut parts = line.split(' ');

    let method = parts.next().and_then(|w| w.parse().ok());
    let path = parts.next().map(ToOwned::to_owned);
    let version = parts.next().and_then(|w| parse_http_version(w).ok());

    method
        .and_then(|method| Some((method, path?, version?)))
        .ok_or(ReadError::WrongRequestLine)
}

#[cfg(test)]
mod test {
    #[test]
    fn next_header_deadline_waits_for_body_reader_handoff() {
        use super::*;
        use std::io::Write;
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        for head in [None, Some(Duration::from_secs(1))] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (socket, _) = listener.accept().unwrap();
            let probe = Connection::from(socket.try_clone().unwrap());
            let (read, write) = RefinedTcpStream::new(Connection::from(socket));
            let deadlines = Arc::new(Mutex::new(RequestDeadlines {
                head,
                body: Some(Duration::from_secs(60)),
            }));
            let mut connection = ClientConnection::new(write, read, Some(probe), deadlines);
            peer.write_all(b"POST /body HTTP/1.1\r\nContent-Length: 2048\r\n\r\n").unwrap();
            peer.write_all(&[b'x'; 2048]).unwrap();
            peer.write_all(b"GET /next HTTP/1.1\r\n\r\n").unwrap();
            let mut request = connection.next().unwrap();
            let body_cell = connection.read_deadline.clone();
            let body_deadline = *body_cell.lock().unwrap();
            assert!(body_deadline.is_some());

            connection.prepare_head_deadline(head);
            assert_eq!(*body_cell.lock().unwrap(), body_deadline,
                "preparing the next head must neither remove nor shorten the body deadline");
            let mut body = Vec::new();
            request.as_reader().read_to_end(&mut body).unwrap();
            assert_eq!(body, [b'x'; 2048]);
            // Reading the body to EOF releases its sequential stream while the Request
            // (and its response writer) remains alive.
            let before_head = Instant::now();
            let mut byte = [0];
            connection.next_header_source.read_exact(&mut byte).unwrap();
            assert_eq!(byte, [b'G']);
            let armed = *connection.read_deadline.lock().unwrap();
            match head {
                None => assert_eq!(armed, None),
                Some(duration) => assert!(armed.unwrap() >= before_head + duration),
            }
            request.set_read_deadline(None);
            assert_eq!(*connection.read_deadline.lock().unwrap(), armed,
                "a completed request must not clear the successor header deadline");
            request.close_without_response();
        }
    }

    #[test]
    fn test_parse_request_line() {
        let (method, path, ver) = super::parse_request_line("GET /hello HTTP/1.1").unwrap();

        assert!(method == crate::Method::Get);
        assert!(path == "/hello");
        assert!(ver == crate::common::HTTPVersion(1, 1));

        assert!(super::parse_request_line("GET /hello").is_err());
        assert!(super::parse_request_line("qsd qsd qsd").is_err());
    }
}
