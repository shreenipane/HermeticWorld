use std::io::Error as IoError;
use std::io::{self, Cursor, ErrorKind, Read, Write};

use std::fmt;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::str::FromStr;

use std::sync::mpsc::Sender;

use crate::connection::Connection;
use crate::util::{EqualReader, FusedReader};
use crate::{HTTPVersion, Header, Method, Response};
use chunked_transfer::Decoder;

/// Represents an HTTP request made by a client.
///
/// A `Request` object is what is produced by the server, and is your what
/// your code must analyse and answer.
///
/// This object implements the `Send` trait, therefore you can dispatch your requests to
/// worker threads.
///
/// # Pipelining
///
/// If a client sends multiple requests in a row (without waiting for the response), then you will
/// get multiple `Request` objects simultaneously. This is called *requests pipelining*.
/// Tiny-http automatically reorders the responses so that you don't need to worry about the order
/// in which you call `respond` or `into_writer`.
///
/// This mechanic is disabled if:
///
///  - The body of a request is large enough (handling requires pipelining requires storing the
///    body of the request in a buffer ; if the body is too big, tiny-http will avoid doing that)
///  - A request sends a `Expect: 100-continue` header (which means that the client waits to
///    know whether its body will be processed before sending it)
///  - A request sends a `Connection: close` header or `Connection: upgrade` header (used for
///    websockets), which indicates that this is the last request that will be received on this
///    connection
///
/// # Automatic cleanup
///
/// HERMETIC PATCH: if a `Request` object is destroyed without `into_writer` or `respond` being
/// called, the connection is shut down without any response (upstream wrote an empty 500 reply
/// stamped with the host's `Date`).
///
/// # Testing
///
/// If you want to build fake requests to test your server, use [`TestRequest`](crate::test::TestRequest).
pub struct Request {
    // where to read the body from
    data_reader: Option<Box<dyn Read + Send + 'static>>,

    // if this writer is empty, then the request has been answered
    response_writer: Option<Box<dyn Write + Send + 'static>>,

    remote_addr: Option<SocketAddr>,

    // true if HTTPS, false if HTTP
    secure: bool,

    method: Method,

    path: String,

    http_version: HTTPVersion,

    headers: Vec<Header>,

    body_length: Option<usize>,

    // true if a `100 Continue` response must be sent when `as_reader()` is called
    must_send_continue: bool,

    // If Some, a message must be sent after responding
    notify_when_responded: Option<Sender<()>>,

    // HERMETIC PATCH: duplicate handle on the client socket (None for test requests).
    peer_probe: Option<Connection>,

    // HERMETIC PATCH: the connection's absolute read deadline (None for test requests).
    read_deadline: Option<crate::util::refined_tcp_stream::DeadlineCell>,

    // HERMETIC PATCH: the connection's absolute write deadline (None for test requests).
    write_deadline: Option<crate::util::refined_tcp_stream::DeadlineCell>,
}

struct NotifyOnDrop<R> {
    sender: Sender<()>,
    inner: R,
}

impl<R: Read> Read for NotifyOnDrop<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}
impl<R: Write> Write for NotifyOnDrop<R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl<R> Drop for NotifyOnDrop<R> {
    fn drop(&mut self) {
        self.sender.send(()).unwrap();
    }
}

/// Error that can happen when building a `Request` object.
#[derive(Debug)]
pub enum RequestCreationError {
    /// The client sent an `Expect` header that was not recognized by tiny-http.
    ExpectationFailed,

    /// Error while reading data from the socket during the creation of the `Request`.
    CreationIoError(IoError),
}

impl From<IoError> for RequestCreationError {
    fn from(err: IoError) -> RequestCreationError {
        RequestCreationError::CreationIoError(err)
    }
}

/// Builds a new request.
///
/// After the request line and headers have been read from the socket, a new `Request` object
/// is built.
///
/// You must pass a `Read` that will allow the `Request` object to read from the incoming data.
/// It is the responsibility of the `Request` to read only the data of the request and not further.
///
/// The `Write` object will be used by the `Request` to write the response.
#[allow(clippy::too_many_arguments)]
pub fn new_request<R, W>(
    secure: bool,
    method: Method,
    path: String,
    version: HTTPVersion,
    headers: Vec<Header>,
    remote_addr: Option<SocketAddr>,
    mut source_data: R,
    writer: W,
) -> Result<Request, RequestCreationError>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    // finding the transfer-encoding header
    let transfer_encoding = headers
        .iter()
        .find(|h: &&Header| h.field.equiv("Transfer-Encoding"))
        .map(|h| h.value.clone());

    // finding the content-length header
    let content_length = if transfer_encoding.is_some() {
        // if transfer-encoding is specified, the Content-Length
        // header must be ignored (RFC2616 #4.4)
        None
    } else {
        headers
            .iter()
            .find(|h: &&Header| h.field.equiv("Content-Length"))
            .and_then(|h| FromStr::from_str(h.value.as_str()).ok())
    };

    // true if the client sent a `Expect: 100-continue` header
    let expects_continue = {
        match headers
            .iter()
            .find(|h: &&Header| h.field.equiv("Expect"))
            .map(|h| h.value.as_str())
        {
            None => false,
            Some(v) if v.eq_ignore_ascii_case("100-continue") => true,
            _ => return Err(RequestCreationError::ExpectationFailed),
        }
    };

    // true if the client sent a `Connection: upgrade` header
    let connection_upgrade = {
        match headers
            .iter()
            .find(|h: &&Header| h.field.equiv("Connection"))
            .map(|h| h.value.as_str())
        {
            Some(v) if v.to_ascii_lowercase().contains("upgrade") => true,
            _ => false,
        }
    };

    // we wrap `source_data` around a reading whose nature depends on the transfer-encoding and
    // content-length headers
    let reader = if connection_upgrade {
        // if we have a `Connection: upgrade`, always keeping the whole reader
        Box::new(source_data) as Box<dyn Read + Send + 'static>
    } else if let Some(content_length) = content_length {
        if content_length == 0 {
            Box::new(io::empty()) as Box<dyn Read + Send + 'static>
        } else if content_length <= 1024 && !expects_continue {
            // if the content-length is small enough, we just read everything into a buffer

            let mut buffer = vec![0; content_length];
            let mut offset = 0;

            while offset != content_length {
                let read = source_data.read(&mut buffer[offset..])?;
                if read == 0 {
                    // the socket returned EOF, but we were before the expected content-length
                    // aborting
                    let info = "Connection has been closed before we received enough data";
                    let err = IoError::new(ErrorKind::ConnectionAborted, info);
                    return Err(RequestCreationError::CreationIoError(err));
                }

                offset += read;
            }

            Box::new(Cursor::new(buffer)) as Box<dyn Read + Send + 'static>
        } else {
            let (data_reader, _) = EqualReader::new(source_data, content_length); // TODO:
            Box::new(FusedReader::new(data_reader)) as Box<dyn Read + Send + 'static>
        }
    } else if transfer_encoding.is_some() {
        // if a transfer-encoding was specified, then "chunked" is ALWAYS applied
        // over the message (RFC2616 #3.6)
        Box::new(FusedReader::new(Decoder::new(source_data))) as Box<dyn Read + Send + 'static>
    } else {
        // if we have neither a Content-Length nor a Transfer-Encoding,
        // assuming that we have no data
        // TODO: could also be multipart/byteranges
        Box::new(io::empty()) as Box<dyn Read + Send + 'static>
    };

    Ok(Request {
        data_reader: Some(reader),
        response_writer: Some(Box::new(writer) as Box<dyn Write + Send + 'static>),
        remote_addr,
        secure,
        method,
        path,
        http_version: version,
        headers,
        body_length: content_length,
        must_send_continue: expects_continue,
        notify_when_responded: None,
        peer_probe: None,
        read_deadline: None,
        write_deadline: None,
    })
}

impl Request {
    /// Returns true if the request was made through HTTPS.
    #[inline]
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// Returns the method requested by the client (eg. `GET`, `POST`, etc.).
    #[inline]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the resource requested by the client.
    #[inline]
    pub fn url(&self) -> &str {
        &self.path
    }

    /// Returns a list of all headers sent by the client.
    #[inline]
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// Returns the HTTP version of the request.
    #[inline]
    pub fn http_version(&self) -> &HTTPVersion {
        &self.http_version
    }

    /// Returns the length of the body in bytes.
    ///
    /// Returns `None` if the length is unknown.
    #[inline]
    pub fn body_length(&self) -> Option<usize> {
        self.body_length
    }

    /// Returns the address of the client that sent this request.
    ///
    /// The address is always `Some` for TCP listeners, but always `None` for UNIX listeners
    /// (as the remote address of a UNIX client is almost always unnamed).
    ///
    /// Note that this is gathered from the socket. If you receive the request from a proxy,
    /// this function will return the address of the proxy and not the address of the actual
    /// user.
    #[inline]
    pub fn remote_addr(&self) -> Option<&SocketAddr> {
        self.remote_addr.as_ref()
    }

    /// Sends a response with a `Connection: upgrade` header, then turns the `Request` into a `Stream`.
    ///
    /// The main purpose of this function is to support websockets.
    /// If you detect that the request wants to use some kind of protocol upgrade, you can
    ///  call this function to obtain full control of the socket stream.
    ///
    /// If you call this on a non-websocket request, tiny-http will wait until this `Stream` object
    ///  is destroyed before continuing to read or write on the socket. Therefore you should always
    ///  destroy it as soon as possible.
    pub fn upgrade<R: Read>(
        mut self,
        protocol: &str,
        response: Response<R>,
    ) -> Box<dyn ReadWrite + Send> {
        use crate::util::CustomStream;

        response
            .raw_print(
                self.response_writer.as_mut().unwrap().by_ref(),
                self.http_version.clone(),
                &self.headers,
                false,
                Some(protocol),
            )
            .ok(); // TODO: unused result

        self.response_writer.as_mut().unwrap().flush().ok(); // TODO: unused result

        let stream = CustomStream::new(self.extract_reader_impl(), self.extract_writer_impl());
        if let Some(sender) = self.notify_when_responded.take() {
            let stream = NotifyOnDrop {
                sender,
                inner: stream,
            };
            Box::new(stream) as Box<dyn ReadWrite + Send>
        } else {
            Box::new(stream) as Box<dyn ReadWrite + Send>
        }
    }

    /// Allows to read the body of the request.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # extern crate rustc_serialize;
    /// # extern crate tiny_http;
    /// # use rustc_serialize::json::Json;
    /// # use std::io::Read;
    /// # fn get_content_type(_: &tiny_http::Request) -> &'static str { "" }
    /// # fn main() {
    /// # let server = tiny_http::Server::http("0.0.0.0:0").unwrap();
    /// let mut request = server.recv().unwrap();
    ///
    /// if get_content_type(&request) == "application/json" {
    ///     let mut content = String::new();
    ///     request.as_reader().read_to_string(&mut content).unwrap();
    ///     let json: Json = content.parse().unwrap();
    /// }
    /// # }
    /// ```
    ///
    /// If the client sent a `Expect: 100-continue` header with the request, calling this
    ///  function will send back a `100 Continue` response.
    #[inline]
    pub fn as_reader(&mut self) -> &mut dyn Read {
        if self.must_send_continue {
            // HERMETIC PATCH: upstream sent the interim reply through `Response::raw_print`,
            // which added the host's `Date` and a `Server` header. Send the bare status line
            // instead: an interim 1xx reply needs no header fields (RFC 9110 section 15.2).
            if let Some(writer) = self.response_writer.as_mut() {
                let line = format!("HTTP/{} 100 Continue\r\n\r\n", self.http_version);
                writer.write_all(line.as_bytes()).ok();
                writer.flush().ok();
            }
            self.must_send_continue = false;
        }

        self.data_reader.as_mut().unwrap()
    }

    /// Turns the `Request` into a writer.
    ///
    /// The writer has a raw access to the stream to the user.
    /// This function is useful for things like CGI.
    ///
    /// Note that the destruction of the `Writer` object may trigger
    /// some events. For exemple if a client has sent multiple requests and the requests
    /// have been processed in parallel, the destruction of a writer will trigger
    /// the writing of the next response.
    /// Therefore you should always destroy the `Writer` as soon as possible.
    #[inline]
    pub fn into_writer(mut self) -> Box<dyn Write + Send + 'static> {
        let writer = self.extract_writer_impl();
        if let Some(sender) = self.notify_when_responded.take() {
            let writer = NotifyOnDrop {
                sender,
                inner: writer,
            };
            Box::new(writer) as Box<dyn Write + Send + 'static>
        } else {
            writer
        }
    }

    /// Extract the response `Writer` object from the Request, dropping this `Writer` has the same side effects
    /// as the object returned by `into_writer` above.
    ///
    /// This may only be called once on a single request.
    fn extract_writer_impl(&mut self) -> Box<dyn Write + Send + 'static> {
        use std::mem;

        assert!(self.response_writer.is_some());

        let mut writer = None;
        mem::swap(&mut self.response_writer, &mut writer);
        writer.unwrap()
    }

    /// Extract the body `Reader` object from the Request.
    ///
    /// This may only be called once on a single request.
    fn extract_reader_impl(&mut self) -> Box<dyn Read + Send + 'static> {
        use std::mem;

        assert!(self.data_reader.is_some());

        let mut reader = None;
        mem::swap(&mut self.data_reader, &mut reader);
        reader.unwrap()
    }

    /// Sends a response to this request.
    #[inline]
    pub fn respond<R>(mut self, response: Response<R>) -> Result<(), IoError>
    where
        R: Read,
    {
        let res = self.respond_impl(response);
        if let Some(sender) = self.notify_when_responded.take() {
            sender.send(()).unwrap();
        }
        res
    }

    fn respond_impl<R>(&mut self, response: Response<R>) -> Result<(), IoError>
    where
        R: Read,
    {
        let mut writer = self.extract_writer_impl();

        let do_not_send_body = self.method == Method::Head;

        let result = response.raw_print(
            writer.by_ref(),
            self.http_version.clone(),
            &self.headers,
            do_not_send_body,
            None,
        ).and_then(|()| writer.flush());
        if result.is_err() {
            // Close before releasing the sequential writer: otherwise a later response
            // could be emitted in place of this failed or partial response.
            self.shutdown_without_response();
        }
        Self::ignore_client_closing_errors(result)
    }

    fn ignore_client_closing_errors(result: io::Result<()>) -> io::Result<()> {
        result.or_else(|err| match err.kind() {
            ErrorKind::BrokenPipe => Ok(()),
            ErrorKind::ConnectionAborted => Ok(()),
            ErrorKind::ConnectionRefused => Ok(()),
            ErrorKind::ConnectionReset => Ok(()),
            _ => Err(err),
        })
    }

    pub(crate) fn with_notify_sender(mut self, sender: Sender<()>) -> Self {
        self.notify_when_responded = Some(sender);
        self
    }

    /// HERMETIC PATCH: attaches a duplicate handle on the client socket.
    pub(crate) fn with_peer_probe(mut self, probe: Option<Connection>) -> Self {
        self.peer_probe = probe;
        self
    }

    pub(crate) fn with_write_deadline_cell(
        mut self,
        cell: crate::util::refined_tcp_stream::DeadlineCell,
    ) -> Self {
        self.write_deadline = Some(cell);
        self
    }

    /// HERMETIC PATCH: a handle on the connection's absolute write deadline, usable while the
    /// response is being written (the handle outlives `respond`). `None` for test requests.
    pub fn write_deadline(&self) -> Option<crate::util::refined_tcp_stream::DeadlineHandle> {
        self.write_deadline
            .as_ref()
            .map(|c| crate::util::refined_tcp_stream::DeadlineHandle(c.clone()))
    }

    pub(crate) fn with_read_deadline_cell(
        mut self,
        cell: crate::util::refined_tcp_stream::DeadlineCell,
    ) -> Self {
        self.read_deadline = Some(cell);
        self
    }

    /// HERMETIC PATCH: replaces the absolute deadline for reading this request's body (and for
    /// discarding an unread body). `None` removes it. Set by the server from
    /// `Server::set_request_deadlines` when the headers arrive.
    pub fn set_read_deadline(&self, deadline: Option<std::time::Instant>) {
        if let Some(cell) = self.read_deadline.as_ref() {
            match cell.lock() {
                Ok(mut g) => *g = deadline,
                Err(p) => *p.into_inner() = deadline,
            }
        }
    }

    /// HERMETIC PATCH: returns a new handle on the client's TCP socket, or `None` for
    /// Unix-socket and test requests or if the handle cannot be duplicated.
    ///
    /// Intended for watching the connection while a long response is produced, e.g. with
    /// `TcpStream::peek`, which returns `Ok(0)` once the client has closed the connection.
    /// Do not read from it, and do not change its blocking mode or timeouts: they are shared
    /// with the socket this library reads the next request from.
    pub fn try_clone_peer_tcp_stream(&self) -> Option<TcpStream> {
        match self.peer_probe.as_ref() {
            Some(Connection::Tcp(s)) => s.try_clone().ok(),
            _ => None,
        }
    }

    /// HERMETIC PATCH: closes the connection without writing any response (any request
    /// pipelined after this one on the same connection is lost too).
    pub fn close_without_response(mut self) {
        self.shutdown_without_response();
    }

    fn shutdown_without_response(&mut self) {
        if let Some(probe) = self.peer_probe.as_ref() {
            probe.shutdown(Shutdown::Both).ok();
        }
        // Dropping the writer unblocks any pipelined response queued after this one; the
        // socket is already shut down, so nothing more reaches the client.
        self.response_writer = None;
        if let Some(sender) = self.notify_when_responded.take() {
            sender.send(()).ok();
        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            formatter,
            "Request({} {} from {:?})",
            self.method, self.path, self.remote_addr
        )
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        // HERMETIC PATCH: upstream wrote an empty 500 response here (with the host's
        // `Date`); close the connection without any response instead.
        if self.response_writer.is_some() {
            self.shutdown_without_response();
        }
    }
}

/// Dummy trait that regroups the `Read` and `Write` traits.
///
/// Automatically implemented on all types that implement both `Read` and `Write`.
pub trait ReadWrite: Read + Write {}
impl<T> ReadWrite for T where T: Read + Write {}

#[cfg(test)]
mod tests {
    use super::Request;

    #[test]
    fn failed_response_flush_shuts_down_connection() {
        use std::io::{self, Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        struct FlushFails;
        impl Write for FlushFails {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("injected flush failure"))
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (socket, _) = listener.accept().unwrap();
        // A pipelined request can still own another handle after this Request is dropped.
        let _retained = socket.try_clone().unwrap();
        let request = super::new_request(false, crate::Method::Get, "/".into(),
            crate::HTTPVersion(1, 1), vec![], None, io::empty(), FlushFails)
            .unwrap().with_peer_probe(Some(crate::connection::Connection::from(socket)));
        assert!(request.respond(crate::Response::from_string("body")).is_err());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0, "flush failure must close the connection");
    }

    #[test]
    fn must_be_send() {
        #![allow(dead_code)]
        fn f<T: Send>(_: &T) {}
        fn bar(rq: &Request) {
            f(rq);
        }
    }
}
