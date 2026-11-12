# Vendored tiny_http

- Upstream: `tiny_http` 0.12.0 from crates.io (https://github.com/tiny-http/tiny-http),
  checksum `389915df6413a2e74fb181895f933386023c71110878cd0825588928e64cdc82`.
- License: MIT OR Apache-2.0; `LICENSE-MIT` and `LICENSE-APACHE` are the upstream files.
- Why: the Hermetic gateway must never show the agent the host's clock. Upstream tiny_http adds
  `Date: <host SystemTime::now()>` and `Server: tiny-http (Rust)` to every response, and writes
  several replies on its own (400, 408, 417, 505, `100 Continue`, 500 on a dropped request) that
  the application never sees. Approved by the owner on 2026-11-12: same crate and version,
  vendored in-tree and patched; not a new dependency.

Every change is marked `HERMETIC PATCH` in the source.

## Packaging changes

- `Cargo.toml` rewritten: same name, version, dependencies and dependency versions
  (`ascii 1.0`, `chunked_transfer 1`, `log 0.4.4`, `httpdate 1.0.2`), `publish = false`.
  Removed: the `ssl`, `ssl-openssl`, `ssl-rustls` features and their optional dependencies
  (`openssl`, `rustls`, `rustls-pemfile`, `zeroize`), and the dev-dependencies (`rustc-serialize`,
  `sha1`, `fdlimit`); otherwise they would enter `Cargo.lock`. The SSL source files are kept
  unchanged but are never compiled; `check-cfg` declares their feature names.
- `doctest = false` (upstream doc examples need the removed `rustc-serialize`).
- Not copied: `benches/`, `examples/`, `tests/` (need the removed dev-dependencies), CI files.
- Lint settings for this crate only: rustc `dead_code` and `unused_imports` allowed, all clippy
  lints allowed, and `rustfmt.toml` disables formatting, so upstream code stays as it was.
  The workspace settings are unchanged.

## Code changes

1. `src/response.rs` `Response::raw_print`: no longer inserts a `Date` header (host time) or a
   `Server` header; `build_date_header` and the `httpdate`/`SystemTime` imports removed. The
   application supplies any `Date` it wants.
2. `src/client.rs` `ClientConnection::next`: a malformed request line or header (was 400), a read
   timeout (was 408), an unrecognised `Expect` (was 417) and an HTTP version above 1.1 such as an
   HTTP/2 preface (was 505, and the connection kept going) now close the connection without
   writing anything.
3. `src/client.rs`: request and header lines are limited to 16 KiB and a request to 128 header
   lines (upstream buffered a line without limit); more closes the connection.
4. `src/client.rs`: a client that resets the connection before `peer_addr` succeeds no longer
   panics the connection thread (`unwrap` replaced).
5. `src/request.rs` `Request::as_reader`: the `100 Continue` interim reply is written as a bare
   status line, `HTTP/1.x 100 Continue\r\n\r\n`, with no header fields.
6. `src/request.rs` `Drop for Request`: a request dropped without a response shuts the
   connection down without writing anything (was an empty 500 reply with the host `Date`).
7. `src/request.rs`: new `Request::try_clone_peer_tcp_stream()` (a duplicate handle on the
   client socket, for disconnect detection with `TcpStream::peek`) and
   `Request::close_without_response()`; `ClientConnection` keeps a duplicate socket handle
   (`probe`) and attaches one to every request.
8. `src/lib.rs`: at most `MAX_CONNECTIONS` (256) client connections are served at once; a
   connection over the cap is closed immediately without a response.
9. `src/util/equal_reader.rs` `Drop for EqualReader`: discards the unread rest of a body through a
   fixed 8 KiB buffer and at most 1 MiB (upstream allocated a buffer as large as the declared
   `Content-Length`, which aborts the process for a huge value).
10. `src/util/refined_tcp_stream.rs`, `src/client.rs`, `src/request.rs`, `src/lib.rs`,
    `src/connection.rs`: absolute read deadlines. `Server::set_request_deadlines` sets
    `RequestDeadlines { head, body }` (default: none). Before every socket read the read half
    sets the socket timeout to the time left until the connection's current deadline, so slow
    reads cannot outlast it: `head` covers the wait for a request line and headers (a timeout
    closes the connection without a response), `body` covers reading or discarding the body.
    `Request::set_read_deadline` lets the application lift or move the body deadline.
11. `src/response.rs` `choose_transfer_encoding`: a client's `TE: identity` is ignored when the
    response length is unknown (chunked is always acceptable to an HTTP/1.1 client); upstream
    honoured it and then buffered the whole, possibly endless, body.
12. `src/response.rs` `Response::raw_print`: the unknown-length identity path (HTTP/1.0 clients)
    buffers at most `MAX_IDENTITY_BUFFER_BYTES` (8 MiB); a longer body fails before anything is
    written and the connection closes without a response (upstream: `read_to_end`, no limit).
