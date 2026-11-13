
# hermetic-netvm-http

Strict HTTP/1.1 request head parser and forwarding policy filter for the Hermetic World network VM (`TR-NET-3`).

## Guarantees
- `#![forbid(unsafe_code)]`, zero panics (`unwrap`/`expect`/indexing omitted in library code).
- Enforces strict CRLF framing, RFC 9110 `tchar` tokens, ASCII-only header values, and explicit caps (`MAX_HEAD_BYTES = 16 KiB`, `MAX_HEADERS = 100`, `MAX_TARGET_BYTES = 8 KiB`, `MAX_HEADER_NAME_BYTES = 64`, `MAX_HEADER_VALUE_BYTES = 8 KiB`).
- Blocks request smuggling primitives (`Transfer-Encoding`, duplicate/non-zero/non-digit `Content-Length`, duplicate/missing `Host`, authority mismatch, `Expect`, `Upgrade`, `Connection: upgrade`, `obs-fold`).
- Normalises unreserved percent-encodings in paths while rejecting encoded `/`, `\`, NUL, and `.`/`..` segments, and preserves query strings byte-for-byte.
- Filters forwarded headers to a strict allow-list in canonical order and serialises `ForwardRequest` as deterministic sorted-key JSON.


