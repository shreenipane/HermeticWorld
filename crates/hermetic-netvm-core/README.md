
# `hermetic-netvm-core`

Hermetic World network mediation core library and CLI binary (`hermetic-netvm`).

## Overview

`hermetic-netvm-core` isolates benchmark evaluation environments from post-cutoff world state while enforcing strict resource bounds, deterministic behavior, and zero unsafe code (`#![forbid(unsafe_code)]`):

1. **Pluggable Architecture**:
   - `DnsResponder`: answers DNS wire packets from an immutable in-memory table (`StaticDnsResponder` provided).
   - `RequestFilter`: inspects only the bounded HTTP request head (`MethodAllowFilter` forwards `GET` and `HEAD` as canonical JSON, returns `NotAllowed` for other valid HTTP methods, and `Reject` for malformed requests).
   - `Upstream`: fetches frozen world content within an explicit `Instant` deadline and streams the response body (`StaticUpstream` provided).
2. **Bounded Non-Forwarding UDP DNS Loop**:
   - Reads datagrams up to `MAX_DNS_PACKET_BYTES` (`512` bytes); oversized datagrams are dropped without parsing.
   - Enforces a fixed per-source IP token bucket (`DNS_BUCKET_CAPACITY`, `DNS_BUCKET_REFILL_PER_SEC`, bounded to `DNS_MAX_TRACKED_SOURCES` entries).
   - Never forwards queries to external resolvers.
3. **One-Request-Per-Connection HTTP/1.1 Loop & Response Hygiene**:
   - Enforces `MAX_CONCURRENT_CONNECTIONS`, immediately closing excess connections.
   - Enforces `head_timeout`, `chunk_write_timeout`, and `overall_timeout` so slow senders or slow readers cannot hold connection slots past their deadlines.
   - Emits `HTTP/1.1 405 Method Not Allowed` (`Content-Length: 0`, `Connection: close`, no `Date` or `Server` header) for disallowed methods and closes silently on `Reject`.
   - Passes only `content-type`, `content-length`, `etag`, `last-modified` (only when `<= T_clock`), `content-encoding`, `accept-ranges`, and `content-range` from upstream responses; strips `Date`, `Server`, `Set-Cookie`, `Age`, `Via`, all `X-*` headers, and any other headers.
4. **Structured Counter Logging**:
   - Emits JSON lines to `stderr` containing only event names and monotonic integer counters (never request bodies, never timestamps, never host names or host wall-clock time).

## Running

cargo run --bin hermetic-netvm -- \
  --dns 127.0.0.1:5353 \
  --http 127.0.0.1:8080 \
  --config config.json


## Testing

cargo test


