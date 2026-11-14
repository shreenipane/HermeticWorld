# Offline requests test service

The reviewed requests base is
`091991be0da19de9108dbe5e3752917fea3d7fdc` (`psf__requests-2317`). Its
`test_requests.py` reads `HTTPBIN_URL`. Intake declares `test_services:
["httpbin-v1"]` for this repository and base in `task.json`. The canonical
World Manifest accepts the same optional list, commits it in the world root,
and rejects unknown services and duplicate declarations. Existing requests
tasks without a manifest or declaration have an exact repository/base migration
default; grading does not modify their artifacts. An explicit empty list disables
it. An existing World Manifest takes precedence: omission of `test_services`
means an empty list, matching its canonical world root. Conflicting task
declarations fail before creating the grading container.

For container grading and the oracle, `grader.grade` reads the standalone
stdlib service through a pinned, capped regular file descriptor, activates the
container's test interpreter, then injects the source through stdin to Python
isolated mode. No service file is written into the image or repository. The wrapper binds only
`127.0.0.1:8765`, starts a fixed worker pool, sets `HTTPBIN_URL`, removes proxy
settings from the test environment, and waits for `/eval.sh`. It shuts down
its workers when the script exits. The outer grader deadline and container
destruction also terminate the service. Docker networking stays `none`.
Startup failure fails grading; there is no network fallback.

Responses have a fixed `Date` equal to the task's `T_clock`, fixed origin
`127.0.0.1`, canonical JSON, gzip with zero mtime, and a fixed digest-auth
challenge. Headers and URLs in an echo come only from the request. The service
never resolves a name, opens a content file, reads the wall clock or hostname,
or logs requests, errors or credentials. Its only outbound socket writes are
responses on accepted loopback connections. Every request, header set, body,
multipart field count, stream count, redirect count, delay, worker pool,
request count, response size, total output, I/O wait, and run duration has a
named cap in `httpbin_service.py`. Connections carry one request and close;
ambiguous framing, trailers, unsupported encodings and oversized inputs close
without a response. Digest authentication is a deterministic protocol fixture,
not a credential protection mechanism.

Supported endpoints: `/get`, `/head`, `/post`, `/put`, `/patch`, `/delete`,
`/status/N`, `/redirect/N`, `/relative-redirect/N`, `/absolute-redirect/N`,
`/redirect-to`, `/cookies`, `/cookies/set`, `/cookies/delete`, `/response-headers`,
`/basic-auth/user/password`, `/digest-auth/auth/user/password`, `/gzip`,
`/stream/N`, `/headers`, `/user-agent`, `/html`, and `/delay/N`. Request bodies
support bounded content length and chunked framing, forms, JSON, multipart
files and raw data. Endpoint answers and transport failures are tested offline.

## Open integration decisions

This does **not** yet make the historical requests oracle pass. That suite
also hardcodes `https://httpbin.org/…`, replaces the scheme with HTTPS while
retaining the `HTTPBIN_URL` port, redirects to `http://www.google.co.uk`, and
expects a connect timeout from `http://10.255.255.1`. Neither the local service
nor a `HTTPBIN_URL` change supplies those routes. The sealed TLS trust and
HTTP/HTTPS interception policy must be decided before those paths can work;
opening external networking or rewriting tests would violate the task.

AgentVM support remains open: `WorldFilter` currently permits only GET/HEAD,
and the WorldServer v1 frame has no request headers or body. A versioned frame
extension, authority-specific method policy, request-body transport, and
WorldServer endpoint dispatch/auditing are required. Dynamic auth and echo
cannot be represented by static store objects. The local service must not be
exposed directly from the host to AgentVM.

The VM grader supervisor path also remains open. Its sandbox creates a private
network namespace and applies capabilities before exec; it has no declared
service lifecycle or installed Python service payload. The design must specify
loopback setup, the trusted interpreter/payload in the sealed rootfs, child
descriptor isolation (especially result fd 3), and service/test lifetime in
the namespace. The container launcher is not connected to this path. These
items need a coordinated sandbox/network design, and are intentionally listed
as unresolved rather than weakening those boundaries.
