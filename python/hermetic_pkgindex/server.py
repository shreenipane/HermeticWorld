
"""HTTP/1.1 server for the frozen Hermetic World PyPI Simple index."""

from __future__ import annotations

import hashlib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import logging
import socket
import threading
from typing import Any
from urllib.parse import unquote

from hermetic_pkgindex.store import (
    FrozenStore,
    IntegrityError,
    InvalidNameError,
    MissLog,
    MissLogError,
    NotFoundMissError,
    PathTraversalError,
    PkgIndexError,
    StoreLimitError,
    SymlinkError,
    validate_filename,
    validate_sha256,
)

logger = logging.getLogger("hermetic_pkgindex.server")

# Named caps bounding request lines, headers, concurrency, and socket timeouts.
MAX_REQUEST_LINE_BYTES: int = 4096
MAX_HEADER_LINE_BYTES: int = 8192
MAX_HEADER_COUNT: int = 64
MAX_TOTAL_HEADERS_BYTES: int = 32768
MAX_DRAIN_BODY_BYTES: int = 65536
MAX_CONCURRENT_CONNECTIONS: int = 64
REQUEST_QUEUE_SIZE: int = 64
SOCKET_TIMEOUT_SECONDS: float = 10.0

PEP691_JSON_MIME = "application/vnd.pypi.simple.v1+json"
PEP503_HTML_MIME = "text/html; charset=utf-8"
TEXT_PLAIN_MIME = "text/plain; charset=utf-8"


class HttpProtocolError(PkgIndexError):
    """Typed HTTP protocol or validation error mapped to an HTTP status code."""

    def __init__(
        self,
        status: HTTPStatus | int,
        message: str,
        *,
        content_range: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = HTTPStatus(status)
        self.message = message
        self.content_range = content_range


def parse_and_validate_target(raw_target: str) -> str:
    """Validate and percent-decode an origin-form request target path."""
    if not raw_target or not raw_target.startswith("/"):
        raise HttpProtocolError(HTTPStatus.BAD_REQUEST, "Request target must be origin-form.")
    if "#" in raw_target:
        raise HttpProtocolError(HTTPStatus.BAD_REQUEST, "Fragment is not permitted in target.")

    for ch in raw_target:
        code = ord(ch)
        if code < 0x20 or code == 0x7F:
            raise HttpProtocolError(HTTPStatus.BAD_REQUEST, "Control character in request target.")

    raw_path, _, _ = raw_target.partition("?")
    lower_raw = raw_path.lower()

    if "\\" in raw_path or "%5c" in lower_raw:
        raise HttpProtocolError(HTTPStatus.BAD_REQUEST, "Backslash refused in request path.")
    if "\x00" in raw_path or "%00" in lower_raw:
        raise HttpProtocolError(HTTPStatus.BAD_REQUEST, "NUL byte refused in request path.")
    if "%2f" in lower_raw:
        raise HttpProtocolError(HTTPStatus.BAD_REQUEST, "Encoded slash refused in request path.")

    for raw_seg in raw_path.split("/"):
        if raw_seg in (".", ".."):
            raise HttpProtocolError(HTTPStatus.BAD_REQUEST, "Dot segment refused in request path.")
        try:
            decoded_seg = unquote(raw_seg, encoding="utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise HttpProtocolError(
                HTTPStatus.BAD_REQUEST, "Invalid UTF-8 percent-encoding in path."
            ) from exc
        if decoded_seg in (".", ".."):
            raise HttpProtocolError(
                HTTPStatus.BAD_REQUEST, "Encoded dot segment refused in request path."
            )

    try:
        decoded_path = unquote(raw_path, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise HttpProtocolError(
            HTTPStatus.BAD_REQUEST, "Invalid UTF-8 percent-encoding in path."
        ) from exc

    if "\x00" in decoded_path or "\\" in decoded_path:
        raise HttpProtocolError(HTTPStatus.BAD_REQUEST, "Unsafe character in decoded path.")

    for seg in decoded_path.split("/"):
        if seg in (".", ".."):
            raise HttpProtocolError(HTTPStatus.BAD_REQUEST, "Traversal segment in decoded path.")

    return decoded_path


def negotiate_index_format(accept_header: str | None) -> str:
    """Choose 'json' or 'html' based on Accept header quality values, defaulting to 'html'."""
    if not accept_header or not accept_header.strip():
        return "html"

    json_q: float | None = None
    html_q: float | None = None

    for item in accept_header.split(","):
        parts = [p.strip() for p in item.strip().split(";") if p.strip()]
        if not parts:
            continue
        media_type = parts[0].lower()
        q = 1.0
        for param in parts[1:]:
            if param.lower().startswith("q="):
                try:
                    q_val = float(param[2:].strip())
                    if 0.0 <= q_val <= 1.0:
                        q = q_val
                except ValueError:
                    q = 0.0

        if media_type in ("application/vnd.pypi.simple.v1+json", "application/json"):
            if json_q is None or q > json_q:
                json_q = q
        elif media_type in ("text/html", "application/vnd.pypi.simple.v1+html"):
            if html_q is None or q > html_q:
                html_q = q
        elif media_type == "text/*":
            if html_q is None:
                html_q = q
        elif media_type == "*/*":
            if html_q is None:
                html_q = q

    effective_json = json_q if json_q is not None else 0.0
    effective_html = html_q if html_q is not None else 0.0

    if effective_json > 0.0 and effective_json > effective_html:
        return "json"
    return "html"


def parse_single_byte_range(range_header: str, total_size: int) -> tuple[int, int]:
    """Parse an HTTP single byte Range header and return inclusive (start, end)."""
    if total_size <= 0:
        raise HttpProtocolError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "Range not satisfiable for empty resource.",
            content_range=f"bytes */{total_size}",
        )

    value = range_header.strip()
    if not value.lower().startswith("bytes="):
        raise HttpProtocolError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "Only 'bytes' range unit is supported.",
            content_range=f"bytes */{total_size}",
        )

    spec = value[6:].strip()
    if not spec or "," in spec or "-" not in spec:
        raise HttpProtocolError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "Only a single byte range is supported.",
            content_range=f"bytes */{total_size}",
        )

    start_str, sep, end_str = spec.partition("-")
    if not sep or "-" in end_str:
        raise HttpProtocolError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "Malformed byte range specification.",
            content_range=f"bytes */{total_size}",
        )

    start_str = start_str.strip()
    end_str = end_str.strip()

    if not start_str and not end_str:
        raise HttpProtocolError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "Empty byte range bounds.",
            content_range=f"bytes */{total_size}",
        )

    if not start_str:
        # Suffix byte range: bytes=-<suffix_length>
        if not end_str.isdigit():
            raise HttpProtocolError(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                "Invalid suffix byte range.",
                content_range=f"bytes */{total_size}",
            )
        suffix_len = int(end_str)
        if suffix_len <= 0:
            raise HttpProtocolError(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                "Suffix byte range length must be positive.",
                content_range=f"bytes */{total_size}",
            )
        start = max(0, total_size - suffix_len)
        end = total_size - 1
        return start, end

    if not start_str.isdigit():
        raise HttpProtocolError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "Invalid start offset in byte range.",
            content_range=f"bytes */{total_size}",
        )
    start = int(start_str)
    if start >= total_size:
        raise HttpProtocolError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "Start offset beyond end of resource.",
            content_range=f"bytes */{total_size}",
        )

    if not end_str:
        return start, total_size - 1

    if not end_str.isdigit():
        raise HttpProtocolError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "Invalid end offset in byte range.",
            content_range=f"bytes */{total_size}",
        )
    end = int(end_str)
    if end < start:
        raise HttpProtocolError(
            HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
            "End offset precedes start offset.",
            content_range=f"bytes */{total_size}",
        )

    end = min(end, total_size - 1)
    return start, end


class HermeticHTTPServer(ThreadingHTTPServer):
    """Bounded multi-threaded HTTP/1.1 server for the frozen package store."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = REQUEST_QUEUE_SIZE

    def __init__(
        self,
        server_address: tuple[str, int],
        store: FrozenStore,
        miss_log: MissLog,
        *,
        max_connections: int = MAX_CONCURRENT_CONNECTIONS,
        socket_timeout: float = SOCKET_TIMEOUT_SECONDS,
    ) -> None:
        self.store = store
        self.miss_log = miss_log
        self.socket_timeout = socket_timeout
        self._conn_semaphore = threading.BoundedSemaphore(max_connections)
        super().__init__(server_address, HermeticRequestHandler)

    def get_request(self) -> tuple[socket.socket, Any]:
        sock, addr = super().get_request()
        sock.settimeout(self.socket_timeout)
        return sock, addr

    def process_request(self, request: socket.socket | bytes, client_address: Any) -> None:
        if not self._conn_semaphore.acquire(blocking=False):
            if isinstance(request, socket.socket):
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._conn_semaphore.release()
            raise

    def process_request_thread(self, request: socket.socket | bytes, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._conn_semaphore.release()


class HermeticRequestHandler(BaseHTTPRequestHandler):
    """Deterministic HTTP/1.1 handler emitting strictly bounded, minimal headers."""

    protocol_version = "HTTP/1.1"
    server: HermeticHTTPServer  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("%s - " + format, self.address_string(), *args)

    def handle_one_request(self) -> None:
        """Read and handle a single HTTP/1.1 request, then close the connection."""
        self.close_connection = True
        try:
            method, raw_target, version, headers = self._read_bounded_request()
            if method is None:
                return

            self.command = method
            self.path = raw_target
            self.request_version = version

            if version != "HTTP/1.1":
                raise HttpProtocolError(
                    HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
                    "Only HTTP/1.1 is supported.",
                )

            clean_path = parse_and_validate_target(raw_target)

            if method not in ("GET", "HEAD"):
                self._drain_small_body(headers)
                raise HttpProtocolError(
                    HTTPStatus.METHOD_NOT_ALLOWED,
                    f"Method {method} is not allowed.",
                )

            self._dispatch(clean_path, headers)

        except HttpProtocolError as exc:
            self._send_error_response(exc.status, exc.message, content_range=exc.content_range)
        except (socket.timeout, BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unhandled internal error while serving request: %s", exc)
            try:
                self._send_error_response(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "Internal server error.",
                )
            except OSError:
                pass

    def _read_bounded_request(
        self,
    ) -> tuple[str | None, str, str, dict[str, str]]:
        """Read request line and headers with explicit named byte and count caps."""
        raw_line = self.rfile.readline(MAX_REQUEST_LINE_BYTES + 1)
        if not raw_line:
            return None, "", "", {}
        if len(raw_line) > MAX_REQUEST_LINE_BYTES or not raw_line.endswith(b"\n"):
            raise HttpProtocolError(
                HTTPStatus.REQUEST_URI_TOO_LONG,
                "Request line exceeds size cap.",
            )

        try:
            line = raw_line.rstrip(b"\r\n").decode("ascii")
        except UnicodeDecodeError as exc:
            raise HttpProtocolError(
                HTTPStatus.BAD_REQUEST,
                "Non-ASCII bytes in request line.",
            ) from exc

        parts = line.split(" ")
        if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
            raise HttpProtocolError(
                HTTPStatus.BAD_REQUEST,
                "Malformed HTTP request line.",
            )
        method, raw_target, version = parts

        headers: dict[str, str] = {}
        header_count = 0
        total_header_bytes = 0

        while True:
            hline = self.rfile.readline(MAX_HEADER_LINE_BYTES + 1)
            if not hline:
                raise HttpProtocolError(
                    HTTPStatus.BAD_REQUEST,
                    "Unexpected EOF while reading headers.",
                )
            if len(hline) > MAX_HEADER_LINE_BYTES or not hline.endswith(b"\n"):
                raise HttpProtocolError(
                    HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "Single header line exceeds size cap.",
                )
            if hline in (b"\r\n", b"\n"):
                break

            header_count += 1
            total_header_bytes += len(hline)
            if header_count > MAX_HEADER_COUNT or total_header_bytes > MAX_TOTAL_HEADERS_BYTES:
                raise HttpProtocolError(
                    HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "Headers exceed count or total byte cap.",
                )

            try:
                decoded = hline.rstrip(b"\r\n").decode("latin-1")
            except UnicodeDecodeError as exc:
                raise HttpProtocolError(
                    HTTPStatus.BAD_REQUEST,
                    "Invalid header encoding.",
                ) from exc

            if ":" not in decoded:
                raise HttpProtocolError(
                    HTTPStatus.BAD_REQUEST,
                    "Malformed header line without colon.",
                )
            name, _, value = decoded.partition(":")
            key = name.strip().lower()
            if not key or any(ch.isspace() for ch in key):
                raise HttpProtocolError(
                    HTTPStatus.BAD_REQUEST,
                    "Invalid header field name.",
                )
            val = value.strip()
            if key in headers:
                headers[key] = f"{headers[key]}, {val}"
            else:
                headers[key] = val

        return method, raw_target, version, headers

    def _drain_small_body(self, headers: dict[str, str]) -> None:
        """Read up to MAX_DRAIN_BODY_BYTES on rejected POST/PUT requests to avoid TCP RST."""
        if "transfer-encoding" in headers:
            return
        cl_raw = headers.get("content-length")
        if not cl_raw or not cl_raw.isdigit():
            return
        cl = int(cl_raw)
        if 0 < cl <= MAX_DRAIN_BODY_BYTES:
            try:
                self.rfile.read(cl)
            except OSError:
                pass

    def _dispatch(self, clean_path: str, headers: dict[str, str]) -> None:
        """Route GET/HEAD requests for /simple/, /simple/<project>/, and /files/<sha>/<fn>."""
        if clean_path == "/simple/":
            self._handle_root_index(headers)
            return

        if clean_path.startswith("/simple/") and clean_path.endswith("/"):
            inner = clean_path[len("/simple/") : -1]
            if inner and "/" not in inner:
                self._handle_project_index(clean_path, inner, headers)
                return

        if clean_path.startswith("/files/"):
            rest = clean_path[len("/files/") :]
            segments = rest.split("/")
            if len(segments) == 2 and segments[0] and segments[1]:
                self._handle_file_download(clean_path, segments[0], segments[1], headers)
                return

        raise HttpProtocolError(HTTPStatus.NOT_FOUND, "Not found.")

    def _handle_root_index(self, headers: dict[str, str]) -> None:
        try:
            projects = self.server.store.list_projects()
        except SymlinkError as exc:
            raise HttpProtocolError(HTTPStatus.FORBIDDEN, str(exc)) from exc
        except (IntegrityError, StoreLimitError) as exc:
            logger.error("Store error listing projects: %s", exc)
            raise HttpProtocolError(
                HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error."
            ) from exc

        fmt = negotiate_index_format(headers.get("accept"))
        if fmt == "json":
            body = render_root_json(projects)
            content_type = PEP691_JSON_MIME
        else:
            body = render_root_html(projects)
            content_type = PEP503_HTML_MIME

        etag = hashlib.sha256(body).hexdigest()
        self._send_bytes_response(HTTPStatus.OK, content_type, body, etag=etag)

    def _handle_project_index(
        self,
        clean_path: str,
        raw_project: str,
        headers: dict[str, str],
    ) -> None:
        try:
            page = self.server.store.get_project_page(raw_project)
        except InvalidNameError as exc:
            raise HttpProtocolError(HTTPStatus.BAD_REQUEST, str(exc)) from exc
        except NotFoundMissError as exc:
            from hermetic_pkgindex.store import normalize_project_name

            norm = normalize_project_name(raw_project)
            try:
                self.server.miss_log.record_project_miss(norm, clean_path)
            except (MissLogError, SymlinkError) as log_exc:
                logger.error("Failed recording project miss for %s: %s", norm, log_exc)
                raise HttpProtocolError(
                    HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error."
                ) from log_exc
            raise HttpProtocolError(HTTPStatus.NOT_FOUND, "Project not found.") from exc
        except SymlinkError as exc:
            raise HttpProtocolError(HTTPStatus.FORBIDDEN, str(exc)) from exc
        except (IntegrityError, StoreLimitError) as exc:
            logger.error("Store error loading project %r: %s", raw_project, exc)
            raise HttpProtocolError(
                HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error."
            ) from exc

        fmt = negotiate_index_format(headers.get("accept"))
        if fmt == "json":
            body = page.json_bytes
            content_type = PEP691_JSON_MIME
        else:
            body = page.html_bytes
            content_type = PEP503_HTML_MIME

        etag = hashlib.sha256(body).hexdigest()
        self._send_bytes_response(HTTPStatus.OK, content_type, body, etag=etag)

    def _handle_file_download(
        self,
        clean_path: str,
        raw_sha256: str,
        raw_filename: str,
        headers: dict[str, str],
    ) -> None:
        try:
            sha256 = validate_sha256(raw_sha256)
            filename = validate_filename(raw_filename)
        except InvalidNameError as exc:
            raise HttpProtocolError(HTTPStatus.NOT_FOUND, "File not found.") from exc

        try:
            verified = self.server.store.verify_and_prepare_file(sha256, filename)
        except NotFoundMissError as exc:
            try:
                self.server.miss_log.record_file_miss(sha256, filename, clean_path)
            except (MissLogError, SymlinkError) as log_exc:
                logger.error("Failed recording file miss for %s/%s: %s", sha256, filename, log_exc)
                raise HttpProtocolError(
                    HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error."
                ) from log_exc
            raise HttpProtocolError(HTTPStatus.NOT_FOUND, "File not found.") from exc
        except SymlinkError as exc:
            raise HttpProtocolError(HTTPStatus.FORBIDDEN, str(exc)) from exc
        except (IntegrityError, StoreLimitError) as exc:
            raise HttpProtocolError(
                HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error."
            ) from exc

        range_header = headers.get("range")
        if range_header is not None:
            start, end = parse_single_byte_range(range_header, verified.size)
            slice_len = end - start + 1
            self.send_response_only(HTTPStatus.PARTIAL_CONTENT)
            self.send_header("Content-Type", verified.content_type)
            self.send_header("Content-Length", str(slice_len))
            self.send_header("Content-Range", f"bytes {start}-{end}/{verified.size}")
            self.send_header("ETag", f'"{verified.sha256}"')
            self.end_headers()
            if self.command == "GET":
                for chunk in self.server.store.iter_file_range(verified, start, end):
                    self.wfile.write(chunk)
            self.wfile.flush()
            return

        self.send_response_only(HTTPStatus.OK)
        self.send_header("Content-Type", verified.content_type)
        self.send_header("Content-Length", str(verified.size))
        self.send_header("ETag", f'"{verified.sha256}"')
        self.end_headers()
        if self.command == "GET" and verified.size > 0:
            for chunk in self.server.store.iter_file_range(verified, 0, verified.size - 1):
                self.wfile.write(chunk)
        self.wfile.flush()

    def _send_bytes_response(
        self,
        status: HTTPStatus,
        content_type: str,
        body: bytes,
        *,
        etag: str | None = None,
        content_range: str | None = None,
    ) -> None:
        """Send response with strictly controlled headers (no Date, Server, or Last-Modified)."""
        self.send_response_only(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if content_range is not None:
            self.send_header("Content-Range", content_range)
        if etag is not None:
            self.send_header("ETag", f'"{etag}"')
        self.end_headers()
        if self.command == "GET" and body:
            self.wfile.write(body)
        self.wfile.flush()

    def _send_error_response(
        self,
        status: HTTPStatus,
        message: str,
        *,
        content_range: str | None = None,
    ) -> None:
        """Send a plain-text error response without Date or Server headers."""
        body = (message + "\n").encode("utf-8")
        self.send_response_only(status)
        self.send_header("Content-Type", TEXT_PLAIN_MIME)
        self.send_header("Content-Length", str(len(body)))
        if content_range is not None:
            self.send_header("Content-Range", content_range)
        self.end_headers()
        if getattr(self, "command", "GET") != "HEAD":
            self.wfile.write(body)
        self.wfile.flush()


from hermetic_pkgindex.store import render_root_html, render_root_json  # noqa: E402


