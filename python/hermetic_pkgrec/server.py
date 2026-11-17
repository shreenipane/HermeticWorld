"""HTTP/1.1 recording proxy server for PEP 503/691 simple index."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
from pathlib import Path
import socket
import stat
import threading
from typing import Any
from urllib.parse import unquote

from hermetic_pkgrec.constants import (
    FILE_CHUNK_BYTES,
    MAX_CONCURRENT_CONNECTIONS,
    MAX_DIST_FILE_BYTES,
    MAX_DRAIN_BODY_BYTES,
    MAX_HEADER_COUNT,
    MAX_HEADER_LINE_BYTES,
    MAX_RANGE_DIGITS,
    MAX_REQUEST_LINE_BYTES,
    MAX_TOTAL_HEADERS_BYTES,
    OCTET_STREAM_MIME,
    PEP503_HTML_MIME,
    PEP691_JSON_MIME,
    REQUEST_QUEUE_SIZE,
    REQUEST_READ_DEADLINE_SECONDS,
    SOCKET_TIMEOUT_SECONDS,
    TEXT_PLAIN_MIME,
)
from hermetic_pkgrec.errors import (
    CutoffError,
    HashMismatchError,
    ManifestError,
    OversizeFileError,
    PkgRecError,
    ProjectOverFileCapError,
    StoreError,
    SymlinkError,
    UpstreamError,
    UpstreamHttpError,
)
from hermetic_pkgrec.filter import (
    filter_project_files,
    normalize_project_name,
    parse_iso8601_ns,
    parse_upstream_page,
    render_project_html,
    render_project_json,
    render_root_html,
    render_root_json,
    validate_filename,
    validate_sha256,
)
from hermetic_pkgrec.manifest import Manifest
from hermetic_pkgrec.store import RecordingStore
from hermetic_pkgrec.upstream import UpstreamClient

logger = logging.getLogger("hermetic_pkgrec.server")

_TOKEN_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
_SINGLETON_HEADERS = frozenset({"host", "content-length", "transfer-encoding", "range"})


def _content_type_for_filename(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        return "application/gzip"
    if lower.endswith(".zip") or lower.endswith(".whl"):
        return "application/zip"
    return OCTET_STREAM_MIME


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

        if media_type in (PEP691_JSON_MIME, "application/json"):
            if json_q is None or q > json_q:
                json_q = q
        elif media_type in ("text/html", "application/vnd.pypi.simple.v1+html"):
            if html_q is None or q > html_q:
                html_q = q
        elif media_type in ("text/*", "*/*"):
            if html_q is None:
                html_q = q

    effective_json = json_q if json_q is not None else 0.0
    effective_html = html_q if html_q is not None else 0.0

    if effective_json > 0.0 and effective_json > effective_html:
        return "json"
    return "html"


def parse_and_validate_target(raw_target: str) -> str:
    """Validate and percent-decode an origin-form request target path."""
    if not raw_target or not raw_target.startswith("/"):
        raise PkgRecError("Request target must be origin-form.")
    if "#" in raw_target:
        raise PkgRecError("Fragment is not permitted in target.")

    for ch in raw_target:
        code = ord(ch)
        if code < 0x20 or code == 0x7F:
            raise PkgRecError("Control character in request target.")

    raw_path, _, _ = raw_target.partition("?")
    lower_raw = raw_path.lower()

    if "\\" in raw_path or "%5c" in lower_raw:
        raise PkgRecError("Backslash refused in request path.")
    if "\x00" in raw_path or "%00" in lower_raw:
        raise PkgRecError("NUL byte refused in request path.")
    if "%2f" in lower_raw:
        raise PkgRecError("Encoded slash refused in request path.")

    for raw_seg in raw_path.split("/"):
        if raw_seg in (".", ".."):
            raise PkgRecError("Dot segment refused in request path.")
        try:
            decoded_seg = unquote(raw_seg, encoding="utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise PkgRecError("Invalid UTF-8 percent-encoding in path.") from exc
        if decoded_seg in (".", ".."):
            raise PkgRecError("Encoded dot segment refused in request path.")

    try:
        decoded_path = unquote(raw_path, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PkgRecError("Invalid UTF-8 percent-encoding in path.") from exc

    if "\x00" in decoded_path or "\\" in decoded_path:
        raise PkgRecError("Unsafe character in decoded path.")
    for ch in decoded_path:
        code = ord(ch)
        if code < 0x20 or 0x7F <= code <= 0x9F:
            raise PkgRecError("Control character in decoded path.")

    return decoded_path


@dataclass(frozen=True, slots=True)
class KnownFileInfo:
    project: str
    filename: str
    sha256: str
    upload_time: str
    yank_decision: str
    upstream_url: str


class RecordingProxyServer(ThreadingHTTPServer):
    """Bounded recording HTTP server proxying between pip/uv and upstream."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = REQUEST_QUEUE_SIZE

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        upstream: UpstreamClient,
        store: RecordingStore,
        manifest: Manifest,
        cutoff: str,
        manifest_path: str | Path | None = None,
        yank_table: dict[str, str] | None = None,
        miss_log_path: str | Path | None = None,
        max_connections: int = MAX_CONCURRENT_CONNECTIONS,
        socket_timeout: float = SOCKET_TIMEOUT_SECONDS,
        request_read_deadline: float = REQUEST_READ_DEADLINE_SECONDS,
    ) -> None:
        self.upstream = upstream
        self.store = store
        self.manifest = manifest
        self.cutoff = cutoff
        self.cutoff_ns = parse_iso8601_ns(cutoff)
        self.manifest_path = Path(manifest_path).resolve() if manifest_path else None
        self.yank_table = yank_table or {}
        # Keep path as supplied without .resolve() to prevent following symlinks.
        self.miss_log_path = Path(miss_log_path) if miss_log_path else None
        self.socket_timeout = socket_timeout
        self.request_read_deadline = request_read_deadline
        self._conn_semaphore = threading.BoundedSemaphore(max_connections)

        self._files_lock = threading.Lock()
        self._miss_lock = threading.Lock()
        self.known_files: dict[tuple[str, str], KnownFileInfo] = {}
        self._admitted_projects: set[str] = {rec.project for rec in manifest.files}

        # Pre-populate known files from existing manifest if present.
        for rec in manifest.files:
            self.known_files[(rec.sha256, rec.filename)] = KnownFileInfo(
                project=rec.project,
                filename=rec.filename,
                sha256=rec.sha256,
                upload_time=rec.upload_time,
                yank_decision=rec.yank_decision,
                upstream_url="",
            )

        super().__init__(server_address, RecordingProxyHandler)

    def admit_project(self, project: str) -> None:
        with self._files_lock:
            self._admitted_projects.add(project)

    def get_admitted_projects(self) -> list[str]:
        with self._files_lock:
            return sorted(self._admitted_projects)

    def register_file(self, info: KnownFileInfo) -> None:
        with self._files_lock:
            self.known_files[(info.sha256, info.filename)] = info

    def get_known_file(self, sha256: str, filename: str) -> KnownFileInfo | None:
        with self._files_lock:
            return self.known_files.get((sha256, filename))

    def record_miss(self, miss_kind: str, identifier: str) -> None:
        if not self.miss_log_path:
            return
        entry = {"kind": miss_kind, "name": identifier}
        line = (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8")
        target = Path(self.miss_log_path)
        with self._miss_lock:
            # Check for symlink before opening
            try:
                st = os.lstat(target)
                if stat.S_ISLNK(st.st_mode):
                    raise SymlinkError(f"Refusing symlink miss log: {target}")
                if not stat.S_ISREG(st.st_mode):
                    raise StoreError(f"Miss log is not a regular file: {target}")
            except FileNotFoundError:
                parent = target.parent
                try:
                    pst = os.lstat(parent)
                    if stat.S_ISLNK(pst.st_mode):
                        raise SymlinkError(f"Refusing symlink parent of miss log: {parent}")
                except FileNotFoundError:
                    parent.mkdir(parents=True, exist_ok=True)

            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                fd = os.open(target, flags, 0o600)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise SymlinkError(f"Refusing symlink miss log: {target}") from exc
                raise StoreError(f"Failed opening miss log: {exc}") from exc

            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise StoreError(f"Miss log is not a regular file: {target}")
                try:
                    os.fchmod(fd, 0o600)
                except OSError:
                    pass

                view = memoryview(line)
                total = 0
                max_loops = (len(line) // 4096) + 2
                for _ in range(max_loops):
                    if total >= len(line):
                        break
                    written = os.write(fd, view[total:])
                    if written <= 0:
                        raise StoreError("Failed writing to miss log.")
                    total += written
                os.fsync(fd)
            finally:
                os.close(fd)

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


class RecordingProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler executing cutoff filtering and recording fetched packages."""

    protocol_version = "HTTP/1.1"
    server: RecordingProxyServer  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("%s - " + format, self.address_string(), *args)

    def handle_one_request(self) -> None:
        self.close_connection = True
        self.request_version = self.protocol_version
        self.command = ""
        self.path = ""
        self._response_started = False
        try:
            self._handle_guarded()
        except OSError:
            self.close_connection = True

    def _read_request_with_deadline(
        self,
    ) -> tuple[str | None, str, str, dict[str, str]]:
        expired = threading.Event()

        def _expire() -> None:
            expired.set()
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(self.server.request_read_deadline, _expire)
        timer.daemon = True
        timer.start()
        try:
            result = self._read_bounded_request()
        finally:
            timer.cancel()
        if expired.is_set():
            raise TimeoutError("Request head not received within deadline.")
        return result

    def _read_bounded_request(
        self,
    ) -> tuple[str | None, str, str, dict[str, str]]:
        raw_line = self.rfile.readline(MAX_REQUEST_LINE_BYTES + 1)
        if not raw_line:
            return None, "", "", {}
        if len(raw_line) > MAX_REQUEST_LINE_BYTES or not raw_line.endswith(b"\n"):
            self._send_error_response(HTTPStatus.REQUEST_URI_TOO_LONG, "Request line exceeds cap.")
            return None, "", "", {}

        try:
            line = raw_line.rstrip(b"\r\n").decode("ascii")
        except UnicodeDecodeError:
            self._send_error_response(HTTPStatus.BAD_REQUEST, "Non-ASCII request line.")
            return None, "", "", {}

        parts = line.split(" ")
        if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
            self._send_error_response(HTTPStatus.BAD_REQUEST, "Malformed request line.")
            return None, "", "", {}

        method, raw_target, version = parts
        headers: dict[str, str] = {}
        header_count = 0
        total_header_bytes = 0

        while True:
            hline = self.rfile.readline(MAX_HEADER_LINE_BYTES + 1)
            if not hline:
                self._send_error_response(HTTPStatus.BAD_REQUEST, "Unexpected EOF in headers.")
                return None, "", "", {}
            if len(hline) > MAX_HEADER_LINE_BYTES or not hline.endswith(b"\n"):
                self._send_error_response(
                    HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, "Header line exceeds cap."
                )
                return None, "", "", {}
            if hline in (b"\r\n", b"\n"):
                break
            if hline[:1] in (b" ", b"\t"):
                self._send_error_response(HTTPStatus.BAD_REQUEST, "Line folding refused.")
                return None, "", "", {}

            header_count += 1
            total_header_bytes += len(hline)
            if header_count > MAX_HEADER_COUNT or total_header_bytes > MAX_TOTAL_HEADERS_BYTES:
                self._send_error_response(
                    HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, "Headers exceed cap."
                )
                return None, "", "", {}

            try:
                decoded = hline.rstrip(b"\r\n").decode("latin-1")
            except UnicodeDecodeError:
                self._send_error_response(HTTPStatus.BAD_REQUEST, "Invalid header encoding.")
                return None, "", "", {}

            if ":" not in decoded:
                self._send_error_response(HTTPStatus.BAD_REQUEST, "Malformed header without colon.")
                return None, "", "", {}

            name, _, value = decoded.partition(":")
            if not name or any(ch not in _TOKEN_CHARS for ch in name):
                self._send_error_response(HTTPStatus.BAD_REQUEST, "Invalid header field name.")
                return None, "", "", {}

            key = name.lower()
            val = value.strip(" \t")
            if any((ord(ch) < 0x20 and ch != "\t") or ord(ch) == 0x7F for ch in val):
                self._send_error_response(HTTPStatus.BAD_REQUEST, "Control char in header.")
                return None, "", "", {}

            if key in headers:
                if key in _SINGLETON_HEADERS:
                    self._send_error_response(HTTPStatus.BAD_REQUEST, f"Repeated {key} header.")
                    return None, "", "", {}
                headers[key] = f"{headers[key]}, {val}"
            else:
                headers[key] = val

        if version == "HTTP/1.1" and not headers.get("host"):
            self._send_error_response(HTTPStatus.BAD_REQUEST, "Missing Host header.")
            return None, "", "", {}

        return method, raw_target, version, headers

    def _handle_guarded(self) -> None:
        method, raw_target, version, headers = self._read_request_with_deadline()
        if method is None:
            return

        self.command = method
        self.path = raw_target

        if version != "HTTP/1.1":
            self._send_error_response(
                HTTPStatus.HTTP_VERSION_NOT_SUPPORTED, "Only HTTP/1.1 is supported."
            )
            return

        try:
            clean_path = parse_and_validate_target(raw_target)
        except PkgRecError as exc:
            self._send_error_response(HTTPStatus.BAD_REQUEST, str(exc))
            return

        if method not in ("GET", "HEAD"):
            self._send_error_response(
                HTTPStatus.METHOD_NOT_ALLOWED, f"Method {method} not allowed."
            )
            return

        try:
            self._dispatch(clean_path, headers)
        except SymlinkError as exc:
            logger.error("Refused symlink: %s", exc)
            self._send_error_response(HTTPStatus.FORBIDDEN, "Forbidden.")
        except (StoreError, OSError, ManifestError) as exc:
            logger.error("Store, manifest or OS error: %s", exc)
            self._send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error.")

    def _dispatch(self, clean_path: str, headers: dict[str, str]) -> None:
        if clean_path in ("/simple", "/simple/"):
            self._handle_root_index(headers)
            return

        if clean_path.startswith("/simple/"):
            inner = clean_path[len("/simple/") :].rstrip("/")
            if inner and "/" not in inner:
                self._handle_project_page(inner, headers)
                return

        if clean_path.startswith("/files/"):
            rest = clean_path[len("/files/") :]
            segments = rest.split("/")
            if len(segments) == 2 and segments[0] and segments[1]:
                self._handle_file_fetch(segments[0], segments[1], headers)
                return

        try:
            self.server.record_miss("path", clean_path)
        except (SymlinkError, StoreError, OSError) as exc:
            logger.error("Failed recording miss for path %s: %s", clean_path, exc)
            self._send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error.")
            return

        self._send_error_response(HTTPStatus.NOT_FOUND, "Not found.")

    def _handle_root_index(self, headers: dict[str, str]) -> None:
        admitted = self.server.get_admitted_projects()
        fmt = negotiate_index_format(headers.get("accept"))
        if fmt == "json":
            body = render_root_json(admitted)
            chosen_type = PEP691_JSON_MIME
        else:
            body = render_root_html(admitted)
            chosen_type = PEP503_HTML_MIME

        etag = hashlib.sha256(body).hexdigest()
        self._send_bytes_response(HTTPStatus.OK, chosen_type, body, etag=etag)

    def _handle_project_page(self, raw_project: str, headers: dict[str, str]) -> None:
        try:
            norm_proj = normalize_project_name(raw_project)
        except CutoffError as exc:
            logger.warning("Invalid project name %r: %s", raw_project, exc)
            self._send_error_response(HTTPStatus.BAD_REQUEST, "Invalid project name.")
            return

        try:
            content_bytes, content_type = self.server.upstream.fetch_project_page(
                norm_proj, headers.get("accept")
            )
        except UpstreamHttpError as exc:
            try:
                self.server.record_miss("project", norm_proj)
            except (SymlinkError, StoreError, OSError) as log_exc:
                logger.error("Failed recording miss: %s", log_exc)
                self._send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error.")
                return
            self._send_error_response(exc.status_code, "Project not found upstream.")
            return
        except UpstreamError as exc:
            logger.error("Upstream error fetching project %s: %s", norm_proj, exc)
            self._send_error_response(HTTPStatus.BAD_GATEWAY, "Bad Gateway.")
            return

        try:
            entries = parse_upstream_page(content_bytes, content_type)
        except UpstreamError as exc:
            logger.error("Failed parsing upstream page for %s: %s", norm_proj, exc)
            self._send_error_response(HTTPStatus.BAD_GATEWAY, "Bad Gateway.")
            return

        # Filter against package cutoff and rewrite yank status.
        try:
            result = filter_project_files(
                norm_proj,
                entries,
                self.server.cutoff_ns,
                yank_table=self.server.yank_table,
            )
        except ProjectOverFileCapError as exc:
            logger.warning("Project %s exceeded file cap: %s", norm_proj, exc)
            self.server.manifest.record_project_over_file_cap(norm_proj)
            if self.server.manifest_path:
                self.server.manifest.save(self.server.manifest_path)
            self._send_error_response(HTTPStatus.BAD_GATEWAY, "Bad Gateway.")
            return
        except CutoffError as exc:
            logger.warning("Cutoff error for %s: %s", norm_proj, exc)
            self._send_error_response(HTTPStatus.BAD_REQUEST, "Bad request.")
            return

        # Record missing upload times, unyanked entries, and hash/filename defects in manifest.
        for item in result.missing_upload_time:
            self.server.manifest.record_missing_upload_time(item["project"], item["filename"])
        for item in result.unyanked_after_cutoff:
            self.server.manifest.record_unyanked_after_cutoff(item["project"], item["filename"])
        for item in result.unyanked_unknown_date:
            self.server.manifest.record_unyanked_unknown_date(item["project"], item["filename"])
        for item in result.missing_hash:
            self.server.manifest.record_missing_hash(item["project"], item["filename"])
        for item in result.invalid_hash:
            self.server.manifest.record_invalid_hash(item["project"], item["filename"])
        for item in result.invalid_filename:
            self.server.manifest.record_invalid_filename(item["project"], item["filename"])

        if self.server.manifest_path and (
            result.missing_upload_time
            or result.unyanked_after_cutoff
            or result.unyanked_unknown_date
            or result.missing_hash
            or result.invalid_hash
            or result.invalid_filename
        ):
            self.server.manifest.save(self.server.manifest_path)

        # If project has at least one file admitted at cutoff, admit it!
        if len(result.files) > 0:
            self.server.admit_project(norm_proj)

        # Register all kept files so subsequent download requests know their upstream source.
        for f in result.files:
            try:
                resolved_url = self.server.upstream.resolve_file_url(f.url, norm_proj)
            except UpstreamError as exc:
                logger.warning("Refused unlisted file URL %s for %s: %s", f.url, f.filename, exc)
                self._send_error_response(HTTPStatus.BAD_GATEWAY, "Bad Gateway.")
                return

            self.server.register_file(
                KnownFileInfo(
                    project=norm_proj,
                    filename=f.filename,
                    sha256=f.sha256,
                    upload_time=f.upload_time,
                    yank_decision=f.yank_decision,
                    upstream_url=resolved_url,
                )
            )

        fmt = negotiate_index_format(headers.get("accept"))
        if fmt == "json":
            body = render_project_json(norm_proj, result.files)
            resp_type = PEP691_JSON_MIME
        else:
            body = render_project_html(norm_proj, result.files)
            resp_type = PEP503_HTML_MIME

        etag = hashlib.sha256(body).hexdigest()
        self._send_bytes_response(HTTPStatus.OK, resp_type, body, etag=etag)

    def _handle_file_fetch(self, raw_sha256: str, raw_filename: str, headers: dict[str, str]) -> None:
        try:
            sha256 = validate_sha256(raw_sha256)
            filename = validate_filename(raw_filename)
        except CutoffError:
            self._send_error_response(HTTPStatus.BAD_REQUEST, "Invalid file parameters.")
            return

        # Check if file is already in the store.
        try:
            in_store = self.server.store.has_file(sha256, filename)
        except SymlinkError as exc:
            logger.error("Refusing symlink store file for %s/%s: %s", sha256, filename, exc)
            self._send_error_response(HTTPStatus.FORBIDDEN, "Forbidden.")
            return

        if in_store:
            known = self.server.get_known_file(sha256, filename)
            if known is not None:
                self.server.manifest.record_file(
                    known.project,
                    known.filename,
                    known.sha256,
                    known.upload_time,
                    known.yank_decision,
                )
                if self.server.manifest_path:
                    self.server.manifest.save(self.server.manifest_path)
            self._stream_local_file(sha256, filename)
            return

        # Not in store: locate known file metadata from recorded project page.
        known = self.server.get_known_file(sha256, filename)
        if known is None or not known.upstream_url:
            try:
                self.server.record_miss("file", f"{sha256}/{filename}")
            except (SymlinkError, StoreError, OSError) as log_exc:
                logger.error("Failed recording miss: %s", log_exc)
                self._send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error.")
                return
            self._send_error_response(HTTPStatus.NOT_FOUND, "File not recorded or found upstream.")
            return

        # Fetch from upstream and stream into the store.
        try:
            stream = self.server.upstream.fetch_file_stream(
                known.upstream_url, max_bytes=MAX_DIST_FILE_BYTES
            )
            self.server.store.save_file_stream(sha256, filename, stream)
        except HashMismatchError as exc:
            logger.error("Hash mismatch for %s: %s", filename, exc)
            self._send_error_response(HTTPStatus.BAD_GATEWAY, "Bad Gateway.")
            return
        except OversizeFileError as exc:
            logger.error("Oversize file %s: %s", filename, exc)
            self._send_error_response(HTTPStatus.BAD_GATEWAY, "Bad Gateway.")
            return
        except UpstreamHttpError as exc:
            try:
                self.server.record_miss("file", f"{sha256}/{filename}")
            except (SymlinkError, StoreError, OSError) as log_exc:
                logger.error("Failed recording miss: %s", log_exc)
                self._send_error_response(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal server error.")
                return
            self._send_error_response(exc.status_code, "File missing upstream.")
            return
        except (UpstreamError, StoreError) as exc:
            logger.error("Error saving file %s: %s", filename, exc)
            self._send_error_response(HTTPStatus.BAD_GATEWAY, "Bad Gateway.")
            return

        # Record file in the manifest and persist.
        self.server.manifest.record_file(
            known.project,
            known.filename,
            known.sha256,
            known.upload_time,
            known.yank_decision,
        )
        if self.server.manifest_path:
            self.server.manifest.save(self.server.manifest_path)

        # Stream the freshly saved file back to the client.
        self._stream_local_file(sha256, filename)

    def _stream_local_file(self, sha256: str, filename: str) -> None:
        try:
            fd = self.server.store.open_file_for_reading(sha256, filename)
        except SymlinkError as exc:
            logger.error("Refusing symlink store file for %s/%s: %s", sha256, filename, exc)
            self._send_error_response(HTTPStatus.FORBIDDEN, "Forbidden.")
            return
        except (StoreError, OSError) as exc:
            logger.error("Error opening store file %s/%s: %s", sha256, filename, exc)
            self._send_error_response(HTTPStatus.NOT_FOUND, "File not found in store.")
            return

        try:
            st = os.fstat(fd)
            size = st.st_size

            content_type = _content_type_for_filename(filename)
            self._response_started = True
            self.send_response_only(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            self.send_header("ETag", f'"{sha256}"')
            self.end_headers()

            if self.command == "GET" and size > 0:
                max_loops = (size // FILE_CHUNK_BYTES) + 2
                for _ in range(max_loops):
                    chunk = os.read(fd, FILE_CHUNK_BYTES)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            self.wfile.flush()
        finally:
            os.close(fd)

    def send_response_only(self, code: int, message: str | None = None) -> None:
        """Send status line and ensure connection closes; omit Date and Server headers."""
        super().send_response_only(code, message)
        self.send_header("Connection", "close")

    def _send_bytes_response(
        self,
        status: HTTPStatus,
        content_type: str,
        body: bytes,
        *,
        etag: str | None = None,
    ) -> None:
        self._response_started = True
        self.send_response_only(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if etag is not None:
            self.send_header("ETag", f'"{etag}"')
        self.end_headers()
        if self.command == "GET" and body:
            self.wfile.write(body)
        self.wfile.flush()

    def _send_error_response(self, status: HTTPStatus | int, message: str) -> None:
        if self._response_started:
            return
        body = (message + "\n").encode("utf-8")
        self._response_started = True
        self.send_response_only(status)
        self.send_header("Content-Type", TEXT_PLAIN_MIME)
        self.send_header("Content-Length", str(len(body)))
        if status == HTTPStatus.METHOD_NOT_ALLOWED:
            self.send_header("Allow", "GET, HEAD")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.wfile.flush()
