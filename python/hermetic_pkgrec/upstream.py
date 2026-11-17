"""Pluggable upstream client interface with HTTP and offline fixture implementations."""

from __future__ import annotations

import abc
from collections.abc import Iterator
import http.client
import json
import socket
import ssl
import threading
from typing import Any
from urllib.parse import urljoin, urlsplit

from hermetic_pkgrec.constants import (
    CONNECT_TIMEOUT_SECONDS,
    DEFAULT_SOCKET_TIMEOUT,
    FILE_CHUNK_BYTES,
    MAX_DIST_FILE_BYTES,
    MAX_DRAIN_BODY_BYTES,
    MAX_INDEX_RESPONSE_BYTES,
    MAX_REDIRECTS,
    PEP503_HTML_MIME,
    PEP691_JSON_MIME,
)
from hermetic_pkgrec.errors import (
    CrossHostRedirectError,
    InsecureUpstreamError,
    OversizeFileError,
    UpstreamError,
    UpstreamHttpError,
    UpstreamResponseTooLargeError,
    UpstreamTimeoutError,
)


class UpstreamClient(abc.ABC):
    """Abstract interface for upstream package index interactions."""

    @abc.abstractmethod
    def fetch_project_page(self, project: str, accept: str | None = None) -> tuple[bytes, str]:
        """Fetch the simple index page for a project. Returns (content_bytes, content_type)."""

    @abc.abstractmethod
    def fetch_root_index(self, accept: str | None = None) -> tuple[bytes, str]:
        """Fetch the root /simple/ index page. Returns (content_bytes, content_type)."""

    @abc.abstractmethod
    def fetch_file_stream(self, url: str, max_bytes: int = MAX_DIST_FILE_BYTES) -> Iterator[bytes]:
        """Stream distribution file bytes chunk-by-chunk up to max_bytes."""

    @abc.abstractmethod
    def resolve_file_url(self, file_url: str, project: str) -> str:
        """Resolve a relative or absolute file URL against the upstream base."""


class HttpUpstreamClient(UpstreamClient):
    """Production HTTP/HTTPS upstream client with strict security boundaries and bounded I/O."""

    def __init__(
        self,
        base_url: str,
        *,
        file_hosts: list[str] | set[str] | None = None,
        allow_insecure: bool = False,
        timeout: float = DEFAULT_SOCKET_TIMEOUT,
        max_redirects: int = MAX_REDIRECTS,
    ) -> None:
        if not base_url or not isinstance(base_url, str):
            raise UpstreamError("Base URL must be a non-empty string.")

        parsed = urlsplit(base_url)
        if not parsed.scheme or not parsed.netloc:
            raise UpstreamError(f"Malformed upstream base URL: {base_url!r}")

        is_fixture_host = parsed.hostname in ("127.0.0.1", "localhost")
        if parsed.scheme.lower() != "https" and not (allow_insecure or is_fixture_host):
            raise InsecureUpstreamError(
                f"Insecure upstream scheme {parsed.scheme!r} refused. Only HTTPS is allowed."
            )

        # Normalize trailing slash on base URL path.
        path = parsed.path
        if not path.endswith("/"):
            path += "/"

        self.base_url = f"{parsed.scheme}://{parsed.netloc}{path}"
        self.parsed_base = parsed
        self.allow_insecure = allow_insecure or is_fixture_host
        self.timeout = timeout
        self.max_redirects = max_redirects

        # Explicit allowlist of file hosts (index host + extra hosts).
        self._allowed_file_hosts: set[tuple[str, int | None]] = set()
        index_host = (parsed.hostname or "").lower()
        index_port = parsed.port
        if index_host:
            self._allowed_file_hosts.add((index_host, None))
            if index_port is not None:
                self._allowed_file_hosts.add((index_host, index_port))

        if file_hosts:
            for item in file_hosts:
                if not item or not isinstance(item, str):
                    continue
                cleaned = item.strip().lower()
                if ":" in cleaned:
                    h, _, p_str = cleaned.partition(":")
                    try:
                        self._allowed_file_hosts.add((h, int(p_str)))
                    except ValueError:
                        raise UpstreamError(f"Invalid port in file host: {item!r}")
                else:
                    self._allowed_file_hosts.add((cleaned, None))

    def validate_file_url(self, url: str) -> None:
        """Validate a file URL against allowlisted hosts, HTTPS requirement, and userinfo ban."""
        if not url or not isinstance(url, str):
            raise UpstreamError("File URL must be a non-empty string.")

        parsed = urlsplit(url)
        if parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or ""):
            raise InsecureUpstreamError("File URL containing userinfo is refused.")

        scheme = (parsed.scheme or "").lower()
        is_fixture_host = parsed.hostname in ("127.0.0.1", "localhost")
        if scheme != "https" and not (self.allow_insecure or is_fixture_host):
            raise InsecureUpstreamError(
                f"Insecure scheme {scheme!r} refused. Only HTTPS is allowed."
            )
        if scheme not in ("https", "http"):
            raise InsecureUpstreamError(f"Unsupported scheme {scheme!r}.")

        host = (parsed.hostname or "").lower()
        if not host:
            raise UpstreamError("Missing host in file URL.")

        default_port = 443 if scheme == "https" else 80
        port = parsed.port

        if port is not None and port != default_port:
            if (host, port) not in self._allowed_file_hosts:
                raise UpstreamError(f"Non-default port {port} for host {host} not allowlisted.")
        else:
            if (host, None) not in self._allowed_file_hosts and (host, default_port) not in self._allowed_file_hosts:
                raise UpstreamError(f"File host not allowlisted: {host}")

    def resolve_file_url(self, file_url: str, project: str) -> str:
        """Resolve a file URL against the upstream base or project URL and validate against allowlist."""
        if not file_url or not isinstance(file_url, str):
            raise UpstreamError("File URL must be a non-empty string.")

        if not (file_url.startswith("http://") or file_url.startswith("https://")):
            project_base = urljoin(self.base_url, f"{project}/")
            resolved = urljoin(project_base, file_url)
        else:
            resolved = file_url

        self.validate_file_url(resolved)
        return resolved

    def _open_connection(self, host: str, port: int, scheme: str) -> http.client.HTTPConnection:
        if scheme == "https":
            context = ssl.create_default_context()
            return http.client.HTTPSConnection(
                host, port=port, timeout=self.timeout, context=context
            )
        return http.client.HTTPConnection(host, port=port, timeout=self.timeout)

    def _request_with_redirects(
        self,
        method: str,
        initial_url: str,
        headers: dict[str, str],
    ) -> tuple[int, dict[str, str], http.client.HTTPResponse, http.client.HTTPConnection]:
        """Execute HTTP request following redirects only within the same origin host."""
        current_url = initial_url
        parsed_origin = urlsplit(initial_url)
        conn: http.client.HTTPConnection | None = None

        for redirect_hop in range(self.max_redirects + 1):
            curr_split = urlsplit(current_url)

            # Enforce same origin host on all hops.
            if curr_split.netloc.lower() != parsed_origin.netloc.lower():
                if conn is not None:
                    conn.close()
                raise CrossHostRedirectError(
                    f"Cross-host redirect refused: from {parsed_origin.netloc} to {curr_split.netloc}"
                )

            # Check HTTPS scheme on all hops unless test fixture.
            if curr_split.scheme.lower() != "https" and not self.allow_insecure:
                if conn is not None:
                    conn.close()
                raise InsecureUpstreamError("Redirect to insecure HTTP refused.")

            port = curr_split.port or (443 if curr_split.scheme == "https" else 80)
            target = curr_split.path or "/"
            if curr_split.query:
                target += f"?{curr_split.query}"

            try:
                conn = self._open_connection(curr_split.hostname or "127.0.0.1", port, curr_split.scheme)
                req_headers = dict(headers)
                req_headers["Host"] = curr_split.netloc
                conn.request(method, target, headers=req_headers)
                resp = conn.getresponse()
            except socket.timeout as exc:
                if conn is not None:
                    conn.close()
                raise UpstreamTimeoutError("Upstream socket timed out.") from exc
            except (OSError, http.client.HTTPException) as exc:
                if conn is not None:
                    conn.close()
                raise UpstreamError(f"HTTP connection failed: {exc}") from exc

            # Redirect handling.
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.getheader("Location")
                resp.read(MAX_DRAIN_BODY_BYTES)  # Drain response body bounded by cap.
                conn.close()
                if not location:
                    raise UpstreamError("Redirect response missing Location header.")
                if redirect_hop >= self.max_redirects:
                    raise UpstreamError(f"Redirect limit ({self.max_redirects}) exceeded.")
                current_url = urljoin(current_url, location)
                continue

            # Return live response and holding connection.
            resp_headers: dict[str, str] = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, resp_headers, resp, conn

        raise UpstreamError("Unexpected end of redirect loop.")

    def fetch_project_page(self, project: str, accept: str | None = None) -> tuple[bytes, str]:
        url = urljoin(self.base_url, f"{project}/")
        return self._fetch_index_page(url, accept)

    def fetch_root_index(self, accept: str | None = None) -> tuple[bytes, str]:
        return self._fetch_index_page(self.base_url, accept)

    def _fetch_index_page(self, url: str, accept: str | None) -> tuple[bytes, str]:
        headers: dict[str, str] = {
            "Accept": accept
            or f"{PEP691_JSON_MIME}, {PEP503_HTML_MIME};q=0.5, text/html;q=0.1",
            "User-Agent": "hermetic-pkgrec/1.0",
        }
        status, resp_headers, resp, conn = self._request_with_redirects("GET", url, headers)
        try:
            if status != 200:
                raise UpstreamHttpError(status, f"Failed fetching index from {url}")

            chunks: list[bytes] = []
            total = 0
            max_loops = (MAX_INDEX_RESPONSE_BYTES // FILE_CHUNK_BYTES) + 2
            for _ in range(max_loops):
                chunk = resp.read(FILE_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_INDEX_RESPONSE_BYTES:
                    raise UpstreamResponseTooLargeError("Upstream index response exceeds size cap.")
                chunks.append(chunk)

            content_type = resp_headers.get("content-type", PEP503_HTML_MIME)
            return b"".join(chunks), content_type
        finally:
            conn.close()

    def fetch_file_stream(self, url: str, max_bytes: int = MAX_DIST_FILE_BYTES) -> Iterator[bytes]:
        self.validate_file_url(url)
        headers = {
            "Accept": "*/*",
            "User-Agent": "hermetic-pkgrec/1.0",
        }
        status, resp_headers, resp, conn = self._request_with_redirects("GET", url, headers)
        try:
            if status != 200:
                raise UpstreamHttpError(status, f"Failed fetching file from {url}")

            total = 0
            max_loops = (max_bytes // FILE_CHUNK_BYTES) + 2
            for _ in range(max_loops):
                chunk = resp.read(FILE_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise OversizeFileError(f"Fetched file exceeds size cap {max_bytes}")
                yield chunk
        finally:
            conn.close()


class FixtureUpstreamClient(UpstreamClient):
    """Offline test upstream providing deterministic fixture responses with zero network access."""

    def __init__(
        self,
        *,
        projects: dict[str, Any] | None = None,
        files: dict[str, bytes] | None = None,
        root_projects: list[str] | None = None,
        yank_table: dict[str, str] | None = None,
        default_content_type: str = PEP691_JSON_MIME,
    ) -> None:
        self.projects: dict[str, Any] = projects or {}
        self.files: dict[str, bytes] = files or {}
        self.root_projects: list[str] = root_projects or sorted(self.projects.keys())
        self.yank_table: dict[str, str] = yank_table or {}
        self.default_content_type = default_content_type
        self._lock = threading.Lock()
        self.request_count: int = 0
        self.requests: list[str] = []

    def resolve_file_url(self, file_url: str, project: str) -> str:
        return file_url

    def fetch_project_page(self, project: str, accept: str | None = None) -> tuple[bytes, str]:
        with self._lock:
            self.request_count += 1
            self.requests.append(f"project:{project}")

        from hermetic_pkgrec.filter import normalize_project_name

        norm = normalize_project_name(project)
        content = self.projects.get(norm)
        if content is None:
            content = self.projects.get(project)

        if content is None:
            raise UpstreamHttpError(404, f"Project {project!r} not found in offline fixture.")

        if isinstance(content, dict):
            raw = (json.dumps(content, indent=2) + "\n").encode("utf-8")
            return raw, PEP691_JSON_MIME
        if isinstance(content, str):
            return content.encode("utf-8"), self.default_content_type
        if isinstance(content, bytes):
            return content, self.default_content_type

        raise UpstreamError(f"Unsupported fixture content type: {type(content)}")

    def fetch_root_index(self, accept: str | None = None) -> tuple[bytes, str]:
        with self._lock:
            self.request_count += 1
            self.requests.append("root")
        payload = {
            "meta": {"api-version": "1.0"},
            "projects": [{"name": p} for p in sorted(self.root_projects)],
        }
        return (json.dumps(payload, indent=2) + "\n").encode("utf-8"), PEP691_JSON_MIME

    def fetch_file_stream(self, url: str, max_bytes: int = MAX_DIST_FILE_BYTES) -> Iterator[bytes]:
        with self._lock:
            self.request_count += 1
            self.requests.append(f"file:{url}")
        data = self.files.get(url)
        if data is None:
            # Fall back to matching by basename or sha.
            parts = url.split("/")
            if len(parts) >= 1 and parts[-1] in self.files:
                data = self.files[parts[-1]]

        if data is None:
            raise UpstreamHttpError(404, f"File at {url!r} not found in offline fixture.")

        if len(data) > max_bytes:
            raise OversizeFileError(f"Fixture file {url} exceeds byte cap {max_bytes}")

        view = memoryview(data)
        offset = 0
        total = len(data)
        max_loops = (total // FILE_CHUNK_BYTES) + 2
        for _ in range(max_loops):
            if offset >= total:
                break
            chunk_len = min(FILE_CHUNK_BYTES, total - offset)
            chunk = bytes(view[offset : offset + chunk_len])
            offset += chunk_len
            yield chunk
