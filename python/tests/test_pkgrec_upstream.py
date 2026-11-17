"""Tests covering upstream pluggability, security boundaries, HTTPS enforcement, and redirects."""

from __future__ import annotations

import http.server
from pathlib import Path
import threading
import pytest

from hermetic_pkgrec.errors import (
    CrossHostRedirectError,
    InsecureUpstreamError,
    OversizeFileError,
    UpstreamError,
    UpstreamHttpError,
    UpstreamResponseTooLargeError,
)
from hermetic_pkgrec.upstream import (
    FixtureUpstreamClient,
    HttpUpstreamClient,
)


def test_refuse_non_https_upstream() -> None:
    # Non-HTTPS upstream must be refused.
    with pytest.raises(InsecureUpstreamError):
        HttpUpstreamClient("http://insecure.example.com/simple/")

    with pytest.raises(InsecureUpstreamError):
        HttpUpstreamClient("ftp://ftp.example.com/simple/")

    # HTTPS is accepted.
    client = HttpUpstreamClient("https://pypi.org/simple/")
    assert client.base_url == "https://pypi.org/simple/"

    # Test fixture host (127.0.0.1 or localhost) or allow_insecure is accepted.
    fixture_client = HttpUpstreamClient("http://127.0.0.1:8000/simple/")
    assert fixture_client.allow_insecure is True


def test_fixture_upstream_client() -> None:
    fixture = FixtureUpstreamClient(
        projects={"my-pkg": {"meta": {"api-version": "1.0"}, "name": "my-pkg", "files": []}},
        files={"pkg.whl": b"dummy-data"},
        root_projects=["my-pkg"],
    )

    # Root index
    root_bytes, root_type = fixture.fetch_root_index()
    assert b"my-pkg" in root_bytes

    # Project page
    proj_bytes, proj_type = fixture.fetch_project_page("my-pkg")
    assert b"my-pkg" in proj_bytes

    # File stream
    chunks = list(fixture.fetch_file_stream("pkg.whl"))
    assert b"".join(chunks) == b"dummy-data"

    # 404 for missing project
    with pytest.raises(UpstreamHttpError) as exc_info:
        fixture.fetch_project_page("nonexistent")
    assert exc_info.value.status_code == 404

    # 404 for missing file
    with pytest.raises(UpstreamHttpError) as exc_file:
        list(fixture.fetch_file_stream("missing.whl"))
    assert exc_file.value.status_code == 404

    # Oversize file
    with pytest.raises(OversizeFileError):
        list(fixture.fetch_file_stream("pkg.whl", max_bytes=3))


class _RedirectServerHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        p = self.path.rstrip("/")
        if p == "/cross-host-redirect":
            self.send_response(302)
            self.send_header("Location", "http://other-host.example.com/target")
            self.end_headers()
        elif p == "/safe-redirect":
            self.send_response(302)
            self.send_header("Location", "/final-target")
            self.end_headers()
        elif p == "/final-target":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
        elif p == "/redirect-loop":
            self.send_response(302)
            self.send_header("Location", "/redirect-loop")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args) -> None:
        pass


@pytest.fixture()
def mock_http_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _RedirectServerHandler)
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield host, port
    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


def test_cross_host_redirect_refused(mock_http_server) -> None:
    host, port = mock_http_server
    client = HttpUpstreamClient(f"http://{host}:{port}/", allow_insecure=True)

    with pytest.raises(CrossHostRedirectError):
        client.fetch_project_page("cross-host-redirect")


def test_safe_same_host_redirect_followed(mock_http_server) -> None:
    host, port = mock_http_server
    client = HttpUpstreamClient(f"http://{host}:{port}/", allow_insecure=True)

    body, ct = client.fetch_project_page("safe-redirect")
    assert b'{"status": "ok"}' in body


def test_redirect_drain_is_bounded(mock_http_server, monkeypatch) -> None:
    from hermetic_pkgrec.constants import MAX_DRAIN_BODY_BYTES
    import http.client

    drain_args: list[tuple[tuple, dict]] = []
    orig_read = http.client.HTTPResponse.read

    def tracked_read(self, *args, **kwargs):
        drain_args.append((args, kwargs))
        return orig_read(self, *args, **kwargs)

    monkeypatch.setattr(http.client.HTTPResponse, "read", tracked_read)

    host, port = mock_http_server
    client = HttpUpstreamClient(f"http://{host}:{port}/", allow_insecure=True)
    body, ct = client.fetch_project_page("safe-redirect")
    assert b'{"status": "ok"}' in body

    # Ensure no unbounded read() calls were made during redirect
    unbounded_reads = [args for args, kwargs in drain_args if not args or args[0] is None]
    assert len(unbounded_reads) == 0


def test_redirect_loop_bounded(mock_http_server) -> None:
    host, port = mock_http_server
    client = HttpUpstreamClient(f"http://{host}:{port}/", allow_insecure=True, max_redirects=2)

    with pytest.raises(UpstreamError) as exc_info:
        client.fetch_project_page("redirect-loop")
    assert "Redirect limit" in str(exc_info.value)


def test_resolve_file_url_allowlist_enforcement() -> None:
    client = HttpUpstreamClient(
        "https://pypi.org/simple/",
        file_hosts=["files.pythonhosted.org"],
    )

    # 1. Unlisted host refused before any connection
    with pytest.raises(UpstreamError) as exc_unlisted:
        client.resolve_file_url("https://unlisted-evil.example.com/pkg-1.0.whl", "my-pkg")
    assert "not allowlisted" in str(exc_unlisted.value)

    # 2. Insecure HTTP URL refused (requires HTTPS)
    with pytest.raises(InsecureUpstreamError):
        client.resolve_file_url("http://files.pythonhosted.org/pkg-1.0.whl", "my-pkg")

    # 3. URL with userinfo refused
    with pytest.raises(InsecureUpstreamError):
        client.resolve_file_url("https://user:secret@files.pythonhosted.org/pkg-1.0.whl", "my-pkg")

    # 4. Non-default port refused unless allowlisted
    with pytest.raises(UpstreamError):
        client.resolve_file_url("https://files.pythonhosted.org:8443/pkg-1.0.whl", "my-pkg")

    # 5. Allowlisted host accepted
    resolved = client.resolve_file_url("https://files.pythonhosted.org/pkg-1.0.whl", "my-pkg")
    assert resolved == "https://files.pythonhosted.org/pkg-1.0.whl"

    # 6. Relative URL resolved against index host (which is implicitly allowlisted)
    rel_resolved = client.resolve_file_url("packages/pkg-1.0.whl", "my-pkg")
    assert rel_resolved == "https://pypi.org/simple/my-pkg/packages/pkg-1.0.whl"

