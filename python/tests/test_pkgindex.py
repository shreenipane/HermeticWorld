
"""Offline pytest suite covering all Hermetic World package index requirements."""

from __future__ import annotations

from collections.abc import Iterator
import hashlib
import html.parser
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest

from hermetic_pkgindex import (
    MAX_HEADER_COUNT,
    MAX_HEADER_LINE_BYTES,
    MAX_REQUEST_LINE_BYTES,
    FrozenStore,
    HermeticHTTPServer,
    MissLog,
)

PEP691_MIME = "application/vnd.pypi.simple.v1+json"



def _write_dist_file(store_root: Path, filename: str, content: bytes) -> str:
    sha256 = hashlib.sha256(content).hexdigest()
    target_dir = store_root / "files" / sha256
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / filename).write_bytes(content)
    return sha256


def _write_project(
    store_root: Path,
    normalized_name: str,
    files: list[dict[str, object]],
) -> None:
    proj_dir = store_root / "simple" / normalized_name
    proj_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "meta": {"api-version": "1.0"},
        "name": normalized_name,
        "files": files,
    }
    (proj_dir / "index.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


@pytest.fixture()
def store_env(tmp_path: Path) -> dict[str, object]:
    """Populate a deterministic frozen store with two projects and distribution files."""
    store_root = tmp_path / "store"
    store_root.mkdir()

    wheel_bytes = b"PK\x03\x04fake-wheel-binary-content-0123456789"
    wheel_name = "demo_pkg-1.2.3-py3-none-any.whl"
    wheel_sha = _write_dist_file(store_root, wheel_name, wheel_bytes)

    sdist_bytes = b"fake-tar-gz-sdist-payload-abcdefghijklmnopqrstuvwxyz"
    sdist_name = "demo_pkg-1.2.3.tar.gz"
    sdist_sha = _write_dist_file(store_root, sdist_name, sdist_bytes)

    _write_project(
        store_root,
        "demo-pkg",
        [
            {
                "filename": wheel_name,
                "url": f"/files/{wheel_sha}/{wheel_name}",
                "hashes": {"sha256": wheel_sha},
                "requires-python": ">=3.11",
            },
            {
                "filename": sdist_name,
                "url": f"/files/{sdist_sha}/{sdist_name}",
                "hashes": {"sha256": sdist_sha},
            },
        ],
    )

    alpha_bytes = b"alpha-wheel-content"
    alpha_name = "alpha-0.1.0-py3-none-any.whl"
    alpha_sha = _write_dist_file(store_root, alpha_name, alpha_bytes)
    _write_project(
        store_root,
        "alpha",
        [
            {
                "filename": alpha_name,
                "url": f"/files/{alpha_sha}/{alpha_name}",
                "hashes": {"sha256": alpha_sha},
            }
        ],
    )

    misses_path = tmp_path / "misses.jsonl"
    return {
        "store_root": store_root,
        "misses_path": misses_path,
        "wheel_name": wheel_name,
        "wheel_bytes": wheel_bytes,
        "wheel_sha": wheel_sha,
        "sdist_name": sdist_name,
        "sdist_bytes": sdist_bytes,
        "sdist_sha": sdist_sha,
        "alpha_name": alpha_name,
        "alpha_bytes": alpha_bytes,
        "alpha_sha": alpha_sha,
    }


@pytest.fixture()
def running_server(store_env: dict[str, object]) -> Iterator[dict[str, object]]:
    """Start HermeticHTTPServer on an ephemeral port on 127.0.0.1 in a background thread."""
    store = FrozenStore(store_env["store_root"])  # type: ignore[arg-type]
    miss_log = MissLog(store_env["misses_path"])  # type: ignore[arg-type]
    server = HermeticHTTPServer(("127.0.0.1", 0), store=store, miss_log=miss_log)
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield {
            **store_env,
            "host": host,
            "port": port,
            "server": server,
            "miss_log": miss_log,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def _http_request(
    host: str,
    port: int,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=5.0)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        resp_body = resp.read()
        resp_headers = {k: v for k, v in resp.getheaders()}
        return resp.status, resp_headers, resp_body
    finally:
        conn.close()


def _assert_clean_headers(headers: dict[str, str], allowed: set[str]) -> None:
    lower_keys = {k.lower() for k in headers}
    assert "date" not in lower_keys
    assert "server" not in lower_keys
    assert "last-modified" not in lower_keys
    assert lower_keys <= allowed


def test_root_and_project_pages_html_and_json(running_server: dict[str, object]) -> None:
    """Requirement 1 & 2: PEP 503 HTML default, PEP 691 JSON via Accept, PEP 503 name normalization."""
    host = running_server["host"]  # type: ignore[assignment]
    port = running_server["port"]  # type: ignore[assignment]
    wheel_sha = running_server["wheel_sha"]  # type: ignore[assignment]
    wheel_name = running_server["wheel_name"]  # type: ignore[assignment]

    # Root /simple/ defaults to HTML
    status, headers, body = _http_request(host, port, "GET", "/simple/")
    assert status == 200
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert int(headers["Content-Length"]) == len(body)
    assert headers["ETag"].strip('"') == hashlib.sha256(body).hexdigest()
    _assert_clean_headers(headers, {"content-type", "content-length", "etag"})
    html_text = body.decode("utf-8")
    assert '<a href="/simple/alpha/">alpha</a>' in html_text
    assert '<a href="/simple/demo-pkg/">demo-pkg</a>' in html_text

    # Root /simple/ with PEP 691 Accept header returns JSON
    status, headers, body = _http_request(
        host,
        port,
        "GET",
        "/simple/",
        headers={"Accept": PEP691_MIME},
    )
    assert status == 200
    assert headers["Content-Type"] == PEP691_MIME
    _assert_clean_headers(headers, {"content-type", "content-length", "etag"})
    root_json = json.loads(body.decode("utf-8"))
    assert root_json == {
        "meta": {"api-version": "1.0"},
        "projects": [{"name": "alpha"}, {"name": "demo-pkg"}],
    }

    # Unnormalized project name in URL resolves via PEP 503 normalization
    status, headers, body = _http_request(host, port, "GET", "/simple/Demo_Pkg/")
    assert status == 200
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    _assert_clean_headers(headers, {"content-type", "content-length", "etag"})
    proj_html = body.decode("utf-8")
    assert f'/files/{wheel_sha}/{wheel_name}#sha256={wheel_sha}' in proj_html
    # PEP 503: "<" and ">" in the attribute value have to be encoded as &lt; and &gt;.
    assert 'data-requires-python="&gt;=3.11"' in proj_html
    assert 'data-requires-python=">=3.11"' not in proj_html
    parsed_requires: list[str | None] = []

    class _LinkParser(html.parser.HTMLParser):
        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            if tag == "a":
                attr_map = dict(attrs)
                if "data-requires-python" in attr_map:
                    parsed_requires.append(attr_map["data-requires-python"])

    _LinkParser().feed(proj_html)
    assert parsed_requires == [">=3.11"]

    # Project page JSON via Accept header
    status, headers, body = _http_request(
        host,
        port,
        "GET",
        "/simple/DEMO.PKG/",
        headers={"Accept": PEP691_MIME},
    )
    assert status == 200
    assert headers["Content-Type"] == PEP691_MIME
    _assert_clean_headers(headers, {"content-type", "content-length", "etag"})
    proj_json = json.loads(body.decode("utf-8"))
    assert proj_json["name"] == "demo-pkg"
    assert len(proj_json["files"]) == 2


def test_file_download_and_head_with_hash_check(running_server: dict[str, object]) -> None:
    """Requirement 2 & 4: File GET/HEAD download with SHA-256 ETag and exact headers."""
    host = running_server["host"]  # type: ignore[assignment]
    port = running_server["port"]  # type: ignore[assignment]
    wheel_sha = running_server["wheel_sha"]  # type: ignore[assignment]
    wheel_name = running_server["wheel_name"]  # type: ignore[assignment]
    wheel_bytes = running_server["wheel_bytes"]  # type: ignore[assignment]

    path = f"/files/{wheel_sha}/{wheel_name}"
    status, headers, body = _http_request(host, port, "GET", path)
    assert status == 200
    assert body == wheel_bytes
    assert headers["Content-Type"] == "application/octet-stream"
    assert int(headers["Content-Length"]) == len(wheel_bytes)
    assert headers["ETag"] == f'"{wheel_sha}"'
    _assert_clean_headers(headers, {"content-type", "content-length", "etag"})

    # HEAD returns identical metadata with empty body
    h_status, h_headers, h_body = _http_request(host, port, "HEAD", path)
    assert h_status == 200
    assert h_body == b""
    assert h_headers == headers


def test_corrupted_file_returns_500_and_logs(
    running_server: dict[str, object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Requirement 2: SHA-256 mismatch on stored file returns 500 and logs an error."""
    host = running_server["host"]  # type: ignore[assignment]
    port = running_server["port"]  # type: ignore[assignment]
    store_root: Path = running_server["store_root"]  # type: ignore[assignment]
    alpha_sha: str = running_server["alpha_sha"]  # type: ignore[assignment]
    alpha_name: str = running_server["alpha_name"]  # type: ignore[assignment]

    # Corrupt file bytes in place without changing directory name
    target = store_root / "files" / alpha_sha / alpha_name
    target.write_bytes(b"corrupted-bytes")

    caplog.clear()
    with caplog.at_level("ERROR", logger="hermetic_pkgindex"):
        status, headers, _ = _http_request(host, port, "GET", f"/files/{alpha_sha}/{alpha_name}")

    assert status == 500
    _assert_clean_headers(headers, {"content-type", "content-length"})
    assert any("SHA-256 mismatch" in rec.getMessage() for rec in caplog.records)


def test_single_range_requests(running_server: dict[str, object]) -> None:
    """Requirement 4: Single byte Range requests return 206 with exact slice and headers."""
    host = running_server["host"]  # type: ignore[assignment]
    port = running_server["port"]  # type: ignore[assignment]
    wheel_sha: str = running_server["wheel_sha"]  # type: ignore[assignment]
    wheel_name: str = running_server["wheel_name"]  # type: ignore[assignment]
    wheel_bytes: bytes = running_server["wheel_bytes"]  # type: ignore[assignment]
    path = f"/files/{wheel_sha}/{wheel_name}"

    # Explicit start-end
    status, headers, body = _http_request(
        host, port, "GET", path, headers={"Range": "bytes=2-9"}
    )
    assert status == 206
    assert body == wheel_bytes[2:10]
    assert int(headers["Content-Length"]) == 8
    assert headers["Content-Range"] == f"bytes 2-9/{len(wheel_bytes)}"
    assert headers["ETag"] == f'"{wheel_sha}"'
    _assert_clean_headers(headers, {"content-type", "content-length", "content-range", "etag"})

    # Open-ended start-
    status, headers, body = _http_request(
        host, port, "GET", path, headers={"Range": "bytes=10-"}
    )
    assert status == 206
    assert body == wheel_bytes[10:]
    assert headers["Content-Range"] == f"bytes 10-{len(wheel_bytes) - 1}/{len(wheel_bytes)}"

    # Suffix -N
    status, headers, body = _http_request(
        host, port, "GET", path, headers={"Range": "bytes=-5"}
    )
    assert status == 206
    assert body == wheel_bytes[-5:]

    # Unsatisfiable range -> 416
    status, headers, _ = _http_request(
        host, port, "GET", path, headers={"Range": "bytes=99999-"}
    )
    assert status == 416
    _assert_clean_headers(headers, {"content-type", "content-length", "content-range"})


def test_404_recorded_as_miss_without_timestamps_and_capped(
    running_server: dict[str, object],
    tmp_path: Path,
) -> None:
    """Requirement 3: 404s for projects/files append atomic sequence-numbered JSONL with no timestamps."""
    host = running_server["host"]  # type: ignore[assignment]
    port = running_server["port"]  # type: ignore[assignment]
    misses_path: Path = running_server["misses_path"]  # type: ignore[assignment]

    status1, headers1, _ = _http_request(host, port, "GET", "/simple/Missing_Pkg/")
    assert status1 == 404
    _assert_clean_headers(headers1, {"content-type", "content-length"})

    missing_sha = "a" * 64
    status2, headers2, _ = _http_request(host, port, "GET", f"/files/{missing_sha}/nope-1.0.whl")
    assert status2 == 404
    _assert_clean_headers(headers2, {"content-type", "content-length"})

    # Unknown non-project/non-file path returns 404 without polluting project/file miss log
    status3, _, _ = _http_request(host, port, "GET", "/unknown/route")
    assert status3 == 404

    lines = misses_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2

    rec1 = json.loads(lines[0])
    rec2 = json.loads(lines[1])
    assert rec1 == {
        "kind": "project",
        "path": "/simple/Missing_Pkg/",
        "project": "missing-pkg",
        "seq": 1,
    }
    assert rec2 == {
        "filename": "nope-1.0.whl",
        "kind": "file",
        "path": f"/files/{missing_sha}/nope-1.0.whl",
        "seq": 2,
        "sha256": missing_sha,
    }
    for rec in (rec1, rec2):
        assert not any("time" in k or "date" in k for k in rec)

    # Verify size cap on MissLog keeps file <= max_bytes with valid JSON lines
    capped_path = tmp_path / "capped_misses.jsonl"
    capped_log = MissLog(capped_path, max_bytes=180)
    for i in range(10):
        seq = capped_log.record_project_miss(f"pkg-{i}", f"/simple/pkg-{i}/")
        assert seq == i + 1
    assert capped_path.stat().st_size <= 180
    kept = [json.loads(line) for line in capped_path.read_text(encoding="utf-8").splitlines()]
    assert len(kept) >= 2
    assert kept[-1]["seq"] == 10


def test_methods_405_and_unknown_paths_404(running_server: dict[str, object]) -> None:
    """Requirement 2: POST and other methods return 405; unknown paths return 404."""
    host = running_server["host"]  # type: ignore[assignment]
    port = running_server["port"]  # type: ignore[assignment]

    for method in ("POST", "PUT", "DELETE", "PATCH"):
        status, headers, _ = _http_request(
            host,
            port,
            method,
            "/simple/",
            headers={"Content-Type": "application/json"},
            body=b"{}",
        )
        assert status == 405
        _assert_clean_headers(headers, {"content-type", "content-length"})

    for unknown in ("/", "/simple", "/simple/demo-pkg", "/files/", "/files/abc/def"):
        status, headers, _ = _http_request(host, port, "GET", unknown)
        assert status == 404
        _assert_clean_headers(headers, {"content-type", "content-length"})


def test_request_hygiene_traversal_caps_http_version_and_single_request_per_conn(
    running_server: dict[str, object],
) -> None:
    """Requirement 5: Traversal refused, size caps enforced, HTTP/1.1 only, 1 req/conn."""
    host: str = running_server["host"]  # type: ignore[assignment]
    port: int = running_server["port"]  # type: ignore[assignment]

    # Traversal attempts: "..", encoded "..", encoded "/", NUL, backslash
    bad_paths = [
        "/simple/../secret/",
        "/simple/%2e%2e/secret/",
        "/files/" + ("b" * 64) + "/foo%2fbar.whl",
        "/files/" + ("b" * 64) + "/foo%2Fbar.whl",
        "/files/" + ("b" * 64) + "/foo%00bar.whl",
        "/files/" + ("b" * 64) + "/foo\\bar.whl",
        "/files/" + ("b" * 64) + "/foo%5cbar.whl",
    ]
    for bad in bad_paths:
        status, headers, _ = _http_request(host, port, "GET", bad)
        assert status == 400
        _assert_clean_headers(headers, {"content-type", "content-length"})

    # HTTP/1.0 rejected with 505
    with socket.create_connection((host, port), timeout=5.0) as sock:
        sock.sendall(b"GET /simple/ HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
    assert raw.startswith(b"HTTP/1.1 505 ")
    assert b"\r\nDate:" not in raw
    assert b"\r\nServer:" not in raw

    # One request per connection: second pipelined/sequential request on same socket sees EOF
    with socket.create_connection((host, port), timeout=5.0) as sock:
        sock.sendall(b"GET /simple/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        resp1 = b""
        while b"\r\n\r\n" not in resp1:
            part = sock.recv(4096)
            assert part
            resp1 += part
        header_blob, _, rest = resp1.partition(b"\r\n\r\n")
        assert header_blob.startswith(b"HTTP/1.1 200 ")
        cl_line = [ln for ln in header_blob.split(b"\r\n") if ln.lower().startswith(b"content-length:")][0]
        cl = int(cl_line.split(b":", 1)[1].strip())
        while len(rest) < cl:
            part = sock.recv(4096)
            assert part
            rest += part
        # Server must close connection immediately after the first response
        assert sock.recv(1) == b""

    # Request target size cap enforced (414)
    oversized_target = "/simple/" + ("a" * (MAX_REQUEST_LINE_BYTES + 32)) + "/"
    status, headers, _ = _http_request(host, port, "GET", oversized_target)
    assert status == 414
    _assert_clean_headers(headers, {"content-type", "content-length"})

    # Single header line size cap enforced (431)
    status, headers, _ = _http_request(
        host,
        port,
        "GET",
        "/simple/",
        headers={"X-Huge": "x" * (MAX_HEADER_LINE_BYTES + 32)},
    )
    assert status == 431
    _assert_clean_headers(headers, {"content-type", "content-length"})

    # Header count cap enforced (431)
    many_headers = {f"X-H-{i}": "1" for i in range(MAX_HEADER_COUNT + 5)}
    status, headers, _ = _http_request(host, port, "GET", "/simple/", headers=many_headers)
    assert status == 431
    _assert_clean_headers(headers, {"content-type", "content-length"})


def test_symlinks_inside_store_never_served(
    running_server: dict[str, object],
    tmp_path: Path,
) -> None:
    """Rules: Symlinks inside the store (files or project directories) are never served."""
    host: str = running_server["host"]  # type: ignore[assignment]
    port: int = running_server["port"]  # type: ignore[assignment]
    store_root: Path = running_server["store_root"]  # type: ignore[assignment]

    secret_file = tmp_path / "outside_secret.txt"
    secret_bytes = b"TOP-SECRET-OUTSIDE-STORE"
    secret_file.write_bytes(secret_bytes)
    secret_sha = hashlib.sha256(secret_bytes).hexdigest()

    # Symlinked distribution file inside store
    sym_file_dir = store_root / "files" / secret_sha
    sym_file_dir.mkdir(parents=True, exist_ok=True)
    sym_file = sym_file_dir / "leak-1.0.whl"
    os.symlink(secret_file, sym_file)

    status, headers, body = _http_request(host, port, "GET", f"/files/{secret_sha}/leak-1.0.whl")
    assert status == 403
    assert secret_bytes not in body
    _assert_clean_headers(headers, {"content-type", "content-length"})

    # Symlinked project directory inside store
    outside_proj = tmp_path / "outside_proj"
    outside_proj.mkdir()
    (outside_proj / "index.json").write_text('{"name":"evil","files":[]}', encoding="utf-8")
    os.symlink(outside_proj, store_root / "simple" / "evil")

    # Must not appear in /simple/ listing and must be refused directly
    _, _, root_body = _http_request(host, port, "GET", "/simple/")
    assert b"evil" not in root_body

    status, headers, _ = _http_request(host, port, "GET", "/simple/evil/")
    assert status == 403
    _assert_clean_headers(headers, {"content-type", "content-length"})


def test_cli_entrypoint(store_env: dict[str, object], tmp_path: Path) -> None:
    """Requirement 6: CLI python -m hermetic_pkgindex --store DIR --bind 127.0.0.1:PORT --misses FILE."""
    # Find an unused ephemeral port on 127.0.0.1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    cli_misses = tmp_path / "cli_misses.jsonl"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "hermetic_pkgindex",
            "--store",
            str(store_env["store_root"]),
            "--bind",
            f"127.0.0.1:{port}",
            "--misses",
            str(cli_misses),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        # Poll until listening
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                status, headers, _ = _http_request(
                    "127.0.0.1", port, "GET", "/simple/", headers={"Accept": PEP691_MIME}
                )
                assert status == 200
                _assert_clean_headers(headers, {"content-type", "content-length", "etag"})
                break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("CLI server did not start listening within 5 seconds")

        miss_status, _, _ = _http_request("127.0.0.1", port, "GET", "/simple/cli-miss/")
        assert miss_status == 404
        recorded = json.loads(cli_misses.read_text(encoding="utf-8").strip())
        assert recorded["project"] == "cli-miss"
        assert recorded["seq"] == 1
    finally:
        proc.terminate()
        proc.wait(timeout=5.0)




def _raw_exchange(host: str, port: int, payload: bytes, timeout: float = 5.0) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(payload)
        raw = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except ConnectionResetError:
                break
            if not chunk:
                break
            raw += chunk
    return raw


def test_http09_version_claim_cannot_suppress_status_line(
    running_server: dict[str, object],
) -> None:
    """A client claiming HTTP/0.9 must still get a framed 505, never a bare body."""
    host: str = running_server["host"]  # type: ignore[assignment]
    port: int = running_server["port"]  # type: ignore[assignment]
    raw = _raw_exchange(host, port, b"GET /simple/ HTTP/0.9\r\nHost: x\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 505 ")
    assert b"\r\nContent-Length: " in raw


def test_forbidden_response_never_names_host_paths(
    running_server: dict[str, object],
    tmp_path: Path,
) -> None:
    """Refusals for symlinked store objects must not reveal absolute host paths."""
    host: str = running_server["host"]  # type: ignore[assignment]
    port: int = running_server["port"]  # type: ignore[assignment]
    store_root: Path = running_server["store_root"]  # type: ignore[assignment]

    secret = tmp_path / "outside.bin"
    secret.write_bytes(b"outside")
    sha = hashlib.sha256(b"outside").hexdigest()
    (store_root / "files" / sha).mkdir(parents=True)
    os.symlink(secret, store_root / "files" / sha / "x-1.0.whl")
    outside_proj = tmp_path / "outside_proj2"
    outside_proj.mkdir()
    (outside_proj / "index.json").write_text('{"files":[]}', encoding="utf-8")
    os.symlink(outside_proj, store_root / "simple" / "evil2")

    for path in (f"/files/{sha}/x-1.0.whl", "/simple/evil2/"):
        status, _, body = _http_request(host, port, "GET", path)
        assert status == 403
        assert str(tmp_path).encode() not in body
        assert b"/" not in body.strip()


def test_slow_header_drip_is_cut_by_request_deadline(store_env: dict[str, object]) -> None:
    """A client dripping header bytes under the per-recv timeout is cut at the deadline."""
    store = FrozenStore(store_env["store_root"])  # type: ignore[arg-type]
    miss_log = MissLog(store_env["misses_path"])  # type: ignore[arg-type]
    server = HermeticHTTPServer(
        ("127.0.0.1", 0),
        store=store,
        miss_log=miss_log,
        socket_timeout=5.0,
        request_read_deadline=0.5,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        with socket.create_connection((host, port), timeout=5.0) as sock:
            sock.sendall(b"GET /simple/ HTTP/1.1\r\nHost: x\r\n")
            started = time.monotonic()
            closed = False
            for i in range(40):
                try:
                    sock.sendall(f"X-Drip-{i}: y\r\n".encode())
                except OSError:
                    closed = True
                    break
                sock.settimeout(0.1)
                try:
                    data = sock.recv(4096)
                    if data == b"":
                        closed = True
                        break
                except TimeoutError:
                    pass
                except OSError:
                    closed = True
                    break
            assert closed
            assert time.monotonic() - started < 3.0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


@pytest.mark.parametrize(
    "head",
    [
        b"GET /simple/ HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n folded\r\n\r\n",
        b"GET /simple/ HTTP/1.1\r\nHost : x\r\n\r\n",
        b"GET /simple/ HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n",
        b"GET /simple/ HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        b"GET /simple/ HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"GET /simple/ HTTP/1.1\r\nAccept: */*\r\n\r\n",
        b"GET /simple/ HTTP/1.1\r\nHost: x\r\nX-B: a\rb\r\n\r\n",
    ],
)
def test_ambiguous_request_heads_refused(running_server: dict[str, object], head: bytes) -> None:
    """Folding, padded names, repeated framing headers and a missing Host are refused."""
    host: str = running_server["host"]  # type: ignore[assignment]
    port: int = running_server["port"]  # type: ignore[assignment]
    raw = _raw_exchange(host, port, head)
    assert raw.startswith(b"HTTP/1.1 400 ")


def test_range_with_huge_offsets_is_416_not_500(running_server: dict[str, object]) -> None:
    """Range offsets longer than the digit cap are unsatisfiable, not an internal error."""
    host: str = running_server["host"]  # type: ignore[assignment]
    port: int = running_server["port"]  # type: ignore[assignment]
    path = f"/files/{running_server['wheel_sha']}/{running_server['wheel_name']}"
    for value in ("bytes=" + "9" * 5000 + "-", "bytes=0-" + "9" * 5000, "bytes=-" + "9" * 5000):
        status, _, _ = _http_request(host, port, "GET", path, headers={"Range": value})
        assert status == 416


def test_encoded_control_characters_refused(running_server: dict[str, object]) -> None:
    """Percent-encoded control characters in the path are refused before any lookup."""
    host: str = running_server["host"]  # type: ignore[assignment]
    port: int = running_server["port"]  # type: ignore[assignment]
    misses_path: Path = running_server["misses_path"]  # type: ignore[assignment]
    for bad in ("/files/" + "c" * 64 + "/foo%0abar.whl", "/simple/a%0d%0ab/", "/files/" + "c" * 64 + "/x%7f.whl"):
        status, _, _ = _http_request(host, port, "GET", bad)
        assert status == 400
    assert not misses_path.exists()


def test_unnormalised_project_directory_not_listed(store_env: dict[str, object]) -> None:
    """Only directories reachable by their normalised name are advertised."""
    store_root: Path = store_env["store_root"]  # type: ignore[assignment]
    _write_project(store_root, "Odd_Name", [])
    store = FrozenStore(store_root)
    assert store.list_projects() == ["alpha", "demo-pkg"]


def test_file_replaced_after_verification_is_not_streamed(store_env: dict[str, object]) -> None:
    """Bytes are streamed only from the inode whose digest was verified."""
    store_root: Path = store_env["store_root"]  # type: ignore[assignment]
    store = FrozenStore(store_root)
    sha: str = store_env["alpha_sha"]  # type: ignore[assignment]
    name: str = store_env["alpha_name"]  # type: ignore[assignment]
    original: bytes = store_env["alpha_bytes"]  # type: ignore[assignment]
    verified = store.verify_and_prepare_file(sha, name)
    target = store_root / "files" / sha / name
    replacement = store_root / "files" / sha / "tmp-replacement"
    replacement.write_bytes(b"X" * len(original))
    os.replace(replacement, target)
    from hermetic_pkgindex import IntegrityError

    with pytest.raises(IntegrityError):
        b"".join(store.iter_file_range(verified, 0, verified.size - 1))


def test_failure_after_headers_sent_never_appends_second_response(
    running_server: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An error while streaming closes the connection instead of writing another status line."""
    host: str = running_server["host"]  # type: ignore[assignment]
    port: int = running_server["port"]  # type: ignore[assignment]
    server: HermeticHTTPServer = running_server["server"]  # type: ignore[assignment]
    from hermetic_pkgindex import IntegrityError

    def _broken(*_args: object, **_kwargs: object) -> Iterator[bytes]:
        yield b"PK"
        raise IntegrityError("simulated mid-stream failure")

    monkeypatch.setattr(server.store, "iter_file_range", _broken)
    path = f"/files/{running_server['wheel_sha']}/{running_server['wheel_name']}"
    raw = _raw_exchange(host, port, f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    assert raw.startswith(b"HTTP/1.1 200 ")
    assert raw.count(b"HTTP/1.1 ") == 1
