"""Tests covering the RecordingProxyServer HTTP server, recording, verification, and errors."""

from __future__ import annotations

from collections.abc import Iterator
import hashlib
import http.client
import json
from pathlib import Path
import threading
import pytest

from hermetic_pkgrec.constants import PEP503_HTML_MIME, PEP691_JSON_MIME
from hermetic_pkgrec.manifest import Manifest
from hermetic_pkgrec.server import RecordingProxyServer
from hermetic_pkgrec.store import RecordingStore
from hermetic_pkgrec.upstream import FixtureUpstreamClient, HttpUpstreamClient


def _http_get(host: str, port: int, path: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=5.0)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        body = resp.read()
        return resp.status, resp_headers, body
    finally:
        conn.close()


def _http_method(host: str, port: int, method: str, path: str) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection(host, port, timeout=5.0)
    try:
        conn.request(method, path)
        resp = conn.getresponse()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        body = resp.read()
        return resp.status, resp_headers, body
    finally:
        conn.close()


@pytest.fixture()
def test_env(tmp_path: Path):
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    misses_path = tmp_path / "misses.jsonl"
    cutoff = "2023-01-01T00:00:00Z"

    # Known files
    whl_bytes = b"tiny-wheel"
    whl_sha = hashlib.sha256(whl_bytes).hexdigest()
    whl_name = "demo_pkg-1.0.0-py3-none-any.whl"

    corrupt_bytes = b"corrupted-file-content"
    corrupt_name = "demo_pkg-1.0.1-py3-none-any.whl"
    expected_sha_corrupt = "e" * 64

    oversize_bytes = b"oversize-content-too-large-exceeding-cap"
    oversize_name = "demo_pkg-1.0.2-py3-none-any.whl"
    oversize_sha = hashlib.sha256(oversize_bytes).hexdigest()

    upstream_project_payload = {
        "meta": {"api-version": "1.0"},
        "name": "demo-pkg",
        "files": [
            {
                "filename": whl_name,
                "url": f"https://upstream.test/packages/{whl_name}",
                "hashes": {"sha256": whl_sha},
                "upload-time": "2022-06-01T00:00:00Z",
                "yanked": False,
            },
            {
                # Corrupt hash file: declared sha256 does not match actual bytes!
                "filename": corrupt_name,
                "url": f"https://upstream.test/packages/{corrupt_name}",
                "hashes": {"sha256": expected_sha_corrupt},
                "upload-time": "2022-07-01T00:00:00Z",
                "yanked": False,
            },
            {
                # Oversize file
                "filename": oversize_name,
                "url": f"https://upstream.test/packages/{oversize_name}",
                "hashes": {"sha256": oversize_sha},
                "upload-time": "2022-08-01T00:00:00Z",
                "yanked": False,
            },
            {
                # Dropped after cutoff:
                "filename": "demo_pkg-2.0.0-py3-none-any.whl",
                "url": "https://upstream.test/packages/demo_pkg-2.0.0-py3-none-any.whl",
                "hashes": {"sha256": "9" * 64},
                "upload-time": "2023-01-02T00:00:00Z",
                "yanked": False,
            },
            {
                # Missing upload-time:
                "filename": "demo_pkg-0.1.0-py3-none-any.whl",
                "url": "https://upstream.test/packages/demo_pkg-0.1.0-py3-none-any.whl",
                "hashes": {"sha256": "8" * 64},
                "yanked": False,
            },
            {
                # Yanked after cutoff -> served as not yanked:
                "filename": "demo_pkg-1.0.3-py3-none-any.whl",
                "url": "https://upstream.test/packages/demo_pkg-1.0.3-py3-none-any.whl",
                "hashes": {"sha256": "7" * 64},
                "upload-time": "2022-09-01T00:00:00Z",
                "yanked": "Vulnerability discovered later",
                "yank_time": "2023-05-01T00:00:00Z",
            },
            {
                # Unknown yank date -> served as not yanked and listed:
                "filename": "demo_pkg-1.0.4-py3-none-any.whl",
                "url": "https://upstream.test/packages/demo_pkg-1.0.4-py3-none-any.whl",
                "hashes": {"sha256": "6" * 64},
                "upload-time": "2022-10-01T00:00:00Z",
                "yanked": True,
            },
        ],
    }

    upstream = FixtureUpstreamClient(
        projects={"demo-pkg": upstream_project_payload},
        files={
            whl_name: whl_bytes,
            f"https://upstream.test/packages/{whl_name}": whl_bytes,
            corrupt_name: corrupt_bytes,
            f"https://upstream.test/packages/{corrupt_name}": corrupt_bytes,
            oversize_name: oversize_bytes,
            f"https://upstream.test/packages/{oversize_name}": oversize_bytes,
        },
    )

    store = RecordingStore(store_dir, max_dist_bytes=len(oversize_bytes) - 5)
    manifest = Manifest(cutoff=cutoff)

    server = RecordingProxyServer(
        ("127.0.0.1", 0),
        upstream=upstream,
        store=store,
        manifest=manifest,
        cutoff=cutoff,
        manifest_path=manifest_path,
        miss_log_path=misses_path,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield {
        "host": host,
        "port": port,
        "server": server,
        "store": store,
        "manifest": manifest,
        "manifest_path": manifest_path,
        "misses_path": misses_path,
        "whl_name": whl_name,
        "whl_sha": whl_sha,
        "whl_bytes": whl_bytes,
        "corrupt_name": corrupt_name,
        "expected_sha_corrupt": expected_sha_corrupt,
        "oversize_name": oversize_name,
        "oversize_sha": oversize_sha,
    }

    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


def test_proxy_root_index(test_env) -> None:
    host, port = test_env["host"], test_env["port"]
    upstream = test_env["server"].upstream

    # Initial state: no project page has been requested yet.
    # Root index is empty and requesting it generates no upstream requests.
    status, headers, body = _http_get(host, port, "/simple/", {"Accept": PEP691_JSON_MIME})
    assert status == 200
    assert PEP691_JSON_MIME in headers["content-type"]
    assert "date" not in headers
    assert "server" not in headers

    parsed = json.loads(body.decode("utf-8"))
    assert parsed["meta"]["api-version"] == "1.0"
    assert parsed["projects"] == []
    assert upstream.request_count == 0

    # Request project page to admit demo-pkg
    status_p, _, _ = _http_get(host, port, "/simple/demo-pkg/", {"Accept": PEP691_JSON_MIME})
    assert status_p == 200
    assert upstream.request_count == 1

    # Project is now listed in root index; root index request makes no upstream requests
    status_r, _, body_r = _http_get(host, port, "/simple/", {"Accept": PEP691_JSON_MIME})
    assert status_r == 200
    parsed_r = json.loads(body_r.decode("utf-8"))
    project_names = [p["name"] for p in parsed_r["projects"]]
    assert "demo-pkg" in project_names
    assert upstream.request_count == 1


def test_proxy_project_page_filtering_and_rewriting(test_env) -> None:
    host, port = test_env["host"], test_env["port"]
    status, headers, body = _http_get(host, port, "/simple/demo-pkg/", {"Accept": PEP691_JSON_MIME})
    assert status == 200
    assert PEP691_JSON_MIME in headers["content-type"]

    parsed = json.loads(body.decode("utf-8"))
    files = parsed["files"]
    filenames = [f["filename"] for f in files]

    # Kept:
    assert test_env["whl_name"] in filenames
    # Dropped after cutoff:
    assert "demo_pkg-2.0.0-py3-none-any.whl" not in filenames
    # Missing upload-time refused:
    assert "demo_pkg-0.1.0-py3-none-any.whl" not in filenames

    file_by_name = {f["filename"]: f for f in files}

    # Verify URLs were rewritten to proxy /files/<sha256>/<filename>:
    assert file_by_name[test_env["whl_name"]]["url"] == f"/files/{test_env['whl_sha']}/{test_env['whl_name']}"

    # Yanked after cutoff -> served as not yanked:
    assert file_by_name["demo_pkg-1.0.3-py3-none-any.whl"].get("yanked") in (False, None)

    # Unknown yank date -> served as not yanked:
    assert file_by_name["demo_pkg-1.0.4-py3-none-any.whl"].get("yanked") in (False, None)

    # Check manifest has recorded the refused undated and unyanked files:
    manifest = test_env["manifest"]
    assert any(x["filename"] == "demo_pkg-0.1.0-py3-none-any.whl" for x in manifest.missing_upload_time)
    assert any(x["filename"] == "demo_pkg-1.0.3-py3-none-any.whl" for x in manifest.unyanked_after_cutoff)
    assert any(x["filename"] == "demo_pkg-1.0.4-py3-none-any.whl" for x in manifest.unyanked_unknown_date)


def test_proxy_file_fetch_and_recording(test_env) -> None:
    host, port = test_env["host"], test_env["port"]
    whl_name = test_env["whl_name"]
    whl_sha = test_env["whl_sha"]
    whl_bytes = test_env["whl_bytes"]

    # Before fetch, store does not have file.
    store = test_env["store"]
    assert not store.has_file(whl_sha, whl_name)

    # First fetch project page so proxy registers upstream URL.
    _http_get(host, port, "/simple/demo-pkg/")

    # Fetch file.
    status, headers, body = _http_get(host, port, f"/files/{whl_sha}/{whl_name}")
    assert status == 200
    assert body == whl_bytes
    assert headers["content-length"] == str(len(whl_bytes))
    assert headers["etag"] == f'"{whl_sha}"'

    # Now store must have the file!
    assert store.has_file(whl_sha, whl_name)

    # Manifest must have recorded the file!
    manifest = test_env["manifest"]
    recorded = [f for f in manifest.files if f.filename == whl_name]
    assert len(recorded) == 1
    assert recorded[0].sha256 == whl_sha
    assert recorded[0].project == "demo-pkg"

    # Manifest file on disk must be updated.
    manifest_file = test_env["manifest_path"]
    assert manifest_file.is_file()
    disk_manifest = Manifest.load(manifest_file)
    assert any(f.filename == whl_name for f in disk_manifest.files)

    # Subsequent fetch serves from store directly.
    status2, _, body2 = _http_get(host, port, f"/files/{whl_sha}/{whl_name}")
    assert status2 == 200
    assert body2 == whl_bytes


def test_proxy_file_fetch_store_hit_records_manifest(test_env) -> None:
    host, port = test_env["host"], test_env["port"]
    whl_name = test_env["whl_name"]
    whl_sha = test_env["whl_sha"]
    whl_bytes = test_env["whl_bytes"]
    store = test_env["store"]
    manifest = test_env["manifest"]
    manifest_file = test_env["manifest_path"]

    # Pre-populate store (simulating reuse of store across sessions)
    store.save_file_stream(whl_sha, whl_name, [whl_bytes])
    assert store.has_file(whl_sha, whl_name)
    assert not any(f.filename == whl_name for f in manifest.files)

    # Fetch project page so proxy registers known file metadata
    _http_get(host, port, "/simple/demo-pkg/")

    # Fetch file (store hit)
    status, _, body = _http_get(host, port, f"/files/{whl_sha}/{whl_name}")
    assert status == 200
    assert body == whl_bytes

    # Manifest must now have recorded the file even though it was a store hit!
    assert any(f.filename == whl_name for f in manifest.files)
    disk_manifest = Manifest.load(manifest_file)
    assert any(f.filename == whl_name for f in disk_manifest.files)


def test_manifest_error_handled_with_500(test_env, monkeypatch) -> None:
    from hermetic_pkgrec.errors import ManifestError

    host, port = test_env["host"], test_env["port"]
    whl_name = test_env["whl_name"]
    whl_sha = test_env["whl_sha"]

    _http_get(host, port, "/simple/demo-pkg/")

    def mock_record_file(*args, **kwargs):
        raise ManifestError("Manifest file limit reached.")

    monkeypatch.setattr(test_env["manifest"], "record_file", mock_record_file)

    status, _, _ = _http_get(host, port, f"/files/{whl_sha}/{whl_name}")
    assert status == 500


def test_hash_mismatch_refused(test_env) -> None:
    host, port = test_env["host"], test_env["port"]
    corrupt_name = test_env["corrupt_name"]
    expected_sha = test_env["expected_sha_corrupt"]

    # Register in proxy:
    _http_get(host, port, "/simple/demo-pkg/")

    # Fetching the corrupt file must fail!
    status, _, _ = _http_get(host, port, f"/files/{expected_sha}/{corrupt_name}")
    assert status == 502  # Bad Gateway (hash mismatch refused)

    # File must NOT be saved in the store!
    store = test_env["store"]
    assert not store.has_file(expected_sha, corrupt_name)

    # File must NOT be in manifest!
    manifest = test_env["manifest"]
    assert not any(f.filename == corrupt_name for f in manifest.files)


def test_oversize_refused(test_env) -> None:
    host, port = test_env["host"], test_env["port"]
    oversize_name = test_env["oversize_name"]
    oversize_sha = test_env["oversize_sha"]

    _http_get(host, port, "/simple/demo-pkg/")

    status, _, _ = _http_get(host, port, f"/files/{oversize_sha}/{oversize_name}")
    assert status == 502  # Bad Gateway (oversize refused)

    store = test_env["store"]
    assert not store.has_file(oversize_sha, oversize_name)
    assert not any(f.filename == oversize_name for f in test_env["manifest"].files)


def test_method_not_allowed(test_env) -> None:
    host, port = test_env["host"], test_env["port"]
    status, headers, _ = _http_method(host, port, "POST", "/simple/demo-pkg/")
    assert status == 405
    assert "GET, HEAD" in headers.get("allow", "")


def test_misses_logging(test_env) -> None:
    host, port = test_env["host"], test_env["port"]
    status, _, _ = _http_get(host, port, "/simple/nonexistent-project/")
    assert status == 404

    misses_file = test_env["misses_path"]
    assert misses_file.is_file()
    lines = misses_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 1
    last_record = json.loads(lines[-1])
    assert last_record["kind"] == "project"
    assert last_record["name"] == "nonexistent-project"


def test_root_index_local_rendering_and_upstream_only_hidden(tmp_path: Path) -> None:
    """Item 1: Root index rendered locally (both HTML & JSON), upstream-only project never appears."""
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    cutoff = "2023-01-01T00:00:00Z"

    upstream = FixtureUpstreamClient(
        projects={
            "admitted-pkg": {
                "meta": {"api-version": "1.0"},
                "name": "admitted-pkg",
                "files": [
                    {
                        "filename": "admitted_pkg-1.0.0-py3-none-any.whl",
                        "url": "https://upstream.test/packages/admitted_pkg-1.0.0.whl",
                        "hashes": {"sha256": "1" * 64},
                        "upload-time": "2022-06-01T00:00:00Z",  # at cutoff
                        "yanked": False,
                    }
                ],
            },
            "upstream-only-pkg": {
                "meta": {"api-version": "1.0"},
                "name": "upstream-only-pkg",
                "files": [
                    {
                        "filename": "upstream_only_pkg-2.0.0-py3-none-any.whl",
                        "url": "https://upstream.test/packages/upstream_only_pkg-2.0.0.whl",
                        "hashes": {"sha256": "2" * 64},
                        "upload-time": "2024-01-01T00:00:00Z",  # after cutoff!
                        "yanked": False,
                    }
                ],
            },
        },
        root_projects=["admitted-pkg", "upstream-only-pkg"],
    )

    store = RecordingStore(store_dir)
    manifest = Manifest(cutoff=cutoff)
    server = RecordingProxyServer(
        ("127.0.0.1", 0),
        upstream=upstream,
        store=store,
        manifest=manifest,
        cutoff=cutoff,
        manifest_path=manifest_path,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # 1. Assert empty root index before any project page is requested
        # and verify requesting root index makes no upstream requests.
        status_empty_json, headers_empty_j, body_empty_json = _http_get(
            host, port, "/simple/", {"Accept": PEP691_JSON_MIME}
        )
        assert status_empty_json == 200
        assert PEP691_JSON_MIME in headers_empty_j["content-type"]
        parsed_empty = json.loads(body_empty_json.decode("utf-8"))
        assert parsed_empty["meta"]["api-version"] == "1.0"
        assert parsed_empty["projects"] == []
        assert upstream.request_count == 0

        status_empty_html, headers_empty_h, body_empty_html = _http_get(
            host, port, "/simple/", {"Accept": PEP503_HTML_MIME}
        )
        assert status_empty_html == 200
        assert "text/html" in headers_empty_h["content-type"]
        empty_html = body_empty_html.decode("utf-8")
        assert "admitted-pkg" not in empty_html
        assert "upstream-only-pkg" not in empty_html
        assert upstream.request_count == 0

        # 2. Request page for upstream-only project (files only after cutoff -> 0 admitted files)
        status_u, _, _ = _http_get(host, port, "/simple/upstream-only-pkg/", {"Accept": PEP691_JSON_MIME})
        assert status_u == 200
        assert upstream.request_count == 1  # 1 upstream request for project page

        # Root index still contains nothing; upstream-only project is never listed
        status_mid_j, _, body_mid_j = _http_get(host, port, "/simple/", {"Accept": PEP691_JSON_MIME})
        assert status_mid_j == 200
        parsed_mid = json.loads(body_mid_j.decode("utf-8"))
        assert parsed_mid["projects"] == []
        assert upstream.request_count == 1  # Requesting root index makes no upstream request

        # 3. Request page for admitted project (has file at/before cutoff -> admitted)
        status_a, _, _ = _http_get(host, port, "/simple/admitted-pkg/", {"Accept": PEP691_JSON_MIME})
        assert status_a == 200
        assert upstream.request_count == 2  # 2 upstream requests total

        # 4. Now root index lists admitted-pkg, but upstream-only project is never listed.
        # Requesting root index makes no upstream request at all.
        # Check PEP 691 JSON
        status, headers, body = _http_get(host, port, "/simple/", {"Accept": PEP691_JSON_MIME})
        assert status == 200
        assert PEP691_JSON_MIME in headers["content-type"]
        parsed = json.loads(body.decode("utf-8"))
        assert parsed["meta"]["api-version"] == "1.0"
        project_names = [p["name"] for p in parsed["projects"]]
        assert "admitted-pkg" in project_names
        assert "upstream-only-pkg" not in project_names
        assert upstream.request_count == 2  # Still 2: no upstream request made for root index!

        # Check PEP 503 HTML
        status_h, headers_h, body_h = _http_get(host, port, "/simple/", {"Accept": PEP503_HTML_MIME})
        assert status_h == 200
        assert "text/html" in headers_h["content-type"]
        html_text = body_h.decode("utf-8")
        assert '<a href="/simple/admitted-pkg/">admitted-pkg</a>' in html_text
        assert "upstream-only-pkg" not in html_text
        assert upstream.request_count == 2  # Still 2: no upstream request made for root index!
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_server_refuses_unlisted_host_http_and_userinfo_page(tmp_path: Path) -> None:
    """Item 2: Refuse unlisted file host, HTTP scheme, and userinfo before connection."""
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    cutoff = "2023-01-01T00:00:00Z"

    # Upstream client with allowlist of files.pythonhosted.org
    http_upstream = HttpUpstreamClient(
        "https://pypi.org/simple/",
        file_hosts=["files.pythonhosted.org"],
    )

    # 1. Page with unlisted host
    class MockUnlistedUpstream(FixtureUpstreamClient):
        def resolve_file_url(self, file_url: str, project: str) -> str:
            return http_upstream.resolve_file_url(file_url, project)

    evil_upstream = MockUnlistedUpstream(
        projects={
            "evil-pkg": {
                "meta": {"api-version": "1.0"},
                "name": "evil-pkg",
                "files": [
                    {
                        "filename": "evil_pkg-1.0.0.whl",
                        "url": "https://evil.unlisted-host.com/evil_pkg-1.0.0.whl",
                        "hashes": {"sha256": "e" * 64},
                        "upload-time": "2022-01-01T00:00:00Z",
                        "yanked": False,
                    }
                ],
            },
            "http-pkg": {
                "meta": {"api-version": "1.0"},
                "name": "http-pkg",
                "files": [
                    {
                        "filename": "http_pkg-1.0.0.whl",
                        "url": "http://files.pythonhosted.org/http_pkg-1.0.0.whl",
                        "hashes": {"sha256": "f" * 64},
                        "upload-time": "2022-01-01T00:00:00Z",
                        "yanked": False,
                    }
                ],
            },
            "userinfo-pkg": {
                "meta": {"api-version": "1.0"},
                "name": "userinfo-pkg",
                "files": [
                    {
                        "filename": "userinfo_pkg-1.0.0.whl",
                        "url": "https://user:pass@files.pythonhosted.org/userinfo_pkg-1.0.0.whl",
                        "hashes": {"sha256": "d" * 64},
                        "upload-time": "2022-01-01T00:00:00Z",
                        "yanked": False,
                    }
                ],
            },
        }
    )

    store = RecordingStore(store_dir)
    server = RecordingProxyServer(
        ("127.0.0.1", 0),
        upstream=evil_upstream,
        store=store,
        manifest=Manifest(cutoff=cutoff),
        cutoff=cutoff,
        manifest_path=manifest_path,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # Unlisted host -> 502 Bad Gateway
        status1, _, _ = _http_get(host, port, "/simple/evil-pkg/")
        assert status1 == 502

        # Insecure HTTP -> 502 Bad Gateway
        status2, _, _ = _http_get(host, port, "/simple/http-pkg/")
        assert status2 == 502

        # Userinfo -> 502 Bad Gateway
        status3, _, _ = _http_get(host, port, "/simple/userinfo-pkg/")
        assert status3 == 502
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_concurrent_manifest_saves_never_lose_records(tmp_path: Path) -> None:
    """Item 3: Concurrent manifest saves serialize snapshot+write; all files listed on disk."""
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    cutoff = "2023-01-01T00:00:00Z"

    num_files = 25
    file_specs = []
    files_dict = {}
    for i in range(num_files):
        fname = f"concur_pkg-1.0.{i}-py3-none-any.whl"
        content = f"content-file-{i}".encode("utf-8")
        sha = hashlib.sha256(content).hexdigest()
        file_specs.append((fname, sha, content))
        files_dict[f"https://upstream.test/packages/{fname}"] = content
        files_dict[fname] = content

    upstream = FixtureUpstreamClient(
        projects={
            "concur-pkg": {
                "meta": {"api-version": "1.0"},
                "name": "concur-pkg",
                "files": [
                    {
                        "filename": fname,
                        "url": f"https://upstream.test/packages/{fname}",
                        "hashes": {"sha256": sha},
                        "upload-time": "2022-01-01T00:00:00Z",
                        "yanked": False,
                    }
                    for fname, sha, _ in file_specs
                ],
            }
        },
        files=files_dict,
    )

    store = RecordingStore(store_dir)
    manifest = Manifest(cutoff=cutoff)
    server = RecordingProxyServer(
        ("127.0.0.1", 0),
        upstream=upstream,
        store=store,
        manifest=manifest,
        cutoff=cutoff,
        manifest_path=manifest_path,
        max_connections=32,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # Fetch project page so server registers known files
        status, _, _ = _http_get(host, port, "/simple/concur-pkg/")
        assert status == 200

        # Concurrent fetch of all 25 files
        errors: list[Exception] = []
        statuses: list[int] = []

        def _fetch(fname: str, sha: str) -> None:
            try:
                st, _, b = _http_get(host, port, f"/files/{sha}/{fname}")
                statuses.append(st)
            except Exception as e:
                errors.append(e)

        workers = [
            threading.Thread(target=_fetch, args=(fname, sha))
            for fname, sha, _ in file_specs
        ]
        for w in workers:
            w.start()
        for w in workers:
            w.join(timeout=10.0)

        assert not errors, f"Errors during fetch: {errors}"
        assert all(st == 200 for st in statuses)

        # Inspect final manifest on disk: MUST contain all 25 files!
        assert manifest_path.is_file()
        disk_manifest = Manifest.load(manifest_path)
        disk_filenames = {f.filename for f in disk_manifest.files}
        expected_filenames = {fname for fname, _, _ in file_specs}
        assert disk_filenames == expected_filenames
        assert len(disk_manifest.files) == num_files
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_manifest_records_missing_hash_invalid_hash_invalid_filename(tmp_path: Path) -> None:
    """Item 4: Missing hash, invalid hash, and invalid filename recorded in manifest."""
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    cutoff = "2023-01-01T00:00:00Z"

    upstream = FixtureUpstreamClient(
        projects={
            "defects-pkg": {
                "meta": {"api-version": "1.0"},
                "name": "defects-pkg",
                "files": [
                    {
                        "filename": "missing_hash.whl",
                        "url": "https://upstream.test/packages/missing_hash.whl",
                        "hashes": {},  # No sha256
                        "upload-time": "2022-01-01T00:00:00Z",
                        "yanked": False,
                    },
                    {
                        "filename": "invalid_hash.whl",
                        "url": "https://upstream.test/packages/invalid_hash.whl",
                        "hashes": {"sha256": "bad-sha"},
                        "upload-time": "2022-01-01T00:00:00Z",
                        "yanked": False,
                    },
                    {
                        "filename": "../evil/invalid_filename.whl",
                        "url": "https://upstream.test/packages/invalid_filename.whl",
                        "hashes": {"sha256": "a" * 64},
                        "upload-time": "2022-01-01T00:00:00Z",
                        "yanked": False,
                    },
                    {
                        "filename": "valid_file.whl",
                        "url": "https://upstream.test/packages/valid_file.whl",
                        "hashes": {"sha256": "b" * 64},
                        "upload-time": "2022-01-01T00:00:00Z",
                        "yanked": False,
                    },
                ],
            }
        }
    )

    store = RecordingStore(store_dir)
    manifest = Manifest(cutoff=cutoff)
    server = RecordingProxyServer(
        ("127.0.0.1", 0),
        upstream=upstream,
        store=store,
        manifest=manifest,
        cutoff=cutoff,
        manifest_path=manifest_path,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        status, _, _ = _http_get(host, port, "/simple/defects-pkg/")
        assert status == 200

        assert any(x["filename"] == "missing_hash.whl" for x in manifest.missing_hash)
        assert any(x["filename"] == "invalid_hash.whl" for x in manifest.invalid_hash)
        assert any(x["filename"] == "../evil/invalid_filename.whl" for x in manifest.invalid_filename)

        disk_manifest = Manifest.load(manifest_path)
        assert any(x["filename"] == "missing_hash.whl" for x in disk_manifest.missing_hash)
        assert any(x["filename"] == "invalid_hash.whl" for x in disk_manifest.invalid_hash)
        assert any(x["filename"] == "../evil/invalid_filename.whl" for x in disk_manifest.invalid_filename)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_server_fails_closed_project_over_file_cap(tmp_path: Path, monkeypatch) -> None:
    """Item 5: Project over MAX_FILES_PER_PROJECT fails closed (502) and records in manifest."""
    import hermetic_pkgrec.filter as flt

    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    cutoff = "2023-01-01T00:00:00Z"

    monkeypatch.setattr(flt, "MAX_FILES_PER_PROJECT", 2)

    upstream = FixtureUpstreamClient(
        projects={
            "big-pkg": {
                "meta": {"api-version": "1.0"},
                "name": "big-pkg",
                "files": [
                    {
                        "filename": f"big_pkg-1.0.{i}.whl",
                        "url": f"https://upstream.test/packages/big_pkg-1.0.{i}.whl",
                        "hashes": {"sha256": "a" * 64},
                        "upload-time": "2022-01-01T00:00:00Z",
                        "yanked": False,
                    }
                    for i in range(5)
                ],
            }
        }
    )

    store = RecordingStore(store_dir)
    manifest = Manifest(cutoff=cutoff)
    server = RecordingProxyServer(
        ("127.0.0.1", 0),
        upstream=upstream,
        store=store,
        manifest=manifest,
        cutoff=cutoff,
        manifest_path=manifest_path,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        status, _, body = _http_get(host, port, "/simple/big-pkg/")
        assert status == 502
        assert body == b"Bad Gateway.\n"

        assert any(x["project"] == "big-pkg" for x in manifest.project_over_file_cap)
        disk_manifest = Manifest.load(manifest_path)
        assert any(x["project"] == "big-pkg" for x in disk_manifest.project_over_file_cap)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_symlinked_miss_log_refused_fails_closed(tmp_path: Path) -> None:
    """Item 7: Symlinked miss log refused (no-follow) and request fails closed (500)."""
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    real_misses = tmp_path / "real_misses.jsonl"
    real_misses.write_text("")
    symlink_misses = tmp_path / "symlink_misses.jsonl"
    symlink_misses.symlink_to(real_misses)

    cutoff = "2023-01-01T00:00:00Z"
    upstream = FixtureUpstreamClient(projects={})

    store = RecordingStore(store_dir)
    manifest = Manifest(cutoff=cutoff)
    server = RecordingProxyServer(
        ("127.0.0.1", 0),
        upstream=upstream,
        store=store,
        manifest=manifest,
        cutoff=cutoff,
        manifest_path=manifest_path,
        miss_log_path=symlink_misses,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # Miss occurs -> trying to log to symlinked miss log must fail closed (500)
        status, _, body = _http_get(host, port, "/simple/absent-project/")
        assert status == 500
        # Symlink target must NOT have been written to
        assert real_misses.read_bytes() == b""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_symlinked_stored_file_refused(tmp_path: Path) -> None:
    """Item 7: Symlink in store directory refused by _stream_local_file (403 Forbidden)."""
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    cutoff = "2023-01-01T00:00:00Z"

    store = RecordingStore(store_dir)
    manifest = Manifest(cutoff=cutoff)

    # Create target secret file outside store
    secret_file = tmp_path / "secret.txt"
    secret_file.write_bytes(b"CONFIDENTIAL_DATA")

    # Create symlink inside store/files/<sha>/<filename>
    sha = "7" * 64
    fname = "symlink_target.whl"
    sha_dir = store_dir / "files" / sha
    sha_dir.mkdir(parents=True, exist_ok=True)
    symlink_whl = sha_dir / fname
    symlink_whl.symlink_to(secret_file)

    server = RecordingProxyServer(
        ("127.0.0.1", 0),
        upstream=FixtureUpstreamClient(),
        store=store,
        manifest=manifest,
        cutoff=cutoff,
        manifest_path=manifest_path,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        status, _, body = _http_get(host, port, f"/files/{sha}/{fname}")
        assert status == 403
        assert b"CONFIDENTIAL_DATA" not in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_miss_log_permissions_private(tmp_path: Path) -> None:
    """Item 7: Miss log created with private (0600) permissions."""
    import stat

    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    miss_log_path = tmp_path / "private_misses.jsonl"
    cutoff = "2023-01-01T00:00:00Z"

    store = RecordingStore(store_dir)
    server = RecordingProxyServer(
        ("127.0.0.1", 0),
        upstream=FixtureUpstreamClient(),
        store=store,
        manifest=Manifest(cutoff=cutoff),
        cutoff=cutoff,
        manifest_path=manifest_path,
        miss_log_path=miss_log_path,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        status, _, _ = _http_get(host, port, "/simple/nonexistent-for-perm/")
        assert status == 404
        assert miss_log_path.is_file()
        mode = stat.S_IMODE(miss_log_path.stat().st_mode)
        assert mode == 0o600
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_upstream_error_responses_fixed_no_leaks(tmp_path: Path) -> None:
    """Item 8: Upstream errors return fixed messages to clients; detail kept in logger only."""
    from hermetic_pkgrec.errors import UpstreamError

    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    cutoff = "2023-01-01T00:00:00Z"

    secret_url = "https://internal.top-secret.corp/pypi/simple/leaked"

    class LeakyUpstream(FixtureUpstreamClient):
        def fetch_project_page(self, project: str, accept: str | None = None) -> tuple[bytes, str]:
            raise UpstreamError(f"Connection failed to sensitive URL: {secret_url}")

    server = RecordingProxyServer(
        ("127.0.0.1", 0),
        upstream=LeakyUpstream(),
        store=RecordingStore(store_dir),
        manifest=Manifest(cutoff=cutoff),
        cutoff=cutoff,
        manifest_path=manifest_path,
    )
    host, port = server.server_address[:2]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        status, _, body = _http_get(host, port, "/simple/some-pkg/")
        assert status == 502
        body_text = body.decode("utf-8")
        assert body == b"Bad Gateway.\n"
        assert "internal.top-secret.corp" not in body_text
        assert "sensitive URL" not in body_text
        assert "https://" not in body_text
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

