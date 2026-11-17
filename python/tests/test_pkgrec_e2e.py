"""End-to-end integration test for the full record-and-freeze workflow."""

from __future__ import annotations

import hashlib
import http.client
import json
from pathlib import Path
import threading
import pytest

from hermetic_pkgindex.server import HermeticHTTPServer
from hermetic_pkgindex.store import FrozenStore, MissLog
from hermetic_pkgrec.constants import PEP691_JSON_MIME
from hermetic_pkgrec.freeze import freeze_world
from hermetic_pkgrec.manifest import Manifest
from hermetic_pkgrec.server import RecordingProxyServer
from hermetic_pkgrec.store import RecordingStore
from hermetic_pkgrec.upstream import FixtureUpstreamClient


def test_end_to_end_record_freeze_and_serve(tmp_path: Path) -> None:
    store_dir = tmp_path / "record_store"
    manifest_file = tmp_path / "manifest.json"
    frozen_root = tmp_path / "frozen_root"
    misses_log = tmp_path / "eval_misses.jsonl"
    cutoff = "2023-01-01T00:00:00Z"

    # Upstream content
    pkg1_data = b"wheel-data-for-package-one"
    pkg1_sha = hashlib.sha256(pkg1_data).hexdigest()
    pkg1_name = "pkg_one-1.0.0-py3-none-any.whl"

    pkg2_data = b"wheel-data-for-package-two"
    pkg2_sha = hashlib.sha256(pkg2_data).hexdigest()
    pkg2_name = "pkg_two-2.0.0-py3-none-any.whl"

    # Package three is post-cutoff:
    pkg3_data = b"future-package-data"
    pkg3_sha = hashlib.sha256(pkg3_data).hexdigest()
    pkg3_name = "pkg_three-3.0.0-py3-none-any.whl"

    upstream_pkg1 = {
        "meta": {"api-version": "1.0"},
        "name": "pkg-one",
        "files": [
            {
                "filename": pkg1_name,
                "url": f"https://fixtures.test/packages/{pkg1_name}",
                "hashes": {"sha256": pkg1_sha},
                "upload-time": "2022-05-01T00:00:00Z",
                "yanked": False,
            }
        ],
    }

    upstream_pkg2 = {
        "meta": {"api-version": "1.0"},
        "name": "pkg-two",
        "files": [
            {
                "filename": pkg2_name,
                "url": f"https://fixtures.test/packages/{pkg2_name}",
                "hashes": {"sha256": pkg2_sha},
                "upload-time": "2022-08-01T00:00:00Z",
                "yanked": False,
            }
        ],
    }

    upstream_pkg3 = {
        "meta": {"api-version": "1.0"},
        "name": "pkg-three",
        "files": [
            {
                "filename": pkg3_name,
                "url": f"https://fixtures.test/packages/{pkg3_name}",
                "hashes": {"sha256": pkg3_sha},
                "upload-time": "2023-02-01T00:00:00Z",  # After cutoff!
                "yanked": False,
            }
        ],
    }

    upstream = FixtureUpstreamClient(
        projects={
            "pkg-one": upstream_pkg1,
            "pkg-two": upstream_pkg2,
            "pkg-three": upstream_pkg3,
        },
        files={
            pkg1_name: pkg1_data,
            f"https://fixtures.test/packages/{pkg1_name}": pkg1_data,
            pkg2_name: pkg2_data,
            f"https://fixtures.test/packages/{pkg2_name}": pkg2_data,
            pkg3_name: pkg3_data,
            f"https://fixtures.test/packages/{pkg3_name}": pkg3_data,
        },
        root_projects=["pkg-one", "pkg-two", "pkg-three"],
    )

    store = RecordingStore(store_dir)
    manifest = Manifest(cutoff=cutoff)

    # 1. Start recording proxy
    proxy_server = RecordingProxyServer(
        ("127.0.0.1", 0),
        upstream=upstream,
        store=store,
        manifest=manifest,
        cutoff=cutoff,
        manifest_path=manifest_file,
    )
    proxy_host, proxy_port = proxy_server.server_address[:2]
    proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()

    try:
        # Simulate pip installing pkg-one and pkg-two (task closure)
        # Fetch pkg-one index
        conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=5.0)
        conn.request("GET", "/simple/pkg-one/", headers={"Accept": PEP691_JSON_MIME})
        resp1 = conn.getresponse()
        assert resp1.status == 200
        p1_data = json.loads(resp1.read().decode("utf-8"))
        conn.close()

        # Download pkg-one wheel
        file_url = p1_data["files"][0]["url"]
        conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=5.0)
        conn.request("GET", file_url)
        resp_file1 = conn.getresponse()
        assert resp_file1.status == 200
        assert resp_file1.read() == pkg1_data
        conn.close()

        # Fetch pkg-two index
        conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=5.0)
        conn.request("GET", "/simple/pkg-two/", headers={"Accept": PEP691_JSON_MIME})
        resp2 = conn.getresponse()
        assert resp2.status == 200
        p2_data = json.loads(resp2.read().decode("utf-8"))
        conn.close()

        # Download pkg-two wheel
        file_url2 = p2_data["files"][0]["url"]
        conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=5.0)
        conn.request("GET", file_url2)
        resp_file2 = conn.getresponse()
        assert resp_file2.status == 200
        assert resp_file2.read() == pkg2_data
        conn.close()

        # Verify pkg-three is dropped at cutoff:
        conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=5.0)
        conn.request("GET", "/simple/pkg-three/", headers={"Accept": PEP691_JSON_MIME})
        resp3 = conn.getresponse()
        assert resp3.status == 200
        p3_data = json.loads(resp3.read().decode("utf-8"))
        assert len(p3_data["files"]) == 0  # Post-cutoff file dropped!
        conn.close()

    finally:
        proxy_server.shutdown()
        proxy_server.server_close()
        proxy_thread.join(timeout=2.0)

    # 2. Check recorded manifest and store
    assert manifest_file.is_file()
    saved_manifest = Manifest.load(manifest_file)
    assert len(saved_manifest.files) == 2
    recorded_names = {f.filename for f in saved_manifest.files}
    assert recorded_names == {pkg1_name, pkg2_name}

    assert store.has_file(pkg1_sha, pkg1_name)
    assert store.has_file(pkg2_sha, pkg2_name)

    # 3. Freeze world root
    freeze_world(store_dir, manifest_file, frozen_root, misses_path=misses_log)

    # 4. Start hermetic_pkgindex server on the frozen root
    frozen_store = FrozenStore(frozen_root)
    miss_log = MissLog(misses_log)
    pkgindex_server = HermeticHTTPServer(("127.0.0.1", 0), store=frozen_store, miss_log=miss_log)
    srv_host, srv_port = pkgindex_server.server_address[:2]
    srv_thread = threading.Thread(target=pkgindex_server.serve_forever, daemon=True)
    srv_thread.start()

    try:
        # Agent installs pkg-one from frozen index:
        conn = http.client.HTTPConnection(srv_host, srv_port, timeout=5.0)
        conn.request("GET", "/simple/pkg-one/")
        resp = conn.getresponse()
        assert resp.status == 200
        resp.read()
        conn.close()

        conn = http.client.HTTPConnection(srv_host, srv_port, timeout=5.0)
        conn.request("GET", f"/files/{pkg1_sha}/{pkg1_name}")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == pkg1_data
        conn.close()

        # Agent attempts to install unsealed/unrecorded pkg-three:
        conn = http.client.HTTPConnection(srv_host, srv_port, timeout=5.0)
        conn.request("GET", "/simple/pkg-three/")
        resp_miss = conn.getresponse()
        assert resp_miss.status == 404
        resp_miss.read()
        conn.close()

        # Verify miss went ONLY to misses_log:
        assert misses_log.is_file()
        miss_content = misses_log.read_text(encoding="utf-8")
        assert "pkg-three" in miss_content

        # Frozen root must be untouched:
        assert not (frozen_root / "simple" / "pkg-three").exists()
        assert frozen_store.list_projects() == ["pkg-one", "pkg-two"]

    finally:
        pkgindex_server.shutdown()
        pkgindex_server.server_close()
        srv_thread.join(timeout=2.0)
