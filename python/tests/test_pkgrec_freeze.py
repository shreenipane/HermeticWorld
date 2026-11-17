"""Tests covering freezing of the task closure, manifest determinism, idempotency, and compatibility."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import pytest

from hermetic_pkgindex.server import HermeticHTTPServer
from hermetic_pkgindex.store import FrozenStore, MissLog
from hermetic_pkgrec.cli import main
from hermetic_pkgrec.errors import ExistingFrozenRootError
from hermetic_pkgrec.freeze import freeze_world
from hermetic_pkgrec.manifest import Manifest, canonical_json_bytes
from hermetic_pkgrec.models import ManifestRecord
from hermetic_pkgrec.store import RecordingStore


def _populate_test_store(store_dir: Path, files: list[tuple[str, str, bytes]]) -> RecordingStore:
    store = RecordingStore(store_dir)
    for project, filename, content in files:
        sha256 = hashlib.sha256(content).hexdigest()
        store.save_file_stream(sha256, filename, [content])
    return store


def test_manifest_determinism() -> None:
    """Byte-identical manifest for the same input regardless of insertion order."""
    m1 = Manifest(cutoff="2023-01-01T00:00:00Z")
    m1.record_file("pkg-b", "pkg_b-1.0.whl", "b" * 64, "2022-01-01T00:00:00Z", "not_yanked")
    m1.record_file("pkg-a", "pkg_a-1.0.whl", "a" * 64, "2022-01-01T00:00:00Z", "not_yanked")
    m1.record_missing_upload_time("pkg-b", "pkg_b-0.1.whl")
    m1.record_missing_upload_time("pkg-a", "pkg_a-0.1.whl")
    m1.record_unyanked_after_cutoff("pkg-z", "pkg_z-1.0.whl")
    m1.record_unyanked_unknown_date("pkg-y", "pkg_y-1.0.whl")
    m1.record_missing_hash("pkg-m", "pkg_m-1.0.whl")
    m1.record_invalid_hash("pkg-i", "pkg_i-1.0.whl")
    m1.record_invalid_filename("pkg-f", "../invalid.whl")
    m1.record_project_over_file_cap("pkg-over")

    # In reverse order:
    m2 = Manifest(cutoff="2023-01-01T00:00:00Z")
    m2.record_project_over_file_cap("pkg-over")
    m2.record_invalid_filename("pkg-f", "../invalid.whl")
    m2.record_invalid_hash("pkg-i", "pkg_i-1.0.whl")
    m2.record_missing_hash("pkg-m", "pkg_m-1.0.whl")
    m2.record_unyanked_unknown_date("pkg-y", "pkg_y-1.0.whl")
    m2.record_unyanked_after_cutoff("pkg-z", "pkg_z-1.0.whl")
    m2.record_missing_upload_time("pkg-a", "pkg_a-0.1.whl")
    m2.record_missing_upload_time("pkg-b", "pkg_b-0.1.whl")
    m2.record_file("pkg-a", "pkg_a-1.0.whl", "a" * 64, "2022-01-01T00:00:00Z", "not_yanked")
    m2.record_file("pkg-b", "pkg_b-1.0.whl", "b" * 64, "2022-01-01T00:00:00Z", "not_yanked")

    bytes1 = m1.to_canonical_json()
    bytes2 = m2.to_canonical_json()
    assert bytes1 == bytes2


def test_manifest_load_schema_and_malformed_entries(tmp_path: Path) -> None:
    from hermetic_pkgrec.errors import ManifestError

    # 1. Missing schema in object manifest
    p1 = tmp_path / "m1.json"
    p1.write_text(json.dumps({"cutoff": "2023-01-01T00:00:00Z", "files": []}))
    with pytest.raises(ManifestError, match="schema"):
        Manifest.load(p1)

    # 2. Unsupported schema
    p2 = tmp_path / "m2.json"
    p2.write_text(json.dumps({"schema": "unknown/v2", "cutoff": "", "files": []}))
    with pytest.raises(ManifestError, match="schema"):
        Manifest.load(p2)

    # 3. Malformed record (non-dict)
    p3 = tmp_path / "m3.json"
    p3.write_text(json.dumps({"schema": "hermetic.pkgrec.manifest/1", "files": ["not-a-dict"]}))
    with pytest.raises(ManifestError):
        Manifest.load(p3)

    # 4. Malformed sidecar entry (missing 'project')
    p4 = tmp_path / "m4.json"
    p4.write_text(json.dumps({
        "schema": "hermetic.pkgrec.manifest/1",
        "files": [],
        "missing_upload_time": [{"filename": "f.whl"}],
    }))
    with pytest.raises(ManifestError):
        Manifest.load(p4)

    # 5. Legacy list with malformed entry
    p5 = tmp_path / "m5.json"
    p5.write_text(json.dumps([123]))
    with pytest.raises(ManifestError):
        Manifest.load(p5)


def test_freeze_misses_path_validation(tmp_path: Path) -> None:
    from hermetic_pkgrec.errors import FreezeError

    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    out_dir = tmp_path / "frozen"

    content = b"content-for-pkg"
    sha = hashlib.sha256(content).hexdigest()
    name = "pkg-1.0.whl"

    _populate_test_store(store_dir, [("pkg", name, content)])
    manifest = Manifest(cutoff="2023-01-01T00:00:00Z")
    manifest.record_file("pkg", name, sha, "2022-01-01T00:00:00Z", "not_yanked")
    manifest.save(manifest_path)

    # 1. Sibling path with shared string prefix must succeed.
    misses_sibling = tmp_path / "frozen_misses.jsonl"
    freeze_world(store_dir, manifest_path, out_dir, misses_path=misses_sibling)
    assert out_dir.exists()

    # 2. Inside out_dir must fail even if out_dir already exists.
    misses_inside = out_dir / "inside_misses.jsonl"
    with pytest.raises(FreezeError):
        freeze_world(store_dir, manifest_path, out_dir, misses_path=misses_inside)


def test_failed_freeze_leaves_no_partial_root_and_can_retry(tmp_path: Path) -> None:
    from hermetic_pkgrec.errors import StoreError

    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    out_dir = tmp_path / "frozen"

    c1 = b"file-1"
    s1 = hashlib.sha256(c1).hexdigest()
    n1 = "pkg1-1.0.whl"

    c2 = b"file-2"
    s2 = hashlib.sha256(c2).hexdigest()
    n2 = "pkg2-1.0.whl"

    # Only save file 1 into store; file 2 is missing!
    _populate_test_store(store_dir, [("pkg1", n1, c1)])

    manifest = Manifest(cutoff="2023-01-01T00:00:00Z")
    manifest.record_file("pkg1", n1, s1, "2022-01-01T00:00:00Z", "not_yanked")
    manifest.record_file("pkg2", n2, s2, "2022-01-01T00:00:00Z", "not_yanked")
    manifest.save(manifest_path)

    # Freeze should fail due to missing file 2
    with pytest.raises(StoreError):
        freeze_world(store_dir, manifest_path, out_dir)

    # out_dir must NOT exist as a partial root!
    assert not out_dir.exists()

    # Now add missing file 2 into store and retry
    RecordingStore(store_dir).save_file_stream(s2, n2, [c2])

    # Retry must succeed cleanly, not raise ExistingFrozenRootError
    freeze_world(store_dir, manifest_path, out_dir)
    assert out_dir.exists()


def test_freeze_validates_manifest_path_components(tmp_path: Path) -> None:
    from hermetic_pkgrec.errors import CutoffError, FreezeError

    store_dir = tmp_path / "store"
    store_dir.mkdir(parents=True)
    (store_dir / "files").mkdir(parents=True)
    manifest_path = tmp_path / "manifest.json"
    out_dir = tmp_path / "frozen"
    outside_marker = tmp_path / "escaped_dir"

    # Write a manifest containing a path traversal in sha256
    manifest_data = {
        "schema": "hermetic.pkgrec.manifest/1",
        "cutoff": "2023-01-01T00:00:00Z",
        "files": [
            {
                "filename": "demo_pkg-1.0.whl",
                "project": "demo",
                "sha256": "../../../escaped_dir",
                "upload-time": "2022-01-01T00:00:00Z",
                "yank_decision": "not_yanked",
            }
        ],
    }
    manifest_path.write_text(json.dumps(manifest_data))

    with pytest.raises((CutoffError, FreezeError)):
        freeze_world(store_dir, manifest_path, out_dir)

    assert not out_dir.exists()
    assert not outside_marker.exists()


def test_freeze_idempotency_rejects_mismatched_root(tmp_path: Path) -> None:
    import shutil

    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    out_dir = tmp_path / "frozen"

    content = b"sample-package-data"
    sha = hashlib.sha256(content).hexdigest()
    name = "pkg-1.0.whl"

    _populate_test_store(store_dir, [("sample", name, content)])
    manifest = Manifest(cutoff="2023-01-01T00:00:00Z")
    manifest.record_file("sample", name, sha, "2022-01-01T00:00:00Z", "not_yanked")
    manifest.save(manifest_path)

    freeze_world(store_dir, manifest_path, out_dir)
    assert out_dir.exists()

    # 1. Extra project in simple/ must cause idempotency check to reject
    extra_proj = out_dir / "simple" / "extra-pkg"
    extra_proj.mkdir(parents=True)
    (extra_proj / "index.json").write_text("{}")
    with pytest.raises(ExistingFrozenRootError):
        freeze_world(store_dir, manifest_path, out_dir)

    # Clean up extra project
    shutil.rmtree(extra_proj)

    # 2. Changed yank state in manifest must cause idempotency check to reject
    manifest2 = Manifest(cutoff="2023-01-01T00:00:00Z")
    manifest2.record_file("sample", name, sha, "2022-01-01T00:00:00Z", "yanked")
    manifest_path2 = tmp_path / "manifest2.json"
    manifest2.save(manifest_path2)
    with pytest.raises(ExistingFrozenRootError):
        freeze_world(store_dir, manifest_path2, out_dir)

    # 3. Malformed index.json (non-dict) must not crash _check_idempotent_match
    (out_dir / "simple" / "sample" / "index.json").write_text("[1, 2, 3]")
    with pytest.raises(ExistingFrozenRootError):
        freeze_world(store_dir, manifest_path, out_dir)


def test_freeze_creates_valid_frozen_root(tmp_path: Path) -> None:
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    out_dir = tmp_path / "frozen_root"

    pkg_a_content = b"content-for-package-a"
    pkg_a_sha = hashlib.sha256(pkg_a_content).hexdigest()
    pkg_a_name = "pkg_a-1.0.0-py3-none-any.whl"

    pkg_b_content = b"content-for-package-b"
    pkg_b_sha = hashlib.sha256(pkg_b_content).hexdigest()
    pkg_b_name = "pkg_b-2.0.0.tar.gz"

    _populate_test_store(store_dir, [
        ("pkg-a", pkg_a_name, pkg_a_content),
        ("pkg-b", pkg_b_name, pkg_b_content),
    ])

    manifest = Manifest(cutoff="2023-01-01T00:00:00Z")
    manifest.record_file("pkg-a", pkg_a_name, pkg_a_sha, "2022-05-01T00:00:00Z", "not_yanked")
    manifest.record_file("pkg-b", pkg_b_name, pkg_b_sha, "2022-06-01T00:00:00Z", "yanked")
    manifest.save(manifest_path)

    freeze_world(store_dir, manifest_path, out_dir)

    # Verify frozen root layout
    assert (out_dir / "simple" / "pkg-a" / "index.json").is_file()
    assert (out_dir / "simple" / "pkg-b" / "index.json").is_file()
    assert (out_dir / "files" / pkg_a_sha / pkg_a_name).is_file()
    assert (out_dir / "files" / pkg_b_sha / pkg_b_name).is_file()

    # Verify PEP 691 index contents
    idx_a = json.loads((out_dir / "simple" / "pkg-a" / "index.json").read_text())
    assert idx_a["name"] == "pkg-a"
    assert len(idx_a["files"]) == 1
    assert idx_a["files"][0]["filename"] == pkg_a_name
    assert idx_a["files"][0]["hashes"]["sha256"] == pkg_a_sha
    assert idx_a["files"][0]["yanked"] is False

    idx_b = json.loads((out_dir / "simple" / "pkg-b" / "index.json").read_text())
    assert idx_b["name"] == "pkg-b"
    assert idx_b["files"][0]["yanked"] is True


def test_freeze_idempotency_and_refusal_to_modify(tmp_path: Path) -> None:
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    out_dir = tmp_path / "frozen_root"

    content = b"sample-package-data"
    sha = hashlib.sha256(content).hexdigest()
    name = "pkg-1.0.whl"

    _populate_test_store(store_dir, [("sample", name, content)])
    manifest = Manifest(cutoff="2023-01-01T00:00:00Z")
    manifest.record_file("sample", name, sha, "2022-01-01T00:00:00Z", "not_yanked")
    manifest.save(manifest_path)

    # First freeze: succeeds
    freeze_world(store_dir, manifest_path, out_dir)

    # Idempotent freeze: calling again on the same store/manifest succeeds without modifying
    freeze_world(store_dir, manifest_path, out_dir)

    # Now tamper with frozen root (simulate someone modifying the root)
    tampered_file = out_dir / "files" / sha / name
    tampered_file.write_bytes(b"tampered-content")

    # Re-running freeze on a modified root must REFUSE!
    with pytest.raises(ExistingFrozenRootError):
        freeze_world(store_dir, manifest_path, out_dir)


def test_freeze_refuses_preexisting_unrelated_directory(tmp_path: Path) -> None:
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    out_dir = tmp_path / "preexisting_dir"
    out_dir.mkdir(parents=True)
    (out_dir / "unrelated.txt").write_text("hello")

    content = b"sample-package-data"
    sha = hashlib.sha256(content).hexdigest()
    name = "pkg-1.0.whl"

    _populate_test_store(store_dir, [("sample", name, content)])
    manifest = Manifest(cutoff="2023-01-01T00:00:00Z")
    manifest.record_file("sample", name, sha, "2022-01-01T00:00:00Z", "not_yanked")
    manifest.save(manifest_path)

    with pytest.raises(ExistingFrozenRootError):
        freeze_world(store_dir, manifest_path, out_dir)


def test_compatibility_with_hermetic_pkgindex_and_misses(tmp_path: Path) -> None:
    """Verify hermetic_pkgindex can serve the frozen root and misses go only to the misses file."""
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    out_dir = tmp_path / "frozen_root"
    misses_file = tmp_path / "misses.jsonl"

    content = b"compatibility-test-wheel-content"
    sha = hashlib.sha256(content).hexdigest()
    name = "comp_pkg-1.0.0-py3-none-any.whl"

    _populate_test_store(store_dir, [("comp-pkg", name, content)])
    manifest = Manifest(cutoff="2023-01-01T00:00:00Z")
    manifest.record_file("comp-pkg", name, sha, "2022-01-01T00:00:00Z", "not_yanked")
    manifest.save(manifest_path)

    # Freeze
    freeze_world(store_dir, manifest_path, out_dir, misses_path=misses_file)

    # Now load out_dir with hermetic_pkgindex's FrozenStore!
    frozen_store = FrozenStore(out_dir)
    assert frozen_store.list_projects() == ["comp-pkg"]

    page = frozen_store.get_project_page("comp-pkg")
    assert page.name == "comp-pkg"
    assert b"comp_pkg-1.0.0-py3-none-any.whl" in page.json_bytes
    assert b"comp_pkg-1.0.0-py3-none-any.whl" in page.html_bytes

    verified = frozen_store.verify_and_prepare_file(sha, name)
    assert verified.sha256 == sha
    assert verified.size == len(content)

    # Start HermeticHTTPServer from hermetic_pkgindex on frozen_root
    miss_log = MissLog(misses_file)
    server = HermeticHTTPServer(("127.0.0.1", 0), store=frozen_store, miss_log=miss_log)
    host, port = server.server_address[:2]

    import http.client
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # Request present project
        conn = http.client.HTTPConnection(host, port, timeout=5.0)
        conn.request("GET", "/simple/comp-pkg/")
        resp = conn.getresponse()
        assert resp.status == 200
        resp.read()
        conn.close()

        # Request missing project: must return 404
        conn2 = http.client.HTTPConnection(host, port, timeout=5.0)
        conn2.request("GET", "/simple/missing-project/")
        resp2 = conn2.getresponse()
        assert resp2.status == 404
        resp2.read()
        conn2.close()

        # Verify miss was logged to misses.jsonl and NEVER added to frozen root!
        assert misses_file.is_file()
        misses_data = misses_file.read_text(encoding="utf-8")
        assert "missing-project" in misses_data

        # Frozen root must remain unmodified!
        assert not (out_dir / "simple" / "missing-project").exists()
        assert frozen_store.list_projects() == ["comp-pkg"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_cli_freeze_subcommand(tmp_path: Path) -> None:
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    out_dir = tmp_path / "frozen_root"

    content = b"cli-test-data"
    sha = hashlib.sha256(content).hexdigest()
    name = "cli_pkg-1.0.whl"

    _populate_test_store(store_dir, [("cli-pkg", name, content)])
    manifest = Manifest(cutoff="2023-01-01T00:00:00Z")
    manifest.record_file("cli-pkg", name, sha, "2022-01-01T00:00:00Z", "not_yanked")
    manifest.save(manifest_path)

    # Run freeze through main()
    ret = main(["freeze", "--store", str(store_dir), "--manifest", str(manifest_path), "--out", str(out_dir)])
    assert ret == 0
    assert (out_dir / "simple" / "cli-pkg" / "index.json").is_file()
    assert (out_dir / "files" / sha / name).is_file()
