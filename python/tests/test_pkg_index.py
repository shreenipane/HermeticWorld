"""Unit tests for hermetic_slice.pkg_index."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from hermetic_slice.http import HttpError
from hermetic_slice.pkg_index import (
    IndexBuildError,
    build_index,
    class_b_warnings,
    normalize_name,
    wheel_compatible,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "pkg_index"


@pytest.mark.parametrize(
    "filename, py, expected",
    [
        ("foo-1.0-py2.py3-none-any.whl", "3.9", True),
        ("foo-1.0-cp39-cp39-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "3.9", True),
        ("foo-1.0-cp38-cp38-manylinux1_x86_64.whl", "3.9", False),
        ("foo-1.0-cp37-abi3-manylinux1_x86_64.whl", "3.9", True),
        ("foo-1.0-cp39-cp39-win_amd64.whl", "3.9", False),
        ("foo-1.0-cp39-cp39-macosx_10_9_x86_64.whl", "3.9", False),
        ("malformed_name.whl", "3.9", False),
        ("foo-1.0.tar.gz", "3.9", False),
        ("foo-1.0-build1-cp39-cp39-linux_x86_64.whl", "3.9", False),
        ("foo-1.0-1build-cp39-cp39-linux_x86_64.whl", "3.9", True),
        ("foo-1.0-cp310-abi3-linux_x86_64.whl", "3.9", False),
    ],
)
def test_wheel_compatible_table(filename: str, py: str, expected: bool) -> None:
    """Test wheel compatibility against required tag specifications."""
    assert wheel_compatible(filename, py) is expected


def test_build_index_with_py_fixture(tmp_path: Path) -> None:
    """Test build_index using recorded PyPI py fixture with cutoff 2019-11-14."""
    fixture_path = FIXTURES_DIR / "pypi_py.json"
    assert fixture_path.exists(), f"Missing fixture {fixture_path}"

    fixture_json = json.loads(fixture_path.read_text(encoding="utf-8"))
    releases = fixture_json["releases"]

    # Verify fixture data facts:
    # 1.8.0 was uploaded 2019-02-22T01:34:01...
    # 1.8.1 was uploaded 2019-12-27T12:07:31...
    assert "1.8.0" in releases
    assert "1.8.1" in releases
    rel_180_upload = releases["1.8.0"][0]["upload_time_iso_8601"]
    rel_181_upload = releases["1.8.1"][0]["upload_time_iso_8601"]
    assert rel_180_upload.startswith("2019-02-22")
    assert rel_181_upload.startswith("2019-12-27")

    # Prepare fake files mapping for http_get
    downloaded_files: dict[str, bytes] = {}
    for ver, file_list in releases.items():
        for f in file_list:
            fname = f["filename"]
            content = f"content-for-{fname}".encode("utf-8")
            sha = hashlib.sha256(content).hexdigest()
            f["digests"]["sha256"] = sha
            downloaded_files[f["url"]] = content

    modified_py_json_bytes = json.dumps(fixture_json).encode("utf-8")

    def fake_http_get(url: str) -> bytes:
        if url == "https://pypi.org/pypi/py/json":
            return modified_py_json_bytes
        if url in downloaded_files:
            return downloaded_files[url]
        raise ValueError(f"Unexpected URL: {url}")

    task = {
        "repo": "pytest-dev/pytest",
        "cutoffs": {
            "t_world": "2019-11-14T00:00:00Z",
        },
    }

    env = {
        "python_version": "3.9",
        "implementation_tag": "cp39",
        "packages": [
            {"name": "py", "version": "1.11.0"},
            {"name": "pytest", "version": "5.2.4"},
        ],
        "editable": ["pytest"],
    }

    index_dir = tmp_path / "index"
    report = build_index(task, env, fake_http_get, index_dir, versions_per_package=5)

    # The target project (pytest) must be excluded even though listed in packages
    assert "pytest" in report["excluded"]
    pkg_names = [p["name"] for p in report["packages"]]
    assert "pytest" not in pkg_names
    assert "py" in pkg_names

    py_rep = next(p for p in report["packages"] if p["name"] == "py")

    # Serving py with cutoff 2019-11-14:
    # 1. Newest served version must be 1.8.0
    assert py_rep["served_versions"][0] == "1.8.0"

    # 2. No served file is uploaded after the cutoff
    cutoff_dt = datetime.fromisoformat("2019-11-14T00:00:00+00:00")
    for ver_str in py_rep["served_versions"]:
        for f in releases[ver_str]:
            if f["filename"] in py_rep["served_files"]:
                file_dt = datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
                assert file_dt <= cutoff_dt

    # 3. Installed version 1.11.0 is newer than t_world
    assert py_rep["installed_newer_than_t_world"] is True

    # 4. Check generated PEP 503 HTML
    root_html = (index_dir / "simple" / "index.html").read_text(encoding="utf-8")
    assert '<a href="py/">py</a>' in root_html
    assert "pytest" not in root_html

    py_html = (index_dir / "simple" / "py" / "index.html").read_text(encoding="utf-8")
    assert "Links for py" in py_html

    # Check relative hrefs, #sha256, and data-requires-python
    whl_180 = next(f for f in releases["1.8.0"] if f["filename"].endswith(".whl"))
    expected_sha = whl_180["digests"]["sha256"]
    expected_href = f'../../files/{whl_180["filename"]}#sha256={expected_sha}'
    assert expected_href in py_html
    assert 'data-requires-python="&gt;=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*"' in py_html


def test_build_index_sha256_mismatch(tmp_path: Path) -> None:
    """Test that a sha256 mismatch raises IndexBuildError."""
    pypi_data = {
        "releases": {
            "1.0.0": [
                {
                    "filename": "demo-1.0.0.tar.gz",
                    "url": "https://example.com/demo-1.0.0.tar.gz",
                    "upload_time_iso_8601": "2019-01-01T00:00:00Z",
                    "packagetype": "sdist",
                    "digests": {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
                }
            ]
        }
    }

    def fake_http_get(url: str) -> bytes:
        if url == "https://pypi.org/pypi/demo/json":
            return json.dumps(pypi_data).encode("utf-8")
        if url == "https://example.com/demo-1.0.0.tar.gz":
            return b"corrupted file content"
        raise ValueError(url)

    task = {"repo": "owner/proj", "cutoffs": {"t_world": "2019-11-14T00:00:00Z"}}
    env = {"python_version": "3.9", "packages": [{"name": "demo", "version": "1.0.0"}]}

    with pytest.raises(IndexBuildError, match="SHA256 mismatch"):
        build_index(task, env, fake_http_get, tmp_path / "index")


def test_build_index_package_not_on_pypi(tmp_path: Path) -> None:
    """A package PyPI answers 404 for (conda-only) is reported, not fatal; other errors still raise."""
    content = b"demo sdist bytes"
    pypi_data = {
        "releases": {
            "1.0.0": [
                {
                    "filename": "demo-1.0.0.tar.gz",
                    "url": "https://example.com/demo-1.0.0.tar.gz",
                    "upload_time_iso_8601": "2019-01-01T00:00:00Z",
                    "packagetype": "sdist",
                    "digests": {"sha256": hashlib.sha256(content).hexdigest()},
                }
            ]
        }
    }

    def fake_http_get(url: str) -> bytes:
        if url == "https://pypi.org/pypi/demo/json":
            return json.dumps(pypi_data).encode("utf-8")
        if url == "https://example.com/demo-1.0.0.tar.gz":
            return content
        if url == "https://pypi.org/pypi/conda-only-pkg/json":
            raise HttpError(url, 404)
        if url == "https://pypi.org/pypi/flaky/json":
            raise HttpError(url, 503)
        raise ValueError(url)

    task = {"repo": "owner/proj", "cutoffs": {"t_world": "2019-11-14T00:00:00Z"}}
    env = {
        "python_version": "3.9",
        "packages": [{"name": "conda-only-pkg", "version": "2.0"}, {"name": "demo", "version": "1.0.0"}],
    }
    report = build_index(task, env, fake_http_get, tmp_path / "index")
    by_name = {p["name"]: p for p in report["packages"]}
    assert by_name["conda-only-pkg"]["on_pypi"] is False
    assert by_name["conda-only-pkg"]["served_files"] == []
    assert by_name["demo"]["on_pypi"] is True
    assert by_name["demo"]["served_files"] == ["demo-1.0.0.tar.gz"]
    assert report["totals"]["not_on_pypi"] == 1

    env["packages"].append({"name": "flaky", "version": "1.0"})
    with pytest.raises(HttpError):
        build_index(task, env, fake_http_get, tmp_path / "index2")


def test_class_b_warnings_wording() -> None:
    """Test exact class_b_warnings phrasing."""
    report = {
        "t_world": "2019-11-14T00:00:00Z",
        "packages": [
            {
                "name": "attrs",
                "installed_version": "23.1.0",
                "installed_version_uploaded": "2023-04-16T12:00:00Z",
                "installed_newer_than_t_world": True,
            },
            {
                "name": "oldpkg",
                "installed_version": "1.0.0",
                "installed_version_uploaded": "2018-01-01T00:00:00Z",
                "installed_newer_than_t_world": False,
            },
        ],
    }
    warnings = class_b_warnings(report)
    assert len(warnings) == 1
    assert warnings[0] == (
        "attrs 23.1.0 installed (uploaded 2023-04-16) is newer than T_world 2019-11-14 (repo_only: listed, not rebuilt)"
    )


def test_build_index_cli_unknown_id(tmp_path: Path) -> None:
    """Test build-index CLI exits 1 when given an unknown instance ID."""
    from hermetic_slice.__main__ import main

    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    exit_code = main([
        "build-index",
        "--tasks-dir", str(tasks_dir),
        "--cache", str(cache_dir),
        "--only", "unknown-task-id",
    ])
    assert exit_code == 1


def test_world_probe_cli_unknown_id(tmp_path: Path) -> None:
    """Test world-probe CLI exits 1 when given an unknown instance ID."""
    from hermetic_slice.__main__ import main

    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir(parents=True, exist_ok=True)

    exit_code = main([
        "world-probe",
        "--tasks-dir", str(tasks_dir),
        "--only", "unknown-task-id",
    ])
    assert exit_code == 1

