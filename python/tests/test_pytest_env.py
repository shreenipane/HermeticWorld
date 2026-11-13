
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from hermetic_pytest_env import ScanError, scan
from hermetic_pytest_env.scan import MAX_METADATA_BYTES


def _write_dist_info(
    site: Path,
    dir_name: str,
    metadata: str,
    entry_points: str | None = None,
) -> Path:
    d = site / dir_name
    d.mkdir(parents=True, exist_ok=True)
    (d / "METADATA").write_text(metadata, encoding="utf-8")
    if entry_points is not None:
        (d / "entry_points.txt").write_text(entry_points, encoding="utf-8")
    return d


def _write_egg_info(
    site: Path,
    dir_name: str,
    pkg_info: str,
    entry_points: str | None = None,
) -> Path:
    d = site / dir_name
    d.mkdir(parents=True, exist_ok=True)
    (d / "PKG-INFO").write_text(pkg_info, encoding="utf-8")
    if entry_points is not None:
        (d / "entry_points.txt").write_text(entry_points, encoding="utf-8")
    return d


@pytest.mark.parametrize(
    ("version", "expected_older"),
    [
        ("3.7.4", True),
        ("3.8.0", False),
        ("7.4.0", False),
    ],
)
def test_pytest_versions_and_3_8_boundary(
    tmp_path: Path, version: str, expected_older: bool
) -> None:
    site = tmp_path / "site-packages"
    site.mkdir()
    _write_dist_info(
        site,
        f"pytest-{version}.dist-info",
        f"Metadata-Version: 2.1\nName: pytest\nVersion: {version}\nSummary: pytest\n\nBody text\n",
    )

    inv = scan([str(site)]).to_dict()
    assert inv["pytest"] == {
        "older_than_3_8": expected_older,
        "version": version,
    }


def test_unparsable_version_reported_never_guessed(tmp_path: Path) -> None:
    site = tmp_path / "site-packages"
    site.mkdir()
    _write_dist_info(
        site,
        "pytest-custom.dist-info",
        "Metadata-Version: 2.1\nName: pytest\nVersion: 7.4.0-weird+build\n",
    )

    inv = scan([str(site)]).to_dict()
    assert inv["pytest"] == {"older_than_3_8": None, "version": None}
    assert inv["unparsable"] == [
        {
            "entry": "pytest-custom.dist-info",
            "reason": "unparsable_pep440_version",
            "value": "7.4.0-weird+build",
        }
    ]


def test_plugins_dist_info_and_egg_info_with_folding(tmp_path: Path) -> None:
    site = tmp_path / "site-packages"
    site.mkdir()
    _write_dist_info(
        site,
        "pytest_asyncio-0.21.1.dist-info",
        "Metadata-Version: 2.1\nName: pytest-asyncio\nVersion: 0.21.1\nSummary: folded\n\tcontinuation line\n",
        "[pytest11]\nasyncio = pytest_asyncio.plugin\n\n[console_scripts]\nignored = foo:bar\n",
    )
    _write_egg_info(
        site,
        "pytest_cov-4.1.0.egg-info",
        "Metadata-Version: 2.1\nName: pytest_cov\nVersion: 4.1.0\n",
        "[pytest11]\npytest_cov = pytest_cov.plugin\n",
    )

    inv = scan([str(site)]).to_dict()
    assert inv["plugins"] == [
        {
            "distribution": "pytest-asyncio",
            "module": "pytest_asyncio.plugin",
            "name": "asyncio",
            "version": "0.21.1",
        },
        {
            "distribution": "pytest-cov",
            "module": "pytest_cov.plugin",
            "name": "pytest_cov",
            "version": "4.1.0",
        },
    ]


def test_duplicate_distributions_pep503_conflict(tmp_path: Path) -> None:
    site = tmp_path / "site-packages"
    site.mkdir()
    _write_dist_info(
        site,
        "My_Pkg-1.0.dist-info",
        "Metadata-Version: 2.1\nName: My_Pkg\nVersion: 1.0\n",
    )
    _write_dist_info(
        site,
        "my-pkg-2.0.dist-info",
        "Metadata-Version: 2.1\nName: my-pkg\nVersion: 2.0\n",
    )

    inv = scan([str(site)]).to_dict()
    assert inv["conflicts"] == [
        {
            "dir_index": 0,
            "entries": ["My_Pkg-1.0.dist-info", "my-pkg-2.0.dist-info"],
            "normalized_name": "my-pkg",
        }
    ]


def test_symlinked_dist_info_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside.dist-info"
    outside.mkdir()
    (outside / "METADATA").write_text("Name: evil\nVersion: 1.0\n", encoding="utf-8")

    site = tmp_path / "site-packages"
    site.mkdir()
    os.symlink(outside, site / "evil-1.0.dist-info")

    inv = scan([str(site)]).to_dict()
    assert inv["refused"] == [
        {"entry": "evil-1.0.dist-info", "reason": "symlink_refused"}
    ]


def test_oversized_metadata_refused(tmp_path: Path) -> None:
    site = tmp_path / "site-packages"
    site.mkdir()
    huge = "Name: bigpkg\nVersion: 1.0\nDescription: " + ("x" * (MAX_METADATA_BYTES + 10))
    _write_dist_info(site, "bigpkg-1.0.dist-info", huge)

    inv = scan([str(site)]).to_dict()
    assert inv["refused"] == [
        {"entry": "bigpkg-1.0.dist-info", "reason": "file_too_large"}
    ]


def test_configparser_duplicate_sections_and_keys_refused(tmp_path: Path) -> None:
    site = tmp_path / "site-packages"
    site.mkdir()
    _write_dist_info(
        site,
        "dupsec-1.0.dist-info",
        "Name: dupsec\nVersion: 1.0\n",
        "[pytest11]\na = mod.a\n[pytest11]\nb = mod.b\n",
    )
    _write_dist_info(
        site,
        "dupkey-1.0.dist-info",
        "Name: dupkey\nVersion: 1.0\n",
        "[pytest11]\na = mod.a\na = mod.b\n",
    )

    inv = scan([str(site)]).to_dict()
    reasons = {r["entry"]: r["reason"] for r in inv["refused"]}
    assert reasons == {
        "dupkey-1.0.dist-info": "entry_points_parse_error:DuplicateOptionError",
        "dupsec-1.0.dist-info": "entry_points_parse_error:DuplicateSectionError",
    }


def test_determinism_and_cli(tmp_path: Path) -> None:
    site = tmp_path / "site-packages"
    site.mkdir()
    _write_dist_info(
        site,
        "pytest-7.4.0.dist-info",
        "Name: pytest\nVersion: 7.4.0\n",
    )
    _write_dist_info(
        site,
        "zeta-1.0.dist-info",
        "Name: zeta\nVersion: 1.0\n",
        "[pytest11]\nz = zeta.plugin\n",
    )
    _write_dist_info(
        site,
        "alpha-1.0.dist-info",
        "Name: alpha\nVersion: 1.0\n",
        "[pytest11]\na = alpha.plugin\n",
    )

    out1 = scan([str(site)]).to_json()
    out2 = scan([str(site)]).to_json()
    assert out1 == out2

    # Verify CLI invocation and exit code 0
    proc = subprocess.run(
        [sys.executable, "-m", "hermetic_pytest_env", str(site)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == json.loads(out1)

    # Verify CLI exit code 1 on missing directory
    bad_proc = subprocess.run(
        [sys.executable, "-m", "hermetic_pytest_env", str(tmp_path / "does-not-exist")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad_proc.returncode == 1
    with pytest.raises(ScanError):
        scan([str(tmp_path / "does-not-exist")])


