"""Comprehensive offline tests for class-B substrate inventory and release metadata."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pytest

from hermetic_d5b.check import evaluate_inventory, parse_rfc3339_ns
from hermetic_d5b.inventory import (
    SubstrateEntry,
    build_d5b_inventory,
    load_apt_release_metadata,
    load_conda_release_metadata,
    load_pypi_release_metadata,
    parse_deb822_stanzas,
    scan_conda_packages,
    scan_dpkg_status,
    scan_python_packages,
    scan_rootfs_packages,
    write_canonical_inventory,
    main as cli_main,
)
from hermetic_d5b.model import D5bError, InventoryPackage

CUTOFF = "2024-01-01T00:00:00Z"
PRE_CUTOFF = "2023-06-01T12:00:00Z"
POST_CUTOFF = "2024-06-01T12:00:00Z"


def test_parse_deb822_stanzas():
    raw = (
        "Package: libc6\n"
        "Status: install ok installed\n"
        "Version: 2.31-13\n"
        "Description: GNU C Library\n"
        " An embedded continuation line\n"
        " Another continuation line\n"
        "\n"
        "Package: bash\n"
        "Status: install ok installed\n"
        "Version: 5.1-2\n"
    )
    stanzas = parse_deb822_stanzas(raw)
    assert len(stanzas) == 2
    assert stanzas[0]["Package"] == "libc6"
    assert stanzas[0]["Status"] == "install ok installed"
    assert stanzas[0]["Version"] == "2.31-13"
    assert "An embedded continuation line" in stanzas[0]["Description"]
    assert stanzas[1]["Package"] == "bash"
    assert stanzas[1]["Version"] == "5.1-2"


def test_scan_dpkg_status(tmp_path):
    rootfs = tmp_path / "rootfs"
    dpkg_dir = rootfs / "var/lib/dpkg"
    dpkg_dir.mkdir(parents=True)
    status_file = dpkg_dir / "status"

    # One installed, one uninstalled (deinstall ok config-files), one on hold installed
    status_content = (
        "Package: libc6\n"
        "Status: install ok installed\n"
        "Version: 2.31-13\n"
        "\n"
        "Package: oldpkg\n"
        "Status: deinstall ok config-files\n"
        "Version: 1.0.0\n"
        "\n"
        "Package: heldpkg\n"
        "Status: hold ok installed\n"
        "Version: 3.0.0\n"
    )
    status_file.write_text(status_content)

    pkgs = scan_dpkg_status(rootfs)
    assert len(pkgs) == 2
    names = {p.name for p in pkgs}
    assert names == {"libc6", "heldpkg"}
    assert "oldpkg" not in names


def test_scan_dpkg_status_missing(tmp_path):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    assert scan_dpkg_status(rootfs) == []


def test_scan_python_packages(tmp_path):
    rootfs = tmp_path / "rootfs"
    site_packages = rootfs / "usr/local/lib/python3.10/site-packages"
    site_packages.mkdir(parents=True)

    # 1. Dist-info with METADATA
    dist_info = site_packages / "requests-2.31.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text("Name: requests\nVersion: 2.31.0\n")

    # 2. Egg-info directory with PKG-INFO
    egg_info_dir = site_packages / "urllib3-1.26.15.egg-info"
    egg_info_dir.mkdir()
    (egg_info_dir / "PKG-INFO").write_text("Name: urllib3\nVersion: 1.26.15\n")

    # 3. Egg-info file
    egg_file = site_packages / "certifi-2023.7.22.egg-info"
    egg_file.write_text("Name: certifi\nVersion: 2023.7.22\n")

    # 4. In testbed directory (must be SKIPPED)
    testbed_dist = rootfs / "testbed/.venv/lib/site-packages/repo_dep-0.1.dist-info"
    testbed_dist.mkdir(parents=True)
    (testbed_dist / "METADATA").write_text("Name: repo-dep\nVersion: 0.1\n")

    # 5. In .git directory (must be SKIPPED)
    git_dist = rootfs / ".git/hook_pkg-1.0.dist-info"
    git_dist.mkdir(parents=True)
    (git_dist / "METADATA").write_text("Name: hook-pkg\nVersion: 1.0\n")

    pkgs = scan_python_packages(rootfs)
    names = {p.name for p in pkgs}
    assert "requests" in names
    assert "urllib3" in names
    assert "certifi" in names
    assert "repo-dep" not in names
    assert "hook-pkg" not in names


def test_scan_conda_packages(tmp_path):
    rootfs = tmp_path / "rootfs"
    conda_meta = rootfs / "opt/conda/conda-meta"
    conda_meta.mkdir(parents=True)

    pkg_json = conda_meta / "numpy-1.24.0-py39.json"
    pkg_json.write_text(json.dumps({
        "name": "numpy",
        "version": "1.24.0",
        "fn": "numpy-1.24.0-py39.conda",
        "sha256": "abcdef1234567890" * 4,
    }))

    # In testbed (must be skipped)
    testbed_meta = rootfs / "testbed/conda-meta"
    testbed_meta.mkdir(parents=True)
    (testbed_meta / "evil-1.0.json").write_text(json.dumps({
        "name": "evil",
        "version": "1.0",
    }))

    pkgs = scan_conda_packages(rootfs)
    assert len(pkgs) == 1
    assert pkgs[0].name == "numpy"
    assert pkgs[0].version == "1.24.0"
    assert pkgs[0].ecosystem == "conda"


def test_scan_rootfs_packages_deduplication_and_empty_closed(tmp_path):
    empty_rootfs = tmp_path / "empty"
    empty_rootfs.mkdir()

    with pytest.raises(D5bError, match="empty_rootfs_inventory"):
        scan_rootfs_packages(empty_rootfs)

    with pytest.raises(D5bError, match="not found"):
        scan_rootfs_packages(tmp_path / "nonexistent")


def test_load_apt_release_metadata_with_release_verification(tmp_path):
    pkg_file = tmp_path / "Packages"
    pkg_content = (
        "Package: libc6\n"
        "Version: 2.31-13\n"
        "Architecture: amd64\n"
        "SHA256: " + "a" * 64 + "\n"
        "Filename: pool/main/g/glibc/libc6_2.31-13_amd64.deb\n"
        "\n"
        "Package: bash\n"
        "Version: 5.1-2\n"
        "Architecture: amd64\n"
        "SHA256: " + "b" * 64 + "\n"
        "Filename: pool/main/b/bash/bash_5.1-2_amd64.deb\n"
    ).encode("utf-8")
    pkg_file.write_bytes(pkg_content)
    pkg_sha = hashlib.sha256(pkg_content).hexdigest()

    # Release file with matching hash and RFC 2822 date
    rel_file = tmp_path / "Release"
    rel_content = (
        "Origin: Debian\n"
        "Label: Debian\n"
        "Suite: bullseye\n"
        "Date: Sat, 20 May 2023 12:00:00 UTC\n"
        "SHA256:\n"
        f" {pkg_sha} {len(pkg_content)} main/binary-amd64/Packages\n"
    )
    rel_file.write_text(rel_content)

    meta, sub_map = load_apt_release_metadata(pkg_file, rel_file)
    assert "dpkg" in meta
    assert meta["dpkg"]["libc6"]["2.31-13"] == "2023-05-20T12:00:00Z"
    assert ("libc6", "2.31-13") in sub_map
    entry = sub_map[("libc6", "2.31-13")]
    assert entry.digest == "sha256:" + "a" * 64
    assert entry.date == "2023-05-20T12:00:00Z"


def test_load_apt_release_hash_mismatch_fails_closed(tmp_path):
    pkg_file = tmp_path / "Packages"
    pkg_file.write_bytes(b"Package: libc6\nVersion: 1.0\n")

    rel_file = tmp_path / "Release"
    rel_file.write_text(
        "Date: Sat, 20 May 2023 12:00:00 UTC\n"
        "SHA256:\n"
        " 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 10 Packages\n"
    )

    with pytest.raises(D5bError, match="apt_packages_hash_mismatch"):
        load_apt_release_metadata(pkg_file, rel_file)


def test_load_pypi_release_metadata(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "schema": "hermetic-pkgrec-manifest/v1",
        "cutoff": CUTOFF,
        "files": [
            {
                "project": "requests",
                "filename": "requests-2.31.0-py3-none-any.whl",
                "sha256": "c" * 64,
                "upload-time": "2023-05-22T14:00:00Z",
                "yank_decision": "not_yanked",
            }
        ]
    }))

    meta, sub_map = load_pypi_release_metadata(manifest)
    assert meta["pypi"]["requests"]["2.31.0"]["requests-2.31.0-py3-none-any.whl"] == "2023-05-22T14:00:00Z"
    assert ("requests", "2.31.0") in sub_map
    entry = sub_map[("requests", "2.31.0")]
    assert entry.digest == "sha256:" + "c" * 64
    assert entry.date == "2023-05-22T14:00:00Z"


def test_load_conda_release_metadata(tmp_path):
    repodata = tmp_path / "repodata.json"
    repodata.write_text(json.dumps({
        "packages": {
            "numpy-1.24.0.tar.bz2": {
                "name": "numpy",
                "version": "1.24.0",
                "sha256": "d" * 64,
                "timestamp": 1680307200000,  # 2023-04-01T00:00:00Z
            }
        }
    }))

    meta, sub_map = load_conda_release_metadata(repodata)
    assert meta["conda"]["numpy"]["1.24.0"] == 1680307200000
    assert ("numpy", "1.24.0") in sub_map
    entry = sub_map[("numpy", "1.24.0")]
    assert entry.digest == "sha256:" + "d" * 64
    assert entry.date == "2023-04-01T00:00:00Z"


def test_build_d5b_inventory_full_substrate_at_t(tmp_path):
    rootfs = tmp_path / "rootfs"
    site_packages = rootfs / "usr/lib/python3/dist-packages"
    site_packages.mkdir(parents=True)
    dist = site_packages / "requests-2.31.0.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text("Name: requests\nVersion: 2.31.0\n")

    pypi_manifest = tmp_path / "pypi.json"
    pypi_manifest.write_text(json.dumps({
        "files": [
            {
                "project": "requests",
                "filename": "requests-2.31.0-py3-none-any.whl",
                "sha256": "e" * 64,
                "upload-time": PRE_CUTOFF,
            }
        ]
    }))

    res = build_d5b_inventory(rootfs, CUTOFF, mode="strict", pypi_manifest=pypi_manifest)
    assert res["schema"] == "hermetic-d5b-inventory/v1"
    assert res["substrate_at_t"] == "full"
    assert res["d5b_report"]["result"] == "pass"
    assert res["d5b_report"]["counts"]["ok"] == 1
    assert res["d5b_report"]["counts"]["total"] == 1
    assert len(res["substrate"]) == 1
    sub = res["substrate"][0]
    assert sub["name"] == "requests"
    assert sub["version"] == "2.31.0"
    assert sub["digest"] == "sha256:" + "e" * 64
    assert sub["date"] == PRE_CUTOFF


def test_build_d5b_inventory_partial_substrate_at_t_and_unknown_never_guessed(tmp_path):
    rootfs = tmp_path / "rootfs"
    site_packages = rootfs / "usr/lib/python3/dist-packages"
    site_packages.mkdir(parents=True)

    # 1. Known pre-cutoff package
    d1 = site_packages / "requests-2.31.0.dist-info"
    d1.mkdir()
    (d1 / "METADATA").write_text("Name: requests\nVersion: 2.31.0\n")

    # 2. Unknown package without verified metadata
    d2 = site_packages / "unverified_pkg-1.0.0.dist-info"
    d2.mkdir()
    (d2 / "METADATA").write_text("Name: unverified-pkg\nVersion: 1.0.0\n")

    pypi_manifest = tmp_path / "pypi.json"
    pypi_manifest.write_text(json.dumps({
        "files": [
            {
                "project": "requests",
                "filename": "requests-2.31.0-py3-none-any.whl",
                "sha256": "f" * 64,
                "upload-time": PRE_CUTOFF,
            }
        ]
    }))

    res = build_d5b_inventory(rootfs, CUTOFF, mode="repo_only", pypi_manifest=pypi_manifest)
    assert res["substrate_at_t"] == "partial"
    assert res["d5b_report"]["result"] == "pass_with_warnings"
    assert res["d5b_report"]["counts"]["ok"] == 1
    assert res["d5b_report"]["counts"]["unknown"] == 1
    assert len(res["d5b_report"]["unknown"]) == 1
    assert res["d5b_report"]["unknown"][0]["name"] == "unverified-pkg"

    # Only verified package in substrate, unverified is NOT fabricated
    assert len(res["substrate"]) == 1
    assert res["substrate"][0]["name"] == "requests"


def test_build_d5b_inventory_none_substrate_at_t(tmp_path):
    rootfs = tmp_path / "rootfs"
    site_packages = rootfs / "usr/lib/python3/dist-packages"
    site_packages.mkdir(parents=True)
    d = site_packages / "unknown_pkg-1.0.dist-info"
    d.mkdir()
    (d / "METADATA").write_text("Name: unknown-pkg\nVersion: 1.0\n")

    # No metadata provided
    res = build_d5b_inventory(rootfs, CUTOFF, mode="repo_only")
    assert res["substrate_at_t"] == "none"
    assert res["d5b_report"]["counts"]["ok"] == 0
    assert res["d5b_report"]["counts"]["unknown"] == 1
    assert res["substrate"] == []


def test_substrate_entry_validation():
    # Valid
    s = SubstrateEntry(name="pkg", version="1.0", digest="sha256:" + "a" * 64, date="2023-01-01T00:00:00Z")
    assert s.to_dict()["name"] == "pkg"

    # Invalid digest prefix
    with pytest.raises(D5bError, match="digest format"):
        SubstrateEntry(name="pkg", version="1.0", digest="md5:" + "a" * 32, date="2023-01-01T00:00:00Z")

    # Invalid digest length
    with pytest.raises(D5bError, match="digest format"):
        SubstrateEntry(name="pkg", version="1.0", digest="sha256:abcd", date="2023-01-01T00:00:00Z")

    # Invalid date format
    with pytest.raises(D5bError, match="date format"):
        SubstrateEntry(name="pkg", version="1.0", digest="sha256:" + "a" * 64, date="invalid-date")


def test_cli_inventory(tmp_path, capsys):
    rootfs = tmp_path / "rootfs"
    dpkg_dir = rootfs / "var/lib/dpkg"
    dpkg_dir.mkdir(parents=True)
    (dpkg_dir / "status").write_text("Package: bash\nStatus: install ok installed\nVersion: 5.1\n")

    out_file = tmp_path / "d5b-inventory.json"
    code = cli_main(["--rootfs", str(rootfs), "--cutoff", CUTOFF, "--out", str(out_file)])
    assert code == 0
    assert out_file.is_file()

    data = json.loads(out_file.read_text())
    assert data["schema"] == "hermetic-d5b-inventory/v1"
    assert data["substrate_at_t"] == "none"
    assert len(data["inventory"]["packages"]) == 1


def test_conda_timestamp_seconds_normalized_boundary(tmp_path):
    repodata = tmp_path / "repodata.json"
    repodata.write_text(json.dumps({
        "packages": {
            "pkg1-1.0.tar.bz2": {
                "name": "pkg1",
                "version": "1.0",
                "sha256": "1" * 64,
                "timestamp": 253402300799,  # boundary in seconds
            },
            "pkg2-1.0.tar.bz2": {
                "name": "pkg2",
                "version": "1.0",
                "sha256": "2" * 64,
                "timestamp": 253402300800,  # boundary in milliseconds
            },
            "pkg3-1.0.tar.bz2": {
                "name": "pkg3",
                "version": "1.0",
                "sha256": "3" * 64,
                "timestamp": 1700000000,  # 2023-11-14T22:13:20Z in seconds
            },
        }
    }))

    meta, sub_map = load_conda_release_metadata(repodata)
    assert meta["conda"]["pkg1"]["1.0"] == 253402300799000
    assert meta["conda"]["pkg2"]["1.0"] == 253402300800
    assert meta["conda"]["pkg3"]["1.0"] == 1700000000000
    assert sub_map[("pkg3", "1.0")].date == "2023-11-14T22:13:20Z"


def test_load_pypi_release_metadata_hyphenated_sdist_name(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "files": [
            {
                "project": "python-dateutil",
                "filename": "python-dateutil-2.8.2.tar.gz",
                "sha256": "a" * 64,
                "upload-time": "2023-01-01T00:00:00Z",
            },
            {
                "project": "more-itertools",
                "filename": "more-itertools-9.1.0.zip",
                "sha256": "b" * 64,
                "upload-time": "2023-01-01T00:00:00Z",
            },
        ]
    }))

    meta, sub_map = load_pypi_release_metadata(manifest)
    assert "2.8.2" in meta["pypi"]["python-dateutil"]
    assert ("python-dateutil", "2.8.2") in sub_map
    assert "9.1.0" in meta["pypi"]["more-itertools"]
    assert ("more-itertools", "9.1.0") in sub_map


def test_load_apt_release_metadata_missing_release_fails_closed(tmp_path):
    pkg_file = tmp_path / "Packages"
    pkg_file.write_bytes(b"Package: libc6\nVersion: 1.0\n")

    with pytest.raises(D5bError, match="apt_release"):
        load_apt_release_metadata(pkg_file)


def test_load_apt_release_metadata_empty_table_fails_closed(tmp_path):
    pkg_file = tmp_path / "Packages"
    pkg_file.write_bytes(b"Package: libc6\nVersion: 1.0\n")

    rel_file = tmp_path / "Release"
    rel_file.write_text("Date: Sat, 20 May 2023 12:00:00 UTC\n")

    with pytest.raises(D5bError, match="apt_packages_hash_mismatch"):
        load_apt_release_metadata(pkg_file, rel_file)


def test_scan_conda_packages_oversized_meta_fails_closed(tmp_path):
    from hermetic_d5b.inventory import MAX_METADATA_FILE_BYTES
    rootfs = tmp_path / "rootfs"
    conda_meta = rootfs / "opt/conda/conda-meta"
    conda_meta.mkdir(parents=True)

    oversized_file = conda_meta / "bigpkg-1.0.json"
    oversized_file.write_bytes(b" " * (MAX_METADATA_FILE_BYTES + 10))

    with pytest.raises(D5bError):
        scan_conda_packages(rootfs)


def test_scan_egg_info_unreadable_fails_closed(tmp_path):
    from hermetic_d5b.inventory import MAX_METADATA_FILE_BYTES
    rootfs = tmp_path / "rootfs"
    site_packages = rootfs / "usr/local/lib/python3.10/site-packages"
    site_packages.mkdir(parents=True)

    oversized_egg = site_packages / "big-1.0.egg-info"
    oversized_egg.write_bytes(b" " * (MAX_METADATA_FILE_BYTES + 10))

    with pytest.raises(D5bError):
        scan_python_packages(rootfs)


def test_load_pypi_release_metadata_earliest_upload_selected(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "files": [
            {
                "project": "requests",
                "filename": "requests-2.31.0-py2.py3-none-any.whl",
                "sha256": "1" * 64,
                "upload-time": PRE_CUTOFF,
            },
            {
                "project": "requests",
                "filename": "requests-2.31.0.tar.gz",
                "sha256": "2" * 64,
                "upload-time": POST_CUTOFF,
            },
        ]
    }))

    meta, sub_map = load_pypi_release_metadata(manifest)
    sub = sub_map[("requests", "2.31.0")]
    # Must select earliest upload (PRE_CUTOFF), not the later file that overwrites
    assert sub.date == PRE_CUTOFF
    assert sub.digest == "sha256:" + "1" * 64


def test_build_d5b_inventory_ecosystem_scoped_substrate(tmp_path):
    rootfs = tmp_path / "rootfs"
    # 1. PyPI package: pip 23.0
    py_dir = rootfs / "usr/lib/python3/dist-packages/pip-23.0.dist-info"
    py_dir.mkdir(parents=True)
    (py_dir / "METADATA").write_text("Name: pip\nVersion: 23.0\n")

    # 2. Conda package: pip 23.0
    conda_dir = rootfs / "opt/conda/conda-meta"
    conda_dir.mkdir(parents=True)
    (conda_dir / "pip-23.0.json").write_text(json.dumps({
        "name": "pip", "version": "23.0", "fn": "pip-23.0.tar.bz2"
    }))

    pypi_manifest = tmp_path / "pypi.json"
    pypi_manifest.write_text(json.dumps({
        "files": [
            {"project": "pip", "filename": "pip-23.0-py3-none-any.whl", "sha256": "1" * 64, "upload-time": PRE_CUTOFF}
        ]
    }))

    conda_repodata = tmp_path / "repodata.json"
    conda_repodata.write_text(json.dumps({
        "packages": {
            "pip-23.0.tar.bz2": {"name": "pip", "version": "23.0", "sha256": "2" * 64, "timestamp": 1680307200000}
        }
    }))

    res = build_d5b_inventory(rootfs, CUTOFF, mode="strict", pypi_manifest=pypi_manifest, conda_repodata=conda_repodata)
    assert res["substrate_at_t"] == "full"
    # Both packages must have distinct substrate entries preserved without overwriting
    assert len(res["substrate"]) == 2
    digests = {s["digest"] for s in res["substrate"]}
    assert "sha256:" + "1" * 64 in digests
    assert "sha256:" + "2" * 64 in digests


def test_unpinned_metadata_cannot_decide_full_substrate(tmp_path):
    rootfs = tmp_path / "rootfs"
    py_dir = rootfs / "usr/lib/python3/dist-packages/requests-2.31.0.dist-info"
    py_dir.mkdir(parents=True)
    (py_dir / "METADATA").write_text("Name: requests\nVersion: 2.31.0\n")

    unpinned_metadata = {
        "pypi": {
            "requests": {
                "2.31.0": {
                    "requests-2.31.0.tar.gz": PRE_CUTOFF,
                }
            }
        }
    }

    res = build_d5b_inventory(rootfs, CUTOFF, mode="strict", metadata_data=unpinned_metadata)
    # Even though all packages are ok via unpinned metadata, substrate_at_t must NOT be "full"
    # because there is no verified substrate entry for requests. It must report "partial".
    assert res["d5b_report"]["counts"]["ok"] == 1
    assert res["substrate"] == []
    assert res["substrate_at_t"] == "partial"


def test_unpinned_metadata_does_not_overwrite_verified_version(tmp_path):
    rootfs = tmp_path / "rootfs"
    py_dir = rootfs / "usr/lib/python3/dist-packages/requests-2.31.0.dist-info"
    py_dir.mkdir(parents=True)
    (py_dir / "METADATA").write_text("Name: requests\nVersion: 2.31.0\n")

    # Verified manifest has PRE_CUTOFF
    pypi_manifest = tmp_path / "pypi.json"
    pypi_manifest.write_text(json.dumps({
        "files": [
            {"project": "requests", "filename": "requests-2.31.0-py3-none-any.whl", "sha256": "1" * 64, "upload-time": PRE_CUTOFF}
        ]
    }))

    # Unpinned metadata attempts to overwrite with POST_CUTOFF
    unpinned_metadata = {
        "pypi": {
            "requests": {
                "2.31.0": {
                    "requests-2.31.0-py3-none-any.whl": POST_CUTOFF,
                }
            }
        }
    }

    res = build_d5b_inventory(rootfs, CUTOFF, mode="strict", pypi_manifest=pypi_manifest, metadata_data=unpinned_metadata)
    # Must retain verified PRE_CUTOFF, so it remains ok and full
    assert res["d5b_report"]["counts"]["ok"] == 1
    assert res["substrate_at_t"] == "full"






