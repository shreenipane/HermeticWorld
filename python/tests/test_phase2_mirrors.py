"""Offline test suite for Phase 2 package mirrors (PyPI, conda, Debian/Ubuntu, git)."""

from __future__ import annotations

import hashlib
import json
import pytest

from hermetic_ecosystem_cut.cut import CutError
from hermetic_ecosystem_cut.mirror import build_mirror, verify_mirror

CUTOFF = "2023-04-01T00:00:00Z"
CUTOFF_MS = 1680307200000
FUTURE_MS = 1704067200000
FUTURE_DATE = "2024-01-01T00:00:00Z"
PRE_UBUNTU_CUTOFF = "2023-02-01T00:00:00Z"
PRE_DEBIAN_CUTOFF = "2005-01-01T00:00:00Z"

BODY = b"offline phase 2 test package content\n"


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def make_blobs():
    blobs: dict[str, bytes] = {}

    def blob(raw: bytes) -> str:
        digest = hashlib.sha256(raw).hexdigest()
        blobs[digest] = raw
        return digest

    return blobs, blob


def test_phase2_mirrors_all_four_ecosystems_end_to_end():
    blobs, blob = make_blobs()
    artifact_hash = blob(BODY)

    packages = [
        # 1. PyPI
        {
            "ecosystem": "pypi-simple",
            "name": "mypkg",
            "metadata": blob(
                encoded({
                    "meta": {"api-version": "1.1"},
                    "name": "mypkg",
                    "files": [
                        {
                            "filename": "mypkg-1.0.0.tar.gz",
                            "hashes": {"sha256": artifact_hash},
                            "size": len(BODY),
                            "upload-time": CUTOFF,
                        },
                        {
                            "filename": "mypkg-2.0.0.tar.gz",
                            "hashes": {"sha256": artifact_hash},
                            "size": len(BODY),
                            "upload-time": FUTURE_DATE,
                        },
                    ],
                })
            ),
            "artifacts": {"mypkg-1.0.0.tar.gz": artifact_hash},
        },
        # 2. Conda
        {
            "ecosystem": "conda",
            "name": "conda-forge/linux-64",
            "metadata": blob(
                encoded({
                    "info": {"subdir": "linux-64"},
                    "repodata_version": 1,
                    "packages": {
                        "mypkg-1.0.0.tar.bz2": {
                            "name": "mypkg",
                            "version": "1.0.0",
                            "build": "0",
                            "timestamp": CUTOFF_MS,
                            "sha256": artifact_hash,
                        },
                        "mypkg-2.0.0.tar.bz2": {
                            "name": "mypkg",
                            "version": "2.0.0",
                            "build": "0",
                            "timestamp": FUTURE_MS,
                            "sha256": artifact_hash,
                        },
                    },
                    "packages.conda": {},
                })
            ),
            "artifacts": {"mypkg-1.0.0.tar.bz2": artifact_hash},
        },
        # 3. Apt (Ubuntu on/after 2023-03-01)
        {
            "ecosystem": "apt",
            "name": "ubuntu/jammy",
            "metadata": blob(
                encoded({
                    "dist": "ubuntu",
                    "suite": "jammy",
                    "snapshot_id": "20230401T000000Z",
                    "files": {
                        "dists/jammy/InRelease": {"sha256": artifact_hash, "content_type": "text/plain"},
                        "pool/main/m/mypkg/mypkg_1.0.0_amd64.deb": {
                            "sha256": artifact_hash,
                            "content_type": "application/vnd.debian.binary-package",
                        },
                    },
                })
            ),
            "artifacts": {
                "dists/jammy/InRelease": artifact_hash,
                "pool/main/m/mypkg/mypkg_1.0.0_amd64.deb": artifact_hash,
            },
        },
        # 4. Git static mirror (dumb HTTP)
        {
            "ecosystem": "git",
            "name": "github.com/myorg/myrepo.git",
            "metadata": blob(b"2222222222222222222222222222222222222222\trefs/heads/main\n"),
            "artifacts": {
                "HEAD": blob(b"ref: refs/heads/main\n"),
                "info/refs": blob(b"2222222222222222222222222222222222222222\trefs/heads/main\n"),
                "objects/info/packs": blob(b"P pack-2222222222222222222222222222222222222222.pack\n"),
                "objects/pack/pack-2222222222222222222222222222222222222222.pack": artifact_hash,
                "objects/pack/pack-2222222222222222222222222222222222222222.idx": artifact_hash,
            },
        },
    ]

    recipe = {"cutoff": CUTOFF, "packages": packages}
    build = build_mirror(encoded(recipe), blobs)
    files = dict(build.files)

    # 1. PyPI assertions
    assert f"pypi.org/files/{artifact_hash}/mypkg-1.0.0.tar.gz" in files
    assert f"pypi.org/files/{artifact_hash}/mypkg-2.0.0.tar.gz" not in files
    pypi_index = files["pypi.org/simple/mypkg/index.html"]
    assert b"mypkg-1.0.0.tar.gz" in pypi_index
    assert b"mypkg-2.0.0.tar.gz" not in pypi_index

    # 2. Conda assertions
    conda_repodata = json.loads(files["conda.anaconda.org/conda-forge/linux-64/repodata.json"])
    assert "mypkg-1.0.0.tar.bz2" in conda_repodata["packages"]
    assert "mypkg-2.0.0.tar.bz2" not in conda_repodata["packages"]
    assert "conda.anaconda.org/conda-forge/linux-64/mypkg-1.0.0.tar.bz2" in files
    assert "conda.anaconda.org/conda-forge/linux-64/mypkg-2.0.0.tar.bz2" not in files

    # 3. Apt assertions
    assert "snapshot.ubuntu.com/ubuntu/20230401T000000Z/dists/jammy/InRelease" in files
    assert "snapshot.ubuntu.com/ubuntu/20230401T000000Z/pool/main/m/mypkg/mypkg_1.0.0_amd64.deb" in files

    # 4. Git assertions
    assert "github.com/myorg/myrepo.git/HEAD" in files
    assert "github.com/myorg/myrepo.git/info/refs" in files
    assert "github.com/myorg/myrepo.git/objects/info/packs" in files
    assert "github.com/myorg/myrepo.git/objects/pack/pack-2222222222222222222222222222222222222222.pack" in files
    assert "github.com/myorg/myrepo.git/objects/pack/pack-2222222222222222222222222222222222222222.idx" in files

    # Verification passes
    verified = verify_mirror(build.manifest, files, build.reports, build.root_sha256, CUTOFF)
    assert verified.root_sha256 == build.root_sha256


def test_tr_pkg_5_ubuntu_snapshot_before_2023_03_01_refused():
    blobs, blob = make_blobs()
    artifact_hash = blob(BODY)
    packages = [
        {
            "ecosystem": "apt",
            "name": "ubuntu/jammy",
            "metadata": blob(
                encoded({
                    "dist": "ubuntu",
                    "suite": "jammy",
                    "files": {
                        "dists/jammy/InRelease": {"sha256": artifact_hash},
                    },
                })
            ),
            "artifacts": {"dists/jammy/InRelease": artifact_hash},
        }
    ]
    recipe = {"cutoff": PRE_UBUNTU_CUTOFF, "packages": packages}
    with pytest.raises(CutError, match="ubuntu snapshot before 2023-03-01 is unavailable"):
        build_mirror(encoded(recipe), blobs)


def test_debian_snapshot_before_2005_03_12_refused():
    blobs, blob = make_blobs()
    artifact_hash = blob(BODY)
    packages = [
        {
            "ecosystem": "apt",
            "name": "debian/sarge",
            "metadata": blob(
                encoded({
                    "dist": "debian",
                    "suite": "sarge",
                    "files": {
                        "dists/sarge/Release": {"sha256": artifact_hash},
                    },
                })
            ),
            "artifacts": {"dists/sarge/Release": artifact_hash},
        }
    ]
    recipe = {"cutoff": PRE_DEBIAN_CUTOFF, "packages": packages}
    with pytest.raises(CutError, match="debian snapshot before 2005-03-12 is unavailable"):
        build_mirror(encoded(recipe), blobs)


def test_conda_mismatched_artifact_sha_refused():
    blobs, blob = make_blobs()
    artifact_hash = blob(BODY)
    packages = [
        {
            "ecosystem": "conda",
            "name": "conda-forge/linux-64",
            "metadata": blob(
                encoded({
                    "info": {"subdir": "linux-64"},
                    "repodata_version": 1,
                    "packages": {
                        "mypkg-1.0.0.tar.bz2": {
                            "name": "mypkg",
                            "version": "1.0.0",
                            "build": "0",
                            "timestamp": CUTOFF_MS,
                            "sha256": "0" * 64,  # wrong digest
                        },
                    },
                    "packages.conda": {},
                })
            ),
            "artifacts": {"mypkg-1.0.0.tar.bz2": artifact_hash},
        }
    ]
    recipe = {"cutoff": CUTOFF, "packages": packages}
    with pytest.raises(CutError, match="conda artifact digest mismatch"):
        build_mirror(encoded(recipe), blobs)


def test_git_hostile_path_traversal_refused():
    blobs, blob = make_blobs()
    artifact_hash = blob(BODY)
    packages = [
        {
            "ecosystem": "git",
            "name": "github.com/myorg/myrepo.git",
            "metadata": blob(b"refs"),
            "artifacts": {
                "../escape": artifact_hash,
            },
        }
    ]
    recipe = {"cutoff": CUTOFF, "packages": packages}
    with pytest.raises(CutError, match="invalid mirror artifact key"):
        build_mirror(encoded(recipe), blobs)


def test_apt_non_string_dist_raises_cut_error():
    blobs, blob = make_blobs()
    packages = [
        {
            "ecosystem": "apt",
            "name": "ubuntu/jammy",
            "metadata": blob(
                encoded({
                    "dist": [],  # non-string hostile input
                    "suite": "jammy",
                    "files": {},
                })
            ),
            "artifacts": {},
        }
    ]
    recipe = {"cutoff": CUTOFF, "packages": packages}
    with pytest.raises(CutError, match="invalid apt distribution"):
        build_mirror(encoded(recipe), blobs)


def test_apt_mismatched_content_type_override_rejected():
    blobs, blob = make_blobs()
    artifact_hash = blob(BODY)
    packages = [
        {
            "ecosystem": "apt",
            "name": "ubuntu/jammy",
            "metadata": blob(
                encoded({
                    "dist": "ubuntu",
                    "suite": "jammy",
                    "snapshot_id": "20230401T000000Z",
                    "files": {
                        "pool/main/m/mypkg/mypkg_1.0.0_amd64.deb": {
                            "sha256": artifact_hash,
                            "content_type": "text/plain",  # Mismatched override
                        },
                    },
                })
            ),
            "artifacts": {
                "pool/main/m/mypkg/mypkg_1.0.0_amd64.deb": artifact_hash,
            },
        }
    ]
    recipe = {"cutoff": CUTOFF, "packages": packages}
    with pytest.raises(CutError, match="invalid apt content type"):
        build_mirror(encoded(recipe), blobs)


def test_apt_snapshot_date_after_cutoff_and_route_mismatch():
    blobs, blob = make_blobs()
    artifact_hash = blob(BODY)

    # 1. Snapshot date in metadata is after cutoff
    packages_future_snap = [
        {
            "ecosystem": "apt",
            "name": "ubuntu/jammy",
            "metadata": blob(
                encoded({
                    "dist": "ubuntu",
                    "suite": "jammy",
                    "snapshot_id": "20230402T000000Z",  # Cutoff is 2023-04-01
                    "files": {
                        "dists/jammy/InRelease": {"sha256": artifact_hash, "content_type": "text/plain"},
                    },
                })
            ),
            "artifacts": {"dists/jammy/InRelease": artifact_hash},
        }
    ]
    with pytest.raises(CutError, match="apt snapshot date is after cutoff"):
        build_mirror(encoded({"cutoff": CUTOFF, "packages": packages_future_snap}), blobs)

    # 2. Explicit route snapshot ID mismatch
    blobs2, blob2 = make_blobs()
    artifact_hash2 = blob2(BODY)
    packages_route_mismatch = [
        {
            "ecosystem": "apt",
            "name": "snapshot.ubuntu.com/ubuntu/20230301T000000Z",
            "metadata": blob2(
                encoded({
                    "dist": "ubuntu",
                    "suite": "jammy",
                    "snapshot_id": "20230401T000000Z",  # does not match route's 20230301T000000Z
                    "files": {
                        "dists/jammy/InRelease": {"sha256": artifact_hash2, "content_type": "text/plain"},
                    },
                })
            ),
            "artifacts": {"dists/jammy/InRelease": artifact_hash2},
        }
    ]
    with pytest.raises(CutError, match="apt route snapshot id mismatch"):
        build_mirror(encoded({"cutoff": CUTOFF, "packages": packages_route_mismatch}), blobs2)


def test_conda_duplicate_filename_digest_validated_before_merge():
    blobs, blob = make_blobs()
    artifact_hash = blob(BODY)
    # packages has wrong digest; packages.conda has correct digest for the same filename
    packages = [
        {
            "ecosystem": "conda",
            "name": "conda-forge/linux-64",
            "metadata": blob(
                encoded({
                    "info": {"subdir": "linux-64"},
                    "repodata_version": 1,
                    "packages": {
                        "dup-1.0.0.tar.bz2": {
                            "name": "dup",
                            "version": "1.0.0",
                            "build": "0",
                            "timestamp": CUTOFF_MS,
                            "sha256": "0" * 64,  # wrong digest that would be masked by merge
                        },
                    },
                    "packages.conda": {
                        "dup-1.0.0.tar.bz2": {
                            "name": "dup",
                            "version": "1.0.0",
                            "build": "0",
                            "timestamp": CUTOFF_MS,
                            "sha256": artifact_hash,  # valid digest
                        },
                    },
                })
            ),
            "artifacts": {"dup-1.0.0.tar.bz2": artifact_hash},
        }
    ]
    recipe = {"cutoff": CUTOFF, "packages": packages}
    with pytest.raises(CutError, match="conda artifact digest mismatch"):
        build_mirror(encoded(recipe), blobs)


def test_conda_cut_error_suppresses_cause_and_fixed_message():
    blobs, blob = make_blobs()
    packages = [
        {
            "ecosystem": "conda",
            "name": "conda-forge/linux-64",
            "metadata": blob(
                encoded({
                    "info": {"subdir": "linux-64"},
                    "repodata_version": 1,
                    "packages": "not-a-dict",  # causes HermeticCondaCutError
                })
            ),
            "artifacts": {},
        }
    ]
    recipe = {"cutoff": CUTOFF, "packages": packages}
    with pytest.raises(CutError, match="^invalid conda repodata$") as exc_info:
        build_mirror(encoded(recipe), blobs)
    assert exc_info.value.__cause__ is None
