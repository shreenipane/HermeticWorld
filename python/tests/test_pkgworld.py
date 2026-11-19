"""Offline unit and integration tests for hermetic_pkgworld.

Tests deterministic Merkle tree computation, canonical leaf generation,
zero-package signoff verification, artifact tampering fail-closed behavior,
and CLI interface. No network access required.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from hermetic_pkgbase.builder import BaselineBuilder, OfflineFixtureFetcher
from hermetic_pkgbase.planner import Planner
from hermetic_pkgbase.spec import parse_spec
from hermetic_pkgbase.resolver import OfflineFixtureResolver
from hermetic_pkgrec.freeze import freeze_world
from hermetic_pkgrec.manifest import Manifest
from hermetic_pkgrec.store import RecordingStore
from hermetic_pkgworld.constants import (
    PKG_EMPTY_TAG,
    PKG_LEAF_TAG,
    PKG_NODE_TAG,
)
from hermetic_pkgworld.errors import (
    BaselineError,
    ClosureError,
    CutoffMismatchError,
    IntegrityError,
    PkgWorldError,
    SafeIOError,
)
from hermetic_pkgworld.evidence import (
    canonical_json_bytes,
    compute_baseline_root,
    compute_closure_root,
    compute_leaf_hash,
    compute_merkle_root,
    compute_package_evidence,
)
from hermetic_pkgworld.cli import main as cli_main


def _create_test_closure(
    tmp_path: Path,
    cutoff: str,
    files: list[tuple[str, str, bytes, str]],  # (project, filename, content, yank_decision)
) -> Path:
    """Helper to produce a verified Layer-1 frozen closure via hermetic_pkgrec freeze."""
    store_dir = tmp_path / "store"
    manifest_path = tmp_path / "manifest.json"
    out_dir = tmp_path / "frozen_closure"

    rec_store = RecordingStore(store_dir)
    manifest = Manifest(cutoff=cutoff)

    for project, filename, content, yank_dec in files:
        sha256 = hashlib.sha256(content).hexdigest()
        rec_store.save_file_stream(sha256, filename, [content])
        manifest.record_file(project, filename, sha256, cutoff, yank_dec)

    manifest.save(manifest_path)
    freeze_world(store_dir, manifest_path, out_dir)
    return out_dir


def _create_test_baseline(
    tmp_path: Path,
    cutoff_month: str,
    fixture_packages: dict[str, list[dict[str, object]]],
    fixture_files: dict[str, bytes],
) -> Path:
    """Helper to produce a verified Layer-2 frozen baseline store via hermetic_pkgbase."""
    spec = parse_spec({"cutoff_month": cutoff_month, "fixed_tools": ["pytest"]})
    resolver = OfflineFixtureResolver(fixture_packages)
    plan = Planner().plan(spec, resolver)

    store_dir = tmp_path / "baseline_store"
    builder = BaselineBuilder(store_dir)
    fetcher = OfflineFixtureFetcher(fixture_files)
    builder.build(plan, fetcher)
    return store_dir


@pytest.fixture
def baseline_fixtures() -> tuple[dict[str, list[dict[str, object]]], dict[str, bytes]]:
    pytest_whl = b"PK\x03\x04pytest-7.4.0-wheel-content"
    sha_pytest = hashlib.sha256(pytest_whl).hexdigest()

    packages = {
        "pytest": [
            {
                "version": "7.4.0",
                "upload_time": "2024-04-15T12:00:00Z",
                "dependencies": [],
                "files": [
                    {
                        "filename": "pytest-7.4.0-py3-none-any.whl",
                        "sha256": sha_pytest,
                        "upload_time": "2024-04-15T12:00:00Z",
                        "size_bytes": len(pytest_whl),
                        "yanked": False,
                    }
                ],
            }
        ]
    }
    files = {sha_pytest: pytest_whl}
    return packages, files


# ---------------------------------------------------------------------------
# 1. Known-Answer & Merkle Properties
# ---------------------------------------------------------------------------


def test_merkle_leaf_hash_and_empty_tree() -> None:
    """Verify Merkle leaf hashing with domain separation and empty tree hash."""
    empty_root = compute_merkle_root([])
    expected_empty = hashlib.sha256(PKG_EMPTY_TAG).digest()
    assert empty_root == expected_empty

    path = "/test/path"
    val = b'{"key":"val"}\n'
    leaf_hash = compute_leaf_hash(PKG_LEAF_TAG, path, val)

    # Reconstruct expected hash manually
    expected_hasher = hashlib.sha256()
    expected_hasher.update(b"hw-pkg-leaf\0")
    expected_hasher.update(len(path.encode("utf-8")).to_bytes(4, "little"))
    expected_hasher.update(path.encode("utf-8"))
    expected_hasher.update(len(val).to_bytes(4, "little"))
    expected_hasher.update(val)
    assert leaf_hash == expected_hasher.digest()


def test_merkle_binary_reduction_odd_promotion() -> None:
    """Verify that an odd node at any level of the Merkle tree is promoted unchanged."""
    leaf1 = hashlib.sha256(b"leaf1").digest()
    leaf2 = hashlib.sha256(b"leaf2").digest()
    leaf3 = hashlib.sha256(b"leaf3").digest()

    # Manual level reduction for 3 leaves:
    # Level 1: pair(leaf1, leaf2), promote leaf3
    parent12 = hashlib.sha256(PKG_NODE_TAG + leaf1 + leaf2).digest()
    # Level 2: pair(parent12, leaf3)
    expected_root = hashlib.sha256(PKG_NODE_TAG + parent12 + leaf3).digest()

    actual_root = compute_merkle_root([leaf1, leaf2, leaf3])
    assert actual_root == expected_root


# ---------------------------------------------------------------------------
# 2. Layer-1 Closure: Zero Packages Representation & Determinism
# ---------------------------------------------------------------------------


def test_zero_packages_closure_signoff(tmp_path: Path) -> None:
    """A task with no third-party packages must be represented explicitly and verifiably.

    Signed off by pkgrec with zero files, it produces a deterministic, non-empty 64-hex digest.
    """
    closure_dir = _create_test_closure(tmp_path, "2024-01-01T00:00:00Z", [])

    root, summary = compute_closure_root(closure_dir)
    assert root.startswith("sha256:")
    assert len(root) == 7 + 64
    assert root != ""
    assert summary["files_count"] == 0
    assert summary["cutoff"] == "2024-01-01T00:00:00Z"

    # Running again on identical input must yield the exact same root
    root_repeat, _ = compute_closure_root(closure_dir)
    assert root == root_repeat


def test_unverified_empty_directory_refused(tmp_path: Path) -> None:
    """An arbitrary empty directory without pkgrec signoff manifest fails closed."""
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir(parents=True)

    with pytest.raises(ClosureError, match="Missing package closure manifest"):
        compute_closure_root(empty_dir)


def test_closure_order_invariance_and_determinism(tmp_path: Path) -> None:
    """Different manifest insertion orders yield the exact same closure_root."""
    f1 = ("alpha", "alpha-1.0.whl", b"alpha-content", "not_yanked")
    f2 = ("beta", "beta-2.0.whl", b"beta-content", "yanked")
    f3 = ("gamma", "gamma-3.0.whl", b"gamma-content", "not_yanked")

    dir_a = _create_test_closure(tmp_path / "a", "2024-01-01T00:00:00Z", [f1, f2, f3])
    dir_b = _create_test_closure(tmp_path / "b", "2024-01-01T00:00:00Z", [f3, f1, f2])

    root_a, _ = compute_closure_root(dir_a)
    root_b, _ = compute_closure_root(dir_b)
    assert root_a == root_b


# ---------------------------------------------------------------------------
# 3. Layer-1 Closure: Tamper Detection & Safety
# ---------------------------------------------------------------------------


def test_closure_tampered_artifact_fails_closed(tmp_path: Path) -> None:
    """Tampering with an artifact file on disk fails closed immediately."""
    closure_dir = _create_test_closure(
        tmp_path,
        "2024-01-01T00:00:00Z",
        [("pkg", "pkg-1.0.whl", b"original-content", "not_yanked")],
    )

    # Corrupt the wheel bytes on disk
    orig_sha = hashlib.sha256(b"original-content").hexdigest()
    art_path = closure_dir / "files" / orig_sha / "pkg-1.0.whl"
    art_path.write_bytes(b"tampered-content")

    with pytest.raises(IntegrityError, match="Digest mismatch"):
        compute_closure_root(closure_dir)


def test_closure_missing_artifact_fails_closed(tmp_path: Path) -> None:
    """Missing an artifact file on disk fails closed."""
    closure_dir = _create_test_closure(
        tmp_path,
        "2024-01-01T00:00:00Z",
        [("pkg", "pkg-1.0.whl", b"content", "not_yanked")],
    )

    sha = hashlib.sha256(b"content").hexdigest()
    (closure_dir / "files" / sha / "pkg-1.0.whl").unlink()

    with pytest.raises(IntegrityError, match="Missing distribution file"):
        compute_closure_root(closure_dir)


def test_closure_rogue_file_fails_closed(tmp_path: Path) -> None:
    """Injecting an undeclared rogue file into the closure fails closed."""
    closure_dir = _create_test_closure(
        tmp_path,
        "2024-01-01T00:00:00Z",
        [("pkg", "pkg-1.0.whl", b"content", "not_yanked")],
    )

    # Add an undeclared rogue file
    rogue_dir = closure_dir / "files" / ("a" * 64)
    rogue_dir.mkdir(parents=True)
    (rogue_dir / "rogue.whl").write_bytes(b"rogue")

    with pytest.raises(ClosureError, match="Undeclared rogue file"):
        compute_closure_root(closure_dir)


def test_closure_symlinked_artifact_refused(tmp_path: Path) -> None:
    """Symlinked artifacts in closure are strictly refused."""
    closure_dir = _create_test_closure(
        tmp_path,
        "2024-01-01T00:00:00Z",
        [("pkg", "pkg-1.0.whl", b"content", "not_yanked")],
    )
    sha = hashlib.sha256(b"content").hexdigest()
    art_path = closure_dir / "files" / sha / "pkg-1.0.whl"
    outside_target = tmp_path / "outside.whl"
    outside_target.write_bytes(b"content")

    art_path.unlink()
    art_path.symlink_to(outside_target)

    with pytest.raises((PkgWorldError, OSError)):
        compute_closure_root(closure_dir)


# ---------------------------------------------------------------------------
# 4. Layer-2 Baseline: Computation, Immutability & Cutoff
# ---------------------------------------------------------------------------


def test_baseline_root_computation(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """Verify Layer-2 baseline root computation and baseline_month extraction."""
    pkg_meta, pkg_files = baseline_fixtures
    store_dir = _create_test_baseline(tmp_path, "2024-05", pkg_meta, pkg_files)

    root, month, summary = compute_baseline_root(store_dir)
    assert root.startswith("sha256:")
    assert len(root) == 7 + 64
    assert month == "2024-05"
    assert summary["files_count"] == 1
    assert summary["cutoff_month"] == "2024-05"

    # Determinism check
    root_repeat, month_repeat, _ = compute_baseline_root(store_dir)
    assert root == root_repeat
    assert month == month_repeat


def test_unfrozen_baseline_store_refused(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """A baseline store lacking the .frozen immutability marker fails closed."""
    pkg_meta, pkg_files = baseline_fixtures
    store_dir = _create_test_baseline(tmp_path, "2024-05", pkg_meta, pkg_files)

    # Make parent writable to remove .frozen
    os.chmod(store_dir, 0o700)
    (store_dir / ".frozen").unlink()

    with pytest.raises(BaselineError, match="not frozen"):
        compute_baseline_root(store_dir)


def test_baseline_cutoff_month_mismatch_refused(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """Supplying a baseline with a cutoff month different from expected fails closed."""
    pkg_meta, pkg_files = baseline_fixtures
    store_dir = _create_test_baseline(tmp_path, "2024-05", pkg_meta, pkg_files)

    with pytest.raises(CutoffMismatchError, match="does not match expected month"):
        compute_baseline_root(store_dir, expected_month="2023-01")


def test_baseline_tampered_artifact_fails_closed(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """Tampering with an artifact inside a frozen baseline store fails closed."""
    pkg_meta, pkg_files = baseline_fixtures
    store_dir = _create_test_baseline(tmp_path, "2024-05", pkg_meta, pkg_files)

    # Tamper with file
    files_dir = store_dir / "files"
    sha = list(pkg_files.keys())[0]
    art_path = files_dir / sha / "pytest-7.4.0-py3-none-any.whl"

    # Temporarily adjust permissions to simulate tampering
    os.chmod(store_dir, 0o700)
    os.chmod(files_dir, 0o700)
    os.chmod(files_dir / sha, 0o700)
    os.chmod(art_path, 0o600)
    art_path.write_bytes(b"tampered-data")
    os.chmod(art_path, 0o400)
    os.chmod(files_dir / sha, 0o500)
    os.chmod(files_dir, 0o500)
    os.chmod(store_dir, 0o500)

    with pytest.raises(IntegrityError, match="Digest mismatch"):
        compute_baseline_root(store_dir)


# ---------------------------------------------------------------------------
# 5. Full Package Evidence Integration & CLI
# ---------------------------------------------------------------------------


def test_compute_package_evidence_end_to_end(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """compute_package_evidence returns valid PackagesRecord dictionary."""
    closure_dir = _create_test_closure(
        tmp_path / "closure",
        "2024-05-01T00:00:00Z",
        [("requests", "requests-2.28.1.whl", b"req-content", "not_yanked")],
    )
    pkg_meta, pkg_files = baseline_fixtures
    baseline_dir = _create_test_baseline(tmp_path / "baseline", "2024-05", pkg_meta, pkg_files)

    evidence = compute_package_evidence(
        closure_dir,
        baseline_dir,
        expected_pkg_cutoff="2024-05-01T00:00:00Z",
    )

    assert set(evidence.keys()) == {"closure_root", "baseline_month", "baseline_root"}
    assert evidence["closure_root"].startswith("sha256:")
    assert evidence["baseline_root"].startswith("sha256:")
    assert evidence["baseline_month"] == "2024-05"


def test_cli_pkgworld_success(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """CLI execution prints canonical JSON {closure_root, baseline_month, baseline_root}."""
    closure_dir = _create_test_closure(
        tmp_path / "closure",
        "2024-05-01T00:00:00Z",
        [("requests", "requests-2.28.1.whl", b"req-content", "not_yanked")],
    )
    pkg_meta, pkg_files = baseline_fixtures
    baseline_dir = _create_test_baseline(tmp_path / "baseline", "2024-05", pkg_meta, pkg_files)

    rc = cli_main(["--pkg-closure", str(closure_dir), "--pkg-baseline", str(baseline_dir)])
    assert rc == 0

    out = capsys.readouterr().out
    data = json.loads(out)
    assert "closure_root" in data
    assert "baseline_month" in data
    assert "baseline_root" in data
    assert data["baseline_month"] == "2024-05"


def test_cli_pkgworld_missing_argument(capsys: pytest.CaptureFixture[str]) -> None:
    """CLI fails with non-zero exit code when required directories are omitted."""
    rc = cli_main([])
    assert rc == 1
    err = capsys.readouterr().err
    assert "Error: Missing required closure directory" in err


def test_cli_pkgworld_tampered_fails(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """CLI fails closed with exit 1 on corrupted or tampered inputs."""
    closure_dir = _create_test_closure(
        tmp_path / "closure",
        "2024-05-01T00:00:00Z",
        [("requests", "requests-2.28.1.whl", b"req-content", "not_yanked")],
    )
    pkg_meta, pkg_files = baseline_fixtures
    baseline_dir = _create_test_baseline(tmp_path / "baseline", "2024-05", pkg_meta, pkg_files)

    # Tamper with closure file
    sha = hashlib.sha256(b"req-content").hexdigest()
    (closure_dir / "files" / sha / "requests-2.28.1.whl").write_bytes(b"tampered")

    rc = cli_main(["--closure", str(closure_dir), "--baseline", str(baseline_dir)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "Digest mismatch" in err



# ---------------------------------------------------------------------------
# 6. Regression tests for CodeRabbit review findings
# ---------------------------------------------------------------------------


def test_cutoff_month_trailing_newline_rejected(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """Finding 2: cutoff_month with trailing newline must be rejected (\\Z vs $)."""
    pkg_meta, pkg_files = baseline_fixtures
    store_dir = _create_test_baseline(tmp_path, "2024-05", pkg_meta, pkg_files)

    # Tamper baseline-manifest.json: inject trailing newline into cutoff_month
    os.chmod(store_dir, 0o700)
    manifest_path = store_dir / "baseline-manifest.json"
    os.chmod(manifest_path, 0o600)
    raw = manifest_path.read_bytes()
    manifest_data = json.loads(raw)
    manifest_data["cutoff_month"] = "2024-05\n"
    manifest_path.write_bytes(json.dumps(manifest_data, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    os.chmod(manifest_path, 0o400)
    os.chmod(store_dir, 0o500)

    with pytest.raises(BaselineError, match="Invalid or missing cutoff_month"):
        compute_baseline_root(store_dir)


def test_closure_symlinked_root_rejected(tmp_path: Path) -> None:
    """Finding 9: A symlinked closure root directory must be rejected before resolve()."""
    real_dir = _create_test_closure(tmp_path / "real", "2024-01-01T00:00:00Z", [])
    symlink_dir = tmp_path / "symlink_closure"
    symlink_dir.symlink_to(real_dir)

    with pytest.raises(ClosureError, match="must not be a symlink"):
        compute_closure_root(symlink_dir)


def test_baseline_symlinked_root_rejected(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """Finding 9: A symlinked baseline root directory must be rejected before resolve()."""
    pkg_meta, pkg_files = baseline_fixtures
    store_dir = _create_test_baseline(tmp_path / "real", "2024-05", pkg_meta, pkg_files)
    symlink_dir = tmp_path / "symlink_baseline"
    symlink_dir.symlink_to(store_dir)

    with pytest.raises(BaselineError, match="must not be a symlink"):
        compute_baseline_root(symlink_dir)


def test_closure_absolute_filename_path_traversal_rejected(tmp_path: Path) -> None:
    """Finding 10 (CWE-22): An absolute filename in the closure manifest must be rejected."""
    closure_dir = tmp_path / "closure"
    closure_dir.mkdir(parents=True)

    # Craft a manifest with an absolute filename
    hostile_manifest = {
        "schema": "hermetic.pkgrec.manifest/1",
        "cutoff": "2024-01-01T00:00:00Z",
        "files": [
            {
                "project": "evilpkg",
                "filename": "/etc/hostname",
                "sha256": "a" * 64,
                "upload-time": "2024-01-01T00:00:00Z",
                "yank_decision": "not_yanked",
            }
        ],
    }
    (closure_dir / "manifest.json").write_bytes(
        json.dumps(hostile_manifest, sort_keys=True).encode("utf-8") + b"\n"
    )

    with pytest.raises(ClosureError, match="Unsafe distribution filename"):
        compute_closure_root(closure_dir, verify_files=False)


def test_closure_dotdot_filename_path_traversal_rejected(tmp_path: Path) -> None:
    """Finding 10 (CWE-22): A .. filename in the closure manifest must be rejected."""
    closure_dir = tmp_path / "closure"
    closure_dir.mkdir(parents=True)

    hostile_manifest = {
        "schema": "hermetic.pkgrec.manifest/1",
        "cutoff": "2024-01-01T00:00:00Z",
        "files": [
            {
                "project": "evilpkg",
                "filename": "..",
                "sha256": "b" * 64,
                "upload-time": "2024-01-01T00:00:00Z",
                "yank_decision": "not_yanked",
            }
        ],
    }
    (closure_dir / "manifest.json").write_bytes(
        json.dumps(hostile_manifest, sort_keys=True).encode("utf-8") + b"\n"
    )

    with pytest.raises(ClosureError, match="Unsafe distribution filename"):
        compute_closure_root(closure_dir, verify_files=False)


def test_closure_slash_filename_path_traversal_rejected(tmp_path: Path) -> None:
    """Finding 10 (CWE-22): A filename with separators in the closure manifest must be rejected."""
    closure_dir = tmp_path / "closure"
    closure_dir.mkdir(parents=True)

    hostile_manifest = {
        "schema": "hermetic.pkgrec.manifest/1",
        "cutoff": "2024-01-01T00:00:00Z",
        "files": [
            {
                "project": "evilpkg",
                "filename": "sub/../../etc/passwd",
                "sha256": "c" * 64,
                "upload-time": "2024-01-01T00:00:00Z",
                "yank_decision": "not_yanked",
            }
        ],
    }
    (closure_dir / "manifest.json").write_bytes(
        json.dumps(hostile_manifest, sort_keys=True).encode("utf-8") + b"\n"
    )

    with pytest.raises(ClosureError, match="Unsafe distribution filename"):
        compute_closure_root(closure_dir, verify_files=False)


def test_baseline_absolute_filename_path_traversal_rejected(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """Finding 10 (CWE-22): An absolute filename in the baseline plan must be rejected."""
    pkg_meta, pkg_files = baseline_fixtures
    store_dir = _create_test_baseline(tmp_path, "2024-05", pkg_meta, pkg_files)

    # Tamper baseline-plan.json with an absolute filename
    os.chmod(store_dir, 0o700)
    plan_path = store_dir / "baseline-plan.json"
    os.chmod(plan_path, 0o600)
    plan_data = json.loads(plan_path.read_bytes())
    plan_data["files"][0]["filename"] = "/etc/hostname"
    plan_path.write_bytes(json.dumps(plan_data, sort_keys=True).encode("utf-8") + b"\n")
    os.chmod(plan_path, 0o400)
    # Must also update .frozen plan_hash to match the tampered plan
    frozen_path = store_dir / ".frozen"
    os.chmod(frozen_path, 0o600)
    new_plan_hash = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    frozen_data = json.loads(frozen_path.read_bytes())
    frozen_data["plan_hash"] = new_plan_hash
    frozen_path.write_bytes(json.dumps(frozen_data, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    os.chmod(frozen_path, 0o400)
    os.chmod(store_dir, 0o500)

    with pytest.raises(BaselineError, match="Unsafe distribution filename"):
        compute_baseline_root(store_dir, verify_files=False)


def test_baseline_plan_hash_mismatch_rejected(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """Finding 5: A tampered baseline-plan.json must be rejected via plan_hash binding."""
    pkg_meta, pkg_files = baseline_fixtures
    store_dir = _create_test_baseline(tmp_path, "2024-05", pkg_meta, pkg_files)

    # Tamper baseline-plan.json without updating .frozen
    os.chmod(store_dir, 0o700)
    plan_path = store_dir / "baseline-plan.json"
    os.chmod(plan_path, 0o600)
    plan_data = json.loads(plan_path.read_bytes())
    # Modify upload-time — this changes the plan bytes and thus the hash
    plan_data["files"][0]["upload-time"] = "2099-01-01T00:00:00Z"
    plan_path.write_bytes(json.dumps(plan_data, sort_keys=True).encode("utf-8") + b"\n")
    os.chmod(plan_path, 0o400)
    os.chmod(store_dir, 0o500)

    with pytest.raises(BaselineError, match="plan hash mismatch"):
        compute_baseline_root(store_dir, verify_files=False)


def test_freeze_reuse_without_manifest_rejected(tmp_path: Path) -> None:
    """Finding 1: An existing root with files/ and simple/ but no manifest.json must not pass
    idempotency check; freeze_world should refuse to modify it."""
    from hermetic_pkgrec.errors import ExistingFrozenRootError

    # Create a valid frozen closure first
    closure_dir = _create_test_closure(
        tmp_path / "first",
        "2024-01-01T00:00:00Z",
        [("pkg", "pkg-1.0.whl", b"content", "not_yanked")],
    )

    # Remove its manifest.json to simulate a legacy root without manifest
    manifest = closure_dir / "manifest.json"
    manifest.unlink()

    # Try to freeze again into the same directory — should refuse since manifest is missing
    store_dir = tmp_path / "store2"
    manifest_path = tmp_path / "manifest2.json"

    rec_store = RecordingStore(store_dir)
    new_manifest = Manifest(cutoff="2024-01-01T00:00:00Z")
    sha = hashlib.sha256(b"content").hexdigest()
    rec_store.save_file_stream(sha, "pkg-1.0.whl", [b"content"])
    new_manifest.record_file("pkg", "pkg-1.0.whl", sha, "2024-01-01T00:00:00Z", "not_yanked")
    new_manifest.save(manifest_path)

    with pytest.raises(ExistingFrozenRootError):
        freeze_world(store_dir, manifest_path, closure_dir)


def test_short_reads_handled_until_eof_without_truncation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Finding 6: os.read returning fewer bytes than requested before EOF must not
    cause premature termination of bounded reads or false digest mismatches."""
    from hermetic_pkgworld.evidence import _read_regular_file_bounded, _verify_file_hash_on_disk

    test_data = b"x" * 10_000
    expected_sha = hashlib.sha256(test_data).hexdigest()
    test_file = tmp_path / "data.bin"
    test_file.write_bytes(test_data)

    real_os_read = os.read

    def fake_short_read(fd: int, n: int) -> bytes:
        return real_os_read(fd, min(n, 50))

    monkeypatch.setattr(os, "read", fake_short_read)

    result_bytes = _read_regular_file_bounded(test_file, max_bytes=20_000)
    assert len(result_bytes) == 10_000
    assert result_bytes == test_data

    _verify_file_hash_on_disk(test_file, expected_sha)


def test_read_os_error_wrapped_in_safe_io_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Finding 7: Filesystem OSError from os.read must be wrapped in SafeIOError."""
    from hermetic_pkgworld.evidence import _read_regular_file_bounded, _verify_file_hash_on_disk
    from hermetic_pkgworld.errors import SafeIOError

    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"content")

    def broken_read(fd: int, n: int) -> bytes:
        raise OSError("Simulated I/O hardware failure")

    monkeypatch.setattr(os, "read", broken_read)

    with pytest.raises(SafeIOError, match="Error reading file.*Simulated I/O hardware failure"):
        _read_regular_file_bounded(test_file, max_bytes=1000)

    with pytest.raises(SafeIOError, match="Error reading file.*Simulated I/O hardware failure"):
        _verify_file_hash_on_disk(test_file, "a" * 64)


def test_check_no_rogue_files_stops_project_scan_after_two_entries(tmp_path: Path) -> None:
    """Finding 8: Project index directory scan in _check_no_rogue_files stops reading
    after at most 2 entries (MAX_PROJECT_SUB_ENTRIES)."""
    from hermetic_pkgworld.evidence import _check_no_rogue_files
    from hermetic_pkgworld.errors import ClosureError

    root = tmp_path / "root"
    proj_dir = root / "simple" / "sample-pkg"
    proj_dir.mkdir(parents=True)

    (proj_dir / "index.json").write_text("{}")
    for i in range(10):
        (proj_dir / f"extra_{i}.txt").write_text("rogue")

    (root / "files").mkdir(parents=True)

    real_scandir = os.scandir
    yielded_count = 0

    class CountingScandir:
        def __init__(self, path: str | os.PathLike[str]) -> None:
            self._real = real_scandir(path)
            self._is_proj = Path(path) == proj_dir

        def __enter__(self) -> CountingScandir:
            self._real.__enter__()
            return self

        def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
            self._real.__exit__(exc_type, exc_val, exc_tb)

        def __iter__(self) -> CountingScandir:
            return self

        def __next__(self) -> os.DirEntry[str]:
            nonlocal yielded_count
            entry = next(self._real)
            if self._is_proj:
                yielded_count += 1
            return entry

    orig_scandir = os.scandir
    try:
        os.scandir = CountingScandir  # type: ignore[assignment]
        with pytest.raises(ClosureError, match="Unexpected files in project index directory"):
            _check_no_rogue_files(root, expected_files=set(), expected_projects={"sample-pkg"})
        assert yielded_count <= 2
    finally:
        os.scandir = orig_scandir


def test_baseline_rejects_boolean_total_files(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """CR Finding: total_files in baseline-manifest.json must reject booleans (True/False)."""
    pkg_meta, pkg_files = baseline_fixtures
    baseline_dir = _create_test_baseline(tmp_path / "baseline", "2024-05", pkg_meta, pkg_files)
    manifest_path = baseline_dir / "baseline-manifest.json"
    os.chmod(baseline_dir, 0o700)
    os.chmod(manifest_path, 0o600)
    manifest_data = json.loads(manifest_path.read_text("utf-8"))
    manifest_data["total_files"] = True
    manifest_path.write_text(json.dumps(manifest_data), "utf-8")

    with pytest.raises(BaselineError, match="Invalid total_files"):
        compute_baseline_root(baseline_dir)


def test_closure_rejects_dangling_symlink_inventory_dir(tmp_path: Path) -> None:
    """CR Finding: Dangling symlinks for files/ or simple/ must be rejected even with zero files."""
    cutoff = "2024-05-01T00:00:00Z"
    closure_dir = _create_test_closure(tmp_path / "closure", cutoff, [])
    os.chmod(closure_dir, 0o700)

    # Remove the existing empty files directory and replace with a dangling symlink
    files_dir = closure_dir / "files"
    if files_dir.exists() or files_dir.is_symlink():
        files_dir.rmdir()
    files_dir.symlink_to(closure_dir / "nonexistent")

    with pytest.raises(ClosureError, match="files path is not a genuine directory"):
        compute_closure_root(closure_dir)

    files_dir.unlink()
    # Remove existing simple directory and replace with a dangling symlink
    simple_dir = closure_dir / "simple"
    if simple_dir.exists() or simple_dir.is_symlink():
        simple_dir.rmdir()
    simple_dir.symlink_to(closure_dir / "nonexistent")

    with pytest.raises(ClosureError, match="simple path is not a genuine directory"):
        compute_closure_root(closure_dir)


def test_evidence_translates_invalid_root_path_to_safe_io_error(tmp_path: Path) -> None:
    """CR Finding: validate_path ValueError (e.g. from '..') must be translated to SafeIOError."""
    unsafe_path = tmp_path / "foo" / ".." / "bar"

    with pytest.raises(SafeIOError, match="Invalid or unsafe closure directory path"):
        compute_closure_root(unsafe_path)

    with pytest.raises(SafeIOError, match="Invalid or unsafe baseline directory path"):
        compute_baseline_root(unsafe_path)


def test_baseline_rejects_non_boolean_yanked(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """CR Finding: Non-boolean yanked values (like 'false' or 1) in baseline plan must be rejected."""
    pkg_meta, pkg_files = baseline_fixtures
    baseline_dir = _create_test_baseline(tmp_path / "baseline", "2024-05", pkg_meta, pkg_files)
    os.chmod(baseline_dir, 0o700)
    plan_path = baseline_dir / "baseline-plan.json"
    os.chmod(plan_path, 0o600)
    plan_data = json.loads(plan_path.read_text("utf-8"))
    plan_data["files"][0]["yanked"] = "false"
    new_plan_bytes = json.dumps(plan_data).encode("utf-8")
    plan_path.write_bytes(new_plan_bytes)

    # Update .frozen marker to match new plan bytes so plan hash check passes
    frozen_path = baseline_dir / ".frozen"
    os.chmod(frozen_path, 0o600)
    frozen_data = json.loads(frozen_path.read_text("utf-8"))
    frozen_data["plan_hash"] = hashlib.sha256(new_plan_bytes).hexdigest()
    frozen_path.write_text(json.dumps(frozen_data), "utf-8")

    with pytest.raises(BaselineError, match="Invalid yanked field"):
        compute_baseline_root(baseline_dir)


def test_baseline_translates_frozen_marker_symlink_error(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """CR Finding: UnsafePathError/StoreIOError from is_store_frozen must be translated to SafeIOError."""
    pkg_meta, pkg_files = baseline_fixtures
    baseline_dir = _create_test_baseline(tmp_path / "baseline", "2024-05", pkg_meta, pkg_files)
    os.chmod(baseline_dir, 0o700)
    frozen_path = baseline_dir / ".frozen"
    os.chmod(frozen_path, 0o600)
    frozen_target = tmp_path / "real_frozen"
    frozen_path.rename(frozen_target)
    frozen_path.symlink_to(frozen_target)

    with pytest.raises(SafeIOError, match="Failed inspecting frozen marker"):
        compute_baseline_root(baseline_dir)


def test_record_loops_reject_sha256_with_trailing_newline(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """CR Finding: validate_sha256 rejects sha256 with trailing newline in closure and baseline."""
    cutoff = "2024-05-01T00:00:00Z"
    pytest_whl = b"PK\x03\x04pytest-7.4.0-wheel-content"
    closure_dir = _create_test_closure(
        tmp_path / "closure",
        cutoff,
        [("pytest", "pytest-7.4.0-py3-none-any.whl", pytest_whl, "allowed_kept")],
    )
    os.chmod(closure_dir, 0o700)
    manifest_path = closure_dir / "manifest.json"
    os.chmod(manifest_path, 0o600)
    manifest_data = json.loads(manifest_path.read_text("utf-8"))
    manifest_data["files"][0]["sha256"] = manifest_data["files"][0]["sha256"] + "\n"
    manifest_path.write_text(json.dumps(manifest_data), "utf-8")

    with pytest.raises(ClosureError, match="Closure file record has invalid sha256"):
        compute_closure_root(closure_dir, verify_files=False)

    pkg_meta, pkg_files = baseline_fixtures
    baseline_dir = _create_test_baseline(tmp_path / "baseline", "2024-05", pkg_meta, pkg_files)
    os.chmod(baseline_dir, 0o700)
    plan_path = baseline_dir / "baseline-plan.json"
    os.chmod(plan_path, 0o600)
    plan_data = json.loads(plan_path.read_text("utf-8"))
    plan_data["files"][0]["sha256"] = plan_data["files"][0]["sha256"] + "\n"
    new_plan_bytes = json.dumps(plan_data).encode("utf-8")
    plan_path.write_bytes(new_plan_bytes)

    frozen_path = baseline_dir / ".frozen"
    os.chmod(frozen_path, 0o600)
    frozen_data = json.loads(frozen_path.read_text("utf-8"))
    frozen_data["plan_hash"] = hashlib.sha256(new_plan_bytes).hexdigest()
    frozen_path.write_text(json.dumps(frozen_data), "utf-8")

    with pytest.raises(BaselineError, match="Baseline plan file record has invalid sha256"):
        compute_baseline_root(baseline_dir, verify_files=False)


def test_inventory_scan_translates_os_error_to_safe_io_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CR Finding: OSError during scandir in _check_no_rogue_files must translate to SafeIOError."""
    cutoff = "2024-05-01T00:00:00Z"
    closure_dir = _create_test_closure(tmp_path / "closure", cutoff, [])

    # Ensure files directory exists
    (closure_dir / "files").mkdir(exist_ok=True)

    real_scandir = os.scandir

    def failing_scandir(path: str | os.PathLike[str], *args: object, **kwargs: object) -> object:
        if Path(path) == closure_dir / "files":
            raise OSError("Simulated hardware scan error")
        return real_scandir(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", failing_scandir)
    with pytest.raises(SafeIOError, match="Failed scanning files/ directory"):
        compute_closure_root(closure_dir)


def test_baseline_plan_files_exceeding_max_total_files_rejected(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CR Finding: Baseline plan files count exceeding MAX_TOTAL_FILES must be rejected."""
    import hermetic_pkgworld.evidence as ev

    pkg_meta, pkg_files = baseline_fixtures
    baseline_dir = _create_test_baseline(tmp_path / "baseline", "2024-05", pkg_meta, pkg_files)

    # When total_files declared > MAX_TOTAL_FILES
    monkeypatch.setattr(ev, "MAX_TOTAL_FILES", 0)
    with pytest.raises(BaselineError, match="Invalid total_files"):
        compute_baseline_root(baseline_dir)


def test_baseline_manifest_cutoff_timestamp_mismatch_rejected(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """CR Finding: baseline-manifest.json cutoff_timestamp mismatch with plan must be rejected."""
    pkg_meta, pkg_files = baseline_fixtures
    baseline_dir = _create_test_baseline(tmp_path / "baseline", "2024-05", pkg_meta, pkg_files)
    os.chmod(baseline_dir, 0o700)
    manifest_path = baseline_dir / "baseline-manifest.json"
    os.chmod(manifest_path, 0o600)
    manifest_data = json.loads(manifest_path.read_text("utf-8"))
    manifest_data["cutoff_timestamp"] = "2024-05-02T00:00:00Z"
    manifest_path.write_text(json.dumps(manifest_data), "utf-8")

    with pytest.raises(BaselineError, match="Baseline plan cutoff_timestamp.*mismatch with baseline manifest"):
        compute_baseline_root(baseline_dir)


def test_package_evidence_rejects_closure_cutoff_mismatch(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """CR Finding: compute_package_evidence must reject closure cutoff mismatch with expected_pkg_cutoff."""
    cutoff_closure = "2024-05-01T00:00:00Z"
    pytest_whl = b"PK\x03\x04pytest-7.4.0-wheel-content"
    closure_dir = _create_test_closure(
        tmp_path / "closure",
        cutoff_closure,
        [("pytest", "pytest-7.4.0-py3-none-any.whl", pytest_whl, "allowed_kept")],
    )

    pkg_meta, pkg_files = baseline_fixtures
    baseline_dir = _create_test_baseline(tmp_path / "baseline", "2024-05", pkg_meta, pkg_files)

    with pytest.raises(CutoffMismatchError, match="Closure cutoff.*does not match expected package cutoff"):
        compute_package_evidence(
            closure_dir,
            baseline_dir,
            expected_pkg_cutoff="2024-05-15T00:00:00Z",
        )


def test_record_loops_reject_project_names_with_path_separators(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """CR Finding: Project names with '/', '\\', or NUL must be rejected before building index paths."""
    cutoff = "2024-05-01T00:00:00Z"
    pytest_whl = b"PK\x03\x04pytest-7.4.0-wheel-content"
    closure_dir = _create_test_closure(
        tmp_path / "closure",
        cutoff,
        [("pytest", "pytest-7.4.0-py3-none-any.whl", pytest_whl, "allowed_kept")],
    )
    os.chmod(closure_dir, 0o700)
    manifest_path = closure_dir / "manifest.json"
    os.chmod(manifest_path, 0o600)
    manifest_data = json.loads(manifest_path.read_text("utf-8"))
    manifest_data["files"][0]["project"] = "/etc"
    manifest_path.write_text(json.dumps(manifest_data), "utf-8")

    with pytest.raises(ClosureError, match="Unsafe project name in closure manifest"):
        compute_closure_root(closure_dir, verify_files=False)

    pkg_meta, pkg_files = baseline_fixtures
    baseline_dir = _create_test_baseline(tmp_path / "baseline", "2024-05", pkg_meta, pkg_files)
    os.chmod(baseline_dir, 0o700)
    plan_path = baseline_dir / "baseline-plan.json"
    os.chmod(plan_path, 0o600)
    plan_data = json.loads(plan_path.read_text("utf-8"))
    plan_data["files"][0]["project"] = "sub\\pkg"
    new_plan_bytes = json.dumps(plan_data).encode("utf-8")
    plan_path.write_bytes(new_plan_bytes)

    frozen_path = baseline_dir / ".frozen"
    os.chmod(frozen_path, 0o600)
    frozen_data = json.loads(frozen_path.read_text("utf-8"))
    frozen_data["plan_hash"] = hashlib.sha256(new_plan_bytes).hexdigest()
    frozen_path.write_text(json.dumps(frozen_data), "utf-8")

    with pytest.raises(BaselineError, match="Unsafe project name in baseline plan"):
        compute_baseline_root(baseline_dir, verify_files=False)


def test_record_loops_reject_duplicate_file_identities(
    tmp_path: Path,
    baseline_fixtures: tuple[dict[str, list[dict[str, object]]], dict[str, bytes]],
) -> None:
    """CR Finding: Duplicate (project, filename, sha256) identities must be rejected."""
    cutoff = "2024-05-01T00:00:00Z"
    pytest_whl = b"PK\x03\x04pytest-7.4.0-wheel-content"
    closure_dir = _create_test_closure(
        tmp_path / "closure",
        cutoff,
        [("pytest", "pytest-7.4.0-py3-none-any.whl", pytest_whl, "allowed_kept")],
    )
    os.chmod(closure_dir, 0o700)
    manifest_path = closure_dir / "manifest.json"
    os.chmod(manifest_path, 0o600)
    manifest_data = json.loads(manifest_path.read_text("utf-8"))
    # Duplicate the entry but with different upload-time
    dup_entry = dict(manifest_data["files"][0])
    dup_entry["upload-time"] = "2024-01-01T00:00:00Z"
    manifest_data["files"].append(dup_entry)
    manifest_path.write_text(json.dumps(manifest_data), "utf-8")

    with pytest.raises(ClosureError, match="Duplicate file record identity in closure manifest"):
        compute_closure_root(closure_dir, verify_files=False)

    pkg_meta, pkg_files = baseline_fixtures
    baseline_dir = _create_test_baseline(tmp_path / "baseline", "2024-05", pkg_meta, pkg_files)
    os.chmod(baseline_dir, 0o700)
    plan_path = baseline_dir / "baseline-plan.json"
    os.chmod(plan_path, 0o600)
    plan_data = json.loads(plan_path.read_text("utf-8"))
    dup_plan_entry = dict(plan_data["files"][0])
    dup_plan_entry["yanked"] = True
    plan_data["files"].append(dup_plan_entry)
    new_plan_bytes = json.dumps(plan_data).encode("utf-8")
    plan_path.write_bytes(new_plan_bytes)

    # Update manifest total_files and .frozen plan_hash
    manifest_b_path = baseline_dir / "baseline-manifest.json"
    os.chmod(manifest_b_path, 0o600)
    manifest_b_data = json.loads(manifest_b_path.read_text("utf-8"))
    manifest_b_data["total_files"] = len(plan_data["files"])
    manifest_b_path.write_text(json.dumps(manifest_b_data), "utf-8")

    frozen_path = baseline_dir / ".frozen"
    os.chmod(frozen_path, 0o600)
    frozen_data = json.loads(frozen_path.read_text("utf-8"))
    frozen_data["plan_hash"] = hashlib.sha256(new_plan_bytes).hexdigest()
    frozen_path.write_text(json.dumps(frozen_data), "utf-8")

    with pytest.raises(BaselineError, match="Duplicate file record identity in baseline plan"):
        compute_baseline_root(baseline_dir, verify_files=False)
