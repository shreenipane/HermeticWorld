"""Offline pytest suite covering all Layer 2 ecosystem baseline requirements (TR-PKG-4).

Tests:
1. Baseline spec validation, capping, and parsing.
2. Transitive closure correctness on a small fixture graph including:
   - Dependency cycle handling
   - Dependency that only exists after the cutoff (excluded from files, listed as unresolved)
   - Known-answer canonical JSON plan output
3. Named caps enforcement (depth cap, package count cap, total bytes cap).
4. Determinism across multiple planner and builder invocations.
5. Storage measurement per ecosystem and per package.
6. Content-addressed store builder with SHA-256 verification and mismatch refusal.
7. Immutability of frozen baseline store (subsequent modification refused).
8. Full compatibility with hermetic_pkgindex FrozenStore.
9. Safe I/O refusing symlinks and path traversal.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import pytest

from hermetic_pkgbase import (
    CANONICAL_FIXED_TOOLS,
    BaselineBuilder,
    BaselineSpec,
    CapExceededError,
    DepthCapExceededError,
    HashMismatchError,
    MAX_FILE_BYTES,
    MAX_FILENAME_BYTES,
    OfflineFixtureFetcher,
    OfflineFixtureResolver,
    PackageCountCapExceededError,
    PkgBaseError,
    Plan,
    Planner,
    ResolutionError,
    ResolvedFile,
    ResolvedRelease,
    SpecValidationError,
    StorageReport,
    StoreImmutableError,
    StoreIOError,
    TotalBytesCapExceededError,
    UnsafePathError,
    is_store_frozen,
    normalize_project_name,
    parse_cutoff_month,
    parse_rfc3339_nanos,
    parse_spec,
    parse_top_packages_file,
    validate_distribution_filename,
)
from hermetic_pkgbase.safe_io import (
    freeze_directory_tree,
    safe_ensure_dir,
    safe_write_file,
)
from hermetic_pkgindex import FrozenStore


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Fixture payload data
WHEEL_PYTEST_740 = b"PK\x03\x04pytest-7.4.0-wheel-binary-payload-data"
WHEEL_PYTEST_730 = b"PK\x03\x04pytest-7.3.0-wheel-binary-payload-data"
WHEEL_PLUGGY = b"PK\x03\x04pluggy-1.2.0-wheel-binary-payload-data"
WHEEL_PLUGGY_CORE = b"PK\x03\x04pluggy-core-0.1.0-wheel-binary-payload-data"
WHEEL_INICONFIG = b"PK\x03\x04iniconfig-2.0.0-wheel-binary-payload-data"
WHEEL_FUTURE_PLUGIN = b"PK\x03\x04future-plugin-9.9.9-wheel-binary-payload-data"
WHEEL_TOP_TOOL = b"PK\x03\x04top-tool-1.0.0-wheel-binary-payload-data"

SHA_PYTEST_740 = _sha256(WHEEL_PYTEST_740)
SHA_PYTEST_730 = _sha256(WHEEL_PYTEST_730)
SHA_PLUGGY = _sha256(WHEEL_PLUGGY)
SHA_PLUGGY_CORE = _sha256(WHEEL_PLUGGY_CORE)
SHA_INICONFIG = _sha256(WHEEL_INICONFIG)
SHA_FUTURE_PLUGIN = _sha256(WHEEL_FUTURE_PLUGIN)
SHA_TOP_TOOL = _sha256(WHEEL_TOP_TOOL)


@pytest.fixture()
def fixture_packages() -> dict[str, list[dict[str, object]]]:
    """Fixture graph containing:

    - Multiple versions of pytest (7.3.0, 7.4.0 before cutoff; 8.0.0 after cutoff)
    - Direct dependencies: pluggy and iniconfig
    - Circular dependency: pluggy <-> pluggy-core
    - Dependency that ONLY exists after cutoff: iniconfig -> future-plugin
    - Top tool package: top-tool
    """
    return {
        "pytest": [
            {
                "version": "8.0.0",
                "upload_time": "2024-05-10T12:00:00Z",  # AFTER cutoff 2024-05
                "dependencies": ["pluggy", "iniconfig"],
                "files": [
                    {
                        "filename": "pytest-8.0.0-py3-none-any.whl",
                        "sha256": "0" * 64,
                        "upload_time": "2024-05-10T12:00:00Z",
                        "size_bytes": 5000,
                    }
                ],
            },
            {
                "version": "7.4.0",
                "upload_time": "2024-04-15T12:00:00Z",  # BEFORE cutoff 2024-05
                "dependencies": ["pluggy", "iniconfig"],
                "files": [
                    {
                        "filename": "pytest-7.4.0-py3-none-any.whl",
                        "sha256": SHA_PYTEST_740,
                        "upload_time": "2024-04-15T12:00:00Z",
                        "size_bytes": len(WHEEL_PYTEST_740),
                        "requires_python": ">=3.8",
                    }
                ],
            },
            {
                "version": "7.3.0",
                "upload_time": "2023-04-01T12:00:00Z",  # Older pre-cutoff
                "dependencies": ["pluggy"],
                "files": [
                    {
                        "filename": "pytest-7.3.0-py3-none-any.whl",
                        "sha256": SHA_PYTEST_730,
                        "upload_time": "2023-04-01T12:00:00Z",
                        "size_bytes": len(WHEEL_PYTEST_730),
                    }
                ],
            },
        ],
        "pluggy": [
            {
                "version": "1.2.0",
                "upload_time": "2023-06-20T10:00:00Z",  # BEFORE cutoff
                "dependencies": ["pluggy-core"],  # Part of cycle
                "files": [
                    {
                        "filename": "pluggy-1.2.0-py3-none-any.whl",
                        "sha256": SHA_PLUGGY,
                        "upload_time": "2023-06-20T10:00:00Z",
                        "size_bytes": len(WHEEL_PLUGGY),
                    }
                ],
            }
        ],
        "pluggy-core": [
            {
                "version": "0.1.0",
                "upload_time": "2023-06-19T10:00:00Z",  # BEFORE cutoff
                "dependencies": ["pluggy"],  # Cycles back to pluggy!
                "files": [
                    {
                        "filename": "pluggy_core-0.1.0-py3-none-any.whl",
                        "sha256": SHA_PLUGGY_CORE,
                        "upload_time": "2023-06-19T10:00:00Z",
                        "size_bytes": len(WHEEL_PLUGGY_CORE),
                    }
                ],
            }
        ],
        "iniconfig": [
            {
                "version": "2.0.0",
                "upload_time": "2023-01-10T08:00:00Z",  # BEFORE cutoff
                "dependencies": ["future-plugin"],  # Depends on future-plugin!
                "files": [
                    {
                        "filename": "iniconfig-2.0.0-py3-none-any.whl",
                        "sha256": SHA_INICONFIG,
                        "upload_time": "2023-01-10T08:00:00Z",
                        "size_bytes": len(WHEEL_INICONFIG),
                    }
                ],
            }
        ],
        "future-plugin": [
            {
                # ONLY exists after cutoff 2024-05! (Uploaded in June 2024)
                "version": "9.9.9",
                "upload_time": "2024-06-01T10:00:00Z",
                "dependencies": [],
                "files": [
                    {
                        "filename": "future_plugin-9.9.9-py3-none-any.whl",
                        "sha256": SHA_FUTURE_PLUGIN,
                        "upload_time": "2024-06-01T10:00:00Z",
                        "size_bytes": len(WHEEL_FUTURE_PLUGIN),
                    }
                ],
            }
        ],
        "top-tool": [
            {
                "version": "1.0.0",
                "upload_time": "2024-01-01T00:00:00Z",
                "dependencies": [],
                "files": [
                    {
                        "filename": "top_tool-1.0.0-py3-none-any.whl",
                        "sha256": SHA_TOP_TOOL,
                        "upload_time": "2024-01-01T00:00:00Z",
                        "size_bytes": len(WHEEL_TOP_TOOL),
                    }
                ],
            }
        ],
    }


@pytest.fixture()
def fixture_fetcher() -> OfflineFixtureFetcher:
    return OfflineFixtureFetcher(
        {
            SHA_PYTEST_740: WHEEL_PYTEST_740,
            SHA_PYTEST_730: WHEEL_PYTEST_730,
            SHA_PLUGGY: WHEEL_PLUGGY,
            SHA_PLUGGY_CORE: WHEEL_PLUGGY_CORE,
            SHA_INICONFIG: WHEEL_INICONFIG,
            SHA_FUTURE_PLUGIN: WHEEL_FUTURE_PLUGIN,
            SHA_TOP_TOOL: WHEEL_TOP_TOOL,
        }
    )


# ---------------------------------------------------------------------------
# 1. Baseline Spec Validation, Capping, and Parsing
# ---------------------------------------------------------------------------


def test_spec_validation_success(tmp_path: Path) -> None:
    top_file = tmp_path / "top_pypi.txt"
    top_file.write_text("top-tool\n# comment\nanother-tool\n", encoding="utf-8")

    spec_dict = {
        "cutoff_month": "2024-05",
        "fixed_tools": ["pytest"],
        "top_n_per_ecosystem": {"pypi": 1},
        "top_packages_files": {"pypi": str(top_file)},
    }
    spec = parse_spec(spec_dict)
    assert spec.cutoff_month == "2024-05"
    assert spec.cutoff_timestamp == "2024-05-01T00:00:00Z"
    assert spec.fixed_tools == ("pytest",)
    assert spec.top_n_per_ecosystem == {"pypi": 1}

    seeds = spec.get_seed_packages("pypi")
    assert seeds == ["pytest", "top-tool"]


def test_spec_canonical_fixed_tools_default() -> None:
    spec = parse_spec({"cutoff_month": "2024-05"})
    assert set(spec.fixed_tools) == set(CANONICAL_FIXED_TOOLS)
    assert "pytest" in spec.fixed_tools
    assert "uv" in spec.fixed_tools
    assert "cython" in spec.fixed_tools


def test_spec_cutoff_month_boundaries() -> None:
    y, m, iso_ts, ns = parse_cutoff_month("2024-05")
    assert y == 2024
    assert m == 5
    assert iso_ts == "2024-05-01T00:00:00Z"
    assert ns == 1714521600 * 1_000_000_000

    # Invalid formats
    for invalid in ["2024", "2024-00", "2024-13", "2024/05", "2024-5", "", "abc"]:
        with pytest.raises(SpecValidationError):
            parse_cutoff_month(invalid)


def test_spec_caps_enforced(tmp_path: Path) -> None:
    # Top-N cap
    with pytest.raises(CapExceededError):
        parse_spec({"cutoff_month": "2024-05", "top_n": 500_000})

    # Fixed tools cap
    excessive_tools = [f"tool-{i}" for i in range(300)]
    with pytest.raises(CapExceededError):
        parse_spec({"cutoff_month": "2024-05", "fixed_tools": excessive_tools})

    # Oversized spec string
    with pytest.raises(CapExceededError):
        parse_spec(b"{" + b'"a": 1, ' * 200_000 + b'"cutoff_month": "2024-05"}')


def test_top_packages_file_formats(tmp_path: Path) -> None:
    # 1. JSON list
    f_list = tmp_path / "top_list.json"
    f_list.write_text(json.dumps(["alpha", "beta", "gamma"]), encoding="utf-8")
    assert parse_top_packages_file(f_list, max_count=2) == ["alpha", "beta"]

    # 2. JSON rows object
    f_rows = tmp_path / "top_rows.json"
    f_rows.write_text(
        json.dumps({"rows": [{"project": "pkg-a"}, {"project": "pkg-b"}]}),
        encoding="utf-8",
    )
    assert parse_top_packages_file(f_rows, max_count=10) == ["pkg-a", "pkg-b"]

    # 3. Plain text
    f_txt = tmp_path / "top.txt"
    f_txt.write_text("# header\npkg-one\n\npkg-two # comment\n", encoding="utf-8")
    assert parse_top_packages_file(f_txt, max_count=10) == ["pkg-one", "pkg-two"]


# ---------------------------------------------------------------------------
# 2. Transitive Closure, Cycles, and Post-Cutoff Dependency Exclusion
# ---------------------------------------------------------------------------


def test_transitive_closure_with_cycle_and_post_cutoff_dependency(
    fixture_packages: dict[str, list[dict[str, object]]]
) -> None:
    """Core correctness test:

    - Computes transitive closure at cutoff 2024-05.
    - Resolves pytest 7.4.0 (pre-cutoff version), NOT 8.0.0 (post-cutoff).
    - Resolves circular dependency pluggy <-> pluggy-core safely.
    - Excludes future-plugin (only exists post-cutoff) and lists it in unresolved.
    """
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest"]})
    resolver = OfflineFixtureResolver(fixture_packages)
    planner = Planner()

    plan = planner.plan(spec, resolver)

    # 1. Check resolved projects
    assert sorted(plan.resolved_projects) == ["iniconfig", "pluggy", "pluggy-core", "pytest"]
    assert "future-plugin" not in plan.resolved_projects

    # 2. Check files in plan
    file_names = [f.filename for f in plan.files]
    assert "pytest-7.4.0-py3-none-any.whl" in file_names
    assert "pytest-8.0.0-py3-none-any.whl" not in file_names
    assert "pluggy-1.2.0-py3-none-any.whl" in file_names
    assert "pluggy_core-0.1.0-py3-none-any.whl" in file_names
    assert "iniconfig-2.0.0-py3-none-any.whl" in file_names
    assert "future_plugin-9.9.9-py3-none-any.whl" not in file_names

    # 3. Check unresolved list: future-plugin must be listed, not guessed
    unresolved_names = [u.project for u in plan.unresolved]
    assert "future-plugin" in unresolved_names

    # 4. Check deterministic sorting of files
    for i in range(len(plan.files) - 1):
        assert (plan.files[i].project, plan.files[i].filename) <= (
            plan.files[i + 1].project,
            plan.files[i + 1].filename,
        )


def test_known_answer_canonical_json_plan(
    fixture_packages: dict[str, list[dict[str, object]]]
) -> None:
    """Verify exact structure of canonical JSON plan against known-answer format."""
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest"]})
    resolver = OfflineFixtureResolver(fixture_packages)
    plan = Planner().plan(spec, resolver)

    canonical_json = plan.to_canonical_json()
    assert canonical_json.endswith("\n")
    data = json.loads(canonical_json)

    assert data["cutoff_month"] == "2024-05"
    assert data["cutoff_timestamp"] == "2024-05-01T00:00:00Z"
    assert "files" in data
    assert "resolved_projects" in data
    assert "storage" in data
    assert "unresolved" in data
    assert "unresolved_packages" not in data

    # Check that each file dictionary contains required fields
    for f in data["files"]:
        assert "project" in f
        assert "filename" in f
        assert "sha256" in f
        assert "upload-time" in f
        assert "upload_time" not in f
        assert "size_bytes" in f
        assert "ecosystem" in f

    # Verify no host paths or usernames leaked into plan
    raw_text = canonical_json
    assert "/home/" not in raw_text
    assert sys.platform not in raw_text


# ---------------------------------------------------------------------------
# 3. Named Caps (Depth, Package Count, Total Bytes)
# ---------------------------------------------------------------------------


def test_depth_cap_exceeded() -> None:
    # A -> B -> C -> D -> E (depth 4)
    chain_packages = {
        "p0": [{"version": "1.0", "upload_time": "2024-01-01T00:00:00Z", "dependencies": ["p1"], "files": [{"filename": "p0.whl", "sha256": "a" * 64, "size_bytes": 100}]}],
        "p1": [{"version": "1.0", "upload_time": "2024-01-01T00:00:00Z", "dependencies": ["p2"], "files": [{"filename": "p1.whl", "sha256": "b" * 64, "size_bytes": 100}]}],
        "p2": [{"version": "1.0", "upload_time": "2024-01-01T00:00:00Z", "dependencies": ["p3"], "files": [{"filename": "p2.whl", "sha256": "c" * 64, "size_bytes": 100}]}],
        "p3": [{"version": "1.0", "upload_time": "2024-01-01T00:00:00Z", "dependencies": [], "files": [{"filename": "p3.whl", "sha256": "d" * 64, "size_bytes": 100}]}],
    }
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["p0"]})
    resolver = OfflineFixtureResolver(chain_packages)

    # depth cap of 2 should fail on p3 (depth 3)
    planner = Planner(max_depth=2)
    with pytest.raises(DepthCapExceededError):
        planner.plan(spec, resolver)


def test_package_count_cap_exceeded() -> None:
    graph = {
        "p0": [{"version": "1.0", "upload_time": "2024-01-01T00:00:00Z", "dependencies": ["p1", "p2"], "files": [{"filename": "p0.whl", "sha256": "a" * 64, "size_bytes": 10}]}],
        "p1": [{"version": "1.0", "upload_time": "2024-01-01T00:00:00Z", "dependencies": [], "files": [{"filename": "p1.whl", "sha256": "b" * 64, "size_bytes": 10}]}],
        "p2": [{"version": "1.0", "upload_time": "2024-01-01T00:00:00Z", "dependencies": [], "files": [{"filename": "p2.whl", "sha256": "c" * 64, "size_bytes": 10}]}],
    }
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["p0"]})
    resolver = OfflineFixtureResolver(graph)

    planner = Planner(max_packages=2)
    with pytest.raises(PackageCountCapExceededError):
        planner.plan(spec, resolver)


def test_total_bytes_cap_exceeded() -> None:
    graph = {
        "p0": [{"version": "1.0", "upload_time": "2024-01-01T00:00:00Z", "dependencies": [], "files": [{"filename": "p0.whl", "sha256": "a" * 64, "size_bytes": 5000}]}],
    }
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["p0"]})
    resolver = OfflineFixtureResolver(graph)

    planner = Planner(max_total_bytes=1000)
    with pytest.raises(TotalBytesCapExceededError):
        planner.plan(spec, resolver)


# ---------------------------------------------------------------------------
# 4. Determinism
# ---------------------------------------------------------------------------


def test_planner_determinism(
    fixture_packages: dict[str, list[dict[str, object]]]
) -> None:
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest"]})
    resolver = OfflineFixtureResolver(fixture_packages)
    planner = Planner()

    first_json = planner.plan(spec, resolver).to_canonical_json()
    for _ in range(5):
        repeat_json = planner.plan(spec, resolver).to_canonical_json()
        assert repeat_json == first_json


# ---------------------------------------------------------------------------
# 5. Storage Footprint Measurement
# ---------------------------------------------------------------------------


def test_storage_measurement(
    fixture_packages: dict[str, list[dict[str, object]]]
) -> None:
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest"]})
    resolver = OfflineFixtureResolver(fixture_packages)
    plan = Planner().plan(spec, resolver)

    storage = plan.storage
    assert storage.file_count == len(plan.files)
    assert storage.package_count == len(plan.resolved_projects)
    assert storage.total_bytes == sum(f.size_bytes for f in plan.files)

    # Check per-ecosystem and per-package sums
    assert storage.by_ecosystem["pypi"] == storage.total_bytes
    assert sum(storage.by_package.values()) == storage.total_bytes
    assert "pytest" in storage.by_package
    assert "pluggy" in storage.by_package


# ---------------------------------------------------------------------------
# 6. Builder, SHA-256 Verification, and Hash Mismatch Refusal
# ---------------------------------------------------------------------------


def test_builder_success_and_directory_structure(
    tmp_path: Path,
    fixture_packages: dict[str, list[dict[str, object]]],
    fixture_fetcher: OfflineFixtureFetcher,
) -> None:
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest"]})
    resolver = OfflineFixtureResolver(fixture_packages)
    plan = Planner().plan(spec, resolver)

    store_dir = tmp_path / "baseline_store"
    builder = BaselineBuilder(store_dir)
    built_path = builder.build(plan, fixture_fetcher)

    assert built_path == store_dir
    assert is_store_frozen(store_dir)

    # Verify store directory structure
    simple_dir = store_dir / "simple"
    files_dir = store_dir / "files"
    assert simple_dir.is_dir()
    assert files_dir.is_dir()
    assert (store_dir / ".frozen").is_file()
    assert (store_dir / "baseline-manifest.json").is_file()

    # Verify project index files
    for proj in ["pytest", "pluggy", "pluggy-core", "iniconfig"]:
        idx = simple_dir / proj / "index.json"
        assert idx.is_file()
        data = json.loads(idx.read_text(encoding="utf-8"))
        assert data["meta"]["api-version"] == "1.0"
        assert data["name"] == proj
        assert len(data["files"]) >= 1

    # Verify distribution file exists and content matches
    pytest_whl_path = files_dir / SHA_PYTEST_740 / "pytest-7.4.0-py3-none-any.whl"
    assert pytest_whl_path.is_file()
    assert pytest_whl_path.read_bytes() == WHEEL_PYTEST_740


def test_builder_hash_mismatch_refused(
    tmp_path: Path,
    fixture_packages: dict[str, list[dict[str, object]]],
    fixture_fetcher: OfflineFixtureFetcher,
) -> None:
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest"]})
    resolver = OfflineFixtureResolver(fixture_packages)
    plan = Planner().plan(spec, resolver)

    # Corrupted fetcher returning invalid bytes for iniconfig
    corrupted_files = {
        SHA_PYTEST_740: WHEEL_PYTEST_740,
        SHA_PLUGGY: WHEEL_PLUGGY,
        SHA_PLUGGY_CORE: WHEEL_PLUGGY_CORE,
        SHA_INICONFIG: b"X" * len(WHEEL_INICONFIG),
    }
    corrupted_fetcher = OfflineFixtureFetcher(corrupted_files)

    store_dir = tmp_path / "corrupted_store"
    builder = BaselineBuilder(store_dir)

    with pytest.raises(HashMismatchError) as exc_info:
        builder.build(plan, corrupted_fetcher)

    assert "SHA-256 digest mismatch" in str(exc_info.value)
    # Ensure corrupted file is not retained in store
    corrupted_file = store_dir / "files" / SHA_INICONFIG / "iniconfig-2.0.0-py3-none-any.whl"
    assert not corrupted_file.exists()


# ---------------------------------------------------------------------------
# 7. Frozen Baseline Immutability
# ---------------------------------------------------------------------------


def test_frozen_baseline_immutability(
    tmp_path: Path,
    fixture_packages: dict[str, list[dict[str, object]]],
    fixture_fetcher: OfflineFixtureFetcher,
) -> None:
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest"]})
    resolver = OfflineFixtureResolver(fixture_packages)
    plan = Planner().plan(spec, resolver)

    store_dir = tmp_path / "immutable_store"
    builder = BaselineBuilder(store_dir)
    builder.build(plan, fixture_fetcher)

    # 1. Calling build on an already-frozen store must raise StoreImmutableError
    with pytest.raises(StoreImmutableError) as exc_info:
        builder.build(plan, fixture_fetcher)
    assert "already frozen" in str(exc_info.value)

    # 2. Check read-only permissions on files and directories
    st_marker = os.lstat(store_dir / ".frozen")
    assert stat.S_IMODE(st_marker.st_mode) == 0o400

    st_dir = os.lstat(store_dir / "files")
    assert stat.S_IMODE(st_dir.st_mode) == 0o500


# ---------------------------------------------------------------------------
# 8. Compatibility with hermetic_pkgindex FrozenStore
# ---------------------------------------------------------------------------


def test_compatibility_with_hermetic_pkgindex_frozen_store(
    tmp_path: Path,
    fixture_packages: dict[str, list[dict[str, object]]],
    fixture_fetcher: OfflineFixtureFetcher,
) -> None:
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest"]})
    resolver = OfflineFixtureResolver(fixture_packages)
    plan = Planner().plan(spec, resolver)

    store_dir = tmp_path / "pkgindex_compat_store"
    builder = BaselineBuilder(store_dir)
    builder.build(plan, fixture_fetcher)

    # Open with hermetic_pkgindex.store.FrozenStore
    frozen_store = FrozenStore(store_dir)

    # 1. list_projects()
    projects = frozen_store.list_projects()
    assert projects == ["iniconfig", "pluggy", "pluggy-core", "pytest"]

    # 2. get_project_page()
    page = frozen_store.get_project_page("pytest")
    assert page.name == "pytest"
    assert b"pytest-7.4.0-py3-none-any.whl" in page.json_bytes
    assert b"pytest-7.4.0-py3-none-any.whl" in page.html_bytes
    assert b"data-requires-python=" in page.html_bytes

    # 3. verify_and_prepare_file()
    verified = frozen_store.verify_and_prepare_file(
        SHA_PYTEST_740, "pytest-7.4.0-py3-none-any.whl"
    )
    assert verified.sha256 == SHA_PYTEST_740
    assert verified.filename == "pytest-7.4.0-py3-none-any.whl"
    assert verified.size == len(WHEEL_PYTEST_740)

    # 4. Stream byte range
    chunks = list(frozen_store.iter_file_range(verified, 0, verified.size - 1))
    assert b"".join(chunks) == WHEEL_PYTEST_740


# ---------------------------------------------------------------------------
# 9. Safe I/O Refusing Symlinks and Path Traversal
# ---------------------------------------------------------------------------


def test_safe_io_symlink_refused(tmp_path: Path) -> None:
    real_file = tmp_path / "real.txt"
    real_file.write_text("content", encoding="utf-8")

    link_file = tmp_path / "link.txt"
    try:
        os.symlink(real_file, link_file)
    except OSError:
        pytest.skip("Symlinks not supported in environment")

    with pytest.raises(UnsafePathError):
        parse_top_packages_file(link_file, max_count=10)


def test_safe_io_path_traversal_refused(tmp_path: Path) -> None:
    unsafe_path = tmp_path / ".." / "escape.txt"
    with pytest.raises(UnsafePathError):
        BaselineBuilder(unsafe_path)


def test_diamond_dependency_graph() -> None:
    # A -> B and C; both B and C -> D
    d_content = b"content-of-pkg-d"
    sha_d = _sha256(d_content)
    graph = {
        "pkg-a": [{"version": "1.0", "upload_time": "2024-01-01T00:00:00Z", "dependencies": ["pkg-b", "pkg-c"], "files": [{"filename": "pkg_a-1.0.whl", "sha256": "a" * 64, "size_bytes": 100}]}],
        "pkg-b": [{"version": "1.0", "upload_time": "2024-01-01T00:00:00Z", "dependencies": ["pkg-d"], "files": [{"filename": "pkg_b-1.0.whl", "sha256": "b" * 64, "size_bytes": 100}]}],
        "pkg-c": [{"version": "1.0", "upload_time": "2024-01-01T00:00:00Z", "dependencies": ["pkg-d"], "files": [{"filename": "pkg_c-1.0.whl", "sha256": "c" * 64, "size_bytes": 100}]}],
        "pkg-d": [{"version": "1.0", "upload_time": "2024-01-01T00:00:00Z", "dependencies": [], "files": [{"filename": "pkg_d-1.0.whl", "sha256": sha_d, "size_bytes": len(d_content)}]}],
    }
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pkg-a"]})
    resolver = OfflineFixtureResolver(graph)
    plan = Planner().plan(spec, resolver)

    assert sorted(plan.resolved_projects) == ["pkg-a", "pkg-b", "pkg-c", "pkg-d"]
    # D is only included once
    d_files = [f for f in plan.files if f.project == "pkg-d"]
    assert len(d_files) == 1
    assert plan.storage.total_bytes == 300 + len(d_content)


def test_spec_from_json_file(tmp_path: Path) -> None:
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(
        json.dumps({
            "cutoff_month": "2024-03",
            "fixed_tools": ["pytest", "hypothesis"],
        }),
        encoding="utf-8",
    )
    spec = parse_spec(spec_file)
    assert spec.cutoff_month == "2024-03"
    assert spec.cutoff_timestamp == "2024-03-01T00:00:00Z"
    assert spec.fixed_tools == ("pytest", "hypothesis")


def test_empty_top_packages_file(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("# only comments\n\n   # and spaces\n", encoding="utf-8")
    result = parse_top_packages_file(empty_file, max_count=10)
    assert result == []


# ---------------------------------------------------------------------------
# Regression Tests for Defects 1-7
# ---------------------------------------------------------------------------


class HostileResolver:
    """Untrusted pluggable resolver returning hostile/invalid results (Defect 1)."""

    def resolve_package(
        self,
        project: str,
        cutoff_epoch_ns: int,
        ecosystem: str = "pypi",
    ) -> ResolvedRelease | None:
        if project == "pkg-postcutoff":
            return ResolvedRelease(
                project="pkg-postcutoff",
                version="1.0.0",
                upload_time="2024-01-01T00:00:00Z",
                upload_time_ns=1704067200 * 1_000_000_000,
                files=(
                    ResolvedFile(
                        filename="pkg_postcutoff-1.0.0-py3-none-any.whl",
                        sha256="a" * 64,
                        upload_time="2024-06-01T00:00:00Z",
                        upload_time_ns=1717200000 * 1_000_000_000,
                        size_bytes=100,
                        project="pkg-postcutoff",
                    ),
                ),
                dependencies=(),
            )
        elif project == "pkg-badhash":
            return ResolvedRelease(
                project="pkg-badhash",
                version="1.0.0",
                upload_time="2024-01-01T00:00:00Z",
                upload_time_ns=1704067200 * 1_000_000_000,
                files=(
                    ResolvedFile(
                        filename="pkg_badhash-1.0.0-py3-none-any.whl",
                        sha256="not-a-valid-sha256-hex",
                        upload_time="2024-01-01T00:00:00Z",
                        upload_time_ns=1704067200 * 1_000_000_000,
                        size_bytes=100,
                        project="pkg-badhash",
                    ),
                ),
                dependencies=(),
            )
        elif project == "pkg-negsize":
            return ResolvedRelease(
                project="pkg-negsize",
                version="1.0.0",
                upload_time="2024-01-01T00:00:00Z",
                upload_time_ns=1704067200 * 1_000_000_000,
                files=(
                    ResolvedFile(
                        filename="pkg_negsize-1.0.0-py3-none-any.whl",
                        sha256="b" * 64,
                        upload_time="2024-01-01T00:00:00Z",
                        upload_time_ns=1704067200 * 1_000_000_000,
                        size_bytes=-42,
                        project="pkg-negsize",
                    ),
                ),
                dependencies=(),
            )
        elif project == "pkg-mismatched":
            return ResolvedRelease(
                project="pkg-other-project",
                version="1.0.0",
                upload_time="2024-01-01T00:00:00Z",
                upload_time_ns=1704067200 * 1_000_000_000,
                files=(
                    ResolvedFile(
                        filename="pkg_other-1.0.0-py3-none-any.whl",
                        sha256="c" * 64,
                        upload_time="2024-01-01T00:00:00Z",
                        upload_time_ns=1704067200 * 1_000_000_000,
                        size_bytes=100,
                        project="pkg-other-project",
                    ),
                ),
                dependencies=(),
            )
        return None


def test_regression_defect1_hostile_resolver_refused() -> None:
    """1. The cutoff and resolver validation enforced in Planner.plan."""
    spec = parse_spec({
        "cutoff_month": "2024-05",
        "fixed_tools": ["pkg-postcutoff", "pkg-badhash", "pkg-negsize", "pkg-mismatched"],
    })
    resolver = HostileResolver()
    planner = Planner()
    plan = planner.plan(spec, resolver)

    assert len(plan.files) == 0
    assert len(plan.resolved_projects) == 0

    unresolved_by_project = {u.project: u.reason for u in plan.unresolved}
    assert "pkg-postcutoff" in unresolved_by_project
    assert "cutoff" in unresolved_by_project["pkg-postcutoff"].lower()

    assert "pkg-badhash" in unresolved_by_project
    assert "sha256" in unresolved_by_project["pkg-badhash"].lower()

    assert "pkg-negsize" in unresolved_by_project
    assert "size_bytes" in unresolved_by_project["pkg-negsize"].lower()

    assert "pkg-mismatched" in unresolved_by_project
    assert "mismatch" in unresolved_by_project["pkg-mismatched"].lower()


def test_regression_defect2_filename_validation(tmp_path: Path) -> None:
    """2. Strict filename validation in planner and builder."""
    invalid_filenames = ["../x", "a/b", ".frozen", "x" * 300 + ".whl"]

    # 1. Direct validation helper
    for bad_name in invalid_filenames:
        with pytest.raises(ValueError):
            validate_distribution_filename(bad_name)

    # 2. Builder validation raises UnsafePathError
    for bad_name in invalid_filenames:
        bad_file = ResolvedFile(
            filename=bad_name,
            sha256="a" * 64,
            upload_time="2024-01-01T00:00:00Z",
            upload_time_ns=1704067200 * 1_000_000_000,
            size_bytes=10,
            project="test-pkg",
        )
        dummy_spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["test-pkg"]})
        bad_plan = Plan(
            spec=dummy_spec,
            files=(bad_file,),
            unresolved=(),
            storage=StorageReport.from_files((bad_file,)),
            resolved_projects=("test-pkg",),
        )
        builder = BaselineBuilder(tmp_path / f"store_{abs(hash(bad_name))}")
        with pytest.raises(UnsafePathError):
            builder.build(bad_plan, lambda p, f, s: b"dummydata!")

    # 3. Planner validation puts in unresolved
    class BadFilenameResolver:
        def resolve_package(self, project: str, cutoff_epoch_ns: int, ecosystem: str = "pypi") -> ResolvedRelease | None:
            return ResolvedRelease(
                project=project,
                version="1.0.0",
                upload_time="2024-01-01T00:00:00Z",
                upload_time_ns=1704067200 * 1_000_000_000,
                files=(
                    ResolvedFile(
                        filename="../x",
                        sha256="a" * 64,
                        upload_time="2024-01-01T00:00:00Z",
                        upload_time_ns=1704067200 * 1_000_000_000,
                        size_bytes=10,
                        project=project,
                    ),
                ),
                dependencies=(),
            )

    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["my-pkg"]})
    plan = Planner().plan(spec, BadFilenameResolver())
    assert "my-pkg" in [u.project for u in plan.unresolved]


def test_regression_defect3_fetched_bytes_bounds(tmp_path: Path) -> None:
    """3. Refuse content whose length differs from size_bytes, above per-file cap, and total-bytes cap."""
    content = b"exact-content-1234"
    sha = hashlib.sha256(content).hexdigest()

    # Case A: Fetched length differs from declared size_bytes
    file_mismatch = ResolvedFile(
        filename="pkg-1.0.whl",
        sha256=sha,
        upload_time="2024-01-01T00:00:00Z",
        upload_time_ns=1704067200 * 1_000_000_000,
        size_bytes=len(content) + 10,
        project="my-pkg",
    )
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["my-pkg"]})
    plan = Plan(
        spec=spec,
        files=(file_mismatch,),
        unresolved=(),
        storage=StorageReport.from_files((file_mismatch,)),
        resolved_projects=("my-pkg",),
    )
    builder = BaselineBuilder(tmp_path / "store_mismatch")
    with pytest.raises(StoreIOError) as exc_info:
        builder.build(plan, lambda p, f, s: content)
    assert "does not match declared size_bytes" in str(exc_info.value)

    # Case B: Content exceeds per-file cap
    file_huge = ResolvedFile(
        filename="huge-1.0.whl",
        sha256=sha,
        upload_time="2024-01-01T00:00:00Z",
        upload_time_ns=1704067200 * 1_000_000_000,
        size_bytes=len(content),
        project="my-pkg",
    )
    plan_huge = Plan(
        spec=spec,
        files=(file_huge,),
        unresolved=(),
        storage=StorageReport.from_files((file_huge,)),
        resolved_projects=("my-pkg",),
    )
    builder_low_file_cap = BaselineBuilder(
        tmp_path / "store_low_file_cap",
        max_file_bytes=len(content) - 5,
    )
    with pytest.raises(CapExceededError) as exc_info:
        builder_low_file_cap.build(plan_huge, lambda p, f, s: content)
    assert "per-file cap" in str(exc_info.value)

    # Case C: Running total exceeds total-bytes cap
    f1_data = b"file-one-data"
    f2_data = b"file-two-data"
    f1 = ResolvedFile(
        filename="f1-1.0.whl",
        sha256=hashlib.sha256(f1_data).hexdigest(),
        upload_time="2024-01-01T00:00:00Z",
        upload_time_ns=1704067200 * 1_000_000_000,
        size_bytes=len(f1_data),
        project="p1",
    )
    f2 = ResolvedFile(
        filename="f2-1.0.whl",
        sha256=hashlib.sha256(f2_data).hexdigest(),
        upload_time="2024-01-01T00:00:00Z",
        upload_time_ns=1704067200 * 1_000_000_000,
        size_bytes=len(f2_data),
        project="p2",
    )
    plan_total = Plan(
        spec=spec,
        files=(f1, f2),
        unresolved=(),
        storage=StorageReport.from_files((f1, f2)),
        resolved_projects=("p1", "p2"),
    )
    builder_low_total = BaselineBuilder(
        tmp_path / "store_low_total",
        max_total_bytes=len(f1_data) + 2,
    )
    fetch_map = {"f1-1.0.whl": f1_data, "f2-1.0.whl": f2_data}
    with pytest.raises(TotalBytesCapExceededError):
        builder_low_total.build(plan_total, lambda p, f, s: fetch_map[f])


def test_regression_defect4_upload_time_and_fixture_errors() -> None:
    """4. Unknown upload time listed as unresolved; fixture parse errors raise ResolutionError."""
    # Case A: Missing upload time -> unresolved with reason "unknown upload time"
    missing_time_packages = {
        "missing-time-pkg": [
            {
                "version": "1.0.0",
                "dependencies": [],
                "files": [
                    {
                        "filename": "missing_time-1.0.0-py3-none-any.whl",
                        "sha256": "0" * 64,
                        "size_bytes": 100,
                    }
                ],
            }
        ]
    }
    spec_missing = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["missing-time-pkg"]})
    res_missing = OfflineFixtureResolver(missing_time_packages)
    plan_missing = Planner().plan(spec_missing, res_missing)
    unresolved_map = {u.project: u.reason for u in plan_missing.unresolved}
    assert unresolved_map.get("missing-time-pkg") == "unknown upload time"

    # Case B: Unparseable upload time -> unresolved with reason "unknown upload time"
    unparseable_time_packages = {
        "bad-time-pkg": [
            {
                "version": "1.0.0",
                "upload_time": "invalid-timestamp-string",
                "dependencies": [],
                "files": [
                    {
                        "filename": "bad_time-1.0.0-py3-none-any.whl",
                        "sha256": "0" * 64,
                        "upload_time": "invalid-timestamp-string",
                        "size_bytes": 100,
                    }
                ],
            }
        ]
    }
    spec_bad_time = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["bad-time-pkg"]})
    res_bad_time = OfflineFixtureResolver(unparseable_time_packages)
    plan_bad = Planner().plan(spec_bad_time, res_bad_time)
    unresolved_map_bad = {u.project: u.reason for u in plan_bad.unresolved}
    assert unresolved_map_bad.get("bad-time-pkg") == "unknown upload time"

    # Case C: Fixture parse error (non-integer size_bytes) raises ResolutionError, NOT ValueError
    bad_fixture = {
        "bad-size-pkg": [
            {
                "version": "1.0.0",
                "upload_time": "2024-01-01T00:00:00Z",
                "dependencies": [],
                "files": [
                    {
                        "filename": "bad_size-1.0.0-py3-none-any.whl",
                        "sha256": "0" * 64,
                        "upload_time": "2024-01-01T00:00:00Z",
                        "size_bytes": "not-an-integer-size",
                    }
                ],
            }
        ]
    }
    res_bad_fixture = OfflineFixtureResolver(bad_fixture)
    with pytest.raises(ResolutionError) as exc_info:
        res_bad_fixture.resolve_package("bad-size-pkg", 1714521600 * 1_000_000_000)
    assert not isinstance(exc_info.value, ValueError)


def test_regression_defect5_descriptor_safe_io(tmp_path: Path) -> None:
    """5. Descriptor-based safe I/O with O_NOFOLLOW refusing symlinks and path races."""
    # Ensure directory creation and permissions (0700)
    target_dir = tmp_path / "safe_dir" / "subdir"
    safe_ensure_dir(target_dir, mode=0o700)
    assert target_dir.is_dir()
    assert stat.S_IMODE(os.lstat(target_dir).st_mode) == 0o700

    # Ensure file creation and permissions (0600)
    target_file = target_dir / "file.txt"
    safe_write_file(target_file, b"safe content", mode=0o600)
    assert target_file.is_file()
    assert stat.S_IMODE(os.lstat(target_file).st_mode) == 0o600

    # Ensure freeze tree sets files to 0400 and dirs to 0500
    freeze_directory_tree(tmp_path / "safe_dir")
    assert stat.S_IMODE(os.lstat(target_file).st_mode) == 0o400
    assert stat.S_IMODE(os.lstat(target_dir).st_mode) == 0o500
    assert stat.S_IMODE(os.lstat(tmp_path / "safe_dir").st_mode) == 0o500

    # Ensure symlinks in directory component are refused
    link_dir = tmp_path / "link_dir"
    try:
        os.symlink(tmp_path / "safe_dir", link_dir)
    except OSError:
        pytest.skip("Symlink creation not supported on filesystem")
    with pytest.raises(UnsafePathError):
        safe_ensure_dir(link_dir / "nested")


def test_regression_defect6_rebuild_unfrozen_store_interrupted(
    tmp_path: Path,
    fixture_packages: dict[str, list[dict[str, object]]],
    fixture_fetcher: OfflineFixtureFetcher,
) -> None:
    """6. Rebuilding an unfrozen, partially built store succeeds with byte-identical output to clean build."""
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest"]})
    resolver = OfflineFixtureResolver(fixture_packages)
    plan = Planner().plan(spec, resolver)

    # 1. Clean build
    clean_store = tmp_path / "clean_store"
    BaselineBuilder(clean_store).build(plan, fixture_fetcher)
    assert is_store_frozen(clean_store)

    # 2. Interrupted build
    interrupted_store = tmp_path / "interrupted_store"
    fetch_count = 0

    def flaky_fetcher(project: str, filename: str, sha256: str) -> bytes:
        nonlocal fetch_count
        fetch_count += 1
        if fetch_count == 2:
            raise RuntimeError("Midway network or IO failure during fetch!")
        return fixture_fetcher.fetch(project, filename, sha256)

    builder_interrupted = BaselineBuilder(interrupted_store)
    with pytest.raises(RuntimeError):
        builder_interrupted.build(plan, flaky_fetcher)

    # Store must remain unfrozen after failure
    assert not is_store_frozen(interrupted_store)

    # 3. Resume build with reliable fetcher on the unfrozen store
    builder_interrupted.build(plan, fixture_fetcher)
    assert is_store_frozen(interrupted_store)

    # 4. Verify byte-identical output
    clean_manifest = (clean_store / "baseline-manifest.json").read_bytes()
    rebuilt_manifest = (interrupted_store / "baseline-manifest.json").read_bytes()
    assert rebuilt_manifest == clean_manifest

    clean_frozen = (clean_store / ".frozen").read_bytes()
    rebuilt_frozen = (interrupted_store / ".frozen").read_bytes()
    assert rebuilt_frozen == clean_frozen

    for proj in plan.resolved_projects:
        clean_idx = (clean_store / "simple" / proj / "index.json").read_bytes()
        rebuilt_idx = (interrupted_store / "simple" / proj / "index.json").read_bytes()
        assert rebuilt_idx == clean_idx

    for f in plan.files:
        clean_f = (clean_store / "files" / f.sha256 / f.filename).read_bytes()
        rebuilt_f = (interrupted_store / "files" / f.sha256 / f.filename).read_bytes()
        assert rebuilt_f == clean_f


def test_regression_defect7_plan_json_no_duplicate_spellings(
    fixture_packages: dict[str, list[dict[str, object]]]
) -> None:
    """7. Plan JSON has only upload-time and unresolved, no duplicate spellings."""
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest"]})
    resolver = OfflineFixtureResolver(fixture_packages)
    plan = Planner().plan(spec, resolver)

    plan_dict = plan.to_dict()
    assert "unresolved" in plan_dict
    assert "unresolved_packages" not in plan_dict

    for file_dict in plan_dict["files"]:
        assert "upload-time" in file_dict
        assert "upload_time" not in file_dict

    # Also verify in canonical JSON serialization
    raw_json = plan.to_canonical_json()
    parsed = json.loads(raw_json)
    assert "unresolved" in parsed
    assert "unresolved_packages" not in parsed
    for file_dict in parsed["files"]:
        assert "upload-time" in file_dict
        assert "upload_time" not in file_dict


def test_regression_defect8_existing_artifact_symlink_refused(tmp_path: Path) -> None:
    """8. An existing artifact replaced by a symlink to a file with the right content must be refused."""
    content = b"genuine-artifact-content-bytes-12345"
    sha = hashlib.sha256(content).hexdigest()
    filename = "test_pkg-1.0.0-py3-none-any.whl"

    resolved_file = ResolvedFile(
        filename=filename,
        sha256=sha,
        upload_time="2024-01-01T00:00:00Z",
        upload_time_ns=1704067200 * 1_000_000_000,
        size_bytes=len(content),
        project="test-pkg",
    )
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["test-pkg"]})
    plan = Plan(
        spec=spec,
        files=(resolved_file,),
        unresolved=(),
        storage=StorageReport.from_files((resolved_file,)),
        resolved_projects=("test-pkg",),
    )

    store_dir = tmp_path / "symlink_store"
    files_dir = store_dir / "files" / sha
    files_dir.mkdir(parents=True, exist_ok=True)

    # Valid external file with the EXACT matching content and hash
    external_file = tmp_path / "external_target.whl"
    external_file.write_bytes(content)

    # Replace artifact with a symlink to the external file
    symlink_file = files_dir / filename
    os.symlink(external_file, symlink_file)

    # Building against this store must refuse the symlink
    builder = BaselineBuilder(store_dir)
    with pytest.raises(UnsafePathError):
        builder.build(plan, lambda p, f, s: content)

    # Store must not be marked frozen
    assert not is_store_frozen(store_dir)

    # Also verify that a symlink sha256 directory is refused
    store_dir2 = tmp_path / "symlink_dir_store"
    files_parent = store_dir2 / "files"
    files_parent.mkdir(parents=True, exist_ok=True)
    real_sha_dir = tmp_path / "real_sha_dir"
    real_sha_dir.mkdir(parents=True, exist_ok=True)
    os.symlink(real_sha_dir, files_parent / sha)

    builder2 = BaselineBuilder(store_dir2)
    with pytest.raises(UnsafePathError):
        builder2.build(plan, lambda p, f, s: content)
    assert not is_store_frozen(store_dir2)


# ---------------------------------------------------------------------------
# Regression Tests for CodeRabbit Review Fixes
# ---------------------------------------------------------------------------


def test_regression_project_name_fullmatch_rejects_trailing_newline() -> None:
    """Finding 8: Project name with trailing newline rejected by fullmatch."""
    with pytest.raises(SpecValidationError):
        normalize_project_name("pytest\n")

    with pytest.raises(SpecValidationError):
        parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest\n"]})


def test_regression_top_n_dict_alias_enforces_ecosystem_cap() -> None:
    """Finding 10: top_n dictionary alias enforces MAX_ECOSYSTEMS cap."""
    over_cap_dict = {f"eco_{i}": 10 for i in range(17)}
    with pytest.raises(CapExceededError):
        parse_spec({"cutoff_month": "2024-05", "top_n": over_cap_dict})

    valid_cap_dict = {f"eco_{i}": 10 for i in range(16)}
    spec = parse_spec({"cutoff_month": "2024-05", "top_n": valid_cap_dict})
    assert len(spec.top_n_per_ecosystem) == 16


def test_regression_timestamp_requires_explicit_timezone() -> None:
    """Finding 6: parse_rfc3339_nanos requires explicit timezone (Z or offset)."""
    with pytest.raises(ResolutionError):
        parse_rfc3339_nanos("2024-01-31T23:30:00")

    # Explicit Z and offset remain supported
    ns_z = parse_rfc3339_nanos("2024-01-31T23:30:00Z")
    assert ns_z > 0
    ns_offset = parse_rfc3339_nanos("2024-01-31T23:30:00+00:00")
    assert ns_offset == ns_z


def test_regression_post_cutoff_release_with_bad_file_skipped() -> None:
    """Finding 4: Releases at or after cutoff are skipped before validating files."""
    packages = {
        "dual-rel": [
            {
                "version": "2.0.0",
                "upload_time": "2024-06-01T00:00:00Z",  # post-cutoff (cutoff is 2024-05)
                "dependencies": [],
                "files": [
                    {
                        "filename": "dual_rel-2.0.0.whl",
                        "sha256": "bad-sha256-invalid",  # invalid sha256
                        "size_bytes": 100,
                        "upload_time": "2024-06-01T00:00:00Z",
                    }
                ],
            },
            {
                "version": "1.0.0",
                "upload_time": "2024-04-01T00:00:00Z",  # pre-cutoff
                "dependencies": [],
                "files": [
                    {
                        "filename": "dual_rel-1.0.0.whl",
                        "sha256": "a" * 64,
                        "size_bytes": 100,
                        "upload_time": "2024-04-01T00:00:00Z",
                    }
                ],
            },
        ]
    }
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["dual-rel"]})
    resolver = OfflineFixtureResolver(packages)
    plan = Planner().plan(spec, resolver)
    assert "dual-rel" in plan.resolved_projects
    assert len(plan.files) == 1
    assert plan.files[0].filename == "dual_rel-1.0.0.whl"


def test_regression_mismatched_upload_time_and_ns_rejected() -> None:
    """Finding 7: Inconsistent upload_time and upload_time_ns representations rejected."""
    class InconsistentFileResolver:
        def resolve_package(self, project: str, cutoff_epoch_ns: int, ecosystem: str = "pypi") -> ResolvedRelease | None:
            return ResolvedRelease(
                project="inconsistent-pkg",
                version="1.0.0",
                upload_time="2024-01-01T00:00:00Z",
                upload_time_ns=1704067200 * 1_000_000_000,
                files=(
                    ResolvedFile(
                        filename="inconsistent_pkg-1.0.0.whl",
                        sha256="a" * 64,
                        upload_time="2024-06-01T00:00:00Z",  # post-cutoff string!
                        upload_time_ns=1704067200 * 1_000_000_000,  # pre-cutoff ns!
                        size_bytes=100,
                        project="inconsistent-pkg",
                    ),
                ),
                dependencies=(),
            )

    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["inconsistent-pkg"]})
    plan = Planner().plan(spec, InconsistentFileResolver())
    assert "inconsistent-pkg" not in plan.resolved_projects
    unresolved_reasons = {u.project: u.reason for u in plan.unresolved}
    assert "inconsistent-pkg" in unresolved_reasons
    assert "does not match upload_time_ns" in unresolved_reasons["inconsistent-pkg"]

    class InconsistentReleaseResolver:
        def resolve_package(self, project: str, cutoff_epoch_ns: int, ecosystem: str = "pypi") -> ResolvedRelease | None:
            return ResolvedRelease(
                project="inconsistent-rel",
                version="1.0.0",
                upload_time="2024-06-01T00:00:00Z",  # post-cutoff string!
                upload_time_ns=1704067200 * 1_000_000_000,  # pre-cutoff ns!
                files=(
                    ResolvedFile(
                        filename="inconsistent_rel-1.0.0.whl",
                        sha256="a" * 64,
                        upload_time="2024-01-01T00:00:00Z",
                        upload_time_ns=1704067200 * 1_000_000_000,
                        size_bytes=100,
                        project="inconsistent-rel",
                    ),
                ),
                dependencies=(),
            )

    spec_rel = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["inconsistent-rel"]})
    plan_rel = Planner().plan(spec_rel, InconsistentReleaseResolver())
    assert "inconsistent-rel" not in plan_rel.resolved_projects
    unresolved_reasons_rel = {u.project: u.reason for u in plan_rel.unresolved}
    assert "inconsistent-rel" in unresolved_reasons_rel
    assert "does not match upload_time_ns" in unresolved_reasons_rel["inconsistent-rel"]


def test_regression_fetcher_oserror_converted_to_store_io_error(tmp_path: Path) -> None:
    """Finding 5: Operational fetch failures convert to StoreIOError, preserving cause."""
    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["test-pkg"]})
    res_file = ResolvedFile(
        filename="test_pkg-1.0.whl",
        sha256="a" * 64,
        upload_time="2024-01-01T00:00:00Z",
        upload_time_ns=1704067200 * 1_000_000_000,
        size_bytes=10,
        project="test-pkg",
    )
    plan = Plan(
        spec=spec,
        files=(res_file,),
        unresolved=(),
        storage=StorageReport.from_files((res_file,)),
        resolved_projects=("test-pkg",),
    )

    def failing_fetcher(p: str, f: str, s: str) -> bytes:
        raise OSError("Connection reset by peer")

    builder = BaselineBuilder(tmp_path / "store_fetch_fail")
    with pytest.raises(StoreIOError) as exc_info:
        builder.build(plan, failing_fetcher)
    assert isinstance(exc_info.value.__cause__, OSError)


def test_regression_failed_freeze_leaves_no_committed_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixture_packages: dict[str, list[dict[str, object]]],
    fixture_fetcher: OfflineFixtureFetcher,
) -> None:
    """Finding 2: A failed freeze unlinks .frozen and does not commit an immutable state."""
    import hermetic_pkgbase.builder as builder_module

    spec = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest"]})
    resolver = OfflineFixtureResolver(fixture_packages)
    plan = Planner().plan(spec, resolver)

    store_dir = tmp_path / "fail_freeze_store"

    def faulty_freeze(root: str | os.PathLike[str]) -> None:
        raise StoreIOError("Simulated disk error during directory tree freeze")

    monkeypatch.setattr(builder_module, "freeze_directory_tree", faulty_freeze)

    builder = BaselineBuilder(store_dir)
    with pytest.raises(StoreIOError):
        builder.build(plan, fixture_fetcher)

    # .frozen marker must NOT be present
    assert not (store_dir / ".frozen").exists()
    assert not is_store_frozen(store_dir)


def test_regression_incomplete_build_prevents_different_plan_contamination(
    tmp_path: Path,
    fixture_packages: dict[str, list[dict[str, object]]],
    fixture_fetcher: OfflineFixtureFetcher,
) -> None:
    """Finding 3: Incomplete build rejects reuse by a different plan."""
    spec_a = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pytest"]})
    spec_b = parse_spec({"cutoff_month": "2024-05", "fixed_tools": ["pluggy"]})

    resolver = OfflineFixtureResolver(fixture_packages)
    plan_a = Planner().plan(spec_a, resolver)
    plan_b = Planner().plan(spec_b, resolver)

    store_dir = tmp_path / "contaminate_store"
    fetch_count = 0

    def flaky_fetcher(p: str, f: str, s: str) -> bytes:
        nonlocal fetch_count
        fetch_count += 1
        if fetch_count == 2:
            raise RuntimeError("Interrupted")
        return fixture_fetcher.fetch(p, f, s)

    builder_a = BaselineBuilder(store_dir)
    with pytest.raises(RuntimeError):
        builder_a.build(plan_a, flaky_fetcher)

    assert not is_store_frozen(store_dir)

    # Attempting to build Plan B in the same store must fail closed
    builder_b = BaselineBuilder(store_dir)
    with pytest.raises(StoreIOError) as exc_info:
        builder_b.build(plan_b, fixture_fetcher)
    assert "different plan" in str(exc_info.value) or "another plan" in str(exc_info.value)



