"""Comprehensive tests for D7 build recipe emission, validation, and deep audit integration."""

from __future__ import annotations

import io
import json
import os
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from hermetic_d7 import (
    RECIPE_SCHEMA,
    RecipeEntry,
    build_recipe,
    emit_recipe,
    parse_recipe,
    run_deep_audit,
)
from hermetic_d7.deep_audit import BuildRequest
from hermetic_d7.normalise import (
    HermeticD7Error,
    InvalidArtifactError,
    ResourceLimitError,
    SecurityViolationError,
)
from hermetic_d7.recipe import (
    MAX_ARGS,
    MAX_RECIPE_ENTRIES,
    MAX_UNATTRIBUTED_ENTRIES,
    RecipeFormatError,
    RecipeSecurityError,
    scan_built_artifacts,
)


def _setup_fixture_world(root: Path) -> dict[str, bytes]:
    """Create a fixture world tree with sources, built artifacts, and orphans."""
    # Source tree
    src = root / "src" / "fastmath"
    src.mkdir(parents=True)
    (src / "fastmath.c").write_bytes(b"int add(int a, int b) { return a + b; }\n")
    (src / "setup.py").write_bytes(b"from setuptools import setup; setup(name='fastmath')\n")

    # Built extension module
    lib = root / "lib"
    lib.mkdir(parents=True)
    ext_payload = b"\x7fELFfake_fastmath_compiled_extension_bytes\n"
    (lib / "fastmath.cpython-311-x86_64-linux-gnu.so").write_bytes(ext_payload)

    # Built wheel in dist/ (valid zip archive)
    dist = root / "dist"
    dist.mkdir(parents=True)
    wheel_buf = io.BytesIO()
    with zipfile.ZipFile(wheel_buf, "w") as zf:
        zf.writestr("fastmath/__init__.py", b"__version__ = '1.0.0'\n")
    wheel_payload = wheel_buf.getvalue()
    (dist / "fastmath-1.0.0-cp311-cp311-linux_x86_64.whl").write_bytes(wheel_payload)

    # Built sdist in dist/ (valid gzip-compressed tar archive)
    sdist_buf = io.BytesIO()
    with tarfile.open(fileobj=sdist_buf, mode="w:gz") as tf:
        pkg_data = b"__version__ = '1.0.0'\n"
        ti = tarfile.TarInfo("fastmath-1.0.0/setup.py")
        ti.size = len(pkg_data)
        ti.mode = 0o644
        tf.addfile(ti, io.BytesIO(pkg_data))
    sdist_payload = sdist_buf.getvalue()
    (dist / "fastmath-1.0.0.tar.gz").write_bytes(sdist_payload)

    # Orphan compiled extension module in opt/ without any build record
    opt = root / "opt" / "orphan"
    opt.mkdir(parents=True)
    orphan_payload = b"\x7fELFfake_orphan_unattributed_extension_bytes\n"
    (opt / "unattributed_mod.so").write_bytes(orphan_payload)

    # Build record describing provenance for the wheel, sdist, and extension
    build_record = {
        "entries": [
            {
                "id": "fastmath-so",
                "artifact": "lib/fastmath.cpython-311-x86_64-linux-gnu.so",
                "source": "src/fastmath",
                "builder": "gcc",
                "args": ["-shared", "-O2"],
            },
            {
                "id": "fastmath-wheel",
                "artifact": "dist/fastmath-1.0.0-cp311-cp311-linux_x86_64.whl",
                "source": "src/fastmath",
                "builder": "python-wheel",
                "args": ["--no-isolation"],
            },
            {
                "id": "fastmath-sdist",
                "artifact": "dist/fastmath-1.0.0.tar.gz",
                "source": "src/fastmath",
                "builder": "python-sdist",
                "args": ["--no-isolation"],
            },
        ]
    }
    (root / "build-record.json").write_text(json.dumps(build_record, indent=2))

    return {
        "fastmath-so": ext_payload,
        "fastmath-wheel": wheel_payload,
        "fastmath-sdist": sdist_payload,
        "orphan": orphan_payload,
    }


class FixtureBuilder:
    """Isolated builder fixture that rebuilds known artifacts from source."""

    def __init__(
        self,
        payloads: dict[str, bytes],
        *,
        alter_id: str | None = None,
        alter_bytes: bytes | None = None,
    ) -> None:
        self.payloads = payloads
        self.alter_id = alter_id
        self.alter_bytes = alter_bytes
        self.requests: list[BuildRequest] = []

    def build(self, request: BuildRequest) -> None:
        self.requests.append(request)
        out_file = request.output_dir / request.artifact_name
        if self.alter_id == request.entry.id and self.alter_bytes is not None:
            out_file.write_bytes(self.alter_bytes)
        else:
            out_file.write_bytes(self.payloads[request.entry.id])


def test_fixture_seal_produces_known_answer_recipe(tmp_path: Path) -> None:
    """A fixture seal produces a known-answer d7-recipe.json with permissions 0600."""
    world = tmp_path / "world"
    world.mkdir()
    _setup_fixture_world(world)

    recipe_data = emit_recipe(world, build_manifest=world / "build-record.json")

    recipe_path = world / "d7-recipe.json"
    assert recipe_path.is_file()
    assert stat.S_IMODE(recipe_path.stat().st_mode) == 0o600

    doc = json.loads(recipe_data.decode("utf-8"))
    assert doc["schema"] == RECIPE_SCHEMA

    # Entries are sorted deterministically by id
    expected_entries = [
        {
            "args": ["--no-isolation"],
            "artifact": "dist/fastmath-1.0.0.tar.gz",
            "builder": "python-sdist",
            "id": "fastmath-sdist",
            "source": "src/fastmath",
        },
        {
            "args": ["-shared", "-O2"],
            "artifact": "lib/fastmath.cpython-311-x86_64-linux-gnu.so",
            "builder": "gcc",
            "id": "fastmath-so",
            "source": "src/fastmath",
        },
        {
            "args": ["--no-isolation"],
            "artifact": "dist/fastmath-1.0.0-cp311-cp311-linux_x86_64.whl",
            "builder": "python-wheel",
            "id": "fastmath-wheel",
            "source": "src/fastmath",
        },
    ]
    assert doc["entries"] == expected_entries

    # Orphan extension module is placed in unattributed, never guessed
    assert doc["unattributed"] == ["opt/orphan/unattributed_mod.so"]

    # Invariants: no host paths in output
    text = recipe_data.decode("utf-8")
    assert str(tmp_path) not in text
    assert "/home/" not in text


def test_round_trip_through_deep_audit_with_fixture_builder(tmp_path: Path) -> None:
    """hermetic_d7 --deep-audit consumes the sealer's recipe output directly."""
    world = tmp_path / "world"
    world.mkdir()
    payloads = _setup_fixture_world(world)

    emit_recipe(world, build_manifest=world / "build-record.json")

    builder = FixtureBuilder(payloads)
    report = run_deep_audit(world, "d7-recipe.json", builder=builder)

    # Orphan unattributed_mod.so is present, so verdict must be incomplete (not identical)
    assert report["verdict"] == "incomplete"
    assert report["verdict"] != "identical"
    assert report["audit_only"] is True
    assert report["gating"] is False
    assert report["detector"] == "D7"
    assert report["recipe"] == "d7-recipe.json"
    assert [e["id"] for e in report["entries"]] == ["fastmath-sdist", "fastmath-so", "fastmath-wheel"]
    assert all(e["verdict"] == "identical" for e in report["entries"])
    assert report["unattributed"] == ["opt/orphan/unattributed_mod.so"]
    assert str(tmp_path) not in json.dumps(report)

    # When all artifacts are attributed and rebuilds are identical, verdict is identical
    (world / "opt" / "orphan" / "unattributed_mod.so").unlink()
    emit_recipe(world, build_manifest=world / "build-record.json")
    report_clean = run_deep_audit(world, "d7-recipe.json", builder=builder)
    assert report_clean["verdict"] == "identical"
    assert report_clean["unattributed"] == []

    # If the builder produces differing content, deep audit reports differing
    differ_builder = FixtureBuilder(
        payloads,
        alter_id="fastmath-so",
        alter_bytes=b"\x7fELFdiffering_compiled_bytes\n",
    )
    differ_report = run_deep_audit(world, "d7-recipe.json", builder=differ_builder)
    assert differ_report["verdict"] == "differs"
    entry_differs = next(e for e in differ_report["entries"] if e["id"] == "fastmath-so")
    assert entry_differs["verdict"] == "differs"


def test_hostile_symlinked_inputs_refused(tmp_path: Path) -> None:
    """Symlinked world root, output, artifact, or source is refused."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"host secret\n")

    world = tmp_path / "world"
    world.mkdir()
    _setup_fixture_world(world)

    # 1. Symlinked world root refused
    link_root = tmp_path / "symlink_root"
    link_root.symlink_to(world)
    with pytest.raises(SecurityViolationError):
        emit_recipe(link_root)

    # 2. Symlinked output path refused
    link_out = tmp_path / "symlink_recipe.json"
    link_out.symlink_to(outside / "recipe.json")
    with pytest.raises(SecurityViolationError):
        emit_recipe(world, output_path=link_out)

    # 3. Symlinked artifact refused
    shutil_world = tmp_path / "world_sym_art"
    shutil_world.mkdir()
    _setup_fixture_world(shutil_world)
    (shutil_world / "lib" / "fastmath.cpython-311-x86_64-linux-gnu.so").unlink()
    (shutil_world / "lib" / "fastmath.cpython-311-x86_64-linux-gnu.so").symlink_to(outside / "secret.txt")
    with pytest.raises(SecurityViolationError):
        emit_recipe(shutil_world)

    # 4. Symlinked source refused
    shutil_world2 = tmp_path / "world_sym_src"
    shutil_world2.mkdir()
    _setup_fixture_world(shutil_world2)
    import shutil
    shutil.rmtree(shutil_world2 / "src" / "fastmath")
    (shutil_world2 / "src" / "fastmath").symlink_to(outside)
    with pytest.raises(SecurityViolationError):
        emit_recipe(shutil_world2, build_manifest=shutil_world2 / "build-record.json")

    # 5. Path traversal in artifact refused
    with pytest.raises(SecurityViolationError):
        emit_recipe(
            world,
            entries=[
                {
                    "id": "traversal-art",
                    "artifact": "../outside/secret.txt",
                    "source": "src/fastmath",
                    "builder": "gcc",
                    "args": [],
                }
            ],
        )

    # 6. Path traversal in source refused
    with pytest.raises(SecurityViolationError):
        emit_recipe(
            world,
            entries=[
                {
                    "id": "traversal-src",
                    "artifact": "lib/fastmath.cpython-311-x86_64-linux-gnu.so",
                    "source": "../../etc",
                    "builder": "gcc",
                    "args": [],
                }
            ],
        )

    # 7. Symlinked orphan artifact in tree refused
    shutil_world3 = tmp_path / "world_sym_orphan"
    shutil_world3.mkdir()
    _setup_fixture_world(shutil_world3)
    (shutil_world3 / "opt" / "orphan" / "unattributed_mod.so").unlink()
    (shutil_world3 / "opt" / "orphan" / "unattributed_mod.so").symlink_to(outside / "secret.txt")
    with pytest.raises(SecurityViolationError):
        emit_recipe(shutil_world3)


def test_byte_identical_output_across_two_runs(tmp_path: Path) -> None:
    """Byte-identical output across two independent runs on identical trees."""
    world_a = tmp_path / "world_a"
    world_b = tmp_path / "world_b"
    world_a.mkdir()
    world_b.mkdir()

    _setup_fixture_world(world_a)
    _setup_fixture_world(world_b)

    bytes_a = emit_recipe(world_a)
    bytes_b = emit_recipe(world_b)

    assert bytes_a == bytes_b
    assert (world_a / "d7-recipe.json").read_bytes() == (world_b / "d7-recipe.json").read_bytes()

    # Repeated seal on the exact same directory gives identical output
    bytes_a2 = emit_recipe(world_a)
    assert bytes_a == bytes_a2


def test_provenance_not_established_listed_in_unattributed_never_guessed(tmp_path: Path) -> None:
    """Artifacts whose provenance cannot be established are listed in unattributed, never guessed."""
    world = tmp_path / "world"
    world.mkdir()
    (world / "lib").mkdir(parents=True)
    (world / "lib" / "ext1.so").write_bytes(b"\x7fELFext1")
    (world / "lib" / "ext2.so").write_bytes(b"\x7fELFext2")
    (world / "dist").mkdir(parents=True)
    (world / "dist" / "built.whl").write_bytes(b"PKbuilt")

    # Only ext1 has verified source and builder
    (world / "src" / "ext1").mkdir(parents=True)
    (world / "src" / "ext1" / "code.c").write_bytes(b"code")

    manifest = {
        "entries": [
            {
                "id": "ext1",
                "artifact": "lib/ext1.so",
                "source": "src/ext1",
                "builder": "gcc",
                "args": ["-shared"],
            },
            # ext2 lists a missing source directory -> provenance cannot be established!
            {
                "id": "ext2",
                "artifact": "lib/ext2.so",
                "source": "src/missing_source",
                "builder": "gcc",
                "args": [],
            },
        ],
        # generated files listed by the build without complete provenance
        "generated_files": ["dist/built.whl"],
    }
    # Build manifest passed explicitly from outside world tree
    recipe_data = emit_recipe(world, build_manifest=manifest)
    doc = json.loads(recipe_data.decode("utf-8"))

    # Only ext1 is attributed
    assert [e["id"] for e in doc["entries"]] == ["ext1"]
    assert doc["entries"][0]["artifact"] == "lib/ext1.so"

    # ext2 (missing source) and built.whl (unattributed) are in unattributed
    assert doc["unattributed"] == ["dist/built.whl", "lib/ext2.so"]


def test_empty_seal_produces_clean_empty_recipe_and_identical_audit(tmp_path: Path) -> None:
    """A recipe with no entries and no unattributed artifacts stays refused."""
    world = tmp_path / "world"
    world.mkdir()
    (world / "src").mkdir()
    (world / "src" / "pure.py").write_text("x = 1\n")

    # A recipe with zero entries and no unattributed artifacts is refused (cannot report identical)
    with pytest.raises(InvalidArtifactError):
        emit_recipe(world)

    with pytest.raises(InvalidArtifactError, match="non-empty list"):
        parse_recipe(b'{"schema": "hermetic.d7.recipe/1", "entries": [], "unattributed": []}')

    (world / "d7-recipe.json").write_text(json.dumps({"schema": RECIPE_SCHEMA, "entries": [], "unattributed": []}))
    report = run_deep_audit(world, "d7-recipe.json")
    assert report["verdict"] == "error"


def test_recipe_resource_limits_and_caps(tmp_path: Path) -> None:
    """Resource limits: excessive entries, args, or unattributed are refused."""
    world = tmp_path / "world"
    world.mkdir()
    (world / "src" / "pkg").mkdir(parents=True)
    (world / "dist").mkdir(parents=True)
    (world / "dist" / "mod.whl").write_bytes(b"PK")

    # Arg count > MAX_ARGS refused
    bad_args = ["--flag"] * (MAX_ARGS + 1)
    with pytest.raises(InvalidArtifactError):
        emit_recipe(
            world,
            entries=[
                {
                    "id": "bad-args",
                    "artifact": "dist/mod.whl",
                    "source": "src/pkg",
                    "builder": "wheel",
                    "args": bad_args,
                }
            ],
        )

    # Entries cap > MAX_RECIPE_ENTRIES refused
    too_many_entries = [
        {
            "id": f"e{i}",
            "artifact": f"dist/mod_{i}.whl",
            "source": "src/pkg",
            "builder": "wheel",
            "args": [],
        }
        for i in range(MAX_RECIPE_ENTRIES + 1)
    ]
    with pytest.raises(ResourceLimitError):
        emit_recipe(world, entries=too_many_entries)

    # Unattributed cap > MAX_UNATTRIBUTED_ENTRIES refused
    too_many_unattributed = [f"dist/{i}.so" for i in range(MAX_UNATTRIBUTED_ENTRIES + 1)]
    for p in too_many_unattributed:
        (world / p).write_bytes(b"so")
    with pytest.raises(ResourceLimitError):
        emit_recipe(world)


# =============================================================================
# Regression tests for Manager Fix 1 defects
# =============================================================================


def test_regression_defect1_fail_open_verdict(tmp_path: Path) -> None:
    """Defect 1: run_deep_audit never reports 'identical' when unattributed artifacts are present."""
    world = tmp_path / "world"
    world.mkdir()
    (world / "orphan.so").write_bytes(b"\x7fELForphan")

    # Case 1: entries=[] with one unattributed -> verdict is incomplete (not identical), lists unattributed
    recipe_unattributed_only = {
        "schema": RECIPE_SCHEMA,
        "entries": [],
        "unattributed": ["orphan.so"],
    }
    (world / "recipe1.json").write_text(json.dumps(recipe_unattributed_only))
    report1 = run_deep_audit(world, "recipe1.json")
    assert report1["verdict"] == "incomplete"
    assert report1["verdict"] != "identical"
    assert report1["unattributed"] == ["orphan.so"]

    # Case 2: one identical entry plus one unattributed -> verdict is incomplete (not identical)
    (world / "src").mkdir()
    (world / "src" / "lib.c").write_bytes(b"int foo() { return 42; }\n")
    (world / "lib.so").write_bytes(b"\x7fELFlibrary")
    recipe_one_entry_plus_unattributed = {
        "schema": RECIPE_SCHEMA,
        "entries": [
            {
                "id": "my-lib",
                "artifact": "lib.so",
                "source": "src",
                "builder": "gcc",
                "args": ["-shared"],
            }
        ],
        "unattributed": ["orphan.so"],
    }
    (world / "recipe2.json").write_text(json.dumps(recipe_one_entry_plus_unattributed))

    class IdenticalBuilder:
        def build(self, req: BuildRequest) -> None:
            (req.output_dir / req.artifact_name).write_bytes(b"\x7fELFlibrary")

    report2 = run_deep_audit(world, "recipe2.json", builder=IdenticalBuilder())
    assert report2["verdict"] == "incomplete"
    assert report2["verdict"] != "identical"
    assert report2["entries"][0]["verdict"] == "identical"
    assert report2["unattributed"] == ["orphan.so"]

    # Case 3: entries=[] with unattributed=[] stays refused
    empty_recipe_data = json.dumps({"schema": RECIPE_SCHEMA, "entries": [], "unattributed": []}).encode("utf-8")
    with pytest.raises(InvalidArtifactError, match="non-empty list"):
        parse_recipe(empty_recipe_data)

    (world / "recipe3.json").write_text(empty_recipe_data.decode("utf-8"))
    report3 = run_deep_audit(world, "recipe3.json")
    assert report3["verdict"] == "error"


def test_regression_defect2_provenance_from_world_itself(tmp_path: Path) -> None:
    """Defect 2: In-world auto-discovery is removed; build record must come strictly from outside."""
    world = tmp_path / "world"
    world.mkdir()
    (world / "built.so").write_bytes(b"\x7fELFbuilt")
    (world / "src").mkdir()
    (world / "src" / "code.c").write_bytes(b"int x = 1;\n")

    # Hostile task environment plants provenance claim inside the world
    hostile_claim = {
        "entries": [
            {
                "id": "claimed-id",
                "artifact": "built.so",
                "source": "src",
                "builder": "gcc",
                "args": ["-shared"],
            }
        ]
    }
    (world / "d7-build.json").write_text(json.dumps(hostile_claim))
    (world / "build-record.json").write_text(json.dumps(hostile_claim))

    # Without external manifest, in-world files must NOT be auto-discovered
    recipe_bytes = build_recipe(world, build_manifest=None)
    doc = json.loads(recipe_bytes.decode("utf-8"))
    assert doc["entries"] == []
    assert doc["unattributed"] == ["built.so"]

    # Explicitly given manifest is accepted from outside
    outside_manifest = tmp_path / "outside-build-record.json"
    outside_manifest.write_text(json.dumps(hostile_claim))
    recipe_bytes_ext = build_recipe(world, build_manifest=outside_manifest)
    doc_ext = json.loads(recipe_bytes_ext.decode("utf-8"))
    assert [e["id"] for e in doc_ext["entries"]] == ["claimed-id"]

    # Explicit manifest errors are NEVER swallowed
    missing_manifest = tmp_path / "nonexistent-record.json"
    with pytest.raises(RecipeFormatError, match="not found"):
        build_recipe(world, build_manifest=missing_manifest)

    outside_sym = tmp_path / "symlink-record.json"
    outside_sym.symlink_to(outside_manifest)
    with pytest.raises(RecipeSecurityError, match="symlink|unsafe"):
        build_recipe(world, build_manifest=outside_sym)

    bad_json_manifest = tmp_path / "bad.json"
    bad_json_manifest.write_bytes(b"{not json}")
    with pytest.raises(RecipeFormatError, match="valid UTF-8 JSON"):
        build_recipe(world, build_manifest=bad_json_manifest)


def test_regression_defect3_scan_scope_installed_wheel_extensions(tmp_path: Path) -> None:
    """Defect 3: scan_built_artifacts excludes installed wheel extensions via RECORD files."""
    world = tmp_path / "world"
    world.mkdir()

    site_packages = world / "opt" / "env" / "lib" / "python3.11" / "site-packages"
    site_packages.mkdir(parents=True)

    # 50 installed-wheel extensions across 50 packages
    record_lines: list[str] = []
    for i in range(50):
        pkg_dir = site_packages / f"pkg_{i}"
        pkg_dir.mkdir(parents=True)
        so_file = pkg_dir / f"mod_{i}.cpython-311-x86_64-linux-gnu.so"
        so_file.write_bytes(f"\x7fELFpkg_{i}".encode("ascii"))
        record_lines.append(f"pkg_{i}/mod_{i}.cpython-311-x86_64-linux-gnu.so,sha256=xxx,123")

    dist_info = site_packages / "bigpkg-1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "RECORD").write_text("\n".join(record_lines) + "\n")

    # One locally built extension in build/
    build_dir = world / "build"
    build_dir.mkdir(parents=True)
    local_so = build_dir / "locally_built.cpython-311-x86_64-linux-gnu.so"
    local_so.write_bytes(b"\x7fELFlocal_so")

    # Full root scan: installed wheel files excluded, only local_so reported
    root_fd = os.open(world, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        found = scan_built_artifacts(root_fd)
    finally:
        os.close(root_fd)

    assert found == ["build/locally_built.cpython-311-x86_64-linux-gnu.so"]

    # Restricted directory scope scan
    root_fd = os.open(world, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        found_scoped = scan_built_artifacts(root_fd, build_directories=["build"])
    finally:
        os.close(root_fd)

    assert found_scoped == ["build/locally_built.cpython-311-x86_64-linux-gnu.so"]


def test_regression_defect4_fixture_seal_wires_recipe_and_deep_audit_accepts(tmp_path: Path) -> None:
    """Defect 4: seal_world emits d7-recipe.json next to manifest.json outside world tree, accepted by deep audit."""
    from hermetic_e7 import seal_world

    world = tmp_path / "world"
    world.mkdir()
    (world / "src").mkdir()
    (world / "src" / "compute.c").write_bytes(b"int compute() { return 100; }\n")
    (world / "compute.so").write_bytes(b"\x7fELFcompute")

    build_rec = {
        "entries": [
            {
                "id": "compute-so",
                "artifact": "compute.so",
                "source": "src",
                "builder": "gcc",
                "args": ["-shared"],
            }
        ]
    }

    seal_out = tmp_path / "seal_output"
    manifest = seal_world(world, seal_out, build_record=build_rec)

    assert "entries" in manifest
    assert "root" in manifest
    assert (seal_out / "manifest.json").is_file()
    assert (seal_out / "d7-recipe.json").is_file()
    assert not (world / "d7-recipe.json").exists()

    class ComputeBuilder:
        def build(self, req: BuildRequest) -> None:
            (req.output_dir / req.artifact_name).write_bytes(b"\x7fELFcompute")

    report = run_deep_audit(world, seal_out / "d7-recipe.json", builder=ComputeBuilder())
    assert report["verdict"] == "identical"
    assert report["entries"][0]["id"] == "compute-so"
    assert report["entries"][0]["verdict"] == "identical"
    assert report["unattributed"] == []


def test_seal_world_symlinked_build_record_refused(tmp_path: Path) -> None:
    """seal_world refuses a symlinked build record with RecipeSecurityError."""
    from hermetic_e7 import seal_world

    world = tmp_path / "world"
    world.mkdir()
    (world / "src").mkdir()
    (world / "src" / "compute.c").write_bytes(b"int compute() { return 100; }\n")
    (world / "compute.so").write_bytes(b"\x7fELFcompute")

    outside = tmp_path / "outside_record.json"
    outside.write_text('{"entries": []}')
    sym_build_rec = tmp_path / "sym_build_rec.json"
    sym_build_rec.symlink_to(outside)

    seal_out = tmp_path / "seal_output"
    with pytest.raises(RecipeSecurityError, match="symlink"):
        seal_world(world, seal_out, build_record=sym_build_rec)


def test_regression_defect5_load_artifact_restrictions(tmp_path: Path) -> None:
    """Defect 5: load_artifact regular files restricted to compiled extensions and listed generated files."""
    from hermetic_d7.normalise import load_artifact

    # Compiled extension (.so) loads as regular file
    so_path = tmp_path / "libtest.so"
    so_path.write_bytes(b"\x7fELFlibtest")
    loaded_so = load_artifact(so_path)
    assert "libtest.so" in loaded_so
    assert len(loaded_so["libtest.so"].data) == len(b"\x7fELFlibtest")

    # Compiled extension (.dylib, .pyd) loads as regular file
    dylib_path = tmp_path / "libtest.dylib"
    dylib_path.write_bytes(b"dylib_payload")
    loaded_dylib = load_artifact(dylib_path)
    assert "libtest.dylib" in loaded_dylib

    pyd_path = tmp_path / "mod.pyd"
    pyd_path.write_bytes(b"pyd_payload")
    loaded_pyd = load_artifact(pyd_path)
    assert "mod.pyd" in loaded_pyd

    # Explicitly listed generated file loads as regular file
    gen_file = tmp_path / "custom.data"
    gen_file.write_bytes(b"custom_generated_payload")
    loaded_gen = load_artifact(gen_file, generated_files=["custom.data"])
    assert "custom.data" in loaded_gen
    assert len(loaded_gen["custom.data"].data) == len(b"custom_generated_payload")

    # Unknown formats not in generated_files stay refused
    txt_file = tmp_path / "unknown.txt"
    txt_file.write_bytes(b"regular text content")
    with pytest.raises(InvalidArtifactError, match="Unsupported artifact format"):
        load_artifact(txt_file)

    bin_file = tmp_path / "binary.bin"
    bin_file.write_bytes(b"\x00\x01\x02\x03")
    with pytest.raises(InvalidArtifactError, match="Unsupported artifact format"):
        load_artifact(bin_file)


def test_regression_defect6_emit_recipe_atomic_write_symlink_parent(tmp_path: Path) -> None:
    """Defect 6: emit_recipe uses atomic_write: destination parent symlink refused, file 0600."""
    world = tmp_path / "world"
    world.mkdir()
    (world / "lib.so").write_bytes(b"\x7fELFact")

    outside = tmp_path / "outside_secret"
    outside.mkdir()

    # Symlinked parent directory refused
    parent_sym = tmp_path / "parent_link"
    parent_sym.symlink_to(outside)
    with pytest.raises(RecipeSecurityError, match="cannot open output file|safely"):
        emit_recipe(world, output_path=parent_sym / "d7-recipe.json")

    # Symlinked destination file refused
    dest_sym = tmp_path / "dest_sym.json"
    dest_sym.symlink_to(outside / "target.json")
    with pytest.raises(RecipeSecurityError, match="cannot open output file|safely"):
        emit_recipe(world, output_path=dest_sym)

    # Valid output: created with permissions 0600 and replaced atomically
    out_valid = tmp_path / "valid-recipe.json"
    emit_recipe(world, output_path=out_valid)
    assert out_valid.is_file()
    assert stat.S_IMODE(out_valid.stat().st_mode) == 0o600

    # Overwrite existing valid file atomically
    emit_recipe(world, output_path=out_valid)
    assert out_valid.is_file()
    assert stat.S_IMODE(out_valid.stat().st_mode) == 0o600


def test_cr_finding1_source_regular_file_lands_in_unattributed(tmp_path: Path) -> None:
    """CR finding 1: regular file source cannot be built in deep audit; must land in unattributed."""
    world = tmp_path / "world"
    world.mkdir()
    src = world / "src" / "pkg"
    src.mkdir(parents=True)
    setup_file = src / "setup.py"
    setup_file.write_bytes(b"# setup script\n")

    lib = world / "lib"
    lib.mkdir(parents=True)
    ext_file = lib / "fastmath.so"
    ext_file.write_bytes(b"\x7fELFfastmath")

    # Manifest claiming provenance with source pointing to setup.py (regular file, not directory)
    manifest = {
        "entries": [
            {
                "id": "fastmath-entry",
                "artifact": "lib/fastmath.so",
                "source": "src/pkg/setup.py",
                "builder": "gcc",
                "args": ["-shared"],
            }
        ]
    }
    manifest_path = tmp_path / "build-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    recipe_bytes = build_recipe(world, build_manifest=manifest_path)
    doc = json.loads(recipe_bytes.decode("utf-8"))

    # Must NOT be attributed (deep audit requires directory source)
    assert doc["entries"] == []
    # Must land in unattributed under the "never guess" rule
    assert doc["unattributed"] == ["lib/fastmath.so"]

    # Deep audit on this recipe verifies safely as incomplete (not an error)
    recipe_file = tmp_path / "recipe.json"
    recipe_file.write_bytes(recipe_bytes)
    audit = run_deep_audit(world, recipe_file)
    assert audit["verdict"] == "incomplete"
    assert audit["unattributed"] == ["lib/fastmath.so"]


def test_cr_finding3_missing_paths_vs_symlinks(tmp_path: Path) -> None:
    """CR finding 3: missing files raise RecipeFormatError ('does not exist'), while symlinks raise RecipeSecurityError."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_bytes(b"confidential")

    # 1. Missing entry artifact raises RecipeFormatError (not RecipeSecurityError)
    world1 = tmp_path / "world1"
    world1.mkdir()
    with pytest.raises(RecipeFormatError, match="artifact 'lib/nonexistent.so' does not exist in world"):
        build_recipe(
            world1,
            entries=[
                {
                    "id": "missing-art",
                    "artifact": "lib/nonexistent.so",
                    "source": "src",
                    "builder": "gcc",
                    "args": [],
                }
            ],
        )

    # 2. Symlinked entry artifact raises RecipeSecurityError
    world2 = tmp_path / "world2"
    world2.mkdir()
    lib2 = world2 / "lib"
    lib2.mkdir(parents=True)
    sym_art = lib2 / "sym_art.so"
    sym_art.symlink_to(secret)
    with pytest.raises(RecipeSecurityError, match="artifact 'lib/sym_art.so' is a symlink or special file"):
        build_recipe(
            world2,
            entries=[
                {
                    "id": "sym-art",
                    "artifact": "lib/sym_art.so",
                    "source": "src",
                    "builder": "gcc",
                    "args": [],
                }
            ],
        )

    # 3. Missing explicit unattributed raises RecipeFormatError (not RecipeSecurityError)
    world3 = tmp_path / "world3"
    world3.mkdir()
    with pytest.raises(RecipeFormatError, match="unattributed artifact 'opt/missing.so' does not exist in world"):
        build_recipe(world3, unattributed=["opt/missing.so"])

    # 4. Symlinked explicit unattributed raises RecipeSecurityError
    world4 = tmp_path / "world4"
    world4.mkdir()
    sym_unattr = world4 / "sym_unattr.so"
    sym_unattr.symlink_to(secret)
    with pytest.raises(RecipeSecurityError, match="unattributed artifact 'sym_unattr.so' is a symlink|candidate 'sym_unattr.so' is a symlink"):
        build_recipe(world4, unattributed=["sym_unattr.so"])

    # 5. Stale generated_files entry that does not exist is skipped (continue), does not fail build
    world5 = tmp_path / "world5"
    world5.mkdir()
    existing_gen = world5 / "existing_generated.so"
    existing_gen.write_bytes(b"\x7fELFgen")
    manifest_stale_gen = {
        "generated_files": ["nonexistent_stale_file.so", "existing_generated.so"],
    }
    recipe_bytes = build_recipe(world5, build_manifest=manifest_stale_gen)
    doc = json.loads(recipe_bytes.decode("utf-8"))
    assert "existing_generated.so" in doc["unattributed"]
    assert "nonexistent_stale_file.so" not in doc["unattributed"]

    # 6. Symlinked generated_files entry raises RecipeSecurityError
    world6 = tmp_path / "world6"
    world6.mkdir()
    sym_gen = world6 / "sym_gen.so"
    sym_gen.symlink_to(secret)
    manifest_sym_gen = {
        "generated_files": ["sym_gen.so"],
    }
    with pytest.raises(RecipeSecurityError, match="generated file 'sym_gen.so' is a symlink|candidate 'sym_gen.so' is a symlink"):
        build_recipe(world6, build_manifest=manifest_sym_gen)
