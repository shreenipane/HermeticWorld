"""Regression tests for automated CodeRabbit review findings in ecosystems worktree."""

import base64
import hashlib
import io
import json
import zipfile
import pytest

from hermetic_npm_cut.cut import (
    CapExceededError,
    SemVer,
    ValidationError,
    cut_packument,
    parse_semver,
)
from hermetic_ecosystem_cut.cut import CutError
from hermetic_ecosystem_cut.mirror import build_mirror
from hermetic_ecosystem_cut.provenance import (
    ProvenanceError,
    compute_go_mod_h1,
    compute_go_zip_h1,
    verify_go_provenance,
    MAX_UNCOMPRESSED_ZIP_BYTES,
)
from hermetic_ecosystem_cut.resolver import (
    CutoffResolver,
    ResolutionError,
    ResolutionPlan,
    satisfies_req,
)

CUTOFF = "2023-04-01T00:00:00Z"
PAST = "2022-01-01T00:00:00Z"
FUTURE = "2024-01-01T00:00:00Z"


def _make_zip(files: dict[str, bytes], prefix: str = "example.org/demo@v1.0.0/") -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(files.items()):
            zf.writestr(prefix + name, data)
    return bio.getvalue()


# Finding 1: python/hermetic_ecosystem_cut/mirror.py:305-306
def test_mirror_rejects_empty_checksum_when_key_present():
    """Verify that an empty string in expected_sums is rejected rather than treated as absent."""
    mod_bytes = b"module example.org/testmod\n\ngo 1.18\n"
    zip_bytes = _make_zip({"test.go": b"package testmod\n"}, prefix="example.org/testmod@v1.0.0/")

    blobs = {}
    def blob(data: bytes) -> str:
        d = hashlib.sha256(data).hexdigest()
        blobs[d] = data
        return d

    recipe = {
        "cutoff": CUTOFF,
        "packages": [
            {
                "ecosystem": "go",
                "name": "example.org/testmod",
                "metadata": blob(b"v1.0.0\n"),
                "infos": {"v1.0.0": blob(json.dumps({"Version": "v1.0.0", "Time": PAST}).encode("utf-8"))},
                "artifacts": {"v1.0.0.mod": blob(mod_bytes), "v1.0.0.zip": blob(zip_bytes)},
                "sums": {"v1.0.0.mod": ""},
                "sumdb": True,
            },
        ],
    }
    raw_recipe = json.dumps(recipe).encode("utf-8")
    with pytest.raises(CutError):
        build_mirror(raw_recipe, blobs)


# Finding 6: python/hermetic_ecosystem_cut/mirror.py:363
def test_mirror_ignores_embedded_packument_tag_history():
    """Tag history inside the packument is unauthenticated registry data: it must not
    restore non-latest tags; without pinned history they are dropped."""
    tar_bytes = b"\x1f\x8b\x08" + b"\x00" * 20
    packument = {
        "name": "embedded-tags-demo",
        "versions": {
            "1.0.0": {
                "name": "embedded-tags-demo",
                "version": "1.0.0",
                "dist": {"shasum": hashlib.sha1(tar_bytes).hexdigest()},
            },
        },
        "time": {"created": PAST, "modified": PAST, "1.0.0": PAST},
        "dist-tags": {"latest": "1.0.0", "beta": "1.0.0"},
        "dist-tag-history": {
            "beta": [{"version": "1.0.0", "time": PAST}],
        },
    }

    blobs = {}
    def blob(data: bytes) -> str:
        d = hashlib.sha256(data).hexdigest()
        blobs[d] = data
        return d

    recipe = {
        "cutoff": CUTOFF,
        "packages": [
            {
                "ecosystem": "npm",
                "name": "embedded-tags-demo",
                "metadata": blob(json.dumps(packument, sort_keys=True).encode("utf-8")),
                "artifacts": {"1.0.0": blob(tar_bytes)},
            },
        ],
    }
    raw_recipe = json.dumps(recipe).encode("utf-8")
    store = build_mirror(raw_recipe, blobs)
    out_pkg = json.loads(dict(store.files)["registry.npmjs.org/embedded-tags-demo/index.html"])
    # The self-asserted history restores nothing: only "latest" survives the cut.
    assert out_pkg["dist-tags"] == {"latest": "1.0.0"}


# Finding 7: python/hermetic_ecosystem_cut/provenance.py:130
def test_go_zip_h1_hashes_full_entry_names():
    """Verify that Go zip h1 hashing hashes the full entry name (e.g. example.org/demo@v1.0.0/a.go)."""
    prefix = "example.org/demo@v1.0.0/"
    file_bytes = b"package demo\nfunc A() {}\n"
    zip_bytes = _make_zip({"a.go": file_bytes}, prefix=prefix)

    actual_h1 = compute_go_zip_h1(zip_bytes, "example.org/demo", "v1.0.0")

    file_hex = hashlib.sha256(file_bytes).hexdigest()
    full_entry_name = prefix + "a.go"
    expected_line = f"{file_hex}  {full_entry_name}\n".encode("utf-8")
    expected_h1 = "h1:" + base64.b64encode(hashlib.sha256(expected_line).digest()).decode("ascii")

    assert actual_h1 == expected_h1

    # Verify it does NOT equal hashing just "a.go"
    bad_line = f"{file_hex}  a.go\n".encode("utf-8")
    bad_h1 = "h1:" + base64.b64encode(hashlib.sha256(bad_line).digest()).decode("ascii")
    assert actual_h1 != bad_h1


# Finding 8: python/hermetic_ecosystem_cut/resolver.py:348
def test_resolver_reports_missing_artifact_unresolved():
    """Verify that an admitted version whose artifact is absent is recorded as unresolved."""
    resolver = CutoffResolver(CUTOFF)
    pkg = {
        "packument": {
            "name": "missing-art-pkg",
            "versions": {"1.0.0": {"name": "missing-art-pkg", "version": "1.0.0"}},
            "time": {"1.0.0": PAST},
        },
        "artifacts": {},  # "1.0.0" key missing
    }
    plan = resolver.resolve("npm", {"missing-art-pkg": "1.0.0"}, lambda n: pkg)
    assert len(plan.packages) == 0
    assert len(plan.unresolved) == 1
    assert plan.unresolved[0].name == "missing-art-pkg"
    assert plan.unresolved[0].reason == "missing_artifact"


# Finding 10: python/hermetic_ecosystem_cut/resolver.py:456-459
def test_resolver_go_require_block_dependencies():
    """Verify that Go dependencies inside require (...) blocks are parsed."""
    resolver = CutoffResolver(CUTOFF)

    mod_bytes = (
        b"module example.org/rootmod\n\n"
        b"go 1.18\n\n"
        b"require (\n"
        b"\texample.org/dep1 v1.0.0\n"
        b"\texample.org/dep2 v1.2.0 // indirect\n"
        b")\n"
    )
    zip_bytes = _make_zip({"main.go": b"package main\n"}, prefix="example.org/rootmod@v1.0.0/")
    dep1_mod = b"module example.org/dep1\n\ngo 1.18\n"
    dep1_zip = _make_zip({"dep1.go": b"package dep1\n"}, prefix="example.org/dep1@v1.0.0/")
    dep2_mod = b"module example.org/dep2\n\ngo 1.18\n"
    dep2_zip = _make_zip({"dep2.go": b"package dep2\n"}, prefix="example.org/dep2@v1.2.0/")

    db = {
        "example.org/rootmod": {
            "list": "v1.0.0\n",
            "infos": {"v1.0.0": json.dumps({"Version": "v1.0.0", "Time": PAST})},
            "artifacts": {"v1.0.0.mod": mod_bytes, "v1.0.0.zip": zip_bytes},
        },
        "example.org/dep1": {
            "list": "v1.0.0\n",
            "infos": {"v1.0.0": json.dumps({"Version": "v1.0.0", "Time": PAST})},
            "artifacts": {"v1.0.0.mod": dep1_mod, "v1.0.0.zip": dep1_zip},
        },
        "example.org/dep2": {
            "list": "v1.2.0\n",
            "infos": {"v1.2.0": json.dumps({"Version": "v1.2.0", "Time": PAST})},
            "artifacts": {"v1.2.0.mod": dep2_mod, "v1.2.0.zip": dep2_zip},
        },
    }

    plan = resolver.resolve("go", {"example.org/rootmod": "v1.0.0"}, lambda n: db.get(n))
    assert not plan.unresolved
    pkg_names = {p.name for p in plan.packages}
    assert "example.org/dep1" in pkg_names
    assert "example.org/dep2" in pkg_names


# Finding 11: python/hermetic_ecosystem_cut/resolver.py:295
def test_resolver_preserves_multiple_versions_across_roots():
    """Verify that multiple versions of the same package across roots are preserved."""
    resolver = CutoffResolver(CUTOFF)

    shared_pkg = {
        "packument": {
            "name": "shared-child",
            "versions": {
                "1.0.0": {"name": "shared-child", "version": "1.0.0"},
                "2.0.0": {"name": "shared-child", "version": "2.0.0"},
            },
            "time": {"1.0.0": PAST, "2.0.0": PAST},
        },
        "artifacts": {"1.0.0": b"c1", "2.0.0": b"c2"},
    }
    root_a = {
        "packument": {
            "name": "root-a",
            "versions": {
                "1.0.0": {
                    "name": "root-a",
                    "version": "1.0.0",
                    "dependencies": {"shared-child": "=1.0.0"},
                },
            },
            "time": {"1.0.0": PAST},
        },
        "artifacts": {"1.0.0": b"ra"},
    }
    root_b = {
        "packument": {
            "name": "root-b",
            "versions": {
                "1.0.0": {
                    "name": "root-b",
                    "version": "1.0.0",
                    "dependencies": {"shared-child": "=2.0.0"},
                },
            },
            "time": {"1.0.0": PAST},
        },
        "artifacts": {"1.0.0": b"rb"},
    }

    db = {"root-a": root_a, "root-b": root_b, "shared-child": shared_pkg}
    plan = resolver.resolve("npm", {"root-a": "1.0.0", "root-b": "1.0.0"}, lambda n: db.get(n))

    # Verify both child versions exist in packages
    child_versions = {p.version for p in plan.packages if p.name == "shared-child"}
    assert child_versions == {"1.0.0", "2.0.0"}

    # Verify to_recipe groups both versions into one mirror package entry
    recipe = plan.to_recipe()
    child_entries = [p for p in recipe["packages"] if p["name"] == "shared-child"]
    assert len(child_entries) == 1
    assert "1.0.0" in child_entries[0]["artifacts"]
    assert "2.0.0" in child_entries[0]["artifacts"]


# Finding 12: python/hermetic_npm_cut/cut.py:559
def test_cut_packument_snapshots_and_bounds_explicit_tag_history():
    """Verify that explicit tag history is snapshotted and bounded by aggregate cap."""
    packument = {
        "name": "snapshot-test",
        "versions": {"1.0.0": {"name": "snapshot-test", "version": "1.0.0"}},
        "time": {"1.0.0": PAST},
        "dist-tags": {"latest": "1.0.0", "beta": "1.0.0"},
    }
    # Test snapshotting: mutable list inside tag_history
    entries = [{"version": "1.0.0", "time": PAST}]
    tag_history = {"beta": entries}
    out, _ = cut_packument(packument, CUTOFF, tag_history=tag_history)
    assert out["dist-tags"]["beta"] == "1.0.0"

    # Test aggregate byte budget enforcement
    huge_history = {f"tag{i}": [{"version": "1.0.0", "time": PAST}] for i in range(100)}
    huge_history["bloat"] = "x" * (65 * 1024 * 1024)
    with pytest.raises(CapExceededError):
        cut_packument(packument, CUTOFF, tag_history=huge_history)


# Finding 13: python/hermetic_ecosystem_cut/resolver.py:263-265
def test_resolver_enforces_max_packages_closure_limit():
    """Verify that closure limit max_packages is strictly enforced before accepting new packages."""
    resolver = CutoffResolver(CUTOFF, max_packages=1)

    p1 = {
        "packument": {
            "name": "p1",
            "versions": {"1.0.0": {"name": "p1", "version": "1.0.0"}},
            "time": {"1.0.0": PAST},
        },
        "artifacts": {"1.0.0": b"p1"},
    }
    p2 = {
        "packument": {
            "name": "p2",
            "versions": {"1.0.0": {"name": "p2", "version": "1.0.0"}},
            "time": {"1.0.0": PAST},
        },
        "artifacts": {"1.0.0": b"p2"},
    }
    db = {"p1": p1, "p2": p2}

    # Two distinct roots with max_packages=1 must raise ResolutionError
    with pytest.raises(ResolutionError, match="Closure exceeds maximum package count limit"):
        resolver.resolve("npm", {"p1": "1.0.0", "p2": "1.0.0"}, lambda n: db.get(n))

    # Revisit of the SAME package at the limit should succeed
    single_plan = resolver.resolve("npm", {"p1": "1.0.0"}, lambda n: db.get(n))
    assert len(single_plan.packages) == 1


# Finding 14: python/hermetic_ecosystem_cut/resolver.py:291-293
def test_resolver_propagates_runtime_reachability_after_build_visit():
    """Verify that a package reached for build first is expanded for runtime when reached by runtime."""
    resolver = CutoffResolver(CUTOFF, include_build_dependencies=True)

    # root depends on tool (build) and helper (runtime)
    # tool depends on helper (normal)
    # helper depends on deep-dep (normal)
    root = {
        "packument": {
            "name": "root",
            "versions": {
                "1.0.0": {
                    "name": "root",
                    "version": "1.0.0",
                    "dependencies": {"helper": "1.0.0"},
                    "devDependencies": {"tool": "1.0.0"},
                },
            },
            "time": {"1.0.0": PAST},
        },
        "artifacts": {"1.0.0": b"r"},
    }
    tool = {
        "packument": {
            "name": "tool",
            "versions": {
                "1.0.0": {
                    "name": "tool",
                    "version": "1.0.0",
                    "dependencies": {"helper": "1.0.0"},
                },
            },
            "time": {"1.0.0": PAST},
        },
        "artifacts": {"1.0.0": b"t"},
    }
    helper = {
        "packument": {
            "name": "helper",
            "versions": {
                "1.0.0": {
                    "name": "helper",
                    "version": "1.0.0",
                    "dependencies": {"deep-dep": "1.0.0"},
                },
            },
            "time": {"1.0.0": PAST},
        },
        "artifacts": {"1.0.0": b"h"},
    }
    deep = {
        "packument": {
            "name": "deep-dep",
            "versions": {
                "1.0.0": {"name": "deep-dep", "version": "1.0.0"},
            },
            "time": {"1.0.0": PAST},
        },
        "artifacts": {"1.0.0": b"d"},
    }

    db = {"root": root, "tool": tool, "helper": helper, "deep-dep": deep}
    plan = resolver.resolve("npm", {"root": "1.0.0"}, lambda n: db.get(n))

    assert "helper" in plan.runtime_dependencies
    # deep-dep must also be in runtime_dependencies
    assert "deep-dep" in plan.runtime_dependencies


# Finding 15: python/hermetic_ecosystem_cut/resolver.py:430-432
def test_resolver_go_binds_publication_timestamp_to_version():
    """Verify that Go resolver verifies source info Version matches ver before using Time."""
    resolver = CutoffResolver(CUTOFF)

    # Info for v1.2.3 fraudulently contains Version: v1.2.2 with a PAST time
    pkg_go = {
        "list": "v1.2.3\n",
        "infos": {
            "v1.2.3": json.dumps({"Version": "v1.2.2", "Time": PAST}),
        },
        "artifacts": {
            "v1.2.3.mod": b"module example.org/testmod\n\ngo 1.18\n",
            "v1.2.3.zip": _make_zip({"a.go": b"package test\n"}, prefix="example.org/testmod@v1.2.3/"),
        },
    }

    plan = resolver.resolve("go", {"example.org/testmod": "v1.2.3"}, lambda n: pkg_go)
    # Must NOT admit v1.2.3 with mismatched info version
    assert len(plan.packages) == 0
    assert len(plan.unresolved) == 1


# Finding 16: python/hermetic_ecosystem_cut/resolver.py:141-146
def test_satisfies_req_ecosystem_specific_rules():
    """Verify ecosystem-specific version requirement rules."""
    # Cargo: bare version is caret compatible (1.2.3 matches 1.3.0)
    assert satisfies_req("1.3.0", "1.2.3", ecosystem="crates")
    assert not satisfies_req("2.0.0", "1.2.3", ecosystem="crates")

    # npm: wildcards like 1.2.x match
    assert satisfies_req("1.2.3", "1.2.x", ecosystem="npm")
    assert not satisfies_req("1.3.0", "1.2.x", ecosystem="npm")

    # npm: prerelease versions excluded unless requirement opts in
    assert not satisfies_req("1.2.3-alpha.1", "^1.2.0", ecosystem="npm")
    assert satisfies_req("1.2.3-alpha.1", "^1.2.3-alpha", ecosystem="npm")

    # Go: v prefix on requirement and candidate
    assert satisfies_req("v1.2.3", "v1.2.3", ecosystem="go")
    assert satisfies_req("v1.3.0", ">=v1.2.0", ecosystem="go")


# Finding 17: python/hermetic_ecosystem_cut/provenance.py:108-109
def test_go_zip_h1_caps_aggregate_uncompressed_size():
    """Verify that compute_go_zip_h1 refuses archives exceeding aggregate uncompressed size cap."""
    import struct
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("example.org/bomb@v1.0.0/big.txt", b"x")
    raw = bytearray(bio.getvalue())
    cd_sig = b"PK\x01\x02"
    cd_pos = raw.find(cd_sig)
    assert cd_pos != -1
    raw[cd_pos + 24 : cd_pos + 28] = struct.pack("<I", MAX_UNCOMPRESSED_ZIP_BYTES + 1)

    with pytest.raises(ProvenanceError, match="uncompressed size exceeds cap"):
        compute_go_zip_h1(bytes(raw), "example.org/bomb", "v1.0.0")


# Finding 18: python/hermetic_ecosystem_cut/provenance.py:45
def test_go_mod_h1_matches_official_go_format():
    """Verify that compute_go_mod_h1 uses Go's dirhash.Hash1 format (<hex>  go.mod\\n)."""
    mod_bytes = b"module example.org/canonical\n\ngo 1.18\n"
    file_hex = hashlib.sha256(mod_bytes).hexdigest()
    summary_line = f"{file_hex}  go.mod\n".encode("utf-8")
    expected_h1 = "h1:" + base64.b64encode(hashlib.sha256(summary_line).digest()).decode("ascii")

    actual_h1 = compute_go_mod_h1(mod_bytes)
    assert actual_h1 == expected_h1

    # Verify it does NOT equal raw byte sha256
    raw_h1 = "h1:" + base64.b64encode(hashlib.sha256(mod_bytes).digest()).decode("ascii")
    assert actual_h1 != raw_h1


# Finding 19: python/hermetic_ecosystem_cut/resolver.py:395
def test_resolver_resolution_plan_carries_metadata_blobs():
    """Verify that ResolutionPlan carries all generated metadata blobs referenced by to_recipe()."""
    resolver = CutoffResolver(CUTOFF)
    tar_bytes = b"\x1f\x8b\x08" + b"\x00" * 20
    pkg = {
        "packument": {
            "name": "carried-blobs-pkg",
            "versions": {
                "1.0.0": {
                    "name": "carried-blobs-pkg",
                    "version": "1.0.0",
                    "dist": {"shasum": hashlib.sha1(tar_bytes).hexdigest()},
                },
            },
            "time": {"1.0.0": PAST},
        },
        "artifacts": {"1.0.0": tar_bytes},
    }

    plan = resolver.resolve("npm", {"carried-blobs-pkg": "1.0.0"}, lambda n: pkg)
    assert not plan.unresolved
    assert plan.blobs

    recipe = plan.to_recipe()
    # Artifact blobs from input
    art_blobs = {p.artifacts[v]: tar_bytes for p in plan.packages for v in p.artifacts}

    # build_mirror should succeed when provided plan.blobs + artifact blobs
    all_blobs = {**plan.blobs, **art_blobs}
    raw_recipe = json.dumps(recipe).encode("utf-8")
    store = build_mirror(raw_recipe, all_blobs)
    assert store is not None
    files_map = dict(store.files)
    assert "registry.npmjs.org/carried-blobs-pkg/index.html" in files_map
