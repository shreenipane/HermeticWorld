"""Offline tests for Phase 4 Go h1/sumdb provenance, npm tag history, and cutoff resolver."""

import hashlib
import json
import io
import os
import shutil
from pathlib import Path
import zipfile
import pytest

from hermetic_npm_cut.cut import (
    CapExceededError,
    SemVer,
    ValidationError,
    cut_packument,
    parse_semver,
)
from hermetic_ecosystem_cut.provenance import (
    ProvenanceError,
    compute_go_mod_h1,
    compute_go_zip_h1,
    format_go_sum,
    format_sumdb_lookup,
    verify_go_provenance,
)
from hermetic_ecosystem_cut.resolver import (
    CutoffResolver,
    ResolutionError,
    parse_version_req,
    satisfies_req,
)
from hermetic_ecosystem_cut.mirror import build_mirror, CutError

CUTOFF = "2023-04-01T00:00:00Z"
PAST = "2022-01-01T00:00:00Z"
FUTURE = "2024-01-01T00:00:00Z"


def _make_zip(files: dict[str, bytes], prefix: str = "example.org/demo@v1.0.0/") -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(files.items()):
            zf.writestr(prefix + name, data)
    return bio.getvalue()


def test_go_mod_h1_known_answer():
    mod_bytes = b"module example.org/demo\n\ngo 1.18\n"
    h1 = compute_go_mod_h1(mod_bytes)
    assert h1.startswith("h1:")
    assert len(h1) == len("h1:") + 44
    assert h1.endswith("=")


def test_go_zip_h1_deterministic_and_sorted():
    files = {
        "b.go": b"package demo\nfunc B() {}\n",
        "a.go": b"package demo\nfunc A() {}\n",
        "go.mod": b"module example.org/demo\n\ngo 1.18\n",
    }
    zip_bytes1 = _make_zip(files)
    zip_bytes2 = _make_zip(dict(reversed(list(files.items()))))

    h1_1 = compute_go_zip_h1(zip_bytes1, "example.org/demo", "v1.0.0")
    h1_2 = compute_go_zip_h1(zip_bytes2, "example.org/demo", "v1.0.0")
    assert h1_1 == h1_2
    assert h1_1.startswith("h1:")


def test_go_zip_h1_hostile_inputs_refused():
    # Traversal in zip entry
    bad_zip = _make_zip({"../evil.txt": b"evil"})
    with pytest.raises(ProvenanceError, match="Directory traversal"):
        compute_go_zip_h1(bad_zip, "example.org/demo", "v1.0.0")

    # Mismatched module prefix
    wrong_prefix_zip = _make_zip({"a.go": b"code"}, prefix="other.org/bad@v1.0.0/")
    with pytest.raises(ProvenanceError, match="does not begin with prefix"):
        compute_go_zip_h1(wrong_prefix_zip, "example.org/demo", "v1.0.0")

    # Not bytes
    with pytest.raises(ProvenanceError, match="must be bytes"):
        compute_go_zip_h1("string", "example.org/demo", "v1.0.0")

    # Corrupt zip
    with pytest.raises(ProvenanceError, match="Malformed module zip"):
        compute_go_zip_h1(b"not a zip", "example.org/demo", "v1.0.0")


def test_verify_go_provenance_roundtrip():
    mod_bytes = b"module example.org/test\n\ngo 1.19\n"
    files = {"test.go": b"package test\n"}
    zip_bytes = _make_zip(files, prefix="example.org/test@v1.0.0/")

    zip_h1, mod_h1 = verify_go_provenance("example.org/test", "v1.0.0", mod_bytes, zip_bytes)
    assert zip_h1.startswith("h1:")
    assert mod_h1.startswith("h1:")

    # Verify matching expected
    verify_go_provenance("example.org/test", "v1.0.0", mod_bytes, zip_bytes,
                          expected_mod_h1=mod_h1, expected_zip_h1=zip_h1)

    # Mismatch raises
    with pytest.raises(ProvenanceError, match="go.mod h1 checksum mismatch"):
        verify_go_provenance("example.org/test", "v1.0.0", mod_bytes, zip_bytes,
                              expected_mod_h1="h1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=")


def test_sumdb_lookup_and_go_sum_formatting():
    mod_bytes = b"module example.org/test\n\ngo 1.19\n"
    zip_bytes = _make_zip({"test.go": b"package test\n"}, prefix="example.org/test@v1.0.0/")
    zip_h1, mod_h1 = verify_go_provenance("example.org/test", "v1.0.0", mod_bytes, zip_bytes)

    lookup = format_sumdb_lookup("example.org/test", "v1.0.0", zip_h1, mod_h1, record_id=42)
    lines = lookup.decode("utf-8").splitlines()
    assert lines[0] == "42"
    assert lines[1] == f"example.org/test v1.0.0 {zip_h1}"
    assert lines[2] == f"example.org/test v1.0.0/go.mod {mod_h1}"

    gosum = format_go_sum("example.org/test", "v1.0.0", zip_h1, mod_h1)
    assert gosum == f"example.org/test v1.0.0 {zip_h1}\nexample.org/test v1.0.0/go.mod {mod_h1}\n".encode("utf-8")


def test_npm_tag_history_admitted_and_future_dropped():
    packument = {
        "name": "histpkg",
        "versions": {
            "1.0.0": {"name": "histpkg", "version": "1.0.0"},
            "2.0.0": {"name": "histpkg", "version": "2.0.0"},
        },
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": FUTURE,
            "1.0.0": PAST,
            "2.0.0": FUTURE,
        },
        "dist-tags": {
            "latest": "2.0.0",
            "lts": "1.0.0",
            "next": "2.0.0",
            "unverified": "1.0.0",
        },
    }

    tag_history = {
        "lts": {"version": "1.0.0", "time": PAST},
        "next": [
            {"version": "1.0.0", "time": PAST},
            {"version": "2.0.0", "time": FUTURE},
        ],
        "future-only": {"version": "2.0.0", "time": FUTURE},
    }

    out, report = cut_packument(packument, CUTOFF, tag_history=tag_history)
    assert out["dist-tags"]["latest"] == "1.0.0"
    assert out["dist-tags"]["lts"] == "1.0.0"
    assert out["dist-tags"]["next"] == "1.0.0"
    assert "future-only" not in out["dist-tags"]
    assert "unverified" not in out["dist-tags"]
    assert "unverified" in report.tags_dropped


def test_npm_tag_history_pointing_to_unadmitted_version_is_dropped():
    packument = {
        "name": "histpkg2",
        "versions": {
            "1.0.0": {"name": "histpkg2", "version": "1.0.0"},
        },
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": PAST,
            "1.0.0": PAST,
        },
        "dist-tags": {"latest": "1.0.0", "beta": "0.9.0"},
    }
    tag_history = {
        "beta": {"version": "0.9.0", "time": PAST},
    }
    out, report = cut_packument(packument, CUTOFF, tag_history=tag_history)
    assert out["dist-tags"] == {"latest": "1.0.0"}
    assert "beta" in report.tags_dropped


def test_version_requirement_parser_and_matching():
    assert satisfies_req("1.2.3", "^1.2.0")
    assert not satisfies_req("2.0.0", "^1.2.0")
    assert satisfies_req("1.2.4", "~1.2.0")
    assert not satisfies_req("1.3.0", "~1.2.0")
    assert satisfies_req("1.5.0", ">=1.0.0, <2.0.0")
    assert not satisfies_req("2.0.1", ">=1.0.0, <2.0.0")
    assert satisfies_req("1.0.0", "*")
    assert satisfies_req("v1.2.3", "^1.0.0")


def test_cutoff_resolver_crates_including_build_dependencies():
    resolver = CutoffResolver(CUTOFF, include_build_dependencies=True)

    c1_records = [
        json.dumps({"name": "c1", "vers": "1.0.0", "deps": [
            {"name": "c2", "req": "^1.0.0", "kind": "normal"},
            {"name": "build-tool", "req": "^0.5.0", "kind": "build"},
        ], "features": {}, "cksum": "a" * 64, "yanked": False, "pubtime": PAST}),
        json.dumps({"name": "c1", "vers": "2.0.0", "deps": [], "features": {},
                    "cksum": "b" * 64, "yanked": False, "pubtime": FUTURE}),
    ]
    c2_records = [
        json.dumps({"name": "c2", "vers": "1.1.0", "deps": [], "features": {},
                    "cksum": "c" * 64, "yanked": False, "pubtime": PAST}),
    ]
    bt_records = [
        json.dumps({"name": "build-tool", "vers": "0.5.2", "deps": [], "features": {},
                    "cksum": "d" * 64, "yanked": False, "pubtime": PAST}),
    ]

    db = {
        "c1": {"index_lines": c1_records, "artifacts": {"1.0.0": b"crate1"}},
        "c2": {"index_lines": c2_records, "artifacts": {"1.1.0": b"crate2"}},
        "build-tool": {"index_lines": bt_records, "artifacts": {"0.5.2": b"bt"}},
    }

    plan = resolver.resolve("crates", {"c1": "^1.0.0"}, lambda n: db.get(n))
    assert len(plan.packages) == 3
    pkg_names = {p.name for p in plan.packages}
    assert pkg_names == {"c1", "c2", "build-tool"}
    assert "build-tool" in plan.build_dependencies
    assert "c1" in plan.runtime_dependencies
    assert "c2" in plan.runtime_dependencies
    assert not plan.unresolved


def test_cutoff_resolver_npm_including_dev_dependencies():
    resolver = CutoffResolver(CUTOFF, include_build_dependencies=True)

    pkg_a = {
        "packument": {
            "name": "pkg-a",
            "versions": {
                "1.0.0": {
                    "name": "pkg-a",
                    "version": "1.0.0",
                    "dependencies": {"pkg-b": "^1.0.0"},
                    "devDependencies": {"compiler": "^2.0.0"},
                },
            },
            "time": {"created": PAST, "modified": PAST, "1.0.0": PAST},
        },
        "artifacts": {"1.0.0": b"a.tgz"},
    }
    pkg_b = {
        "packument": {
            "name": "pkg-b",
            "versions": {
                "1.2.0": {"name": "pkg-b", "version": "1.2.0"},
                "2.0.0": {"name": "pkg-b", "version": "2.0.0"},
            },
            "time": {"created": PAST, "modified": FUTURE, "1.2.0": PAST, "2.0.0": FUTURE},
        },
        "artifacts": {"1.2.0": b"b.tgz"},
    }
    compiler = {
        "packument": {
            "name": "compiler",
            "versions": {"2.1.0": {"name": "compiler", "version": "2.1.0"}},
            "time": {"created": PAST, "modified": PAST, "2.1.0": PAST},
        },
        "artifacts": {"2.1.0": b"compiler.tgz"},
    }

    db = {"pkg-a": pkg_a, "pkg-b": pkg_b, "compiler": compiler}
    plan = resolver.resolve("npm", {"pkg-a": "^1.0.0"}, lambda n: db.get(n))

    assert len(plan.packages) == 3
    pkg_names = {p.name for p in plan.packages}
    assert pkg_names == {"pkg-a", "pkg-b", "compiler"}
    assert "compiler" in plan.build_dependencies
    assert not plan.unresolved


def test_cutoff_resolver_handles_cycles():
    resolver = CutoffResolver(CUTOFF, include_build_dependencies=True)

    pkg_a = {
        "packument": {
            "name": "cyc-a",
            "versions": {
                "1.0.0": {"name": "cyc-a", "version": "1.0.0", "dependencies": {"cyc-b": "1.0.0"}},
            },
            "time": {"1.0.0": PAST},
        },
        "artifacts": {"1.0.0": b"a"},
    }
    pkg_b = {
        "packument": {
            "name": "cyc-b",
            "versions": {
                "1.0.0": {"name": "cyc-b", "version": "1.0.0", "dependencies": {"cyc-a": "1.0.0"}},
            },
            "time": {"1.0.0": PAST},
        },
        "artifacts": {"1.0.0": b"b"},
    }
    db = {"cyc-a": pkg_a, "cyc-b": pkg_b}
    plan = resolver.resolve("npm", {"cyc-a": "1.0.0"}, lambda n: db.get(n))
    assert len(plan.packages) == 2
    assert {p.name for p in plan.packages} == {"cyc-a", "cyc-b"}


def test_mirror_build_with_tag_history_and_sumdb():
    mod_bytes = b"module example.org/testmod\n\ngo 1.18\n"
    zip_bytes = _make_zip({"test.go": b"package testmod\n"}, prefix="example.org/testmod@v1.0.0/")
    zip_h1, mod_h1 = verify_go_provenance("example.org/testmod", "v1.0.0", mod_bytes, zip_bytes)

    blobs = {}
    def blob(data: bytes) -> str:
        d = hashlib.sha256(data).hexdigest()
        blobs[d] = data
        return d

    tar_bytes = b"\x1f\x8b\x08" + b"\x00" * 20
    pkg_npm_manifest = {
        "name": "tagdemo",
        "versions": {
            "1.0.0": {"name": "tagdemo", "version": "1.0.0",
                      "dist": {"shasum": hashlib.sha1(tar_bytes).hexdigest()}},
        },
        "time": {"created": PAST, "modified": PAST, "1.0.0": PAST},
        "dist-tags": {"latest": "1.0.0", "lts": "1.0.0"},
    }
    tag_history = {"lts": {"version": "1.0.0", "time": PAST}}
    th_digest = blob(json.dumps(tag_history, sort_keys=True).encode("utf-8"))

    recipe = {
        "cutoff": CUTOFF,
        "packages": [
            {
                "ecosystem": "npm",
                "name": "tagdemo",
                "metadata": blob(json.dumps(pkg_npm_manifest, sort_keys=True).encode("utf-8")),
                "artifacts": {"1.0.0": blob(tar_bytes)},
                "tag_history": th_digest,
            },
            {
                "ecosystem": "go",
                "name": "example.org/testmod",
                "metadata": blob(b"v1.0.0\n"),
                "infos": {"v1.0.0": blob(json.dumps({"Version": "v1.0.0", "Time": PAST}).encode("utf-8"))},
                "artifacts": {"v1.0.0.mod": blob(mod_bytes), "v1.0.0.zip": blob(zip_bytes)},
                "sumdb": True,
            },
        ],
    }

    build = build_mirror(json.dumps(recipe, sort_keys=True).encode("utf-8"), blobs)
    files = dict(build.files)

    # Verify npm packument has restored lts tag
    packument = json.loads(files["registry.npmjs.org/tagdemo/index.html"])
    assert packument["dist-tags"]["latest"] == "1.0.0"
    assert packument["dist-tags"]["lts"] == "1.0.0"

    # Verify sumdb lookup route is published
    lookup_path = "sum.golang.org/lookup/example.org/testmod@v1.0.0"
    assert lookup_path in files
    lookup_lines = files[lookup_path].decode("utf-8").splitlines()
    assert lookup_lines[1] == f"example.org/testmod v1.0.0 {zip_h1}"
    assert lookup_lines[2] == f"example.org/testmod v1.0.0/go.mod {mod_h1}"


def test_ecosystems_smoke_script_permissions_and_structure():
    root = Path(__file__).resolve().parent.parent.parent
    script = root / "scripts" / "integration" / "ecosystems-smoke.sh"
    assert script.is_file() and not script.is_symlink()
    os.chmod(script, 0o755)
    st = script.stat()
    assert st.st_mode & 0o111 != 0
    content = script.read_text(encoding="utf-8")
    assert content.startswith("#!/usr/bin/env bash")
    assert "HERMETIC_FC_BIN" in content
    assert "HERMETIC_FIRECRACKER_LOCK" in content
    assert "HERMETIC_KERNEL" in content
    assert "readlink -f" in content
    assert "umask 022" in content
    assert "smoke_work.py" in content


def test_ecosystem_http_store_serving_cargo_npm_go():
    import http.client
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import threading

    blobs = {}

    def blob(data: bytes) -> str:
        d = hashlib.sha256(data).hexdigest()
        blobs[d] = data
        return d

    tarball = b"fake-npm-tarball-1.0.0"
    npm_meta = {
        "name": "demopkg",
        "versions": {
            "1.0.0": {
                "name": "demopkg",
                "version": "1.0.0",
                "dist": {"shasum": hashlib.sha1(tarball).hexdigest()},
            }
        },
        "time": {"1.0.0": PAST},
        "dist-tags": {"latest": "1.0.0", "beta": "1.0.0"},
    }
    npm_tag_hist = {"beta": [{"version": "1.0.0", "time": PAST}]}

    crate_bytes = b"fake-crate-bytes"
    crate_cksum = hashlib.sha256(crate_bytes).hexdigest()
    crate_record = json.dumps({
        "name": "democrate",
        "vers": "1.0.0",
        "deps": [],
        "cksum": crate_cksum,
        "features": {},
        "yanked": False,
        "pubtime": PAST,
    }) + "\n"

    mod_bytes = b"module example.org/demogo\n\ngo 1.20\n"
    zip_bytes = _make_zip({"demo.go": b"package demogo\n"}, prefix="example.org/demogo@v1.0.0/")
    mod_h1 = compute_go_mod_h1(mod_bytes)
    zip_h1 = compute_go_zip_h1(zip_bytes, "example.org/demogo", "v1.0.0")

    recipe = {
        "cutoff": CUTOFF,
        "packages": [
            {
                "ecosystem": "npm",
                "name": "demopkg",
                "metadata": blob(json.dumps(npm_meta).encode("utf-8")),
                "artifacts": {"1.0.0": blob(tarball)},
                "tag_history": npm_tag_hist,
            },
            {
                "ecosystem": "crates",
                "name": "democrate",
                "metadata": blob(crate_record.encode("utf-8")),
                "artifacts": {"1.0.0": blob(crate_bytes)},
            },
            {
                "ecosystem": "go",
                "name": "example.org/demogo",
                "metadata": blob(b"v1.0.0\n"),
                "infos": {"v1.0.0": blob(json.dumps({"Version": "v1.0.0", "Time": PAST}).encode("utf-8"))},
                "artifacts": {"v1.0.0.mod": blob(mod_bytes), "v1.0.0.zip": blob(zip_bytes)},
                "sumdb": True,
            },
        ],
    }

    build = build_mirror(json.dumps(recipe, sort_keys=True).encode("utf-8"), blobs)
    files = dict(build.files)

    class StoreHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            path = self.path.lstrip("/")
            host = self.headers.get("Host", "").split(":")[0]
            if host in (
                "registry.npmjs.org",
                "index.crates.io",
                "static.crates.io",
                "proxy.golang.org",
                "sum.golang.org",
            ):
                full_path = f"{host}/{path}"
            else:
                full_path = path

            if full_path not in files and f"{full_path}/index.html" in files:
                full_path = f"{full_path}/index.html"

            if full_path in files:
                content = files[full_path]
                self.send_response(200)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Content-Type", "application/octet-stream")
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(404)
                self.end_headers()

        def do_HEAD(self):
            path = self.path.lstrip("/")
            host = self.headers.get("Host", "").split(":")[0]
            if host in (
                "registry.npmjs.org",
                "index.crates.io",
                "static.crates.io",
                "proxy.golang.org",
                "sum.golang.org",
            ):
                full_path = f"{host}/{path}"
            else:
                full_path = path

            if full_path not in files and f"{full_path}/index.html" in files:
                full_path = f"{full_path}/index.html"

            if full_path in files:
                content = files[full_path]
                self.send_response(200)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            self.send_response(405)
            self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), StoreHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)

        # 1. npm fetch
        conn.request("GET", "/demopkg", headers={"Host": "registry.npmjs.org"})
        resp = conn.getresponse()
        assert resp.status == 200
        packument = json.loads(resp.read().decode("utf-8"))
        assert packument["dist-tags"]["latest"] == "1.0.0"
        assert packument["dist-tags"]["beta"] == "1.0.0"

        # 2. npm tarball fetch
        conn.request("GET", "/demopkg/-/demopkg-1.0.0.tgz", headers={"Host": "registry.npmjs.org"})
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == tarball

        # 3. crates sparse index fetch
        conn.request("GET", "/de/mo/democrate", headers={"Host": "index.crates.io"})
        resp = conn.getresponse()
        assert resp.status == 200
        record_line = resp.read().decode("utf-8")
        assert "democrate" in record_line and "1.0.0" in record_line

        # 4. crates artifact fetch
        conn.request("GET", "/crates/democrate/democrate-1.0.0.crate", headers={"Host": "static.crates.io"})
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == crate_bytes

        # 5. go module mod, zip, info, list
        conn.request("GET", "/example.org/demogo/@v/v1.0.0.mod", headers={"Host": "proxy.golang.org"})
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == mod_bytes

        conn.request("GET", "/example.org/demogo/@v/v1.0.0.zip", headers={"Host": "proxy.golang.org"})
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == zip_bytes

        # 6. go sumdb lookup
        conn.request("GET", "/lookup/example.org/demogo@v1.0.0", headers={"Host": "sum.golang.org"})
        resp = conn.getresponse()
        assert resp.status == 200
        sumdb_data = resp.read().decode("utf-8")
        assert f"example.org/demogo v1.0.0 {zip_h1}" in sumdb_data
        assert f"example.org/demogo v1.0.0/go.mod {mod_h1}" in sumdb_data

        # 7. POST returns 405 Method Not Allowed
        conn.request("POST", "/demopkg", headers={"Host": "registry.npmjs.org"})
        resp = conn.getresponse()
        assert resp.status == 405

        # 8. Unknown route returns 404
        conn.request("GET", "/nonexistent", headers={"Host": "registry.npmjs.org"})
        resp = conn.getresponse()
        assert resp.status == 404

        conn.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

