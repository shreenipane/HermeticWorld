"""Use real offline clients with exact frozen metadata and artifact bytes."""

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib
import zipfile

import pytest

from hermetic_ecosystem_cut.mirror import build_mirror
from hermetic_ecosystem_cut.install import build_install_configs

MAX_INSTALL_SECONDS = 45
MAX_FIXTURE_ARTIFACT_BYTES = 256 * 1024
CUTOFF = "2023-04-01T00:00:00Z"
VERSIONS = (("1.0.0", CUTOFF), ("1.1.0", "2024-01-01T00:00:00Z"), ("1.2.0", None))


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def crate(version):
    target = io.BytesIO()
    files = {"Cargo.toml": f'[package]\nname="demo"\nversion="{version}"\nedition="2021"\n'.encode(),
             "src/lib.rs": f'pub fn version() -> &\'static str {{ "{version}" }}\n'.encode()}
    with tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as bundle:
        for name, body in sorted(files.items()):
            entry = tarfile.TarInfo(f"demo-{version}/" + name)
            entry.mode, entry.size = 0o644, len(body)
            bundle.addfile(entry, io.BytesIO(body))
    raw = gzip.compress(target.getvalue(), mtime=0)
    assert len(raw) <= MAX_FIXTURE_ARTIFACT_BYTES
    return raw


def mirror_fixture(kind):
    blobs, artifacts, infos, records = {}, {}, {}, []
    def blob(raw):
        key = hashlib.sha256(raw).hexdigest()
        blobs[key] = raw
        return key
    for version, date in VERSIONS:
        if kind == "crates":
            key = blob(crate(version))
            artifacts[version] = key
            records.append(encode(dict(name="demo", vers=version, deps=[], features={},
                                       cksum=key, yanked=False, pubtime=date)))
        else:
            version = "v" + version
            mod = b"module example.org/demo\n\ngo 1.18\n"
            target = io.BytesIO()
            with zipfile.ZipFile(target, mode="w", compression=zipfile.ZIP_STORED) as archive:
                for name, body in sorted({"go.mod": mod, "demo.go": (
                        f'package demo\nfunc Version() string {{ return "{version}" }}\n'.encode())}.items()):
                    entry = zipfile.ZipInfo(f"example.org/demo@{version}/" + name)
                    entry.create_system = 3
                    entry.external_attr = 0o100644 << 16
                    archive.writestr(entry, body)
            zip_body = target.getvalue()
            assert len(zip_body) <= MAX_FIXTURE_ARTIFACT_BYTES
            artifacts[version + ".mod"] = blob(mod)
            artifacts[version + ".zip"] = blob(zip_body)
            infos[version] = blob(encode(dict(Version=version, Time=date)))
            records.append(version.encode())
    package = dict(ecosystem=kind, name="demo" if kind == "crates" else "example.org/demo",
                   metadata=blob(b"\n".join(records) + b"\n"), artifacts=artifacts)
    if kind == "go":
        package["infos"] = infos
    return build_mirror(encode(dict(cutoff=CUTOFF, packages=[package])), blobs)


def cargo_toolchain():
    candidate = shutil.which("cargo")
    if candidate is None:
        return None
    # Resolve rustup shims read-only. The actual binaries can run with an empty
    # private CARGO_HOME and without consulting host rustup/user configuration.
    rustup = shutil.which("rustup")
    if rustup is not None:
        paths = []
        for tool in ("cargo", "rustc"):
            result = subprocess.run([rustup, "which", tool], stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=MAX_INSTALL_SECONDS)
            assert result.returncode == 0 and len(result.stdout) < 4096
            paths.append(os.fsdecode(result.stdout.strip()))
        return tuple(paths)
    compiler = shutil.which("rustc")
    return (candidate, compiler) if compiler is not None else None


@pytest.mark.parametrize("corrupt", [False, True])
def test_frozen_cargo_real_offline_resolution_and_verified_download(tmp_path, corrupt):
    toolchain = cargo_toolchain()
    if toolchain is None:
        pytest.skip("offline Cargo fixture requires a local Rust toolchain")
    build = mirror_fixture("crates")
    files = dict(build.files)
    registry = tmp_path / "registry"
    index = registry / "index"
    (index / "de/mo").mkdir(parents=True)
    # Cargo's filesystem local-registry layout uses the same index records and
    # crate bytes. --offline makes all HTTP and VCS requests unavailable.
    (index / "de/mo/demo").write_bytes(files["index.crates.io/de/mo/demo"])
    (index / "config.json").write_bytes(files["index.crates.io/config.json"])
    body = files["static.crates.io/crates/demo/demo-1.0.0.crate"]
    (registry / "demo-1.0.0.crate").write_bytes(body + (b"tampered" if corrupt else b""))
    home = tmp_path / "home"
    home.mkdir()
    config = home / "config.toml"
    config.write_bytes(dict(build_install_configs().files)["etc/hermetic/cargo-config.toml"])
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "Cargo.toml").write_bytes(
        b'[package]\nname="fixture"\nversion="0.1.0"\nedition="2021"\n'
        b'[dependencies]\ndemo="*"\n[workspace]\n')
    (project / "src/lib.rs").write_bytes(
        b'#[test]\nfn admitted_dependency() { assert_eq!(demo::version(), "1.0.0"); }\n')
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "CARGO_HOME": str(home),
           "CARGO_TARGET_DIR": str(tmp_path / "target"), "RUSTC": toolchain[1],
           "RUSTDOC": str(Path(toolchain[1]).with_name("rustdoc")),
           "CARGO_NET_OFFLINE": "true", "LANG": "C", "TZ": "UTC", "TMPDIR": str(tmp_path)}
    result = subprocess.run([toolchain[0], "test", "--offline", "--lib", "--quiet",
                             "--config", 'source.crates-io.replace-with="frozen"', "--config",
                             'source.frozen.local-registry=' + json.dumps(str(registry))], cwd=project,
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=MAX_INSTALL_SECONDS)
    if corrupt:
        assert result.returncode != 0, "Cargo accepted an artifact with the wrong frozen checksum"
        return
    assert result.returncode == 0, "frozen offline Cargo installation failed"
    lock = tomllib.loads((project / "Cargo.lock").read_text())
    packages = {entry["name"]: entry for entry in lock["package"]}
    assert packages["demo"]["version"] == "1.0.0"
    assert packages["demo"]["checksum"] == hashlib.sha256(body).hexdigest()
    assert all(b"1.1.0" not in data and b"1.2.0" not in data
               for path, data in build.files if not path.endswith(".crate"))


@pytest.mark.skipif(shutil.which("go") is None, reason="offline Go fixture requires a local Go toolchain")
def test_frozen_go_real_offline_latest_and_dependency_install(tmp_path):
    build = mirror_fixture("go")
    proxy = tmp_path / "proxy"
    for path, body in build.files:
        if path.startswith("proxy.golang.org/") and not path.endswith(".headers.json"):
            destination = proxy / path.removeprefix("proxy.golang.org/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
    home = tmp_path / "home"
    home.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    (project / "go.mod").write_bytes(b"module fixture.local/test\n\ngo 1.18\n")
    (project / "fixture_test.go").write_bytes(
        b'package fixture\nimport ("testing"; "example.org/demo")\n'
        b'func TestAdmitted(t *testing.T) { if demo.Version() != "v1.0.0" { t.Fatal("wrong version") } }\n')
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "GOENV": "off", "GOPATH": str(home / "go"),
           "GOCACHE": str(home / "cache"), "GOPROXY": proxy.as_uri(), "GOSUMDB": "off",
           "GONOPROXY": "none", "GONOSUMDB": "*", "GOPRIVATE": "", "GOTOOLCHAIN": "local",
           "GOVCS": "*:off", "CGO_ENABLED": "0", "LANG": "C", "TZ": "UTC", "TMPDIR": str(tmp_path)}
    for args in (["get", "example.org/demo@latest"], ["test", "./..."]):
        result = subprocess.run([shutil.which("go"), *args], cwd=project, env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=MAX_INSTALL_SECONDS)
        assert result.returncode == 0, "frozen offline Go installation failed"
    assert b"example.org/demo v1.0.0" in (project / "go.mod").read_bytes()
    sums = (project / "go.sum").read_bytes()
    assert b"example.org/demo v1.0.0 h1:" in sums
    assert b"example.org/demo v1.0.0/go.mod h1:" in sums
    assert b"v1.1.0" not in sums and b"v1.2.0" not in sums
