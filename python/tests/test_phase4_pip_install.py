"""Install deterministic wheels and their transitive closure with an offline pip."""

import base64
import csv
import hashlib
import io
import json
import subprocess
import sys
import zipfile

from hermetic_ecosystem_cut.install import build_install_configs
from hermetic_ecosystem_cut.mirror import build_mirror

MAX_INSTALL_SECONDS = 30
MAX_FIXTURE_ARTIFACT_BYTES = 256 * 1024
CUTOFF = "2023-04-01T00:00:00Z"


def wheel(name, version):
    distribution = name.replace("-", "_")
    info = f"{distribution}-{version}.dist-info"
    dependency = "Requires-Dist: fixture-dep (>=1)\n" if name == "fixture-root" else ""
    module = f'__version__ = "{version}"\n'
    if name == "fixture-root":
        module += 'from fixture_dep import __version__ as dependency_version\n'
    files = {distribution + "/__init__.py": module.encode(),
             info + "/METADATA": (f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
                                  f"Requires-Python: >=3.8\n{dependency}\n").encode(),
             info + "/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for path, body in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip("=")
        writer.writerow((path, "sha256=" + digest, str(len(body))))
    writer.writerow((info + "/RECORD", "", ""))
    files[info + "/RECORD"] = record.getvalue().encode()
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as bundle:
        for path, body in sorted(files.items()):
            entry = zipfile.ZipInfo(path)
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            bundle.writestr(entry, body)
    raw = target.getvalue()
    assert len(raw) <= MAX_FIXTURE_ARTIFACT_BYTES
    return raw


def frozen_closure():
    blobs, packages = {}, []
    def blob(raw):
        key = hashlib.sha256(raw).hexdigest()
        blobs[key] = raw
        return key
    for name in ("fixture-root", "fixture-dep"):
        entries, artifacts = [], {}
        for version, date in (("1.0.0", CUTOFF), ("1.1.0", "2024-01-01T00:00:00Z"), ("1.2.0", None)):
            body = wheel(name, version)
            filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
            key = blob(body)
            entries.append(dict(filename=filename, size=len(body), hashes={"sha256": key},
                                **{"upload-time": date}))
            artifacts[filename] = key
        metadata = json.dumps(dict(name=name, meta={"api-version": "1.1"}, files=entries)).encode()
        packages.append(dict(ecosystem="pypi-simple", name=name, metadata=blob(metadata), artifacts=artifacts))
    return build_mirror(json.dumps(dict(cutoff=CUTOFF, packages=packages)).encode(), blobs)


def test_frozen_pip_real_offline_transitive_wheel_install(tmp_path):
    build = frozen_closure()
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    published = []
    for path, body in build.files:
        if path.endswith(".whl"):
            leaf = path.rsplit("/", 1)[-1]
            (wheels / leaf).write_bytes(body)
            published.append(leaf)
    assert sorted(published) == ["fixture_dep-1.0.0-py3-none-any.whl", "fixture_root-1.0.0-py3-none-any.whl"]
    home = tmp_path / "home"
    home.mkdir()
    config = tmp_path / "pip.conf"
    config.write_bytes(dict(build_install_configs().files)["etc/hermetic/pip.conf"])
    target = tmp_path / "installed"
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp_path), "LANG": "C", "TZ": "UTC",
           "PIP_CONFIG_FILE": str(config), "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run([
        sys.executable, "-B", "-m", "pip", "--isolated", "--disable-pip-version-check", "install",
        "--no-index", "--find-links", str(wheels), "--no-cache-dir", "--no-compile", "--ignore-installed",
        "--only-binary=:all:", "--target", str(target), "fixture-root>=1",
    ], cwd=tmp_path, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
       timeout=MAX_INSTALL_SECONDS)
    assert result.returncode == 0, "frozen offline pip installation failed"
    for name in ("fixture_root", "fixture_dep"):
        metadata = target / (name + "-1.0.0.dist-info") / "METADATA"
        assert b"Version: 1.0.0\n" in metadata.read_bytes()
    verify = subprocess.run([
        sys.executable, "-B", "-I", "-S", "-c",
        'import sys; sys.path.insert(0, sys.argv[1]); import fixture_root; '
        'assert fixture_root.__version__ == fixture_root.dependency_version == "1.0.0"', str(target),
    ], cwd=tmp_path, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
       timeout=MAX_INSTALL_SECONDS)
    assert verify.returncode == 0
