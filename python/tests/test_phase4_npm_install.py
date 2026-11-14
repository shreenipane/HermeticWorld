"""Install a transitive closure from exact frozen bytes using an isolated npm."""

from contextlib import contextmanager
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import shutil
import subprocess
import tarfile
import threading
from urllib.parse import unquote

import pytest

from hermetic_ecosystem_cut.mirror import build_mirror

MAX_INSTALL_SECONDS = 30
MAX_REQUESTS = 64
MAX_REQUEST_PATH_BYTES = 1024
MAX_SOCKET_SECONDS = 2
MAX_THREAD_SECONDS = 5
MAX_FIXTURE_ARTIFACT_BYTES = 256 * 1024
CUTOFF = "2023-04-01T00:00:00Z"


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def archive(manifest):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as bundle:
        for name, body in sorted({"package.json": encode(manifest),
                                  "index.js": b"module.exports = 1;\n"}.items()):
            entry = tarfile.TarInfo("package/" + name)
            entry.mode = 0o644
            entry.size = len(body)
            bundle.addfile(entry, io.BytesIO(body))
    result = gzip.compress(raw.getvalue(), mtime=0)
    assert len(result) <= MAX_FIXTURE_ARTIFACT_BYTES
    return result


def frozen_closure():
    blobs, packages = {}, []

    def blob(raw):
        digest = hashlib.sha256(raw).hexdigest()
        blobs[digest] = raw
        return digest

    for name in ("@fixture/root", "@fixture/dep"):
        versions, times, artifacts = {}, {}, {}
        for version, date in (("1.0.0", CUTOFF), ("2.0.0", "2024-01-01T00:00:00Z"),
                              ("3.0.0", None)):
            manifest = {"name": name, "version": version, "main": "index.js",
                        "scripts": {"preinstall": 'node -e "process.exit(42)"'}}
            if name == "@fixture/root":
                manifest["dependencies"] = {"@fixture/dep": ">=1.0.0"}
            body = archive(manifest)
            artifacts[version] = blob(body)
            versions[version] = dict(manifest, dist={"shasum": hashlib.sha1(body).hexdigest()})
            times[version] = date
        packages.append(dict(ecosystem="npm", name=name, artifacts=artifacts,
                             metadata=blob(encode(dict(name=name, versions=versions, time=times)))))
    return build_mirror(encode(dict(cutoff=CUTOFF, packages=packages)), blobs)


@contextmanager
def serve(build):
    files, requests = dict(build.files), []

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(MAX_SOCKET_SECONDS)

        def log_message(self, *args):
            pass

        def do_GET(self):
            if len(requests) >= MAX_REQUESTS or len(self.path) > MAX_REQUEST_PATH_BYTES:
                self.send_response_only(429)
                self.end_headers()
                return
            path = unquote(self.path)
            requests.append(path)
            route = "registry.npmjs.org" + path
            if route not in files:
                route += "/index.html"
            body = files.get(route)
            self.send_response_only(200 if body is not None else 404)
            if body is not None:
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.end_headers()

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port, requests
        finally:
            server.shutdown()
            thread.join(MAX_THREAD_SECONDS)
            assert not thread.is_alive()


@pytest.mark.skipif(shutil.which("npm") is None or shutil.which("node") is None,
                    reason="offline npm integration requires local npm and node executables")
def test_frozen_npm_transitive_install_excludes_future_and_unknown_releases(tmp_path):
    build = frozen_closure()
    # Refuse every socket destination except this test's local listener, even if
    # npm attempts to use an unexpected URL. No external DNS or proxy is needed.
    guard = tmp_path / "network.cjs"
    guard.write_text("""
const net = require('node:net');
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function(...args) {
  const options = Array.isArray(args[0]) ? args[0][0] : args[0];
  if (!options || typeof options !== 'object' || options.host !== '127.0.0.1'
      || Number(options.port) !== Number(process.env.FIXTURE_PORT)) {
    throw new Error('fixture refused network destination');
  }
  return connect.apply(this, args);
};
""")
    home = tmp_path / "home"
    home.mkdir()
    user_config, global_config = tmp_path / "user.npmrc", tmp_path / "global.npmrc"
    user_config.write_bytes(b"")
    global_config.write_bytes(b"")
    # An explicit environment prevents host npm configuration, credentials and
    # proxy settings from entering the client or the frozen package bytes.
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(tmp_path),
           "NODE_OPTIONS": "--require=" + str(guard), "LANG": "C", "TZ": "UTC"}
    with serve(build) as (port, requests):
        env["FIXTURE_PORT"] = str(port)
        node, npm = shutil.which("node"), shutil.which("npm")
        for host in ("example.invalid", "192.0.2.1"):
            denied = subprocess.run([node, "-e", "require('node:net').connect({host:process.argv[1],"
                                     "port:Number(process.env.FIXTURE_PORT)})", host],
                                    cwd=tmp_path, env=env, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=MAX_INSTALL_SECONDS)
            assert denied.returncode != 0
        result = subprocess.run([
            npm, "install", "@fixture/root@*", "--ignore-scripts", "--no-audit", "--no-fund",
            "--update-notifier=false", "--fetch-retries=0", "--fetch-timeout=5000",
            "--logs-max=0", "--loglevel=silent", "--replace-registry-host=always",
            "--registry=http://127.0.0.1:" + str(port), "--cache=" + str(tmp_path / "cache"),
            "--userconfig=" + str(user_config), "--globalconfig=" + str(global_config),
        ], cwd=tmp_path, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
           timeout=MAX_INSTALL_SECONDS)
        assert result.returncode == 0, "frozen npm closure installation failed"
    files = dict(build.files)
    lock = json.loads((tmp_path / "package-lock.json").read_bytes())
    for leaf in ("root", "dep"):
        installed = json.loads((tmp_path / f"node_modules/@fixture/{leaf}/package.json").read_bytes())
        assert installed["version"] == "1.0.0"
        assert lock["packages"][f"node_modules/@fixture/{leaf}"]["integrity"] == json.loads(
            files[f"registry.npmjs.org/@fixture/{leaf}/1.0.0"])["dist"]["integrity"]
        assert f"/@fixture/{leaf}" in requests
        assert f"/@fixture/{leaf}/-/{leaf}-1.0.0.tgz" in requests
    assert all("2.0.0" not in path and "3.0.0" not in path for path in requests)
