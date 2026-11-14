"""Known client policy, hash binding and hostile bundle refusal."""

import configparser
import hashlib
import json
import tomllib

import pytest

from hermetic_ecosystem_cut import CutError
from hermetic_ecosystem_cut import install


def test_install_configs_match_frozen_store_authorities_and_disable_fallbacks():
    bundle = install.build_install_configs()
    files = dict(bundle.files)
    pip = configparser.ConfigParser(interpolation=None)
    pip.read_string(files["etc/hermetic/pip.conf"].decode())
    assert pip["global"]["index-url"] == "https://pypi.org/simple/"
    assert pip["global"]["extra-index-url"] == pip["global"]["find-links"] == ""
    assert pip["global"].getboolean("disable-pip-version-check")
    npm = dict(line.split("=", 1) for line in files["etc/hermetic/npmrc"].decode().splitlines())
    assert npm["registry"] == "https://registry.npmjs.org/"
    assert npm["ignore-scripts"] == "true"
    assert npm["audit"] == npm["fund"] == npm["update-notifier"] == "false"
    cargo = tomllib.loads(files["etc/hermetic/cargo-config.toml"].decode())
    assert cargo["source"]["crates-io"]["registry"] == "sparse+https://index.crates.io/"
    assert cargo["registries"]["crates-io"]["protocol"] == "sparse"
    go = dict(line.split("=", 1) for line in files["etc/hermetic/go.env"].decode().splitlines())
    assert go["GOPROXY"] == "https://proxy.golang.org"
    assert go["GONOPROXY"] == "none" and go["GOVCS"] == "*:off"
    assert go["GOTOOLCHAIN"] == "local" and go["GOSUMDB"] == "off"
    manifest = json.loads(bundle.manifest)
    assert manifest["schema"] == "hermetic-install-configs/v1"
    assert manifest["files"] == [dict(path=path, size=len(body), sha256=hashlib.sha256(body).hexdigest())
                                 for path, body in bundle.files]
    assert install.verify_install_configs(bundle.manifest, files) == bundle


def test_install_configs_ignore_host_environment(monkeypatch):
    original = install.build_install_configs()
    for key in ("HOME", "PIP_INDEX_URL", "NPM_CONFIG_REGISTRY", "CARGO_HOME", "GOPROXY",
                "GOPRIVATE", "HTTP_PROXY", "HOSTNAME", "LANG", "TZ", "SOURCE_DATE_EPOCH"):
        monkeypatch.setenv(key, "host-secret")
    assert install.build_install_configs() == original
    assert b"host-secret" not in original.manifest + b"".join(dict(original.files).values())


@pytest.mark.parametrize("kind", ["path", "body", "self-signed", "missing", "extra", "type"])
def test_install_configs_refuse_hostile_bundle_before_installation(kind):
    bundle = install.build_install_configs()
    files, raw = dict(bundle.files), bundle.manifest
    first = next(iter(files))
    if kind == "path":
        files["../../host-secret"] = files.pop(first)
    elif kind in {"body", "self-signed"}:
        files[first] = b"registry=https://host-secret/\n"
        if kind == "self-signed":
            value = json.loads(raw)
            for entry in value["files"]:
                if entry["path"] == first:
                    entry.update(size=len(files[first]), sha256=hashlib.sha256(files[first]).hexdigest())
            raw = json.dumps(value).encode()
    elif kind == "missing":
        del files[first]
    elif kind == "extra":
        files["etc/secret"] = b"host-secret"
    else:
        files[first] = None
    with pytest.raises(CutError) as error:
        install.verify_install_configs(raw, files)
    assert "host-secret" not in str(error.value)


@pytest.mark.parametrize("raw", [b"null", b"{}", b"NaN", b'{"x":1,"x":2}', b"\xff"])
def test_install_configs_hostile_manifest(raw):
    with pytest.raises(CutError):
        install.verify_install_configs(raw, dict(install.build_install_configs().files))


@pytest.mark.parametrize("cap", ["MAX_CONFIG_FILES", "MAX_CONFIG_BYTES", "MAX_CONFIG_MANIFEST_BYTES"])
def test_install_configs_named_caps(monkeypatch, cap):
    monkeypatch.setattr(install, cap, 1)
    with pytest.raises(CutError):
        install.build_install_configs()
