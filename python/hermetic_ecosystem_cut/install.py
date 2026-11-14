"""Deterministic guest client configuration for the frozen WorldServer store.

The authorities are the store's protocol authorities. NetVM intercepts them;
WorldServer is a framed service, not a forward HTTP proxy or a live registry.
The rootfs assembler must install these files and isolate client environment,
home, cache and project configuration. These files are not a network boundary.
"""

from dataclasses import dataclass
import hashlib

from .cut import CutError, _encode
from .mirror import _json

MAX_CONFIG_FILES = 4
MAX_CONFIG_BYTES = 16 * 1024
MAX_CONFIG_MANIFEST_BYTES = 4096


@dataclass(frozen=True)
class InstallConfigs:
    files: tuple[tuple[str, bytes], ...]
    manifest: bytes


def build_install_configs() -> InstallConfigs:
    """Return rootfs-relative files and a manifest binding every config byte.

    No acquisition input, host setting, credential or clock is consulted.
    Go has no direct/VCS fallback, sumdb lookup or automatic toolchain download.
    Disabling sumdb does not authenticate acquisition; go.sum checks still apply.
    """
    files = tuple(sorted({
        "etc/hermetic/pip.conf": (
            b"[global]\nindex-url = https://pypi.org/simple/\nextra-index-url =\n"
            b"find-links =\nno-cache-dir = true\ndisable-pip-version-check = true\n"
        ),
        "etc/hermetic/npmrc": (
            b"registry=https://registry.npmjs.org/\naudit=false\nfund=false\n"
            b"update-notifier=false\nignore-scripts=true\nfetch-retries=0\n"
            b"replace-registry-host=always\n"
        ),
        "etc/hermetic/cargo-config.toml": (
            b'[source.crates-io]\nregistry = "sparse+https://index.crates.io/"\n'
            b'[registries.crates-io]\nprotocol = "sparse"\n'
            b"[net]\nretry = 0\ngit-fetch-with-cli = false\n"
        ),
        "etc/hermetic/go.env": (
            b"GOPROXY=https://proxy.golang.org\nGOSUMDB=off\nGONOSUMDB=*\n"
            b"GONOPROXY=none\nGOPRIVATE=\nGOTOOLCHAIN=local\nGOVCS=*:off\n"
        ),
    }.items()))
    if len(files) > MAX_CONFIG_FILES or sum(len(body) for _, body in files) > MAX_CONFIG_BYTES:
        raise CutError("client configuration cap exceeded")
    manifest = _encode({"schema": "hermetic-install-configs/v1", "files": [
        {"path": path, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        for path, body in files]})
    if len(manifest) > MAX_CONFIG_MANIFEST_BYTES:
        raise CutError("client configuration manifest cap exceeded")
    return InstallConfigs(files, manifest)


def verify_install_configs(raw_manifest: bytes, files: dict[str, bytes]) -> InstallConfigs:
    """Validate an untrusted bundle completely before a rootfs writer uses it."""
    manifest = _json(raw_manifest, MAX_CONFIG_MANIFEST_BYTES)
    if type(files) is not dict or len(files) > MAX_CONFIG_FILES:
        raise CutError("invalid client configuration inventory")
    total = 0
    for path, body in files.items():
        if type(path) is not str or type(body) is not bytes:
            raise CutError("invalid client configuration entry")
        total += len(body)
        if total > MAX_CONFIG_BYTES:
            raise CutError("client configuration byte cap exceeded")
    expected = build_install_configs()
    # An installer accepts exactly this versioned configuration policy, rather
    # than trusting attacker-selected destinations or self-asserted hashes.
    if manifest != _json(expected.manifest, MAX_CONFIG_MANIFEST_BYTES) or files != dict(expected.files):
        raise CutError("client configuration verification failed")
    return expected
