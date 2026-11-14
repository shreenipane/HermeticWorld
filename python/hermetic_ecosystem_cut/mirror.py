"""Offline, digest-checked package store construction for WorldServer DirStore.

The recipe and content-addressed blobs are acquisition inputs, not proof of
historical provenance. Nothing is fetched. Build entirely in memory before any
publication; diagnostic inventories live outside the served store directory.
"""

import base64
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from functools import cmp_to_key
import hashlib
import json
import os
import re
import stat

from hermetic_npm_cut.cut import (
    HermeticNpmCutError, canonical_json_bytes, compare_semver, cut_packument,
    parse_json_bytes, parse_semver, read_regular_file_bounded,
)
from hermetic_safe_io import atomic_write_at, open_parent, validate_path

from .cut import CutError, _time, cut_crates_index, cut_go_versions
from .pypi import cut_pypi_json, cut_pypi_simple

MAX_RECIPE_BYTES = 4 * 1024 * 1024
MAX_PACKAGES = 256
MAX_BLOBS = 8192
MAX_BLOB_BYTES = 64 * 1024 * 1024
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_OUTPUT_BYTES = 512 * 1024 * 1024
MAX_STORE_FILES = 32768
MAX_STORE_DIRECTORIES = 512
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ROUTE_BYTES = 1024
MAX_ROUTE_DEPTH = 32
MAX_STORE_COMPONENT_BYTES = 255
MAX_STAGE_ATTEMPTS = 128
MAX_NAME_BYTES = 128
_PSEUDO_VERSION = re.compile(
    r"v[0-9]+\.[0-9]+\.[0-9]+-(?:[A-Za-z0-9.-]+\.)?[0-9]{14}-[0-9a-f]{12}(?:\+incompatible)?")


@dataclass(frozen=True)
class MirrorBuild:
    """Immutable bytes; store paths are relative to the publication's store/."""

    files: tuple[tuple[str, bytes], ...]
    manifest: bytes
    reports: bytes

    @property
    def root_sha256(self) -> str:
        return _sha(self.manifest)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _go_escape(value: str) -> str:
    return "".join("!" + char.lower() if char.isupper() else char for char in value)


def _digest(value) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise CutError("invalid mirror digest")
    return value


def _json(raw: bytes, cap: int) -> dict:
    if type(raw) is not bytes or len(raw) > cap:
        raise CutError("mirror JSON byte cap or type violation")
    try:
        value = parse_json_bytes(raw, cap)
    except HermeticNpmCutError:
        raise CutError("invalid mirror JSON") from None
    if type(value) is not dict:
        raise CutError("mirror JSON must be an object")
    return value


def _recipe(raw: bytes) -> dict:
    recipe = _json(raw, MAX_RECIPE_BYTES)
    if set(recipe) != {"cutoff", "packages"}:
        raise CutError("invalid mirror recipe fields")
    _time(recipe.get("cutoff"))
    packages = recipe.get("packages")
    if type(packages) is not list or len(packages) > MAX_PACKAGES:
        raise CutError("mirror package count cap or type violation")
    seen = set()
    for package in packages:
        if type(package) is not dict:
            raise CutError("invalid mirror package")
        kind = package.get("ecosystem")
        if type(kind) is not str or kind not in {"crates", "go", "npm", "pypi-simple", "pypi-json"}:
            raise CutError("unsupported mirror ecosystem")
        fields = {"ecosystem", "name", "metadata", "artifacts"}
        if kind == "go":
            fields.add("infos")
        if set(package) != fields:
            raise CutError("invalid mirror package fields")
        name = package.get("name")
        if type(name) is not str or not 0 < len(name) <= MAX_NAME_BYTES:
            raise CutError("invalid mirror package name")
        if kind == "crates":
            pattern = r"[a-z][a-z0-9_-]*"
        elif kind == "npm":
            pattern = r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*"
        elif kind == "go":
            pattern = r"[A-Za-z0-9][A-Za-z0-9._~-]*(?:/[A-Za-z0-9][A-Za-z0-9._~-]*)+"
        else:
            pattern = r"[a-z0-9]+(?:-[a-z0-9]+)*"
        if re.fullmatch(pattern, name) is None:
            raise CutError("invalid mirror package name")
        identity = ("pypi" if kind.startswith("pypi-") else kind, name)
        if identity in seen:
            raise CutError("duplicate mirror package")
        seen.add(identity)
        _digest(package.get("metadata"))
        for field in ("artifacts", "infos") if kind == "go" else ("artifacts",):
            mapping = package.get(field)
            if type(mapping) is not dict or len(mapping) > MAX_BLOBS:
                raise CutError("invalid mirror blob mapping")
            for key, digest in mapping.items():
                if (not key or len(key) > MAX_ROUTE_BYTES or not key.isascii()
                        or re.fullmatch(r"[A-Za-z0-9._+!-]+", key) is None
                        or key in {".", ".."}):
                    raise CutError("invalid mirror artifact key")
                _digest(digest)
    return recipe


def _references(recipe: dict) -> set[str]:
    result = set()
    for package in recipe["packages"]:
        result.add(package["metadata"])
        result.update(package["artifacts"].values())
        result.update(package.get("infos", {}).values())
    if len(result) > MAX_BLOBS:
        raise CutError("mirror blob count cap exceeded")
    return result


def _route(path: str) -> None:
    if (type(path) is not str or len(path) > MAX_ROUTE_BYTES or not path.isascii()
            or len(path.split("/")) > MAX_ROUTE_DEPTH
            or any(not part or part in {".", "..", ".404.json"}
                   or part.lower().endswith(".headers.json")
                   or len(part) > MAX_STORE_COMPONENT_BYTES
                   or re.fullmatch(r"[A-Za-z0-9._@+!~-]+", part) is None
                   for part in path.split("/"))):
        raise CutError("invalid mirror store route")


def build_mirror(raw_recipe: bytes, blobs: dict[str, bytes]) -> MirrorBuild:
    """Transform bounded acquisition bytes into a complete frozen store image.

    Every referenced blob, including excluded downloads, must match its SHA-256.
    A missing admitted artifact aborts the build. Extra blobs are refused, so an
    accidental host inventory cannot be incorporated. Upstream checksums for
    crates, PyPI and npm are additionally verified. Go .mod/.zip checksums are
    acquisition SHA-256 values; this does not replace Go's h1/sumdb provenance.
    """
    recipe = _recipe(raw_recipe)
    references = _references(recipe)
    if type(blobs) is not dict or len(blobs) > MAX_BLOBS:
        raise CutError("mirror blob count cap or type violation")
    # Preserve the byte objects checked below across hashing and later use.
    blobs = blobs.copy()
    if len(blobs) > MAX_BLOBS:
        raise CutError("mirror blob count cap or type violation")
    total = len(raw_recipe)
    for digest, content in blobs.items():
        _digest(digest)
        if type(content) is not bytes or len(content) > MAX_BLOB_BYTES:
            raise CutError("mirror blob byte cap or type violation")
        total += len(content)
        if total > MAX_INPUT_BYTES:
            raise CutError("mirror aggregate input cap exceeded")
        if _sha(content) != digest:
            raise CutError("mirror blob digest mismatch")
    if set(blobs) != references:
        raise CutError("mirror blob inventory mismatch")

    files = {}
    store_directories = set()
    total_output = 0
    reports = []
    projects = []

    def put(path: str, body: bytes, content_type: str) -> None:
        nonlocal total_output
        _route(path)
        sidecar = path + ".headers.json"
        # DirStore falls back to extension-based types when a sidecar is absent.
        # A valid 255-byte artifact basename cannot have an appended sidecar on
        # Linux; the artifact bytes and download route must still be published.
        has_sidecar = len(sidecar.rsplit("/", 1)[-1]) <= MAX_STORE_COMPONENT_BYTES
        if path in files or sidecar in files:
            raise CutError("duplicate mirror store route")
        # A regular file cannot also be a parent directory in DirStore.
        parents = path.split("/")
        for count in range(1, len(parents)):
            if "/".join(parents[:count]) in files:
                raise CutError("conflicting mirror store routes")
        if path in store_directories:
            raise CutError("conflicting mirror store routes")
        store_directories.update("/".join(parents[:count]) for count in range(1, len(parents)))
        headers = canonical_json_bytes({"content_type": content_type})
        total_output += len(body) + (len(headers) if has_sidecar else 0)
        if (total_output > MAX_OUTPUT_BYTES or len(files) + 1 + has_sidecar > MAX_STORE_FILES
                or len(store_directories) + 1 > MAX_STORE_DIRECTORIES):
            raise CutError("mirror store output cap exceeded")
        files[path] = body
        if has_sidecar:
            files[sidecar] = headers

    def artifact(package: dict, key: str) -> bytes:
        digest = package["artifacts"].get(key)
        if digest is None:
            raise CutError("missing admitted mirror artifact")
        return blobs[digest]

    for package in sorted(recipe["packages"], key=lambda item: (item["ecosystem"], item["name"])):
        kind, name = package["ecosystem"], package["name"]
        raw = blobs[package["metadata"]]
        cutoff = recipe["cutoff"]
        used = set()
        if kind == "crates":
            index, report = cut_crates_index(raw, cutoff)
            lower = name.lower()
            if len(lower) <= 2:
                path = f"{len(lower)}/{lower}"
            elif len(lower) == 3:
                path = f"3/{next(iter(lower))}/{lower}"
            else:
                path = f"{lower[:2]}/{lower[2:4]}/{lower}"
            if report.kept:
                put("index.crates.io/" + path, index, "text/plain")
            for line in index.splitlines():
                record = json.loads(line)
                if record["name"] != name:
                    raise CutError("mirror crate name mismatch")
                version = record["vers"]
                body = artifact(package, version)
                if _sha(body) != record["cksum"]:
                    raise CutError("crate artifact digest mismatch")
                used.add(version)
                put(f"static.crates.io/crates/{name}/{name}-{version}.crate", body, "application/gzip")
        elif kind == "go":
            infos = {version: blobs[digest] for version, digest in package["infos"].items()}
            _, admitted, report = cut_go_versions(raw, infos, cutoff)
            tagged = [version for version in admitted if _PSEUDO_VERSION.fullmatch(version) is None]
            listing = "".join(version + "\n" for version in tagged).encode("ascii")
            root = "proxy.golang.org/" + _go_escape(name)
            if report.kept:
                put(root + "/@v/list", listing, "text/plain")
            for version, info in admitted.items():
                put(f"{root}/@v/{_go_escape(version)}.info", info, "application/json")
                for extension, mime in (("mod", "text/plain"), ("zip", "application/zip")):
                    key = f"{version}.{extension}"
                    put(f"{root}/@v/{_go_escape(key)}", artifact(package, key), mime)
                    used.add(key)
            if admitted:
                def compare(left, right):
                    return compare_semver(parse_semver(left.removeprefix("v")),
                                          parse_semver(right.removeprefix("v")))
                stable = [version for version in tagged
                          if parse_semver(version.removeprefix("v")).prerelease is None]
                if tagged:
                    latest = max(stable or tagged, key=cmp_to_key(compare))
                else:
                    latest = max(admitted, key=lambda version: (
                        _time(json.loads(admitted[version])["Time"]), version))
                put(root + "/@latest", admitted[latest], "application/json")
        elif kind.startswith("pypi-"):
            transform = cut_pypi_simple if kind == "pypi-simple" else cut_pypi_json
            index, report = transform(raw, cutoff)
            page = json.loads(index.simple_json)
            if page["name"] != name:
                raise CutError("mirror PyPI project name mismatch")
            if report.kept:
                put(f"pypi.org/simple/{name}/index.html", index.simple_html, "text/html")
                put(f"pypi.org/simple/{name}/index.json", index.simple_json,
                    "application/vnd.pypi.simple.v1+json")
            for entry in page["files"]:
                filename = entry["filename"]
                body = artifact(package, filename)
                if _sha(body) != entry["hashes"]["sha256"] or len(body) != entry["size"]:
                    raise CutError("PyPI artifact digest or size mismatch")
                put("pypi.org" + entry["url"], body, "application/octet-stream")
                used.add(filename)
            if page["files"]:
                projects.append(name)
        else:
            try:
                packument, npm_report = cut_packument(_json(raw, MAX_BLOB_BYTES), cutoff)
            except HermeticNpmCutError:
                raise CutError("invalid npm mirror metadata") from None
            if packument["name"] != name:
                raise CutError("mirror npm package name mismatch")
            if set(packument["dist-tags"]) - {"latest"}:
                raise CutError("npm tag history required")
            for version, manifest in packument["versions"].items():
                if (parse_semver(version) is None or manifest.get("name") != name
                        or manifest.get("version") != version):
                    raise CutError("invalid npm mirror version manifest")
                body = artifact(package, version)
                dist = manifest.get("dist")
                if type(dist) is not dict:
                    raise CutError("missing npm artifact checksum")
                integrity = dist.get("integrity")
                shasum = dist.get("shasum")
                if integrity is not None:
                    if type(integrity) is not str or len(integrity) > 256:
                        raise CutError("invalid npm artifact integrity")
                    algorithm, separator, encoded = integrity.partition("-")
                    if separator != "-" or algorithm not in {"sha256", "sha512"}:
                        raise CutError("unsupported npm artifact integrity")
                    expected = base64.b64encode(hashlib.new(algorithm, body).digest()).decode("ascii")
                    if encoded != expected:
                        raise CutError("npm artifact integrity mismatch")
                if shasum is not None and (type(shasum) is not str
                                          or shasum != hashlib.sha1(body).hexdigest()):
                    raise CutError("npm artifact shasum mismatch")
                if integrity is None and shasum is None:
                    raise CutError("missing npm artifact checksum")
                leaf = name.rsplit("/", 1)[-1]
                tarball = f"/{name}/-/{leaf}-{version}.tgz"
                manifest["dist"] = {
                    "tarball": "https://registry.npmjs.org" + tarball,
                    "shasum": hashlib.sha1(body).hexdigest(),
                    "integrity": "sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode("ascii"),
                }
                put("registry.npmjs.org" + tarball, body, "application/octet-stream")
                put(f"registry.npmjs.org/{name}/{version}", canonical_json_bytes(manifest), "application/json")
                used.add(version)
            if npm_report.kept:
                put(f"registry.npmjs.org/{name}/index.html", canonical_json_bytes(packument), "application/json")
            report = npm_report
        # Supplied excluded downloads remain unserved. Refuse misspellings and
        # unknown artifact associations instead of silently ignoring them.
        inventory = set(package["artifacts"])
        if kind == "go":
            allowed = {version + suffix for version in (*report.kept, *report.after_cutoff, *report.unknown)
                       for suffix in (".mod", ".zip")}
        elif kind == "npm":
            allowed = set(_json(raw, MAX_BLOB_BYTES)["versions"])
        else:
            allowed = set(report.kept) | set(report.after_cutoff) | set(report.unknown)
        if inventory - allowed or used - inventory:
            raise CutError("unrecognized mirror artifact association")
        reports.append({"ecosystem": kind, "name": name, "report": asdict(report)})

    if any(path.startswith("index.crates.io/") for path in files):
        put("index.crates.io/config.json", canonical_json_bytes({
            "dl": "https://static.crates.io/crates/{crate}/{crate}-{version}.crate"}), "application/json")
    if projects:
        html = '<!DOCTYPE html>\n<html><body>\n' + "".join(
            f'<a href="{name}/">{name}</a>\n' for name in sorted(projects)) + '</body></html>\n'
        put("pypi.org/simple/index.html", html.encode("ascii"), "text/html")
    report_bytes = canonical_json_bytes(reports)
    manifest = canonical_json_bytes({
        "schema": "hermetic-offline-mirror/v1", "cutoff": recipe["cutoff"],
        "recipe_sha256": _sha(canonical_json_bytes({
            "cutoff": recipe["cutoff"], "packages": sorted(
                recipe["packages"], key=lambda item: (item["ecosystem"], item["name"]))})),
        "inputs": sorted(references),
        "reports": {"size": len(report_bytes), "sha256": _sha(report_bytes)},
        "files": [{"path": path, "size": len(body), "sha256": _sha(body)}
                  for path, body in sorted(files.items())],
    })
    if (len(manifest) + len(report_bytes) > MAX_MANIFEST_BYTES
            or total_output + len(manifest) + len(report_bytes) > MAX_OUTPUT_BYTES):
        raise CutError("mirror manifest or aggregate output cap exceeded")
    return MirrorBuild(tuple(sorted(files.items())), manifest, report_bytes)


def _directory(parent: int, leaf: str) -> int:
    before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode):
        raise CutError("unsafe mirror directory")
    descriptor = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
    try:
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_mode) != (after.st_dev, after.st_ino, after.st_mode):
            raise CutError("mirror directory changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def verify_mirror(raw_manifest: bytes, files: dict[str, bytes], reports: bytes,
                  expected_sha256: str, cutoff: str) -> MirrorBuild:
    """Authenticate a frozen publication before any consumer installs its bytes.

    The expected manifest digest and cutoff must come from the trusted world
    description, not the supplied publication. This verifies byte integrity and
    the versioned store layout; acquisition still supplies historical provenance.
    No paths are opened and no host state is consulted.
    """
    _digest(expected_sha256)
    _time(cutoff)
    manifest = _json(raw_manifest, MAX_MANIFEST_BYTES)
    if (_sha(raw_manifest) != expected_sha256
            or canonical_json_bytes(manifest) != raw_manifest):
        raise CutError("mirror manifest authentication failed")
    if (set(manifest) != {"schema", "cutoff", "recipe_sha256", "inputs", "reports", "files"}
            or manifest["schema"] != "hermetic-offline-mirror/v1"
            or manifest["cutoff"] != cutoff):
        raise CutError("invalid mirror manifest policy")
    _digest(manifest["recipe_sha256"])
    inputs = manifest["inputs"]
    if type(inputs) is not list or len(inputs) > MAX_BLOBS:
        raise CutError("invalid mirror manifest inputs")
    for value in inputs:
        _digest(value)
    if inputs != sorted(set(inputs)):
        raise CutError("invalid mirror manifest input order")
    if type(reports) is not bytes or len(raw_manifest) + len(reports) > MAX_MANIFEST_BYTES:
        raise CutError("mirror manifest byte cap or type violation")

    def check_body(entry, body):
        if (type(entry["size"]) is not int or not 0 <= entry["size"] <= MAX_OUTPUT_BYTES
                or type(body) is not bytes or len(body) != entry["size"]):
            raise CutError("mirror publication size or type mismatch")
        if _sha(body) != _digest(entry["sha256"]):
            raise CutError("mirror publication digest mismatch")

    report = manifest["reports"]
    if type(report) is not dict or set(report) != {"size", "sha256"}:
        raise CutError("invalid mirror manifest reports")
    check_body(report, reports)
    entries = manifest["files"]
    if (type(entries) is not list or len(entries) > MAX_STORE_FILES
            or type(files) is not dict or len(files) != len(entries)):
        raise CutError("invalid mirror publication inventory")
    files = files.copy()
    if len(files) != len(entries):
        raise CutError("invalid mirror publication inventory")
    # Bound all bodies before hashing any served content, including extras.
    total = len(raw_manifest) + len(reports)
    for path, body in files.items():
        if type(path) is not str or type(body) is not bytes:
            raise CutError("invalid mirror publication entry")
        total += len(body)
        if total > MAX_OUTPUT_BYTES:
            raise CutError("mirror publication output cap exceeded")
    if total > MAX_OUTPUT_BYTES:
        raise CutError("mirror publication output cap exceeded")
    previous = ""
    directories = set()
    paths = set()
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"path", "size", "sha256"}:
            raise CutError("invalid mirror manifest file record")
        path = entry["path"]
        if type(path) is not str or len(path) > MAX_ROUTE_BYTES + len(".headers.json"):
            raise CutError("invalid mirror publication path")
        # Sidecars are authenticated files, but must name a valid served route.
        sidecar = path.endswith(".headers.json")
        route = path.removesuffix(".headers.json") if sidecar else path
        _route(route)
        if sidecar and len(path.rsplit("/", 1)[-1]) > MAX_STORE_COMPONENT_BYTES:
            raise CutError("invalid mirror publication sidecar")
        if path <= previous or path not in files:
            raise CutError("mirror publication order or inventory mismatch")
        previous = path
        parts = path.split("/")
        for count in range(1, len(parts)):
            parent = "/".join(parts[:count])
            if parent in paths:
                raise CutError("conflicting mirror publication paths")
            directories.add(parent)
        if len(directories) + 1 > MAX_STORE_DIRECTORIES:
            raise CutError("mirror publication directory cap exceeded")
        paths.add(path)
        check_body(entry, files[path])
    return MirrorBuild(tuple(sorted(files.items())), raw_manifest, reports)


def build_mirror_files(recipe_path, blob_root, output_path) -> str:
    """Build from digest-named files and atomically publish output/{store,manifest,reports}.

    Output must be absent in a private caller-owned parent. Like WorldServer's
    publication boundary, the host caller and host root are trusted; no concurrent
    same-uid writer may mutate this parent. All operations retain directory fds.
    A VM root has no access to that staging parent. Existing worlds are refused.
    """
    try:
        for path in (recipe_path, output_path):
            validate_path(path)
        probe = os.path.join(os.fspath(blob_root), ".probe")
        validate_path(probe)
        raw = read_regular_file_bounded(recipe_path, MAX_RECIPE_BYTES)
        recipe = _recipe(raw)
        references = _references(recipe)
        # Bound the whole acquisition before reading any blob bytes.
        blobs = {}
        total = len(raw)
        with ExitStack() as inputs:
            directory, _ = open_parent(probe)
            inputs.callback(os.close, directory)
            for digest in sorted(references):
                content = read_regular_file_bounded(
                    digest, min(MAX_BLOB_BYTES, MAX_INPUT_BYTES - total), directory=directory)
                total += len(content)
                blobs[digest] = content
        build = build_mirror(raw, blobs)
        with ExitStack() as handles:
            parent, leaf = open_parent(output_path)
            handles.callback(os.close, parent)
            st = os.fstat(parent)
            if st.st_uid != os.geteuid() or st.st_mode & 0o077:
                raise CutError("mirror output parent must be private and caller owned")
            try:
                os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise CutError("mirror output already exists")
            stage = None
            for attempt in range(MAX_STAGE_ATTEMPTS):
                candidate = f".mirror-stage-{attempt}"
                if candidate == leaf:
                    continue
                try:
                    os.mkdir(candidate, 0o700, dir_fd=parent)
                except FileExistsError:
                    continue
                stage = candidate
                break
            if stage is None:
                raise CutError("mirror staging attempts exhausted")
            # Track only our own entries. Cleanup never enumerates caller data.
            created_files = []
            directories = []
            try:
                root = _directory(parent, stage)
                handles.callback(os.close, root)
                descriptors = {"": root}
                os.mkdir("store", 0o700, dir_fd=root)
                directories.append((root, "store"))
                store = _directory(root, "store")
                handles.callback(os.close, store)
                descriptors["store"] = store
                for path, content in (*(("store/" + path, body) for path, body in build.files),
                                      ("manifest.json", build.manifest), ("reports.json", build.reports)):
                    components = path.split("/")
                    prefix = ""
                    directory = root
                    for component in components[:-1]:
                        child_path = prefix + component
                        if child_path not in descriptors:
                            os.mkdir(component, 0o700, dir_fd=directory)
                            directories.append((directory, component))
                            child = _directory(directory, component)
                            handles.callback(os.close, child)
                            descriptors[child_path] = child
                        directory = descriptors[child_path]
                        prefix = child_path + "/"
                    filename = components[-1]
                    created_files.append((directory, filename))
                    atomic_write_at(directory, filename, content)
                for directory in reversed(tuple(descriptors.values())):
                    os.fsync(directory)
                os.rename(stage, leaf, src_dir_fd=parent, dst_dir_fd=parent)
                stage = None
                os.fsync(parent)
            finally:
                if stage is not None:
                    for directory, filename in reversed(created_files):
                        try:
                            os.unlink(filename, dir_fd=directory)
                        except FileNotFoundError:
                            pass
                    for directory, filename in reversed(directories):
                        os.rmdir(filename, dir_fd=directory)
                    os.rmdir(stage, dir_fd=parent)
        return build.root_sha256
    except (OSError, ValueError, TypeError, HermeticNpmCutError):
        raise CutError("offline mirror build failed") from None
