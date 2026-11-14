"""Offline mirror integrity, admission, publication and hostile-input tests."""

import base64
import hashlib
import json
import os
import stat
import subprocess
import sys

import pytest

from hermetic_ecosystem_cut import CutError
from hermetic_ecosystem_cut import mirror

CUTOFF = "2023-04-01T00:00:00Z"
FUTURE = "2024-01-01T00:00:00Z"
BODY = b"artifact bytes\n"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def fixture():
    blobs = {}

    def blob(raw):
        digest = hashlib.sha256(raw).hexdigest()
        blobs[digest] = raw
        return digest

    artifact = blob(BODY)
    crate = lambda version, date: dict(name="demo", vers=version, deps=[], features={},
                                      cksum=artifact, yanked=False, pubtime=date)
    npm_versions = {version: dict(name="@scope/demo", version=version,
                                 dist=dict(tarball="https://user:secret@host.invalid/a",
                                           integrity="sha512-" + base64.b64encode(
                                               hashlib.sha512(BODY).digest()).decode()))
                    for version in ("1.0.0", "2.0.0", "3.0.0")}
    packages = [
        dict(ecosystem="crates", name="demo", metadata=blob(b"\n".join(
            encoded(crate(version, date)) for version, date in
            (("1.0.0", CUTOFF), ("2.0.0", FUTURE), ("3.0.0", None)))),
             artifacts={version: artifact for version in npm_versions}),
        dict(ecosystem="go", name="example.org/Demo", metadata=blob(b"v1.0.0\nv2.0.0\nv3.0.0\n"),
             infos={version: blob(encoded(dict(Version=version, Time=date)))
                    for version, date in (("v1.0.0", CUTOFF), ("v2.0.0", FUTURE), ("v3.0.0", None))},
             artifacts={version + ext: artifact for version in ("v1.0.0", "v2.0.0", "v3.0.0")
                        for ext in (".mod", ".zip")}),
        dict(ecosystem="pypi-simple", name="demo", metadata=blob(encoded({
            "meta": {"api-version": "1.1"}, "name": "demo", "files": [
                {"filename": f"demo-{version}.tar.gz", "hashes": {"sha256": artifact},
                 "size": len(BODY), "upload-time": date}
                for version, date in (("1.0.0", CUTOFF), ("2.0.0", FUTURE), ("3.0.0", None))]})),
             artifacts={f"demo-{version}.tar.gz": artifact for version in npm_versions}),
        dict(ecosystem="npm", name="@scope/demo", metadata=blob(encoded(dict(
            name="@scope/demo", versions=npm_versions,
            time={"1.0.0": CUTOFF, "2.0.0": FUTURE, "3.0.0": None},
            **{"dist-tags": {"latest": "2.0.0"}}))),
             artifacts={version: artifact for version in npm_versions}),
    ]
    return {"cutoff": CUTOFF, "packages": packages}, blobs


def replace_metadata(recipe, blobs, kind, mutate):
    package = next(item for item in recipe["packages"] if item["ecosystem"] == kind)
    old = package["metadata"]
    value = json.loads(blobs.pop(old))
    mutate(value)
    raw = encoded(value)
    digest = hashlib.sha256(raw).hexdigest()
    package["metadata"] = digest
    blobs[digest] = raw


def test_mirror_all_ecosystems_only_admitted_downloads_and_metadata():
    recipe, blobs = fixture()
    build = mirror.build_mirror(encoded(recipe), blobs)
    files = dict(build.files)
    expected = {
        "static.crates.io/crates/demo/demo-1.0.0.crate",
        "proxy.golang.org/example.org/!demo/@v/v1.0.0.mod",
        "proxy.golang.org/example.org/!demo/@v/v1.0.0.zip",
        f"pypi.org/files/{hashlib.sha256(BODY).hexdigest()}/demo-1.0.0.tar.gz",
        "registry.npmjs.org/@scope/demo/-/demo-1.0.0.tgz",
    }
    assert {path for path, body in build.files if body == BODY} == expected
    assert all(b"2.0.0" not in body and b"3.0.0" not in body and b"secret" not in body
               for path, body in build.files)
    assert not any("2.0.0" in path or "3.0.0" in path for path in files)
    assert files["proxy.golang.org/example.org/!demo/@v/list"] == b"v1.0.0\n"
    assert files["proxy.golang.org/example.org/!demo/@latest"] == encoded(
        dict(Version="v1.0.0", Time=CUTOFF))
    packument = json.loads(files["registry.npmjs.org/@scope/demo/index.html"])
    manifest = packument["versions"]["1.0.0"]
    assert packument["dist-tags"] == {"latest": "1.0.0"}
    assert manifest["dist"]["tarball"] == "https://registry.npmjs.org/@scope/demo/-/demo-1.0.0.tgz"
    assert json.loads(files["registry.npmjs.org/@scope/demo/1.0.0"]) == manifest
    assert b"2.0.0" in build.reports and b"3.0.0" in build.reports
    assert all(not path.startswith(("reports", "manifest")) for path in files)


def test_mirror_hash_manifest_covers_every_served_byte_and_sidecar():
    recipe, blobs = fixture()
    build = mirror.build_mirror(encoded(recipe), blobs)
    manifest = json.loads(build.manifest)
    files = dict(build.files)
    assert [entry["path"] for entry in manifest["files"]] == sorted(files)
    for entry in manifest["files"]:
        body = files[entry["path"]]
        assert entry["size"] == len(body)
        assert entry["sha256"] == hashlib.sha256(body).hexdigest()
    assert manifest["inputs"] == sorted(blobs)
    assert build.root_sha256 == hashlib.sha256(build.manifest).hexdigest()


def test_mirror_manifest_binds_uncertainty_reports():
    recipe, blobs = fixture()
    build = mirror.build_mirror(encoded(recipe), blobs)
    assert json.loads(build.manifest)["reports"] == {
        "size": len(build.reports), "sha256": hashlib.sha256(build.reports).hexdigest()}


def go_only(versions):
    blobs = {}
    def blob(raw):
        digest = hashlib.sha256(raw).hexdigest()
        blobs[digest] = raw
        return digest
    digest = blob(BODY)
    package = dict(ecosystem="go", name="example.org/Demo", metadata=blob(
        "".join(version + "\n" for version, date in versions).encode()),
        infos={version: blob(encoded(dict(Version=version, Time=date))) for version, date in versions},
        artifacts={version + ext: digest for version, date in versions for ext in (".mod", ".zip")})
    return {"cutoff": CUTOFF, "packages": [package]}, blobs


def test_mirror_go_version_paths_escape_uppercase():
    recipe, blobs = go_only([("v1.0.0-RC1", CUTOFF)])
    files = dict(mirror.build_mirror(encoded(recipe), blobs).files)
    prefix = "proxy.golang.org/example.org/!demo/@v/"
    assert files[prefix + "v1.0.0-!r!c1.zip"] == BODY
    assert json.loads(files[prefix + "v1.0.0-!r!c1.info"])["Version"] == "v1.0.0-RC1"
    assert prefix + "v1.0.0-RC1.zip" not in files


def test_mirror_go_list_excludes_pseudo_versions_and_latest_prefers_tag():
    pseudo = "v1.9.0-0.20230331000000-abcdefabcdef"
    recipe, blobs = go_only([("v1.0.0-RC1", CUTOFF), (pseudo, "2023-03-31T00:00:00Z")])
    files = dict(mirror.build_mirror(encoded(recipe), blobs).files)
    prefix = "proxy.golang.org/example.org/!demo/"
    assert files[prefix + "@v/list"] == b"v1.0.0-RC1\n"
    assert json.loads(files[prefix + "@latest"])["Version"] == "v1.0.0-RC1"
    assert files[prefix + "@v/" + pseudo + ".zip"] == BODY


def test_mirror_deterministic_with_order_and_environment_changes(monkeypatch):
    recipe, blobs = fixture()
    first = mirror.build_mirror(encoded(recipe), blobs)
    recipe["packages"].reverse()
    for key in ("TZ", "LANG", "HOSTNAME", "HOME", "SOURCE_DATE_EPOCH"):
        monkeypatch.setenv(key, "host-secret")
    second = mirror.build_mirror(json.dumps(recipe, indent=4).encode(), dict(reversed(list(blobs.items()))))
    assert first == second
    assert b"host-secret" not in first.manifest + first.reports


def test_mirror_empty_known_answer():
    recipe = {"cutoff": CUTOFF, "packages": []}
    build = mirror.build_mirror(encoded(recipe), {})
    assert build.files == ()
    assert build.reports == b"[]"
    assert build.manifest == encoded({
        "schema": "hermetic-offline-mirror/v1", "cutoff": CUTOFF,
        "recipe_sha256": hashlib.sha256(encoded(recipe)).hexdigest(), "inputs": [], "files": [],
        "reports": {"size": 2, "sha256": hashlib.sha256(b"[]").hexdigest()}})


@pytest.mark.parametrize("mutation", ["missing", "corrupt", "extra", "bad-key", "bad-type"])
def test_mirror_blob_inventory_fails_closed(mutation):
    recipe, blobs = fixture()
    digest = hashlib.sha256(BODY).hexdigest()
    if mutation == "missing":
        del blobs[digest]
    elif mutation == "corrupt":
        blobs[digest] = b"host-secret"
    elif mutation == "extra":
        blobs[hashlib.sha256(b"extra").hexdigest()] = b"extra"
    elif mutation == "bad-key":
        blobs["../host-secret"] = b"extra"
    else:
        blobs[digest] = None
    with pytest.raises(CutError) as caught:
        mirror.build_mirror(encoded(recipe), blobs)
    assert "host-secret" not in str(caught.value)


@pytest.mark.parametrize("raw", [b"null", b"{}", b"[]", b"NaN", b"{", b"\xff",
    b'{"cutoff":"secret","cutoff":"secret"}', b'{"x":' * 30 + b'0' + b'}' * 30])
def test_mirror_hostile_recipe_has_typed_error(raw):
    with pytest.raises(CutError):
        mirror.build_mirror(raw, {})


@pytest.mark.parametrize("kind,name", [("go", "../host-secret"), ("npm", "../host-secret"),
    ("crates", "demo/secret"), ("pypi-simple", "Demo"), ([], "demo"), ("go", None)])
def test_mirror_recipe_names_are_validated(kind, name):
    recipe, blobs = fixture()
    recipe["packages"][0].update(ecosystem=kind, name=name)
    with pytest.raises(CutError):
        mirror.build_mirror(encoded(recipe), blobs)


@pytest.mark.parametrize("kind", ["crates", "go", "npm", "pypi-simple"])
def test_mirror_missing_admitted_artifact_aborts(kind):
    recipe, blobs = fixture()
    package = next(item for item in recipe["packages"] if item["ecosystem"] == kind)
    package["artifacts"].clear()
    with pytest.raises(CutError):
        mirror.build_mirror(encoded(recipe), blobs)


def test_mirror_npm_mutable_tag_refused_until_history_is_available():
    recipe, blobs = fixture()
    replace_metadata(recipe, blobs, "npm", lambda value: value["dist-tags"].update(
        {"added-after-cutoff-2026": "1.0.0"}))
    with pytest.raises(CutError, match="tag history required"):
        mirror.build_mirror(encoded(recipe), blobs)


@pytest.mark.parametrize("field,value", [("integrity", "sha512-bad"), ("shasum", "a" * 40),
                                       ("integrity", "sha1-unsupported")])
def test_mirror_npm_upstream_digest_must_match(field, value):
    recipe, blobs = fixture()
    replace_metadata(recipe, blobs, "npm", lambda data: data["versions"]["1.0.0"]["dist"].update(
        {field: value}))
    with pytest.raises(CutError):
        mirror.build_mirror(encoded(recipe), blobs)


def test_mirror_pypi_declared_size_must_match():
    recipe, blobs = fixture()
    replace_metadata(recipe, blobs, "pypi-simple", lambda value: value["files"][0].update(size=1))
    with pytest.raises(CutError, match="size mismatch"):
        mirror.build_mirror(encoded(recipe), blobs)


@pytest.mark.parametrize("cap", ["MAX_RECIPE_BYTES", "MAX_PACKAGES", "MAX_BLOBS", "MAX_BLOB_BYTES",
    "MAX_INPUT_BYTES", "MAX_OUTPUT_BYTES", "MAX_STORE_FILES", "MAX_STORE_DIRECTORIES",
    "MAX_MANIFEST_BYTES", "MAX_ROUTE_BYTES", "MAX_ROUTE_DEPTH", "MAX_NAME_BYTES",
    "MAX_STORE_COMPONENT_BYTES"])
def test_mirror_named_caps_fail_closed(monkeypatch, cap):
    recipe, blobs = fixture()
    monkeypatch.setattr(mirror, cap, 1)
    with pytest.raises(CutError):
        mirror.build_mirror(encoded(recipe), blobs)


def disk_inputs(tmp_path, recipe=None, blobs=None):
    if recipe is None:
        recipe, blobs = fixture()
    source = tmp_path / "recipe.json"
    source.write_bytes(encoded(recipe))
    root = tmp_path / "blobs"
    root.mkdir()
    for digest, body in blobs.items():
        (root / digest).write_bytes(body)
    return source, root, tmp_path / "world"


def test_mirror_atomic_disk_publication_and_existing_world_unchanged(tmp_path):
    source, blobs, output = disk_inputs(tmp_path)
    digest = mirror.build_mirror_files(source, blobs, output)
    assert digest == hashlib.sha256((output / "manifest.json").read_bytes()).hexdigest()
    for entry in json.loads((output / "manifest.json").read_bytes())["files"]:
        path = output / "store" / entry["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"]
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    before = (output / "manifest.json").read_bytes()
    with pytest.raises(CutError):
        mirror.build_mirror_files(source, blobs, output)
    assert (output / "manifest.json").read_bytes() == before
    assert not list(tmp_path.glob(".mirror-stage-*"))


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "parent-symlink"])
def test_mirror_unsafe_blob_never_publishes(tmp_path, kind):
    source, blobs, output = disk_inputs(tmp_path)
    artifact = blobs / hashlib.sha256(BODY).hexdigest()
    artifact.unlink()
    if kind == "symlink":
        artifact.symlink_to(source)
    elif kind == "fifo":
        os.mkfifo(artifact)
    elif kind == "directory":
        artifact.mkdir()
    else:
        moved = tmp_path / "moved"
        blobs.rename(moved)
        blobs.symlink_to(moved, target_is_directory=True)
    with pytest.raises(CutError):
        mirror.build_mirror_files(source, blobs, output)
    assert not output.exists()
    assert not list(tmp_path.glob(".mirror-stage-*"))


def test_mirror_publication_failure_removes_stage_and_never_publishes(tmp_path, monkeypatch):
    source, blobs, output = disk_inputs(tmp_path)
    real_write = mirror.atomic_write_at
    writes = 0

    def fail(directory, leaf, content):
        nonlocal writes
        writes += 1
        real_write(directory, leaf, content)
        if writes == 4:
            raise OSError("host-secret")

    monkeypatch.setattr(mirror, "atomic_write_at", fail)
    with pytest.raises(CutError) as caught:
        mirror.build_mirror_files(source, blobs, output)
    assert "host-secret" not in str(caught.value)
    assert not output.exists()
    assert not list(tmp_path.glob(".mirror-stage-*"))


def test_mirror_empty_disk_build_creates_store_root(tmp_path):
    source, blobs, output = disk_inputs(tmp_path, {"cutoff": CUTOFF, "packages": []}, {})
    mirror.build_mirror_files(source, blobs, output)
    assert (output / "store").is_dir()
    assert list((output / "store").iterdir()) == []


def test_mirror_maximum_pypi_filename_can_be_published(tmp_path):
    recipe, blobs = fixture()
    recipe["packages"] = [package for package in recipe["packages"]
                          if package["ecosystem"] == "pypi-simple"]
    package = next(iter(recipe["packages"]))
    filename = "demo-1.0-" + "p" * (255 - len("demo-1.0--none-any.whl")) + "-none-any.whl"
    assert len(filename) == 255
    def only_file(page):
        page["files"] = [dict(page["files"][0], filename=filename)]
    replace_metadata(recipe, blobs, "pypi-simple", only_file)
    digest = hashlib.sha256(BODY).hexdigest()
    package["artifacts"] = {filename: digest}
    blobs = {key: body for key, body in blobs.items() if key in mirror._references(recipe)}
    source, blob_root, output = disk_inputs(tmp_path, recipe, blobs)
    mirror.build_mirror_files(source, blob_root, output)
    assert (output / "store/pypi.org/files" / digest / filename).read_bytes() == BODY


def test_mirror_publication_uses_pinned_parent_after_directory_swap(tmp_path, monkeypatch):
    source, blobs, _ = disk_inputs(tmp_path)
    parent = tmp_path / "publication"
    parent.mkdir(mode=0o700)
    moved = tmp_path / "moved"
    redirected = tmp_path / "redirected"
    redirected.mkdir(mode=0o700)
    real_rename = mirror.os.rename
    # pathlib.Path.rename also calls os.rename: use the saved implementation.
    def rename_stage(*args, **kwargs):
        real_rename(parent, moved)
        parent.symlink_to(redirected, target_is_directory=True)
        return real_rename(*args, **kwargs)
    monkeypatch.setattr(mirror.os, "rename", rename_stage)
    mirror.build_mirror_files(source, blobs, parent / "world")
    assert (moved / "world/manifest.json").is_file()
    assert list(redirected.iterdir()) == []


def test_mirror_input_validation_happens_before_staging(tmp_path, monkeypatch):
    source, blobs, output = disk_inputs(tmp_path)
    source.write_bytes(b'{"cutoff":"invalid","packages":[]}')
    def refuse(*args, **kwargs):
        pytest.fail("invalid recipe reached publication")
    monkeypatch.setattr(mirror.os, "mkdir", refuse)
    with pytest.raises(CutError):
        mirror.build_mirror_files(source, blobs, output)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_mirror_unsafe_output_is_never_touched(tmp_path, kind):
    source, blobs, output = disk_inputs(tmp_path)
    if kind == "symlink":
        output.symlink_to(blobs, target_is_directory=True)
    elif kind == "fifo":
        os.mkfifo(output)
    else:
        output.mkdir()
    before = output.lstat()
    with pytest.raises(CutError):
        mirror.build_mirror_files(source, blobs, output)
    after = output.lstat()
    assert (before.st_ino, before.st_mode) == (after.st_ino, after.st_mode)
    assert not list(tmp_path.glob(".mirror-stage-*"))


def test_mirror_stage_attempts_are_bounded_and_existing_entries_untouched(tmp_path, monkeypatch):
    source, blobs, output = disk_inputs(tmp_path)
    monkeypatch.setattr(mirror, "MAX_STAGE_ATTEMPTS", 2)
    occupied = tmp_path / ".mirror-stage-0"
    occupied.symlink_to(blobs, target_is_directory=True)
    fifo = tmp_path / ".mirror-stage-1"
    os.mkfifo(fifo)
    with pytest.raises(CutError):
        mirror.build_mirror_files(source, blobs, output)
    assert occupied.is_symlink()
    assert stat.S_ISFIFO(fifo.lstat().st_mode)
    assert not output.exists()


def test_mirror_pypi_json_uses_same_verified_artifact_routes():
    recipe, blobs = fixture()
    recipe["packages"] = [package for package in recipe["packages"]
                          if package["ecosystem"] == "pypi-simple"]
    package = next(iter(recipe["packages"]))
    original = json.loads(blobs.pop(package["metadata"]))
    releases = {}
    for entry in original["files"]:
        entry["digests"] = entry.pop("hashes")
        entry["upload_time_iso_8601"] = entry.pop("upload-time")
        version = entry["filename"].removeprefix("demo-").removesuffix(".tar.gz")
        releases[version] = [entry]
    raw = encoded({"info": {"name": "demo"}, "releases": releases})
    package["ecosystem"] = "pypi-json"
    package["metadata"] = hashlib.sha256(raw).hexdigest()
    blobs[package["metadata"]] = raw
    references = mirror._references(recipe)
    blobs = {key: body for key, body in blobs.items() if key in references}
    files = dict(mirror.build_mirror(encoded(recipe), blobs).files)
    digest = hashlib.sha256(BODY).hexdigest()
    assert files[f"pypi.org/files/{digest}/demo-1.0.0.tar.gz"] == BODY
    assert b"2.0.0" not in files["pypi.org/simple/demo/index.html"]


def test_mirror_cli_error_is_sanitized(tmp_path):
    result = subprocess.run([sys.executable, "-m", "hermetic_ecosystem_cut",
                             str(tmp_path / "host-secret"), str(tmp_path), str(tmp_path / "out")],
                            capture_output=True, timeout=10)
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == b"offline mirror build failed\n"
