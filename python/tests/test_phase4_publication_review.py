"""Publication-root identity and authenticated frozen-bundle regressions."""

import json

import pytest

from hermetic_ecosystem_cut import CutError, mirror
from tests.test_phase4_mirror import CUTOFF, disk_inputs, encoded, fixture


@pytest.mark.parametrize("substitute", ["directory", "symlink"])
def test_mirror_blob_root_is_pinned_for_entire_acquisition(tmp_path, monkeypatch, substitute):
    source, root, output = disk_inputs(tmp_path)
    recipe, bodies = fixture()
    expected = mirror.build_mirror(encoded(recipe), bodies)
    original = tmp_path / "original-blobs"
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    read = mirror.read_regular_file_bounded
    swapped = False

    def substitute_after_first_blob(path, cap, **kwargs):
        nonlocal swapped
        body = read(path, cap, **kwargs)
        if path != source and not swapped:
            swapped = True
            root.rename(original)
            if substitute == "directory":
                root.mkdir()
            else:
                root.symlink_to(replacement, target_is_directory=True)
        return body

    monkeypatch.setattr(mirror, "read_regular_file_bounded", substitute_after_first_blob)
    assert mirror.build_mirror_files(source, root, output) == expected.root_sha256
    assert swapped
    assert (output / "manifest.json").read_bytes() == expected.manifest
    assert list(replacement.iterdir()) == []


def bundle():
    recipe, blobs = fixture()
    return mirror.build_mirror(encoded(recipe), blobs)


def verify(build, **updates):
    args = dict(raw_manifest=build.manifest, files=dict(build.files), reports=build.reports,
                expected_sha256=build.root_sha256, cutoff=CUTOFF)
    args.update(updates)
    return mirror.verify_mirror(**args)


def test_mirror_manifest_verification_returns_immutable_known_bundle(monkeypatch):
    build = bundle()
    for key in ("HOME", "HOSTNAME", "LANG", "TZ", "SOURCE_DATE_EPOCH"):
        monkeypatch.setenv(key, "host-secret")
    files = dict(reversed(build.files))
    verified = verify(build, files=files)
    assert verified == build
    files.clear()
    assert verified == build
    empty = mirror.build_mirror(encoded(dict(cutoff=CUTOFF, packages=[])), {})
    assert verify(empty) == empty


@pytest.mark.parametrize("change", ["body", "missing", "extra", "reports", "hash", "cutoff",
                                   "manifest", "resigned", "type", "path"])
def test_mirror_manifest_verification_refuses_untrusted_changes(change):
    build = bundle()
    files = dict(build.files)
    path = next(iter(files))
    updates = {"files": files}
    if change == "body":
        files[path] = b"host-secret"
    elif change == "missing":
        del files[path]
    elif change == "extra":
        files["host-secret"] = b"extra"
    elif change == "reports":
        updates["reports"] = b"[]"
    elif change == "hash":
        updates["expected_sha256"] = "0" * 64
    elif change == "cutoff":
        updates["cutoff"] = "2000-01-01T00:00:00Z"
    elif change == "type":
        files[path] = None
    elif change == "path":
        files["../host-secret"] = files.pop(path)
    else:
        manifest = json.loads(build.manifest)
        manifest["files"][0]["size"] += 1
        if change == "resigned":
            files[path] += b"!"
            manifest["files"][0]["sha256"] = mirror._sha(files[path])
        updates["raw_manifest"] = encoded(manifest)
    with pytest.raises(CutError) as error:
        verify(build, **updates)
    assert "host-secret" not in str(error.value)


@pytest.mark.parametrize("change", ["schema", "fields", "file-fields", "bool-size", "order",
                                   "duplicate", "traversal", "sidecar", "inputs", "reports-size"])
def test_mirror_manifest_reader_validates_authenticated_schema(change):
    build = bundle()
    manifest = json.loads(build.manifest)
    if change == "schema":
        manifest["schema"] = "host-secret"
    elif change == "fields":
        manifest["host-secret"] = None
    elif change == "file-fields":
        manifest["files"][0]["host-secret"] = 1
    elif change == "bool-size":
        manifest["files"][0]["size"] = True
    elif change == "order":
        manifest["files"].reverse()
    elif change == "duplicate":
        manifest["files"].append(manifest["files"][0])
    elif change == "traversal":
        manifest["files"][0]["path"] = "../host-secret"
    elif change == "sidecar":
        manifest["files"][0]["path"] = "pypi.org/.404.json.headers.json"
    elif change == "inputs":
        manifest["inputs"].append(manifest["inputs"][0])
    else:
        manifest["reports"]["size"] = True
    raw = encoded(manifest)
    with pytest.raises(CutError):
        verify(build, raw_manifest=raw, expected_sha256=mirror._sha(raw))


@pytest.mark.parametrize("cap", ["MAX_STORE_FILES", "MAX_STORE_DIRECTORIES", "MAX_OUTPUT_BYTES",
                                "MAX_MANIFEST_BYTES", "MAX_BLOBS"])
def test_mirror_manifest_reader_enforces_named_caps(monkeypatch, cap):
    build = bundle()
    monkeypatch.setattr(mirror, cap, 1)
    with pytest.raises(CutError):
        verify(build)


@pytest.mark.parametrize("raw", [None, b"null", b"{}", b'{"a":1,"a":2}', b"\xff"])
def test_mirror_manifest_reader_has_typed_hostile_input_errors(raw):
    build = bundle()
    with pytest.raises(CutError):
        verify(build, raw_manifest=raw)
