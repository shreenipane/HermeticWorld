"""An excluded inventory must not reveal a package's existence through metadata."""

import json

import pytest

from hermetic_ecosystem_cut import CutError, mirror
from tests.test_phase4_mirror import fixture, encoded


def excluded_package(kind, state):
    recipe, blobs = fixture()
    package = next(item for item in recipe["packages"] if item["ecosystem"] == kind)
    recipe["packages"] = [package]
    if state == "future":
        recipe["cutoff"] = "2000-01-01T00:00:00Z"
    else:
        if kind == "crates":
            rows = [json.loads(line) for line in blobs[package["metadata"]].splitlines()]
            for row in rows:
                row["pubtime"] = None
            raw = b"\n".join(encoded(row) for row in rows) if state != "empty" else b""
        elif kind == "go":
            raw = blobs[package["metadata"]] if state != "empty" else b""
            if state == "empty":
                package["infos"] = {}
            else:
                for version, digest in package["infos"].items():
                    info = json.loads(blobs[digest])
                    info["Time"] = None
                    data = encoded(info)
                    digest = mirror._sha(data)
                    blobs[digest] = data
                    package["infos"][version] = digest
        else:
            page = json.loads(blobs[package["metadata"]])
            if kind == "npm":
                page["time"] = {version: None for version in page["versions"]}
                if state == "empty":
                    page.update(versions={}, time={})
            else:
                for entry in page["files"]:
                    entry["upload-time"] = None
                if state == "empty":
                    page["files"] = []
            raw = encoded(page)
        digest = mirror._sha(raw)
        package["metadata"] = digest
        blobs[digest] = raw
        if state == "empty":
            package["artifacts"] = {}
    blobs = {digest: body for digest, body in blobs.items() if digest in mirror._references(recipe)}
    return recipe, blobs


@pytest.mark.parametrize("kind", ["crates", "go", "npm", "pypi-simple"])
@pytest.mark.parametrize("state", ["future", "unknown", "empty"])
def test_mirror_unadmitted_package_has_no_served_metadata(kind, state):
    recipe, blobs = excluded_package(kind, state)
    build = mirror.build_mirror(encoded(recipe), blobs)
    assert build.files == ()
    report = next(iter(json.loads(build.reports)))
    assert report["name"] == recipe["packages"][0]["name"]
    assert not report["report"]["kept"]


@pytest.mark.parametrize("kind", ["crates", "go", "npm", "pypi-simple"])
def test_mirror_unadmitted_package_still_validates_artifact_associations(kind):
    recipe, blobs = excluded_package(kind, "empty")
    package = next(iter(recipe["packages"]))
    body = b"unrecognized download"
    digest = mirror._sha(body)
    package["artifacts"] = {"unrecognized": digest}
    blobs[digest] = body
    with pytest.raises(CutError, match="unrecognized mirror artifact association"):
        mirror.build_mirror(encoded(recipe), blobs)
