"""Verified regressions in the offline Phase 4 preparation."""

import json
import os

import pytest

from hermetic_ecosystem_cut import CutError, cut_crates_index, cut_go_versions
from hermetic_ecosystem_cut import cut as ecosystem
from hermetic_npm_cut import cut as npm

CUTOFF = "2023-04-01T00:00:00Z"


def crate(**updates):
    record = dict(name="demo", vers="1.0.0", deps=[], features={}, cksum="a" * 64,
                  yanked=False, pubtime=CUTOFF)
    record.update(updates)
    return json.dumps(record).encode()


@pytest.mark.parametrize("updates", [
    {"deps": [None]}, {"deps": [{"name": "dep", "req": 4}]},
    {"features": {"default": "host-secret"}}, {"features": {"default": [None]}},
    {"features2": []}, {"links": {}}, {"v": True}, {"v": 999}, {"rust_version": []},
])
def test_crates_nested_schema_rejected_even_after_cutoff(updates):
    for date in (CUTOFF, "2024-01-01T00:00:00Z"):
        with pytest.raises(CutError):
            cut_crates_index(crate(**dict(updates, pubtime=date)), CUTOFF)


@pytest.mark.parametrize("version", ["v1.0.0+host-secret", "v1.0.0+incompatible.extra"])
def test_go_noncanonical_build_alias_is_rejected(version):
    data = json.dumps(dict(Version=version, Time=CUTOFF)).encode()
    with pytest.raises(CutError):
        cut_go_versions((version + "\n").encode(), {version: data}, CUTOFF)


def test_go_output_obeys_named_cap(monkeypatch):
    monkeypatch.setattr(ecosystem, "MAX_OUTPUT_BYTES", 1)
    with pytest.raises(CutError):
        cut_go_versions(b"v1.0.0\n", {"v1.0.0": json.dumps(
            dict(Version="v1.0.0", Time=CUTOFF)).encode()}, CUTOFF)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "missing-parent"])
def test_npm_unsafe_report_never_replaces_output(tmp_path, kind):
    source = tmp_path / "input.json"
    output = tmp_path / "output.json"
    report = tmp_path / "report.json"
    source.write_text(json.dumps(dict(name="demo", versions={}, time={})))
    output.write_bytes(b"original")
    if kind == "symlink":
        report.symlink_to(source)
    elif kind == "fifo":
        os.mkfifo(report)
    elif kind == "directory":
        report.mkdir()
    else:
        report = tmp_path / "missing" / "report.json"
    with pytest.raises(npm.HermeticNpmCutError):
        npm.cut_packument_files(source, CUTOFF, output, report)
    assert output.read_bytes() == b"original"


def test_npm_direct_nul_key_matches_byte_parser_rejection():
    data = dict(name="demo", versions={"1.0.0": {"secret\0key": "value"}},
                time={"1.0.0": CUTOFF})
    with pytest.raises(npm.HermeticNpmCutError):
        npm.cut_packument(data, CUTOFF)


def test_npm_publication_retains_parent_handle_after_directory_swap(tmp_path, monkeypatch):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(dict(name="demo", versions={}, time={})))
    parent = tmp_path / "publication"
    parent.mkdir()
    moved = tmp_path / "moved"
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    real_read = npm.read_regular_file_bounded
    def swap(*args, **kwargs):
        result = real_read(*args, **kwargs)
        parent.rename(moved)
        parent.symlink_to(redirected, target_is_directory=True)
        return result
    monkeypatch.setattr(npm, "read_regular_file_bounded", swap)
    npm.cut_packument_files(source, CUTOFF, parent / "out.json", parent / "report.json")
    assert json.loads((moved / "out.json").read_bytes())["name"] == "demo"
    assert json.loads((moved / "report.json").read_bytes())["kept"] == 0
    assert list(redirected.iterdir()) == []
    assert (moved / "out.json").stat().st_mode & 0o777 == 0o600


def test_npm_hardlinked_destinations_rejected_before_writing(tmp_path):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(dict(name="demo", versions={}, time={})))
    output = tmp_path / "out.json"
    report = tmp_path / "report.json"
    output.write_bytes(b"original")
    os.link(output, report)
    with pytest.raises(npm.HermeticNpmCutError):
        npm.cut_packument_files(source, CUTOFF, output, report)
    assert output.read_bytes() == report.read_bytes() == b"original"


def test_crates_well_typed_nested_dependency_and_features_survive():
    dep = dict(name="dep", req="^1.2", features=["std"], optional=True,
               default_features=False, target=None, kind="normal", registry=None, package=None)
    result, _ = cut_crates_index(crate(deps=[dep], features={"default": ["dep/std"]},
                                      features2={"extra": ["dep:dep"]}, v=2,
                                      links="native", rust_version="1.60"), CUTOFF)
    assert json.loads(result)["deps"] == [dep]


def test_go_canonical_incompatible_version_is_admitted():
    version = "v2.0.0+incompatible"
    data = json.dumps(dict(Version=version, Time=CUTOFF)).encode()
    assert cut_go_versions((version + "\n").encode(), {version: data}, CUTOFF)[2].kept == (version,)
