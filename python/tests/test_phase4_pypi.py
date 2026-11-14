"""Offline file-level PyPI admission, hostile inputs and known-answer pages."""

import json
from html.parser import HTMLParser

import pytest

from hermetic_ecosystem_cut import CutError, CutReport, cut_pypi_json, cut_pypi_simple
from hermetic_ecosystem_cut import pypi

CUTOFF = "2023-04-01T00:00:00.000001Z"
BEFORE = "2023-04-01T00:00:00Z"
AFTER = "2023-04-01T00:00:00.000002Z"
DIGEST = "a" * 64


def file(version="1.0", date=CUTOFF, **updates):
    entry = {"filename": f"demo_pkg-{version}.tar.gz", "hashes": {"sha256": DIGEST},
             "size": 7, "url": "https://user:host-secret@host.invalid/file?token=secret",
             "upload-time": date, "yanked": False}
    entry.update(updates)
    return entry


def raw(files, legacy=False, **updates):
    if legacy:
        releases = {}
        for entry in files:
            version = entry.get("version", entry["filename"].removeprefix("demo_pkg-").removesuffix(".tar.gz"))
            converted = dict(entry)
            for simple, api in (("hashes", "digests"), ("upload-time", "upload_time_iso_8601"),
                                ("requires-python", "requires_python")):
                if simple in converted:
                    converted[api] = converted.pop(simple)
            releases.setdefault(version, []).append(converted)
        page = {"info": {"name": "Demo.Pkg", "description": "post-cutoff-secret"},
                "releases": releases, "urls": [file("99.0")],
                "vulnerabilities": [{"id": "post-cutoff-secret"}]}
    else:
        page = {"meta": {"api-version": "1.4", "_last-serial": 999999}, "name": "Demo.Pkg",
                "files": files, "versions": ["1.0", "99.0"], "extension": "host-secret"}
    page.update(updates)
    return json.dumps(page).encode()


@pytest.mark.parametrize("legacy", [False, True])
def test_pypi_file_cutoff_boundary_and_unknown_exclusion(legacy):
    records = [file("0.9", BEFORE), file(), file("2.0", AFTER), file("3.0", None)]
    missing = file("4.0")
    del missing["upload-time"]
    records.append(missing)
    run = cut_pypi_json if legacy else cut_pypi_simple
    index, report = run(raw(records, legacy), CUTOFF)
    assert report == CutReport(("demo_pkg-0.9.tar.gz", "demo_pkg-1.0.tar.gz"),
                              ("demo_pkg-2.0.tar.gz",),
                              ("demo_pkg-3.0.tar.gz", "demo_pkg-4.0.tar.gz"))
    page = json.loads(index.simple_json)
    assert page["versions"] == ["0.9", "1.0"]
    assert [entry["filename"] for entry in page["files"]] == list(report.kept)
    for hidden in (b"host-secret", b"post-cutoff-secret", b"99.0", b"3.0", b"4.0", b"999999"):
        assert hidden not in index.simple_json + index.simple_html


def test_pypi_known_answer_json_and_html_and_source_equivalence():
    index, report = cut_pypi_simple(raw([file()]), CUTOFF)
    assert (index, report) == cut_pypi_json(raw([file()], True), CUTOFF)
    assert index.simple_json == (
        b'{"files":[{"filename":"demo_pkg-1.0.tar.gz","hashes":{"sha256":"' + DIGEST.encode() +
        b'"},"size":7,"upload-time":"2023-04-01T00:00:00.000001Z","url":"/files/' +
        DIGEST.encode() + b'/demo_pkg-1.0.tar.gz","yanked":false}],"meta":{"api-version":"1.1"},'
        b'"name":"demo-pkg","versions":["1.0"]}')
    assert index.simple_html == (
        b'<!DOCTYPE html>\n<html><head><meta name="pypi:repository-version" content="1.0"></head><body>\n'
        b'<a href="/files/' + DIGEST.encode() + b'/demo_pkg-1.0.tar.gz#sha256=' + DIGEST.encode() +
        b'">demo_pkg-1.0.tar.gz</a>\n</body></html>\n')


def test_pypi_same_release_different_file_uploads_are_filtered_individually():
    old = file(filename="demo_pkg-1.0-py3-none-any.whl", version="1.0")
    old["version"] = "1.0"
    new = file(date=AFTER, version="1.0")
    for legacy, run in ((False, cut_pypi_simple), (True, cut_pypi_json)):
        index, report = run(raw([new, old], legacy), CUTOFF)
        assert report.kept == (old["filename"],)
        assert report.after_cutoff == (new["filename"],)
        assert json.loads(index.simple_json)["versions"] == ["1.0"]
        assert new["filename"].encode() not in index.simple_html


@pytest.mark.parametrize("yanked", [True, "reason-added-after-cutoff", ""])
def test_pypi_unknown_yank_date_is_reported_and_reason_removed(yanked):
    index, report = cut_pypi_simple(raw([file(yanked=yanked)]), CUTOFF)
    assert report.yank_unknown == ("demo_pkg-1.0.tar.gz",)
    assert json.loads(index.simple_json)["files"][0]["yanked"] is False
    assert b"reason-added" not in index.simple_json + index.simple_html
    assert b"data-yanked" not in index.simple_html


def test_pypi_html_requires_python_cannot_inject_an_attribute():
    requires = '>=3.8" onclick="bad&<tag>'
    index, _ = cut_pypi_simple(raw([file(**{"requires-python": requires})]), CUTOFF)
    class Anchors(HTMLParser):
        def handle_starttag(self, tag, attrs):
            if tag == "a":
                self.attrs = dict(attrs)
    parser = Anchors()
    parser.feed(index.simple_html.decode())
    assert set(parser.attrs) == {"href", "data-requires-python"}
    assert parser.attrs["data-requires-python"] == requires
    assert json.loads(index.simple_json)["files"][0]["requires-python"] == requires


@pytest.mark.parametrize("changes", [
    {"filename": "../host-secret.tar.gz"}, {"filename": "demo_pkg-1.0\n.tar.gz"},
    {"filename": "other-1.0.tar.gz"}, {"filename": "demo_pkg-1.0-py3-none.whl"},
    {"filename": "demo_pkg-1.0-py3-none-any-extra.whl"},
    {"filename": "demo_pkg-1.0-py3-none-any/evil.whl"},
    {"filename": "demo_pkg-not-a-version.tar.gz"},
    {"hashes": {"sha256": "wrong"}}, {"size": True}, {"size": -1},
    {"size": pypi.MAX_ARTIFACT_BYTES + 1}, {"requires-python": []}, {"yanked": 1},
    {"upload-time": "2023-02-29T00:00:00Z"}, {"upload-time": "2023-04-01"},
    {"upload-time": "2023-04-01T00:00:00.0000001Z"},
    {"upload-time": "2023-04-01T00:00:00+01:00"}, {"upload-time": []},
])
def test_pypi_invalid_file_schema_fails_closed(changes):
    for legacy, run in ((False, cut_pypi_simple), (True, cut_pypi_json)):
        with pytest.raises(CutError) as caught:
            run(raw([file(**changes)], legacy), CUTOFF)
        assert "host-secret" not in str(caught.value)


@pytest.mark.parametrize("payload", [b"\xff", b"null", b"[]", b"NaN", b"{", b'{}',
    b'{"name":"demo","name":"secret"}', b'{"x":1e999}', b'{"x":"\\ud800"}',
    b'{"x":' * 30 + b'0' + b'}' * 30])
def test_pypi_invalid_json_is_typed_and_sanitized(payload):
    for run in (cut_pypi_json, cut_pypi_simple):
        with pytest.raises(CutError) as caught:
            run(payload, CUTOFF)
        assert "secret" not in str(caught.value)


@pytest.mark.parametrize("legacy", [False, True])
def test_pypi_duplicate_filenames_reject_even_excluded_records(legacy):
    run = cut_pypi_json if legacy else cut_pypi_simple
    with pytest.raises(CutError):
        run(raw([file(date=AFTER), file(date=AFTER)], legacy), CUTOFF)


def test_pypi_json_release_filename_mismatch_is_rejected():
    entry = file()
    entry["version"] = "2.0"
    with pytest.raises(CutError):
        cut_pypi_json(raw([entry], True), CUTOFF)


def test_pypi_empty_release_does_not_leak_version():
    index, report = cut_pypi_json(raw([], True, releases={"99.0": []}), CUTOFF)
    assert json.loads(index.simple_json)["versions"] == []
    assert report == CutReport((), (), ())
    assert b"99.0" not in index.simple_json + index.simple_html


@pytest.mark.parametrize("cap", ["MAX_INPUT_BYTES", "MAX_FILE_RECORD_BYTES", "MAX_FILES",
                                  "MAX_OUTPUT_BYTES", "MAX_NAME_BYTES", "MAX_FILENAME_BYTES",
                                  "MAX_REQUIRES_PYTHON_BYTES", "MAX_ARTIFACT_BYTES"])
def test_pypi_named_caps(monkeypatch, cap):
    monkeypatch.setattr(pypi, cap, 1)
    records = [file(**{"requires-python": ">=3.8"}), file("2.0")]
    for legacy, run in ((False, cut_pypi_simple), (True, cut_pypi_json)):
        with pytest.raises(CutError):
            run(raw(records, legacy), CUTOFF)


def test_pypi_release_count_cap(monkeypatch):
    monkeypatch.setattr(pypi, "MAX_RELEASES", 0)
    with pytest.raises(CutError):
        cut_pypi_json(raw([file()], True), CUTOFF)


def test_pypi_deterministic_under_file_key_release_order_and_host_config(monkeypatch):
    records = [file("2.0"), file("0.9"), file()]
    for legacy, run in ((False, cut_pypi_simple), (True, cut_pypi_json)):
        expected = run(raw(records, legacy), CUTOFF)
        monkeypatch.setenv("TZ", "Pacific/Honolulu")
        monkeypatch.setenv("HOSTNAME", "host-secret")
        monkeypatch.setenv("LANG", "host-secret")
        reordered = [dict(reversed(list(entry.items()))) for entry in reversed(records)]
        assert run(raw(reordered, legacy), CUTOFF) == expected


@pytest.mark.parametrize("cutoff", [None, [], "host-secret", "2023-02-29T00:00:00Z"])
def test_pypi_invalid_cutoff_is_typed(cutoff):
    for run in (cut_pypi_json, cut_pypi_simple):
        with pytest.raises(CutError):
            run(b"", cutoff)


def test_pypi_arbitrary_short_input_never_escapes_typed_error():
    for value in range(256):
        for run in (cut_pypi_json, cut_pypi_simple):
            with pytest.raises(CutError):
                run(bytes([value]), CUTOFF)


def test_pypi_old_simple_api_undated_file_without_size_is_excluded_and_reported():
    entry = file()
    del entry["upload-time"]
    del entry["size"]
    index, report = cut_pypi_simple(raw([entry], meta={"api-version": "1.0"}), CUTOFF)
    assert report.unknown == (entry["filename"],)
    assert json.loads(index.simple_json)["files"] == []


@pytest.mark.parametrize("versions", [None, {}, [None], ["1.0\n"], ["host-secret"]])
def test_pypi_simple_versions_schema_is_validated(versions):
    with pytest.raises(CutError):
        cut_pypi_simple(raw([file()], versions=versions), CUTOFF)


def test_pypi_submicrosecond_cutoff_does_not_round_upload_into_world():
    for legacy, run in ((False, cut_pypi_simple), (True, cut_pypi_json)):
        _, report = run(raw([file()], legacy), "2023-04-01T00:00:00.000000999Z")
        assert report.kept == ()
        assert report.after_cutoff == ("demo_pkg-1.0.tar.gz",)


def test_pypi_legacy_sdist_hyphenated_version_matches_release_semantics():
    entry = file("1.0-rc1")
    entry["version"] = "1.0rc1"
    first = cut_pypi_simple(raw([entry]), CUTOFF)
    assert first == cut_pypi_json(raw([entry], True), CUTOFF)
    assert first[1].kept == ("demo_pkg-1.0-rc1.tar.gz",)


def test_pypi_empty_requires_python_is_a_valid_empty_constraint():
    index, _ = cut_pypi_simple(raw([file(**{"requires-python": ""})]), CUTOFF)
    assert json.loads(index.simple_json)["files"][0]["requires-python"] == ""
    assert b'data-requires-python=""' in index.simple_html


def test_pypi_null_size_fails_closed_even_on_excluded_records():
    for date in (None, AFTER):
        with pytest.raises(CutError):
            cut_pypi_simple(raw([file(date=date, size=None)]), CUTOFF)
