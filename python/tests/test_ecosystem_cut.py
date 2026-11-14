"""Offline known-answer and hostile-input tests for Phase 4 ecosystem filters."""

import json
import pytest

from hermetic_ecosystem_cut import CutError, CutReport, cut_crates_index, cut_go_versions
from hermetic_ecosystem_cut import cut

CUTOFF = "2023-04-01T00:00:00.000000001Z"
BEFORE = "2023-04-01T00:00:00Z"
AFTER = "2023-04-01T00:00:00.000000002Z"


def crate(version="1.0.0", date=CUTOFF, **extra):
    return dict(name="demo", vers=version, deps=[], features={}, cksum="a" * 64,
                yanked=False, pubtime=date, **extra)


def lines(*records):
    return b"".join(json.dumps(record).encode() + b"\n" for record in records)


def info(version, date=CUTOFF, **extra):
    return json.dumps(dict(Version=version, Time=date, **extra)).encode()


def test_crates_cutoff_nanosecond_boundary_and_unknown_dates():
    old = crate("0.1.0", BEFORE)
    current = crate()
    current["yanked"] = True
    current["features"] = {"default": ["serde"]}
    output, report = cut_crates_index(
        lines(crate("3.0.0", None), crate("2.0.0", AFTER), current, old), CUTOFF)
    assert report == CutReport(("0.1.0", "1.0.0"), ("2.0.0",), ("3.0.0",),
                               ("0.1.0", "1.0.0"))
    records = [json.loads(line) for line in output.splitlines()]
    assert [record["vers"] for record in records] == ["0.1.0", "1.0.0"]
    assert all(record["yanked"] is False for record in records)
    assert records[1]["features"] == {"default": ["serde"]}
    assert records[1]["cksum"] == "a" * 64
    assert b"2.0.0" not in output and b"3.0.0" not in output


def test_crates_missing_pubtime_is_reported():
    record = crate()
    del record["pubtime"]
    assert cut_crates_index(lines(record), CUTOFF) == (
        b"", CutReport((), (), ("1.0.0",)))


def test_crates_known_answer_and_order_independence():
    record = crate()
    expected = (b'{"cksum":"' + b"a" * 64 +
                b'","deps":[],"features":{},"name":"demo",'
                b'"pubtime":"2023-04-01T00:00:00.000000001Z",'
                b'"vers":"1.0.0","yanked":false}\n')
    assert cut_crates_index(lines(record), CUTOFF)[0] == expected
    records = [crate("1.0.0"), crate("0.1.0")]
    reversed_keys = [dict(reversed(list(item.items()))) for item in reversed(records)]
    assert cut_crates_index(lines(*records), CUTOFF) == cut_crates_index(
        lines(*reversed_keys), CUTOFF)


def test_go_cutoff_and_output_contains_only_admitted_info():
    infos = {"v1.0.0": info("v1.0.0", BEFORE), "v1.1.0": info("v1.1.0"),
             "v2.0.0": info("v2.0.0", AFTER), "v3.0.0": info("v3.0.0", None)}
    output, kept, report = cut_go_versions(
        b"v4.0.0\nv3.0.0\nv2.0.0\nv1.1.0\nv1.0.0\n", infos, CUTOFF)
    assert output == b"v1.0.0\nv1.1.0\n"
    assert list(kept) == ["v1.0.0", "v1.1.0"]
    assert report == CutReport(("v1.0.0", "v1.1.0"), ("v2.0.0",),
                               ("v3.0.0", "v4.0.0"))


def test_go_known_answer_strips_origin_and_is_order_independent():
    original = {"v1.0.0": info("v1.0.0", Origin={"URL": "/host/secret"}),
                "v0.1.0": info("v0.1.0", BEFORE)}
    first = cut_go_versions(b"v1.0.0\nv0.1.0\n", original, CUTOFF)
    second = cut_go_versions(b"v0.1.0\nv1.0.0\n", dict(reversed(list(original.items()))), CUTOFF)
    assert first == second
    assert first[1]["v1.0.0"] == (
        b'{"Time":"2023-04-01T00:00:00.000000001Z","Version":"v1.0.0"}')
    assert b"secret" not in b"".join(first[1].values())


@pytest.mark.parametrize("raw", [b"\xff", b"{}", b"[]", b"null", b"{", b"\n",
                                    b'{"vers":"1.0.0","vers":"2.0.0"}',
                                    b'{"name":"demo","extension":1e999}',
                                    b'{"a":' * 30 + b"0" + b"}" * 30])
def test_crates_malformed_records_fail_closed(raw):
    with pytest.raises(CutError):
        cut_crates_index(raw, CUTOFF)


@pytest.mark.parametrize("changes", [{"name": "../secret"}, {"vers": "../secret"},
    {"name": "0bad"}, {"cksum": "wrong"}, {"yanked": 1}, {"deps": {}},
    {"features": []}, {"unexpected": "future"}, {"pubtime": "2023-02-30T00:00:00Z"},
    {"pubtime": []}, {"pubtime": "2023-04-01"}])
def test_crates_invalid_schema_fails_closed(changes):
    record = crate()
    record.update(changes)
    with pytest.raises(CutError):
        cut_crates_index(lines(record), CUTOFF)


def test_crates_duplicate_versions_and_mixed_names_fail_closed():
    other = crate("2.0.0")
    other["name"] = "other"
    for raw in (lines(crate(), crate()), lines(crate(), other),
                lines(crate(), crate("1.0.0+build"))):
        with pytest.raises(CutError):
            cut_crates_index(raw, CUTOFF)


@pytest.mark.parametrize("raw", [b"v1.0.0\nv1.0.0\n", b"../secret\n", b"v1.0.0\x00\n",
                                    b"\xff\n", b"latest\n", b"1.0.0\n", b"\n"])
def test_go_invalid_version_list_fails_closed(raw):
    with pytest.raises(CutError):
        cut_go_versions(raw, {}, CUTOFF)


@pytest.mark.parametrize("raw", [b'{}', b'[]', b'null', b'NaN', b'\xff',
    b'{"Version":"v2.0.0","Time":null}',
    b'{"Version":"v1.0.0","Version":"v1.0.0"}',
    info("v1.0.0", "bad"), info("v1.0.0", 42)])
def test_go_bad_info_fails_closed(raw):
    with pytest.raises(CutError):
        cut_go_versions(b"v1.0.0\n", {"v1.0.0": raw}, CUTOFF)


def test_go_unlisted_info_fails_closed():
    with pytest.raises(CutError):
        cut_go_versions(b"", {"v1.0.0": info("v1.0.0")}, CUTOFF)


def test_go_missing_time_is_unknown():
    assert cut_go_versions(b"v1.0.0", {"v1.0.0": b'{"Version":"v1.0.0"}'}, CUTOFF) == (
        b"", {}, CutReport((), (), ("v1.0.0",)))


def test_empty_inputs():
    assert cut_crates_index(b"", CUTOFF) == (b"", CutReport((), (), ()))
    assert cut_go_versions(b"", {}, CUTOFF) == (b"", {}, CutReport((), (), ()))


@pytest.mark.parametrize("cap,value", [("MAX_INPUT_BYTES", 8), ("MAX_RECORD_BYTES", 8),
                                       ("MAX_OUTPUT_BYTES", 8), ("MAX_RECORDS", 0)])
def test_crates_named_caps(monkeypatch, cap, value):
    monkeypatch.setattr(cut, cap, value)
    with pytest.raises(CutError):
        cut_crates_index(lines(crate()), CUTOFF)


def test_go_aggregate_cap(monkeypatch):
    data = info("v1.0.0")
    monkeypatch.setattr(cut, "MAX_INPUT_BYTES", len(data))
    with pytest.raises(CutError):
        cut_go_versions(b"v1.0.0\n", {"v1.0.0": data}, CUTOFF)


@pytest.mark.parametrize("cap,value", [("MAX_RECORD_BYTES", 8), ("MAX_RECORDS", 0)])
def test_go_named_caps(monkeypatch, cap, value):
    monkeypatch.setattr(cut, cap, value)
    with pytest.raises(CutError):
        cut_go_versions(b"v1.0.0\n", {"v1.0.0": info("v1.0.0")}, CUTOFF)


@pytest.mark.parametrize("cutoff", [None, [], "bad /host/secret", "2023-02-30T00:00:00Z"])
def test_invalid_cutoff_is_sanitized(cutoff):
    for run in (lambda: cut_crates_index(b"", cutoff),
                lambda: cut_go_versions(b"", {}, cutoff)):
        with pytest.raises(CutError) as error:
            run()
        assert "secret" not in str(error.value)


def test_arbitrary_short_byte_inputs_never_escape_typed_errors():
    for value in range(256):
        raw = bytes([value])
        for run in (lambda: cut_crates_index(raw, CUTOFF),
                    lambda: cut_go_versions(raw, {}, CUTOFF)):
            try:
                run()
            except CutError:
                pass
