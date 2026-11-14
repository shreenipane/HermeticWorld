"""D10 per-record payload fingerprints and provenance verification."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest

from hermetic_d10 import scan_tree
from hermetic_d10.provenance import (
    PROVENANCE_SCHEMA,
    ProvenanceError,
    parse_provenance,
    verify_provenance,
)
from hermetic_d10.carriers import parse_rfc3339_utc

CLOCK = "2025-05-01T00:00:00Z"
T = parse_rfc3339_utc(CLOCK)


def warc(payload: bytes, date: bytes = b"2025-04-01T00:00:00Z") -> bytes:
    return (b"WARC/1.1\r\nWARC-Type: response\r\nWARC-Date: " + date
            + b"\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n"
            + payload + b"\r\n\r\n")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def rec(path: str, record: int, payload: bytes, **over: object) -> dict:
    r = {"path": path, "record": record, "payload_sha256": sha(payload),
         "revision_date": "2025-01-01T00:00:00Z", "scrub": "not_applicable"}
    r.update(over)
    return r


def manifest(records: list[dict], scrubbed: list[str] | None = None) -> bytes:
    return json.dumps({"schema": PROVENANCE_SCHEMA, "records": records,
                       "scrubbed_payloads": scrubbed or []}).encode()


def test_every_warc_record_carries_a_payload_fingerprint(tmp_path: Path) -> None:
    (tmp_path / "a.warc").write_bytes(warc(b"one") + warc(b"two\r\n\r\nWARC/1.1"))
    result = scan_tree(tmp_path, CLOCK)
    digests = [f.to_dict()["payload_sha256"] for f in result.findings]
    assert digests == [sha(b"one"), sha(b"two\r\n\r\nWARC/1.1")]


def test_matching_provenance_verifies_plain_and_gzip(tmp_path: Path) -> None:
    (tmp_path / "a.warc").write_bytes(warc(b"one") + warc(b"two"))
    (tmp_path / "b.warc.gz").write_bytes(gzip.compress(warc(b"three"), mtime=0))
    result = scan_tree(tmp_path, CLOCK)
    gz = next(f for f in result.findings if f.path == "b.warc.gz")
    gz_key = "!".join([gz.path, *gz.member_chain[:-1]])
    m = manifest([rec("a.warc", 1, b"one"), rec("a.warc", 2, b"two"),
                  rec(gz_key, 1, b"three", scrub="applied")])
    report = verify_provenance(result, m, T)
    assert report["verdict"] == "verified", report
    assert report["issues"] == []


def test_provenance_mismatches_gate_with_relative_names(tmp_path: Path) -> None:
    (tmp_path / "a.warc").write_bytes(warc(b"one") + warc(b"leaked fix") + warc(b"three"))
    result = scan_tree(tmp_path, CLOCK)
    m = manifest(
        [rec("a.warc", 1, b"other"),
         rec("a.warc", 2, b"leaked fix"),
         rec("a.warc", 4, b"ghost"),
         rec("a.warc", 3, b"three", revision_date="2025-06-01T00:00:00Z")],
        scrubbed=[sha(b"leaked fix")],
    )
    report = verify_provenance(result, m, T)
    assert report["verdict"] == "gate"
    assert [(i["record"], i["issue"]) for i in report["issues"]] == [
        (1, "payload_fingerprint_mismatch"),
        (2, "scrubbed_payload_present"),
        (3, "revision_after_t_clock"),
        (4, "provenance_without_record"),
    ]
    assert str(tmp_path) not in json.dumps(report)


def test_record_without_provenance_gates(tmp_path: Path) -> None:
    (tmp_path / "a.warc").write_bytes(warc(b"one"))
    report = verify_provenance(scan_tree(tmp_path, CLOCK), manifest([]), T)
    assert report["issues"] == [{"path": "a.warc", "record": 1, "issue": "record_without_provenance"}]


def test_incomplete_scan_never_verifies(tmp_path: Path) -> None:
    (tmp_path / "bad.warc").write_bytes(b"WARC/1.1\r\nContent-Length: 999\r\n\r\nshort")
    report = verify_provenance(scan_tree(tmp_path, CLOCK), manifest([]), T)
    assert report["verdict"] == "error"


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff",
        b"[" * 100000,
        b"{}",
        json.dumps({"schema": "x", "records": [], "scrubbed_payloads": []}).encode(),
        manifest([rec("../a.warc", 1, b"x")]),
        manifest([rec("/abs.warc", 1, b"x")]),
        manifest([rec("a\\b.warc", 1, b"x")]),
        manifest([rec("a.warc", 0, b"x")]),
        manifest([rec("a.warc", True, b"x")]),
        manifest([rec("a.warc", 1, b"x", payload_sha256="ABC")]),
        manifest([rec("a.warc", 1, b"x", scrub="maybe")]),
        manifest([rec("a.warc", 1, b"x", revision_date="yesterday")]),
        manifest([rec("a.warc", 1, b"x", revision_date=5)]),
        manifest([{**rec("a.warc", 1, b"x"), "extra": 1}]),
        manifest([rec("a.warc", 1, b"x"), rec("a.warc", 1, b"x")]),
        manifest([], scrubbed=["nothex"]),
    ],
)
def test_hostile_provenance_manifests_are_refused(raw: bytes, tmp_path: Path) -> None:
    with pytest.raises(ProvenanceError):
        parse_provenance(raw)
    (tmp_path / "a.warc").write_bytes(warc(b"x"))
    report = verify_provenance(scan_tree(tmp_path, CLOCK), raw, T)
    assert report["verdict"] == "error"


def test_oversized_manifest_is_refused() -> None:
    from hermetic_d10.provenance import MAX_PROVENANCE_BYTES

    with pytest.raises(ProvenanceError, match="cap"):
        parse_provenance(b" " * (MAX_PROVENANCE_BYTES + 1))
