"""D10 verification of archive provenance against per-record payload fingerprints.

The sealer writes one provenance manifest (schema `hermetic.d10.provenance/1`)
for the archived pages it ships::

    {"schema": "hermetic.d10.provenance/1",
     "records": [{"path": "archive/pages.warc.gz!pages.warc", "record": 1,
                  "payload_sha256": "<64 hex>",
                  "revision_date": "2020-01-01T00:00:00Z",
                  "scrub": "applied" | "not_applicable"}],
     "scrubbed_payloads": ["<64 hex>", ...]}

`revision_date` is the revision the mutable-content rule selected; `scrub`
states whether the target-thread scrub touched the record;
`scrubbed_payloads` are fingerprints of the content the scrub removed.
Verification is strict and complete: every scanned WARC record must have
exactly one matching entry (same payload fingerprint), every entry must match
a scanned record, revisions must be at or before T_clock, and no record may
carry a scrubbed payload. An incomplete scan never verifies.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from hermetic_d10.carriers import HermeticD10Error, parse_rfc3339_utc
from hermetic_d10.scan import ScanResult

PROVENANCE_SCHEMA = "hermetic.d10.provenance/1"
MAX_PROVENANCE_BYTES = 8 * 1024 * 1024
MAX_PROVENANCE_RECORDS = 100_000
MAX_ISSUES = 1000
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RECORD_KEYS = {"path", "record", "payload_sha256", "revision_date", "scrub"}
_SCRUB_VALUES = {"applied", "not_applicable"}
_WARC_MEMBER = re.compile(r"^<warc:([1-9][0-9]{0,8})>$")


class ProvenanceError(HermeticD10Error):
    """The provenance manifest is malformed; nothing is verified."""


def _rel_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ProvenanceError("provenance path must be a safe relative path")
    return value


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ProvenanceError("duplicate provenance key")
        out[key] = value
    return out


def parse_provenance(data: bytes) -> tuple[dict[tuple[str, int], dict[str, Any]], frozenset[str]]:
    """Strictly parse a manifest into {(path, record): entry} and the scrubbed set."""
    if len(data) > MAX_PROVENANCE_BYTES:
        raise ProvenanceError("provenance manifest exceeds byte cap")
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ProvenanceError("provenance manifest is not valid UTF-8 JSON") from None
    if not isinstance(doc, dict) or set(doc) != {"schema", "records", "scrubbed_payloads"}:
        raise ProvenanceError("provenance manifest has unexpected keys")
    if doc["schema"] != PROVENANCE_SCHEMA:
        raise ProvenanceError("unsupported provenance schema")
    records, scrubbed = doc["records"], doc["scrubbed_payloads"]
    if not isinstance(records, list) or not isinstance(scrubbed, list):
        raise ProvenanceError("records and scrubbed_payloads must be lists")
    if len(records) > MAX_PROVENANCE_RECORDS or len(scrubbed) > MAX_PROVENANCE_RECORDS:
        raise ProvenanceError("provenance record cap exceeded")
    if not all(isinstance(h, str) and _HEX64.fullmatch(h) for h in scrubbed):
        raise ProvenanceError("scrubbed payload fingerprints must be lowercase sha256 hex")
    out: dict[tuple[str, int], dict[str, Any]] = {}
    for raw in records:
        if not isinstance(raw, dict) or set(raw) != _RECORD_KEYS:
            raise ProvenanceError("provenance record has unexpected keys")
        path = _rel_path(raw["path"])
        record = raw["record"]
        if type(record) is not int or not 1 <= record <= 999_999_999:
            raise ProvenanceError("provenance record index must be a positive integer")
        digest = raw["payload_sha256"]
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise ProvenanceError("payload_sha256 must be lowercase sha256 hex")
        if not isinstance(raw["scrub"], str) or raw["scrub"] not in _SCRUB_VALUES:
            raise ProvenanceError("scrub must be 'applied' or 'not_applicable'")
        if not isinstance(raw["revision_date"], str):
            raise ProvenanceError("revision_date must be an RFC 3339 UTC string")
        try:
            revision = parse_rfc3339_utc(raw["revision_date"])
        except (HermeticD10Error, ValueError, OverflowError):
            raise ProvenanceError("revision_date must be an RFC 3339 UTC string") from None
        key = (path, record)
        if key in out:
            raise ProvenanceError("duplicate provenance record")
        out[key] = {"payload_sha256": digest, "revision": revision, "scrub": raw["scrub"]}
    return out, frozenset(scrubbed)


def _record_key(finding: Any) -> tuple[str, int] | None:
    if finding.carrier != "warc_date" or not finding.member_chain:
        return None
    # A record inside a compressed or nested capture is named by its full
    # member chain, e.g. `archive/pages.warc.gz!pages.warc`.
    path = "!".join([finding.path, *finding.member_chain[:-1]])
    match = _WARC_MEMBER.fullmatch(finding.member_chain[-1])
    return (path, int(match.group(1))) if match else None


def verify_provenance(scan: ScanResult, manifest: bytes, t_clock: datetime) -> dict[str, Any]:
    """Return a report with verdict 'verified', 'gate' (issues) or 'error'."""
    report: dict[str, Any] = {"detector": "D10", "check": "provenance", "issues": []}
    try:
        entries, scrubbed = parse_provenance(manifest)
    except ProvenanceError as exc:
        report.update(verdict="error", error=str(exc))
        return report
    if not scan.is_complete():
        report.update(verdict="error", error="scan incomplete; provenance cannot be verified")
        return report
    issues: list[dict[str, Any]] = []

    def issue(path: str, record: int, kind: str) -> None:
        if len(issues) < MAX_ISSUES:
            issues.append({"path": path, "record": record, "issue": kind})

    seen: set[tuple[str, int]] = set()
    for finding in scan.findings:
        key = _record_key(finding)
        if key is None:
            continue
        path, record = key
        seen.add(key)
        digest = finding.payload_sha256
        if digest in scrubbed:
            issue(path, record, "scrubbed_payload_present")
        entry = entries.get(key)
        if entry is None:
            issue(path, record, "record_without_provenance")
            continue
        if entry["payload_sha256"] != digest:
            issue(path, record, "payload_fingerprint_mismatch")
        if entry["revision"] > t_clock:
            issue(path, record, "revision_after_t_clock")
    for path, record in sorted(set(entries) - seen):
        issue(path, record, "provenance_without_record")
    issues.sort(key=lambda i: (i["path"], i["record"], i["issue"]))
    report["issues"] = issues
    report["truncated"] = len(issues) >= MAX_ISSUES
    report["verdict"] = "gate" if issues else "verified"
    return report
