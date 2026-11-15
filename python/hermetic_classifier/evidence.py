"""Run evidence producer: build ``hermetic-run-evidence/v1`` from a real run's artifacts.

The classifier (``run.py``) trusts nothing it is not given; this module is the
host-side step that derives each fact from files instead of accepting asserted
flags:

* ``host.patched_firecracker`` and ``host.hypercall_block`` are true only when the
  Firecracker binary that ran hashes to the ``firecracker_sha256`` of a
  ``hermetic-firecracker-build/v1`` record whose ``patch_sha256`` and
  ``source_sha256`` equal the repository's pinned lock, and that hash differs
  from the unpatched release. The pinned patch is the host clock filter: it
  filters the KVM clock MSRs and blocks ``KVM_HC_CLOCK_PAIRING``, so both facts
  come from the same verified build.
* ``clockprobe`` is the guest probe's JSON-lines output, parsed strictly, plus
  an optional ``kernel_canary`` record.
* ``date_leak_observed`` comes from the run's ``run.json`` (D12); a missing or
  malformed value is never read as "no leak".

Every file is opened without following symlinks and read within a byte cap.
The produced document is checked by ``classify_run`` before it is returned, so
the producer cannot emit evidence the classifier would refuse.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from typing import Any

from .run import (
    INPUT_SCHEMA,
    MAX_PROBE_RECORDS,
    PROBE_RESULTS,
    RunEvidenceError,
    classify_run,
)

BUILD_SCHEMA = "hermetic-firecracker-build/v1"
MAX_LOCK_BYTES = 64 * 1024
MAX_RUN_JSON_BYTES = 1024 * 1024
MAX_PROBE_OUTPUT_BYTES = 1024 * 1024
MAX_FIRECRACKER_BYTES = 256 * 1024 * 1024
READ_CHUNK = 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _open(path: str | os.PathLike[str], cap: int) -> int:
    from hermetic_safe_io import open_regular

    try:
        return open_regular(path, cap)
    except (OSError, ValueError, TypeError):
        raise RunEvidenceError("evidence input refused (missing, symlink or not a regular file)") from None


def _read(path: str | os.PathLike[str], cap: int) -> bytes:
    fd = _open(path, cap)
    try:
        data = b""
        while len(data) <= cap:
            chunk = os.read(fd, min(READ_CHUNK, cap + 1 - len(data)))
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    if len(data) > cap:
        raise RunEvidenceError("evidence input exceeds byte cap")
    return data


def _sha256_file(path: str | os.PathLike[str], cap: int) -> str:
    fd = _open(path, cap)
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = os.read(fd, READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise RunEvidenceError("evidence input exceeds byte cap")
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


def _strict_json(data: bytes, name: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise RunEvidenceError(f"{name} has a duplicate key")
            out[key] = value
        return out

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except RunEvidenceError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise RunEvidenceError(f"{name} is not valid UTF-8 JSON") from None


def _hex(doc: dict[str, Any], key: str, name: str) -> str:
    value = doc.get(key)
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise RunEvidenceError(f"{name}.{key} must be 64 lowercase hex characters")
    return value


def host_facts(firecracker: str | os.PathLike[str], build_record: str | os.PathLike[str],
               pinned_lock: str | os.PathLike[str]) -> dict[str, bool]:
    """Derive the two host facts from the binary, its build record and the pinned lock."""
    build = _strict_json(_read(build_record, MAX_LOCK_BYTES), "build record")
    lock = _strict_json(_read(pinned_lock, MAX_LOCK_BYTES), "pinned lock")
    if not isinstance(build, dict) or not isinstance(lock, dict):
        raise RunEvidenceError("build record and pinned lock must be objects")
    if build.get("schema") != BUILD_SCHEMA:
        raise RunEvidenceError("unknown Firecracker build record schema")
    built = _hex(build, "firecracker_sha256", "build record")
    actual = _sha256_file(firecracker, MAX_FIRECRACKER_BYTES)
    patched = (
        actual == built
        and built != _hex(lock, "firecracker_sha256", "pinned lock")
        and _hex(build, "patch_sha256", "build record") == _hex(lock, "patch_sha256", "pinned lock")
        and _hex(build, "source_sha256", "build record") == _hex(lock, "source_sha256", "pinned lock")
    )
    return {"patched_firecracker": patched, "hypercall_block": patched}


def parse_probe_lines(data: bytes) -> list[dict[str, str]]:
    """Strictly parse guest probe JSON lines into evidence records."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise RunEvidenceError("probe output is not UTF-8") from None
    records: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if len(records) >= MAX_PROBE_RECORDS:
            raise RunEvidenceError("probe output exceeds record cap")
        value = _strict_json(line.encode("utf-8"), "probe record")
        if not isinstance(value, dict) or not {"probe", "result"} <= set(value) or set(value) - {
                "probe", "result", "value", "detail"}:
            raise RunEvidenceError("probe record has unexpected keys")
        if value["result"] not in PROBE_RESULTS:
            raise RunEvidenceError("probe record has an unknown result")
        record: dict[str, str] = {}
        for key in ("probe", "result", "value", "detail"):
            if key in value and value[key] is not None:
                if not isinstance(value[key], str):
                    raise RunEvidenceError("probe record fields must be strings")
                record[key] = value[key]
        records.append(record)
    if not records:
        raise RunEvidenceError("probe output has no records")
    return records


def date_leak_from_run_json(path: str | os.PathLike[str]) -> bool:
    doc = _strict_json(_read(path, MAX_RUN_JSON_BYTES), "run.json")
    if not isinstance(doc, dict) or type(doc.get("date_leak_observed")) is not bool:
        raise RunEvidenceError("run.json lacks a boolean date_leak_observed")
    return doc["date_leak_observed"]


def build_run_evidence(
    *,
    run_digest: str,
    world_sealed: bool,
    host: dict[str, bool] | None,
    clockprobe: list[dict[str, str]] | None,
    date_leak_observed: bool | None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble one microVM evidence document and check it with the classifier."""
    evidence: dict[str, Any] = {
        "schema": INPUT_SCHEMA,
        "run_digest": run_digest,
        "substrate": "microvm",
        "world_sealed": world_sealed,
    }
    if host is not None:
        evidence["host"] = host
    if clockprobe is not None:
        evidence["clockprobe"] = clockprobe
    if date_leak_observed is not None:
        evidence["date_leak_observed"] = date_leak_observed
    for key, value in (extra or {}).items():
        if key in evidence:
            raise RunEvidenceError("extra evidence cannot replace derived facts")
        evidence[key] = value
    classify_run(evidence)
    return evidence


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m hermetic_classifier.evidence")
    parser.add_argument("--run-digest", required=True)
    parser.add_argument("--world-sealed", choices=("true", "false"), required=True)
    parser.add_argument("--firecracker", required=True)
    parser.add_argument("--firecracker-build", required=True)
    parser.add_argument("--pinned-lock", required=True)
    parser.add_argument("--clockprobe", required=True, help="guest probe JSON lines")
    parser.add_argument("--canary", help="kernel_canary record (JSON line)")
    parser.add_argument("--run-json", required=True)
    args = parser.parse_args(argv)
    try:
        records = parse_probe_lines(_read(args.clockprobe, MAX_PROBE_OUTPUT_BYTES))
        if args.canary:
            records += parse_probe_lines(_read(args.canary, MAX_PROBE_OUTPUT_BYTES))
        evidence = build_run_evidence(
            run_digest=args.run_digest,
            world_sealed=args.world_sealed == "true",
            host=host_facts(args.firecracker, args.firecracker_build, args.pinned_lock),
            clockprobe=records,
            date_leak_observed=date_leak_from_run_json(args.run_json),
        )
    except RunEvidenceError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
