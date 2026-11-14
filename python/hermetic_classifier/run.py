"""Run classifier: combine host-side evidence into a run's labels (TR-CLS-1, TR-CLS-2)
and its clock level (TR-VMM-3, architecture section 8.1).

Input is one JSON document (``hermetic-run-evidence/v1``); output is one JSON
document (``hermetic-run-classification/v1``). Pure, deterministic, bounded,
fail closed: any structural problem raises ``RunEvidenceError``; any gap in the
clock evidence lowers the level to ``faked``, never raises it.

Clock rules:
  * substrate ``container`` -> ``real`` (nothing sets the clock).
  * substrate ``microvm`` -> ``hidden`` only when all hold, else ``faked``:
      - ``host.patched_firecracker`` is true (enforce-PV-CPUID patch build);
      - ``host.hypercall_block`` is true (host-side KVM_HC_CLOCK_PAIRING block);
      - the clock probe is complete: every name in ``REQUIRED_PROBES`` appears
        exactly once and no other name appears;
      - every record is ``blocked``, except ``clock_pairing_hc``, which may be
        ``unavailable`` (the probe never issues the call) only when
        ``kernel_canary`` is ``blocked`` (the ring-0 canary covers it);
      - ``date_leak_observed`` (D12) is not true.

Status precedence mirrors ``hermetic-attest`` ``compute_run_status``:
gate_blocked, infra_error, tampered, limit_exceeded, review, unresolved, resolved.
"""

from __future__ import annotations

import json
from typing import Any

import sys

from .baseline import (
    MAX_PATCH_BYTES,
    ClassifierError,
    classify,
    run_status_hint,
    safe_read_file,
    validate_run_digest,
)

INPUT_SCHEMA = "hermetic-run-evidence/v1"
OUTPUT_SCHEMA = "hermetic-run-classification/v1"

MAX_INPUT_BYTES = MAX_PATCH_BYTES
MAX_PROBE_RECORDS = 64
MAX_STRING_CHARS = 4096
MAX_JSON_DEPTH = 8

REQUIRED_PROBES = frozenset(
    {
        "rdtsc",
        "cpuid",
        "kvmclock_msr",
        "clock_pairing_hc",
        "rtc_sysfs_dev",
        "proc_driver_rtc",
        "hpet",
        "dmesg_dates",
        "clocksource_sysfs",
        "posix_clocks",
        "vmclock",
        "cpuinfo",
        "module_load",
        "ring0_paths",
        "kernel_canary",
    }
)
PROBE_RESULTS = frozenset({"blocked", "leak", "unavailable", "error"})
SUBSTRATES = frozenset({"container", "microvm"})
R0_VALUES = frozenset({"pass", "fail"})
CHECK_VALUES = frozenset({"clean", "tripped"})

_TOP_KEYS = frozenset(
    {
        "schema",
        "run_digest",
        "substrate",
        "world_sealed",
        "host",
        "clockprobe",
        "date_leak_observed",
        "sealcheck",
        "grader",
        "patches",
        "infra_error",
        "limit_exceeded",
        "netvm_malformed_frame",
    }
)
_REQUIRED_TOP = frozenset({"schema", "run_digest", "substrate", "world_sealed"})
_HOST_KEYS = frozenset({"patched_firecracker", "hypercall_block"})
_SEALCHECK_KEYS = frozenset({"blocked", "leak"})
_GRADER_KEYS = frozenset({"r0", "r1", "r2", "r3"})
_PATCH_KEYS = frozenset({"agent", "gold"})
_RECORD_KEYS = frozenset({"probe", "result", "value", "detail"})


class RunEvidenceError(ClassifierError):
    """Malformed, oversized or contradictory run evidence."""


def _no_dup_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise RunEvidenceError("duplicate key in evidence")
        out[key] = value
    return out


def _reject_float(_text: str) -> Any:
    raise RunEvidenceError("floats are not allowed in evidence")


def _reject_constant(_text: str) -> Any:
    raise RunEvidenceError("non-finite numbers are not allowed in evidence")


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise RunEvidenceError("evidence nested too deeply")
    if isinstance(value, dict):
        for item in value.values():
            _check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, depth + 1)


def parse_evidence(raw: bytes | str) -> dict[str, Any]:
    """Parse evidence JSON strictly: bounded size, no duplicate keys, no floats."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    if len(raw) > MAX_INPUT_BYTES:
        raise RunEvidenceError("evidence exceeds size cap")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise RunEvidenceError("evidence is not UTF-8") from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_no_dup_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except RunEvidenceError:
        raise
    except (ValueError, RecursionError):
        raise RunEvidenceError("evidence is not valid JSON") from None
    _check_depth(value)
    if not isinstance(value, dict):
        raise RunEvidenceError("evidence must be a JSON object")
    return value


def _obj(value: Any, name: str, keys: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RunEvidenceError(f"{name} must be an object")
    unknown = set(value) - keys
    if unknown:
        raise RunEvidenceError(f"{name} has unknown keys")
    return value


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise RunEvidenceError(f"{name} must be a boolean")
    return value


def _opt_bool(value: Any, name: str) -> bool | None:
    return None if value is None else _bool(value, name)


def _str(value: Any, name: str, *, cap: int = MAX_STRING_CHARS) -> str:
    if not isinstance(value, str):
        raise RunEvidenceError(f"{name} must be a string")
    if len(value) > cap:
        raise RunEvidenceError(f"{name} exceeds length cap")
    return value


def _enum(value: Any, name: str, allowed: frozenset[str]) -> str:
    text = _str(value, name)
    if text not in allowed:
        raise RunEvidenceError(f"{name} has an unknown value")
    return text


def _opt_enum(value: Any, name: str, allowed: frozenset[str]) -> str | None:
    return None if value is None else _enum(value, name, allowed)


def _probe_records(value: Any) -> list[tuple[str, str]] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise RunEvidenceError("clockprobe must be a list")
    if len(value) > MAX_PROBE_RECORDS:
        raise RunEvidenceError("clockprobe exceeds record cap")
    out = []
    for rec in value:
        rec = _obj(rec, "clockprobe record", _RECORD_KEYS)
        if "probe" not in rec or "result" not in rec:
            raise RunEvidenceError("clockprobe record lacks probe or result")
        name = _str(rec["probe"], "probe", cap=64)
        result = _enum(rec["result"], "result", PROBE_RESULTS)
        for extra in ("value", "detail"):
            if extra in rec:
                _str(rec[extra], extra)
        out.append((name, result))
    return out


def clock_level(
    substrate: str,
    host: dict[str, Any] | None,
    records: list[tuple[str, str]] | None,
    date_leak_observed: bool | None,
) -> tuple[str, list[str]]:
    """Return (level, sorted reasons). Reasons explain why a microVM is not hidden."""
    if substrate == "container":
        return "real", ["container_substrate"]
    reasons: set[str] = set()
    host = host or {}
    if host.get("patched_firecracker") is not True:
        reasons.add("no_patched_firecracker")
    if host.get("hypercall_block") is not True:
        reasons.add("no_hypercall_block")
    if date_leak_observed is True:
        reasons.add("date_leak_observed")
    if records is None:
        reasons.add("probe_missing")
    else:
        seen: dict[str, str] = {}
        for name, result in records:
            if name in seen:
                reasons.add("probe_duplicate")
            elif name not in REQUIRED_PROBES:
                reasons.add("probe_unknown_record")
            seen.setdefault(name, result)
        if REQUIRED_PROBES - set(seen):
            reasons.add("probe_incomplete")
        canary_blocked = seen.get("kernel_canary") == "blocked"
        for name, result in records:
            if result == "blocked":
                continue
            if name == "clock_pairing_hc" and result == "unavailable" and canary_blocked:
                continue
            reasons.add("probe_leak" if result == "leak" else "probe_not_blocked")
    if reasons:
        return "faked", sorted(reasons)
    return "hidden", []


def classify_run(evidence: dict[str, Any]) -> dict[str, Any]:
    """Classify one run from parsed evidence. Raises RunEvidenceError on bad input."""
    ev = _obj(evidence, "evidence", _TOP_KEYS)
    missing = _REQUIRED_TOP - set(ev)
    if missing:
        raise RunEvidenceError("evidence lacks required keys")
    if ev["schema"] != INPUT_SCHEMA:
        raise RunEvidenceError("unknown evidence schema")
    digest = _str(ev["run_digest"], "run_digest", cap=80)
    try:
        validate_run_digest(digest)
    except ClassifierError:
        raise RunEvidenceError("run_digest is invalid") from None
    substrate = _enum(ev["substrate"], "substrate", SUBSTRATES)
    sealed = _bool(ev["world_sealed"], "world_sealed")
    host = ev.get("host")
    if host is not None:
        host = _obj(host, "host", _HOST_KEYS)
        for key in host:
            _bool(host[key], f"host.{key}")
    records = _probe_records(ev.get("clockprobe"))
    if substrate == "container" and (records is not None or host is not None):
        raise RunEvidenceError("container substrate cannot carry microVM clock evidence")
    date_leak = _opt_bool(ev.get("date_leak_observed"), "date_leak_observed")
    seal = _obj(ev.get("sealcheck") or {}, "sealcheck", _SEALCHECK_KEYS)
    gate_blocked = _opt_bool(seal.get("blocked"), "sealcheck.blocked") is True
    gate_leak = _opt_bool(seal.get("leak"), "sealcheck.leak")
    grader = _obj(ev.get("grader") or {}, "grader", _GRADER_KEYS)
    r0 = _opt_enum(grader.get("r0"), "r0", R0_VALUES)
    r1 = _opt_enum(grader.get("r1"), "r1", CHECK_VALUES)
    r2 = _opt_enum(grader.get("r2"), "r2", CHECK_VALUES)
    r3 = _opt_enum(grader.get("r3"), "r3", CHECK_VALUES)
    if gate_blocked and r0 is not None:
        raise RunEvidenceError("gate-blocked run cannot carry grader verdicts")
    infra = _opt_bool(ev.get("infra_error"), "infra_error") is True
    limit = _opt_bool(ev.get("limit_exceeded"), "limit_exceeded") is True
    malformed_frame = _opt_bool(ev.get("netvm_malformed_frame"), "netvm_malformed_frame") is True
    patches = ev.get("patches")
    if patches is not None:
        patches = _obj(patches, "patches", _PATCH_KEYS)
        if set(patches) != _PATCH_KEYS:
            raise RunEvidenceError("patches needs agent and gold")
        for key in _PATCH_KEYS:
            if not isinstance(patches[key], str):
                raise RunEvidenceError("patch must be a string")

    level, clock_reasons = clock_level(substrate, host, records, date_leak)
    flags: set[str] = set()
    if date_leak is True:
        flags.add("date_leak_observed")
    elif date_leak is None:
        flags.add("date_sentinel_not_run")
    if gate_leak is None and not gate_blocked:
        flags.add("sealcheck_not_run")

    label: str | None = None
    confidence: int | None = None
    review = False
    if r0 == "pass" and not gate_blocked:
        if patches is None:
            flags.add("unclassified_success")
            review = True
        else:
            result = classify(patches["agent"], patches["gold"])
            label, confidence = result.label, result.confidence
            hint = run_status_hint(label, sealed, gate_leak is True)
            if hint == "review":
                review = True
                if label == "retrieved" and sealed:
                    flags.add("retrieved_in_sealed_world")
                if (label == "retrieved") != (gate_leak is True):
                    flags.add("gate_classifier_disagreement")
    if r0 is None and not gate_blocked:
        flags.add("r0_missing")
    for name, value in (("r1", r1), ("r2", r2), ("r3", r3)):
        if value is None and r0 is not None:
            flags.add(f"{name}_not_run")
        elif value == "tripped":
            flags.add(f"{name}_tripped")
    if r3 == "tripped" or date_leak is True:
        review = True

    if gate_blocked:
        status = "gate_blocked"
    elif infra:
        status = "infra_error"
    elif malformed_frame or r1 == "tripped" or r2 == "tripped":
        status = "tampered"
    elif limit:
        status = "limit_exceeded"
    elif review:
        status = "review"
    elif r0 != "pass":
        status = "unresolved"
    else:
        status = "resolved"

    return {
        "schema": OUTPUT_SCHEMA,
        "run_digest": digest,
        "clock": level,
        "clock_reasons": clock_reasons,
        "label": label,
        "confidence": confidence,
        "status": status,
        "flags": sorted(flags),
    }


def classification_to_json(result: dict[str, Any]) -> str:
    return json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def main(argv: list[str] | None = None) -> int:
    """``python -m hermetic_classifier.run EVIDENCE_FILE``: print the classification JSON.

    Exit 0 on success, 1 on any error (message names no input content).
    """
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        sys.stderr.write("usage: python -m hermetic_classifier.run EVIDENCE_FILE\n")
        return 1
    try:
        text = safe_read_file(args[0], max_bytes=MAX_INPUT_BYTES)
        result = classify_run(parse_evidence(text))
    except ClassifierError as err:
        sys.stderr.write(f"run classifier error: {err}\n")
        return 1
    except (OSError, ValueError):
        sys.stderr.write("run classifier error: cannot read evidence\n")
        return 1
    sys.stdout.write(classification_to_json(result) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
