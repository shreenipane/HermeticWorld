"""Fail-closed escape probe evaluator with evidence sanitisation and canonical digesting."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
import stat
from typing import Any

DEFAULT_RESULTS_CAP_BYTES = 4 * 1024 * 1024
MAX_CHECKS = 1000
MAX_EVIDENCE_INPUT_LEN = 4096
MAX_EVIDENCE_OUTPUT_LEN = 256
MAX_ID_LEN = 128
MAX_VERSION_LEN = 128
MAX_JSON_DEPTH = 8
MAX_JSON_TOKENS = 200_000
MAX_OBJECT_KEYS = 10_000
READ_CHUNK_BYTES = 65_536

NEGATIVE_CHECK_IDS = frozenset(
    {
        "dns_lookup_unknown",
        "dns_delegation",
        "raw_ip",
        "icmp",
        "ipv6",
        "quic",
        "vsock_host_ports",
        "kvmclock_msr",
        "clock_pairing_hypercall",
        "gateway_abuse",
        "model_call_date_scan",
    }
)

POSITIVE_CHECK_IDS = frozenset(
    {
        "pip_install",
        "git_clone",
        "curl_fetch",
        "getrandom_nonblocking",
    }
)

ALL_REQUIRED_CHECK_IDS = NEGATIVE_CHECK_IDS | POSITIVE_CHECK_IDS

_VALID_OUTCOMES = frozenset({"blocked", "escaped", "error", "passed", "failed"})
_ROOT_ALLOWED_KEYS = frozenset({"probe_version", "checks"})
_CHECK_ALLOWED_KEYS = frozenset({"id", "outcome", "evidence"})


class HermeticProbeEvalError(Exception):
    """Base typed error for hermetic_probe_eval."""

    code: str = "HERMETIC_PROBE_EVAL_ERROR"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class CapExceededError(HermeticProbeEvalError):
    code: str = "CAP_EXCEEDED"


class FileSafetyError(HermeticProbeEvalError):
    code: str = "FILE_SAFETY_ERROR"


class JsonParseError(HermeticProbeEvalError):
    code: str = "JSON_PARSE_ERROR"


class ValidationError(HermeticProbeEvalError):
    code: str = "VALIDATION_ERROR"


class ProbeVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ESCAPE = "escape"


@dataclass(frozen=True)
class ProbeEvalReport:
    verdict: str
    failed: list[dict[str, str]]
    escaped: list[str]
    missing: list[str]
    unknown: list[str]
    digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "failed": list(self.failed),
            "escaped": list(self.escaped),
            "missing": list(self.missing),
            "unknown": list(self.unknown),
            "digest": self.digest,
        }


def sanitise_evidence(raw_evidence: str) -> str:
    """Truncate evidence to 256 chars and replace all non-printable ASCII with '?'."""
    prefix = raw_evidence[:MAX_EVIDENCE_OUTPUT_LEN]
    return "".join(ch if 0x20 <= ord(ch) <= 0x7E else "?" for ch in prefix)


def _precheck_json_structure(text: str, max_depth: int, max_tokens: int) -> None:
    depth = 0
    tokens = 0
    in_string = False
    escape = False
    for i in range(len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            tokens += 1
            if tokens > max_tokens:
                raise CapExceededError("JSON token count exceeds cap")
        elif ch == "{" or ch == "[":
            depth += 1
            tokens += 1
            if depth > max_depth:
                raise CapExceededError("JSON nesting depth exceeds cap")
            if tokens > max_tokens:
                raise CapExceededError("JSON token count exceeds cap")
        elif ch == "}" or ch == "]":
            depth -= 1
            if depth < 0:
                raise JsonParseError("Unbalanced closing bracket in JSON")
        elif ch == "," or ch == ":":
            tokens += 1
            if tokens > max_tokens:
                raise CapExceededError("JSON token count exceeds cap")


def _reject_constant(val: str) -> Any:
    raise JsonParseError(f"Non-standard JSON constant rejected: {val}")


def _strict_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(pairs) > MAX_OBJECT_KEYS:
        raise CapExceededError("JSON object key count exceeds cap")
    out: dict[str, Any] = {}
    for k, v in pairs:
        if "\x00" in k:
            raise ValidationError("NUL byte not allowed in JSON key")
        if k in out:
            raise JsonParseError("Duplicate JSON key rejected")
        out[k] = v
    return out


def parse_json_bytes(raw: bytes, max_bytes: int) -> Any:
    if len(raw) > max_bytes:
        raise CapExceededError("JSON payload exceeds byte cap")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JsonParseError("Invalid UTF-8 in JSON input") from exc
    _precheck_json_structure(text, max_depth=MAX_JSON_DEPTH, max_tokens=MAX_JSON_TOKENS)
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_pairs_hook,
            parse_constant=_reject_constant,
        )
    except (CapExceededError, JsonParseError, ValidationError):
        raise
    except RecursionError as exc:
        raise CapExceededError("JSON nesting depth exceeded") from exc
    except ValueError as exc:
        raise JsonParseError("Malformed JSON document") from exc


def read_regular_file_bounded(path: str | os.PathLike[str], max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise FileSafetyError("Refusing to open file (missing, symlink, or OS error)") from exc
    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise FileSafetyError("Unable to stat file descriptor") from exc
        if not stat.S_ISREG(st.st_mode):
            raise FileSafetyError("Refusing non-regular file")
        if st.st_size > max_bytes:
            raise CapExceededError("File size exceeds byte cap")
        chunks: list[bytes] = []
        total = 0
        max_reads = (max_bytes // READ_CHUNK_BYTES) + 3
        for _ in range(max_reads):
            to_read = min(READ_CHUNK_BYTES, max_bytes - total + 1)
            try:
                chunk = os.read(fd, to_read)
            except OSError as exc:
                raise FileSafetyError("Error reading file") from exc
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise CapExceededError("File read exceeded byte cap")
            chunks.append(chunk)
        else:
            raise CapExceededError("Exceeded maximum read iterations")
        return b"".join(chunks)
    finally:
        os.close(fd)


def evaluate_probe_results(data: Any) -> ProbeEvalReport:
    """Evaluate raw escape probe output and produce a fail-closed deterministic report."""
    if not isinstance(data, dict):
        raise ValidationError("Probe output root must be a JSON object")
    if set(data.keys()) != _ROOT_ALLOWED_KEYS:
        raise ValidationError("Probe output must contain exactly 'probe_version' and 'checks'")

    probe_version = data["probe_version"]
    if not isinstance(probe_version, str) or len(probe_version) == 0 or len(probe_version) > MAX_VERSION_LEN:
        raise ValidationError("probe_version must be a non-empty string within length cap")
    if "\x00" in probe_version:
        raise ValidationError("probe_version must not contain NUL bytes")

    raw_checks = data["checks"]
    if not isinstance(raw_checks, list):
        raise ValidationError("'checks' must be a JSON array")
    if len(raw_checks) > MAX_CHECKS:
        raise CapExceededError("checks array exceeds MAX_CHECKS (1000)")

    validated_checks: list[dict[str, str]] = []
    counts_by_id: dict[str, int] = {}

    for entry in raw_checks:
        if not isinstance(entry, dict):
            raise ValidationError("Each check entry must be a JSON object")
        if set(entry.keys()) != _CHECK_ALLOWED_KEYS:
            raise ValidationError("Each check entry must have exact keys: id, outcome, evidence")

        cid = entry["id"]
        outcome = entry["outcome"]
        evidence = entry["evidence"]

        if not isinstance(cid, str) or len(cid) == 0 or len(cid) > MAX_ID_LEN or "\x00" in cid:
            raise ValidationError("Invalid check id")
        if not isinstance(outcome, str) or outcome not in _VALID_OUTCOMES:
            raise ValidationError("Invalid check outcome")
        if not isinstance(evidence, str):
            raise ValidationError("Check evidence must be a string")
        if len(evidence) > MAX_EVIDENCE_INPUT_LEN:
            raise CapExceededError("Check evidence exceeds MAX_EVIDENCE_INPUT_LEN (4096)")

        validated_checks.append({"id": cid, "outcome": outcome, "evidence": evidence})
        counts_by_id[cid] = counts_by_id.get(cid, 0) + 1

    sorted_checks = sorted(
        validated_checks,
        key=lambda c: (c["id"], c["outcome"], c["evidence"]),
    )
    canonical_checks_bytes = json.dumps(
        sorted_checks, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    digest_hex = hashlib.sha256(canonical_checks_bytes).hexdigest()
    digest_str = f"sha256:{digest_hex}"

    missing_ids = sorted(req_id for req_id in ALL_REQUIRED_CHECK_IDS if req_id not in counts_by_id)
    unknown_ids = sorted({c["id"] for c in sorted_checks if c["id"] not in ALL_REQUIRED_CHECK_IDS})
    escaped_ids: set[str] = set()
    failed_entries: list[dict[str, str]] = []

    for chk in sorted_checks:
        cid = chk["id"]
        outcome = chk["outcome"]
        evidence = chk["evidence"]

        if cid not in ALL_REQUIRED_CHECK_IDS:
            failed_entries.append(
                {
                    "id": cid,
                    "outcome": outcome,
                    "reason": "unknown_check_id",
                    "evidence": sanitise_evidence(evidence),
                }
            )
            continue

        if counts_by_id[cid] > 1:
            if cid in NEGATIVE_CHECK_IDS and outcome == "escaped":
                escaped_ids.add(cid)
            failed_entries.append(
                {
                    "id": cid,
                    "outcome": outcome,
                    "reason": "duplicate_check_id",
                    "evidence": sanitise_evidence(evidence),
                }
            )
            continue

        if cid in NEGATIVE_CHECK_IDS:
            if outcome == "blocked":
                # Passing negative check: do NOT include evidence in output.
                continue
            if outcome == "escaped":
                escaped_ids.add(cid)
                reason = "negative_check_escaped"
            elif outcome == "error":
                reason = "check_error"
            else:
                reason = "unexpected_outcome_for_negative_check"
            failed_entries.append(
                {
                    "id": cid,
                    "outcome": outcome,
                    "reason": reason,
                    "evidence": sanitise_evidence(evidence),
                }
            )
        else:
            # cid in POSITIVE_CHECK_IDS
            if outcome == "passed":
                # Passing positive check: do NOT include evidence in output.
                continue
            reason = "check_error" if outcome == "error" else "positive_check_did_not_pass"
            failed_entries.append(
                {
                    "id": cid,
                    "outcome": outcome,
                    "reason": reason,
                    "evidence": sanitise_evidence(evidence),
                }
            )

    failed_sorted = sorted(
        failed_entries,
        key=lambda f: (f["id"], f["reason"], f["outcome"], f["evidence"]),
    )
    escaped_sorted = sorted(escaped_ids)

    if escaped_sorted:
        verdict = ProbeVerdict.ESCAPE
    elif missing_ids or unknown_ids or failed_sorted:
        verdict = ProbeVerdict.FAIL
    else:
        verdict = ProbeVerdict.PASS

    return ProbeEvalReport(
        verdict=verdict.value,
        failed=failed_sorted,
        escaped=escaped_sorted,
        missing=missing_ids,
        unknown=unknown_ids,
        digest=digest_str,
    )


def evaluate_probe_file(
    results_path: str | os.PathLike[str],
    max_bytes: int = DEFAULT_RESULTS_CAP_BYTES,
) -> ProbeEvalReport:
    raw = read_regular_file_bounded(results_path, max_bytes=max_bytes)
    data = parse_json_bytes(raw, max_bytes=max_bytes)
    return evaluate_probe_results(data)
