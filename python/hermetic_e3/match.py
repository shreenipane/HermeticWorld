
"""Safe input loading, strict schema validation, and leak-finding matching.

Documented Matching & Validation Rules
--------------------------------------
1. File Safety & Caps:
   - Symlinks are never followed (checked via ``os.path.islink`` and opened with
     ``os.O_NOFOLLOW``).
   - Non-regular files (directories, FIFOs/named pipes, sockets, device nodes)
     are refused after ``os.fstat`` verification via ``stat.S_ISREG``.
   - File size is capped at ``MAX_FILE_BYTES`` (16 MiB), read in bounded chunks
     of ``READ_CHUNK_BYTES`` up to ``MAX_READ_CHUNKS`` iterations.
   - Entry lists (``leaks`` and ``findings``) are each capped at ``MAX_ENTRIES``
     (200,000).

2. JSON & Schema Strictness:
   - Duplicate object keys anywhere in the JSON document are rejected via
     ``object_pairs_hook``.
   - Non-standard JSON constants (``NaN``, ``Infinity``, ``-Infinity``) are
     rejected.
   - Unknown top-level keys and unknown object fields are rejected.
   - Ground truth requires ``{"leaks": [...]}`` where each leak has exact keys
     ``id`` (non-empty ``str``), ``task`` (non-empty ``str``), ``path``
     (non-empty ``str``), ``line_start`` (``int >= 1``), ``line_end``
     (``int >= line_start``), ``detector_hint`` (``str | None``), and ``kind``
     (``"seeded"`` or ``"real"``). Duplicate leak IDs are rejected.
   - Findings require ``{"findings": [...]}`` where each finding has exact keys
     ``task`` (non-empty ``str``), ``detector`` (non-empty ``str``), ``path``
     (non-empty ``str``), ``line_start`` (``int >= 1``), ``line_end``
     (``int >= line_start``), and ``severity`` (``"gate"``, ``"warning"``, or
     ``"info"``).

3. Severity Filtering:
   - Only findings with ``severity`` in ``{"gate", "warning"}`` participate in
     matching and false-positive counting.
   - Findings with ``severity == "info"`` are completely ignored: they never
     match a leak and never count as false positives.

4. Overlap & Cardinality Rules:
   - A finding matches a leak if and only if:
     (a) ``finding.severity`` is ``"gate"`` or ``"warning"``,
     (b) ``finding.task == leak.task``,
     (c) ``finding.path == leak.path``, and
     (d) their closed line intervals ``[line_start, line_end]`` overlap, i.e.
         ``finding.line_start <= leak.line_end and leak.line_start <= finding.line_end``.
   - Touching ranges overlap (e.g., ``[1, 5]`` and ``[5, 10]`` share line 5).
   - Adjacent non-touching ranges do not overlap (e.g., ``[1, 5]`` and ``[6, 10]``).
   - One finding may match multiple leaks.
   - Each leak is counted at most once regardless of how many findings match it.
   - Any active finding that matches zero leaks is an unmatched finding (used for
     deduplicated false-positive counting).
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from typing import Any, Sequence

from hermetic_e3 import (
    DuplicateKeyError,
    FileSecurityError,
    HermeticE3Error,
    JsonFormatError,
    MAX_ENTRIES,
    MAX_FILE_BYTES,
    MAX_LINE_NUMBER,
    MAX_OBJECT_KEYS,
    MAX_READ_CHUNKS,
    MAX_STRING_LEN,
    READ_CHUNK_BYTES,
    SchemaValidationError,
    SizeLimitError,
)

ALLOWED_LEAK_KINDS: frozenset[str] = frozenset({"seeded", "real"})
ALLOWED_SEVERITIES: frozenset[str] = frozenset({"gate", "warning", "info"})
ACTIVE_SEVERITIES: frozenset[str] = frozenset({"gate", "warning"})

TOP_LEVEL_TRUTH_KEYS: frozenset[str] = frozenset({"leaks"})
TOP_LEVEL_FINDINGS_KEYS: frozenset[str] = frozenset({"findings"})

LEAK_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"id", "task", "path", "line_start", "line_end", "detector_hint", "kind"}
)
FINDING_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"task", "detector", "path", "line_start", "line_end", "severity"}
)


@dataclass(frozen=True, slots=True)
class Leak:
    """Validated ground-truth leak record."""

    id: str
    task: str
    path: str
    line_start: int
    line_end: int
    detector_hint: str | None
    kind: str


@dataclass(frozen=True, slots=True)
class Finding:
    """Validated scanner finding record."""

    task: str
    detector: str
    path: str
    line_start: int
    line_end: int
    severity: str


@dataclass(frozen=True, slots=True)
class MatchResult:
    """Deterministic outcome of matching active findings against ground-truth leaks."""

    matched_leak_ids: tuple[str, ...]
    matched_leak_ids_by_detector: dict[str, tuple[str, ...]]
    unmatched_active_findings: tuple[Finding, ...]
    active_finding_count: int
    ignored_info_finding_count: int


def _no_duplicate_object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON object keys and cap key count per object."""
    if len(pairs) > MAX_OBJECT_KEYS:
        raise SchemaValidationError(
            f"JSON object has {len(pairs)} keys, exceeding cap {MAX_OBJECT_KEYS}"
        )
    result: dict[str, Any] = {}
    for key, value in pairs[:MAX_OBJECT_KEYS]:
        if key in result:
            raise DuplicateKeyError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_bad_constant(constant: str) -> Any:
    """Reject NaN, Infinity, and -Infinity in JSON input."""
    raise JsonFormatError(f"Invalid JSON numeric constant: {constant!r}")


def _read_regular_file_bytes(path: str | os.PathLike[str]) -> bytes:
    """Read raw bytes from a regular file without following symlinks."""
    if not isinstance(path, (str, os.PathLike)):
        raise FileSecurityError("File path must be a str or PathLike")
    try:
        path_str = os.fspath(path)
    except TypeError as exc:
        raise FileSecurityError("Invalid file path type") from exc

    if not isinstance(path_str, str) or not path_str or "\x00" in path_str:
        raise FileSecurityError("File path must be a non-empty valid string")

    try:
        if os.path.islink(path_str):
            raise FileSecurityError(f"Refusing symlink path: {path_str!r}")
    except OSError as exc:
        raise FileSecurityError(f"Cannot inspect path {path_str!r}: {exc}") from exc

    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path_str, open_flags)
    except OSError as exc:
        raise FileSecurityError(f"Refusing or unable to open {path_str!r}: {exc}") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise FileSecurityError(f"Refusing non-regular file: {path_str!r}")
        if st.st_size > MAX_FILE_BYTES:
            raise SizeLimitError(
                f"File {path_str!r} size ({st.st_size} bytes) exceeds {MAX_FILE_BYTES} bytes"
            )

        chunks: list[bytes] = []
        total_bytes = 0
        for _ in range(MAX_READ_CHUNKS):
            chunk = os.read(fd, READ_CHUNK_BYTES)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_FILE_BYTES:
                raise SizeLimitError(
                    f"File {path_str!r} exceeded {MAX_FILE_BYTES} bytes during read"
                )
            chunks.append(chunk)
        else:
            raise SizeLimitError(
                f"File {path_str!r} exceeded maximum chunk read count ({MAX_READ_CHUNKS})"
            )
        return b"".join(chunks)
    except HermeticE3Error:
        raise
    except OSError as exc:
        raise FileSecurityError(f"I/O error while reading {path_str!r}: {exc}") from exc
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def read_strict_json_file(path: str | os.PathLike[str]) -> Any:
    """Safely read and parse a strict JSON file (no symlinks, <= 16 MiB, no duplicate keys)."""
    raw_bytes = _read_regular_file_bytes(path)
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JsonFormatError(f"File is not valid UTF-8: {exc}") from exc

    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicate_object_pairs_hook,
            parse_constant=_reject_bad_constant,
        )
    except HermeticE3Error:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise JsonFormatError(f"Invalid JSON syntax: {exc}") from exc


def _validate_non_empty_str(value: Any, field_name: str) -> str:
    """Validate that a field is a non-empty string within MAX_STRING_LEN."""
    if not isinstance(value, str):
        raise SchemaValidationError(f"Field {field_name!r} must be a string")
    if len(value) == 0:
        raise SchemaValidationError(f"Field {field_name!r} must be non-empty")
    if len(value) > MAX_STRING_LEN:
        raise SizeLimitError(
            f"Field {field_name!r} length ({len(value)}) exceeds {MAX_STRING_LEN}"
        )
    return value


def _validate_optional_str(value: Any, field_name: str) -> str | None:
    """Validate that a field is None or a string within MAX_STRING_LEN."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise SchemaValidationError(f"Field {field_name!r} must be a string or null")
    if len(value) > MAX_STRING_LEN:
        raise SizeLimitError(
            f"Field {field_name!r} length ({len(value)}) exceeds {MAX_STRING_LEN}"
        )
    return value


def _validate_line_int(value: Any, field_name: str) -> int:
    """Validate a strict positive integer line number (rejecting booleans and floats)."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise SchemaValidationError(f"Field {field_name!r} must be an integer")
    if value < 1 or value > MAX_LINE_NUMBER:
        raise SchemaValidationError(
            f"Field {field_name!r} ({value}) must be between 1 and {MAX_LINE_NUMBER}"
        )
    return value


def _validate_exact_keys(
    obj: Any, expected_keys: frozenset[str], context_name: str
) -> dict[str, Any]:
    """Ensure obj is a dict with the exact required keys (rejecting missing or unknown keys)."""
    if not isinstance(obj, dict):
        raise SchemaValidationError(f"{context_name} must be a JSON object")
    if len(obj) > MAX_OBJECT_KEYS:
        raise SchemaValidationError(
            f"{context_name} has {len(obj)} keys, exceeding cap {MAX_OBJECT_KEYS}"
        )
    actual_keys = set(obj.keys())
    unknown = sorted(actual_keys - expected_keys)
    if unknown:
        raise SchemaValidationError(
            f"{context_name} contains unknown field(s): {unknown}"
        )
    missing = sorted(expected_keys - actual_keys)
    if missing:
        raise SchemaValidationError(
            f"{context_name} is missing required field(s): {missing}"
        )
    return obj


def parse_ground_truth(data: Any) -> tuple[Leak, ...]:
    """Validate parsed ground-truth JSON data and return deterministic sorted Leak records."""
    root = _validate_exact_keys(data, TOP_LEVEL_TRUTH_KEYS, "Ground truth root")
    raw_leaks = root["leaks"]
    if not isinstance(raw_leaks, list):
        raise SchemaValidationError("'leaks' must be a list")
    if len(raw_leaks) > MAX_ENTRIES:
        raise SizeLimitError(
            f"'leaks' count ({len(raw_leaks)}) exceeds cap {MAX_ENTRIES}"
        )

    leaks: list[Leak] = []
    seen_ids: set[str] = set()
    for idx, item in enumerate(raw_leaks[:MAX_ENTRIES]):
        obj = _validate_exact_keys(item, LEAK_REQUIRED_KEYS, f"leaks[{idx}]")
        leak_id = _validate_non_empty_str(obj["id"], "id")
        if leak_id in seen_ids:
            raise SchemaValidationError(f"Duplicate leak id: {leak_id!r}")
        seen_ids.add(leak_id)

        task = _validate_non_empty_str(obj["task"], "task")
        path = _validate_non_empty_str(obj["path"], "path")
        line_start = _validate_line_int(obj["line_start"], "line_start")
        line_end = _validate_line_int(obj["line_end"], "line_end")
        if line_end < line_start:
            raise SchemaValidationError(
                f"leaks[{idx}] line_end ({line_end}) < line_start ({line_start})"
            )
        detector_hint = _validate_optional_str(obj["detector_hint"], "detector_hint")
        kind = _validate_non_empty_str(obj["kind"], "kind")
        if kind not in ALLOWED_LEAK_KINDS:
            raise SchemaValidationError(
                f"leaks[{idx}] invalid kind {kind!r}; expected one of {sorted(ALLOWED_LEAK_KINDS)}"
            )
        leaks.append(
            Leak(
                id=leak_id,
                task=task,
                path=path,
                line_start=line_start,
                line_end=line_end,
                detector_hint=detector_hint,
                kind=kind,
            )
        )

    leaks.sort(key=lambda lk: (lk.task, lk.path, lk.line_start, lk.line_end, lk.id))
    return tuple(leaks)


def parse_findings(data: Any) -> tuple[Finding, ...]:
    """Validate parsed findings JSON data and return deterministic sorted Finding records."""
    root = _validate_exact_keys(data, TOP_LEVEL_FINDINGS_KEYS, "Findings root")
    raw_findings = root["findings"]
    if not isinstance(raw_findings, list):
        raise SchemaValidationError("'findings' must be a list")
    if len(raw_findings) > MAX_ENTRIES:
        raise SizeLimitError(
            f"'findings' count ({len(raw_findings)}) exceeds cap {MAX_ENTRIES}"
        )

    findings: list[Finding] = []
    for idx, item in enumerate(raw_findings[:MAX_ENTRIES]):
        obj = _validate_exact_keys(item, FINDING_REQUIRED_KEYS, f"findings[{idx}]")
        task = _validate_non_empty_str(obj["task"], "task")
        detector = _validate_non_empty_str(obj["detector"], "detector")
        path = _validate_non_empty_str(obj["path"], "path")
        line_start = _validate_line_int(obj["line_start"], "line_start")
        line_end = _validate_line_int(obj["line_end"], "line_end")
        if line_end < line_start:
            raise SchemaValidationError(
                f"findings[{idx}] line_end ({line_end}) < line_start ({line_start})"
            )
        severity = _validate_non_empty_str(obj["severity"], "severity")
        if severity not in ALLOWED_SEVERITIES:
            raise SchemaValidationError(
                f"findings[{idx}] invalid severity {severity!r}; expected one of {sorted(ALLOWED_SEVERITIES)}"
            )
        findings.append(
            Finding(
                task=task,
                detector=detector,
                path=path,
                line_start=line_start,
                line_end=line_end,
                severity=severity,
            )
        )

    findings.sort(
        key=lambda fn: (fn.task, fn.path, fn.line_start, fn.line_end, fn.detector, fn.severity)
    )
    return tuple(findings)


def load_ground_truth(path: str | os.PathLike[str]) -> tuple[Leak, ...]:
    """Load and validate ground-truth leaks from a regular JSON file."""
    return parse_ground_truth(read_strict_json_file(path))


def load_findings(path: str | os.PathLike[str]) -> tuple[Finding, ...]:
    """Load and validate scanner findings from a regular JSON file."""
    return parse_findings(read_strict_json_file(path))


def ranges_overlap(
    start_a: int, end_a: int, start_b: int, end_b: int
) -> bool:
    """Return True iff closed line intervals [start_a, end_a] and [start_b, end_b] overlap.

    Touching ranges overlap (e.g. [1, 5] and [5, 10] share line 5).
    Adjacent ranges do not overlap (e.g. [1, 5] and [6, 10] share no lines).
    """
    return start_a <= end_b and start_b <= end_a


def match_findings(
    leaks: Sequence[Leak], findings: Sequence[Finding]
) -> MatchResult:
    """Match active findings against ground-truth leaks deterministically.

    - Only findings with severity in {"gate", "warning"} are evaluated; "info"
      findings are ignored completely.
    - A finding matches a leak when task and path are equal and line ranges
      overlap (inclusive).
    - One finding may match multiple leaks; each leak is counted at most once.
    - Unmatched active findings are preserved for false-positive deduplication.
    """
    if len(leaks) > MAX_ENTRIES:
        raise SizeLimitError(f"Leaks count ({len(leaks)}) exceeds cap {MAX_ENTRIES}")
    if len(findings) > MAX_ENTRIES:
        raise SizeLimitError(f"Findings count ({len(findings)}) exceeds cap {MAX_ENTRIES}")

    leaks_by_loc: dict[tuple[str, str], list[Leak]] = {}
    for leak in leaks[:MAX_ENTRIES]:
        bucket = leaks_by_loc.setdefault((leak.task, leak.path), [])
        bucket.append(leak)

    for loc_key in tuple(leaks_by_loc.keys())[:MAX_ENTRIES]:
        leaks_by_loc[loc_key].sort(key=lambda lk: (lk.line_start, lk.line_end, lk.id))

    matched_overall: set[str] = set()
    matched_by_detector: dict[str, set[str]] = {}
    unmatched_active: list[Finding] = []
    active_count = 0
    ignored_info_count = 0

    for finding in findings[:MAX_ENTRIES]:
        matched_by_detector.setdefault(finding.detector, set())
        if finding.severity not in ACTIVE_SEVERITIES:
            ignored_info_count += 1
            continue

        active_count += 1
        candidates = leaks_by_loc.get((finding.task, finding.path), ())
        if len(candidates) > MAX_ENTRIES:
            raise SizeLimitError(
                f"Candidate leaks count ({len(candidates)}) exceeds cap {MAX_ENTRIES}"
            )

        matched_any = False
        for leak in candidates[:MAX_ENTRIES]:
            if leak.line_start > finding.line_end:
                break
            if ranges_overlap(
                finding.line_start, finding.line_end, leak.line_start, leak.line_end
            ):
                matched_any = True
                matched_overall.add(leak.id)
                matched_by_detector[finding.detector].add(leak.id)

        if not matched_any:
            unmatched_active.append(finding)

    unmatched_active.sort(
        key=lambda fn: (fn.task, fn.path, fn.line_start, fn.line_end, fn.detector, fn.severity)
    )
    sorted_detector_matches: dict[str, tuple[str, ...]] = {
        detector: tuple(sorted(matched_by_detector[detector]))
        for detector in sorted(matched_by_detector.keys())[:MAX_ENTRIES]
    }

    return MatchResult(
        matched_leak_ids=tuple(sorted(matched_overall)),
        matched_leak_ids_by_detector=sorted_detector_matches,
        unmatched_active_findings=tuple(unmatched_active),
        active_finding_count=active_count,
        ignored_info_finding_count=ignored_info_count,
    )


