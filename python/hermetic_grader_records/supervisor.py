"""Supervisor stream reader, outcome resolver, and deterministic JSON reporter."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any, BinaryIO

from hermetic_safe_io import UnsafePathError, atomic_write, open_regular, validate_path

from hermetic_grader_records.record import (
    EndRecord,
    FinishRecord,
    HermeticGraderError,
    MAX_NODEID_LEN,
    MAX_STREAM_BYTES,
    PrematureEOFError,
    RecordError,
    StartRecord,
    iter_records,
)

MAX_EXPECTED_NODEIDS: int = 100_000
MAX_REPORT_BYTES: int = 16 * 1024 * 1024  # 16 MiB


class SupervisorError(HermeticGraderError):
    """Typed error raised by supervisor result evaluation or safe file I/O."""


class UnsafeFileError(SupervisorError):
    """Typed error raised when a path is a symlink, FIFO, device, or non-regular file."""


@dataclass(frozen=True, slots=True)
class SupervisorReport:
    """Deterministic grading outcome report produced by the supervisor."""

    outcomes: dict[str, str]
    unexpected: list[str]
    error: str | None = None

    @property
    def unexpected_count(self) -> int:
        return len(self.unexpected)

    def to_dict(self) -> dict[str, Any]:
        sorted_outcomes = {k: self.outcomes[k] for k in sorted(self.outcomes)}
        sorted_unexpected = sorted(self.unexpected)
        return {
            "error": self.error,
            "outcomes": sorted_outcomes,
            "unexpected": sorted_unexpected,
            "unexpected_count": len(sorted_unexpected),
        }

    def to_json(self) -> str:
        return format_report_json(self)


def _validate_expected_nodeids(expected_nodeids: list[str]) -> list[str]:
    if not isinstance(expected_nodeids, (list, tuple)):
        raise SupervisorError("expected_nodeids must be a list or tuple of strings")
    if len(expected_nodeids) > MAX_EXPECTED_NODEIDS:
        raise SupervisorError("expected_nodeids exceeds MAX_EXPECTED_NODEIDS")

    unique: set[str] = set()
    for item in expected_nodeids:
        if not isinstance(item, str) or len(item) == 0 or len(item) > MAX_NODEID_LEN:
            raise SupervisorError("Invalid nodeid in expected_nodeids")
        if "\x00" in item:
            raise SupervisorError("NUL byte forbidden in expected_nodeids")
        unique.add(item)

    return sorted(unique)


def evaluate_stream(fileobj: BinaryIO, expected_nodeids: list[str]) -> SupervisorReport:
    """Read a binary result stream and resolve deterministic outcomes for expected tests.

    Rules:
    - Completed tests (START + FINISH) keep their recorded outcome.
    - A test with START but no FINISH is marked "failed" (crash or os._exit).
    - If the stream hits clean EOF at a record boundary before END (e.g., os._exit
      or revoked fd identity), tests never started are marked "missing".
    - If a corrupt stream error occurs after some valid records, the valid prefix
      is kept, everything else is marked "failed", and the error is reported.
    - Nodeids not in expected_nodeids are ignored in outcomes and recorded in the
      sorted "unexpected" list.
    """
    sorted_expected = _validate_expected_nodeids(expected_nodeids)
    expected_set = frozenset(sorted_expected)

    completed: dict[str, str] = {}
    started_active: str | None = None
    unexpected_set: set[str] = set()
    stream_error: str | None = None
    corrupt_error: bool = False

    try:
        for record in iter_records(fileobj):
            if isinstance(record, StartRecord):
                if record.nodeid in expected_set:
                    started_active = record.nodeid
                else:
                    unexpected_set.add(record.nodeid)
            elif isinstance(record, FinishRecord):
                if record.nodeid in expected_set:
                    completed[record.nodeid] = record.outcome
                    started_active = None
                else:
                    unexpected_set.add(record.nodeid)
            elif isinstance(record, EndRecord):
                continue
    except PrematureEOFError as exc:
        stream_error = str(exc)
        corrupt_error = False
    except RecordError as exc:
        stream_error = str(exc)
        corrupt_error = True
    except Exception:
        stream_error = "Unhandled stream error"
        corrupt_error = True

    outcomes: dict[str, str] = {}
    for nodeid in sorted_expected:
        if nodeid in completed:
            outcomes[nodeid] = completed[nodeid]
        elif nodeid == started_active:
            outcomes[nodeid] = "failed"
        elif corrupt_error:
            outcomes[nodeid] = "failed"
        else:
            outcomes[nodeid] = "missing"

    return SupervisorReport(
        outcomes=outcomes,
        unexpected=sorted(unexpected_set),
        error=stream_error,
    )


def read_results(fileobj: BinaryIO, expected_nodeids: list[str]) -> dict[str, str]:
    """Map every expected nodeid to passed | failed | skipped | error | missing."""
    return evaluate_stream(fileobj, expected_nodeids).outcomes


def format_report_json(report: SupervisorReport) -> str:
    """Serialize a SupervisorReport into deterministic JSON (sorted keys, sorted lists)."""
    _validate_report_budget(report)
    chunks: list[str] = []
    total = 1  # final newline
    encoder = json.JSONEncoder(sort_keys=True, indent=2, allow_nan=False)
    for chunk in encoder.iterencode(report.to_dict()):
        total += len(chunk)  # ensure_ascii=True: characters equal encoded bytes
        if total > MAX_REPORT_BYTES:
            raise SupervisorError("Report exceeds MAX_REPORT_BYTES")
        chunks.append(chunk)
    return "".join(chunks) + "\n"


def _validate_report_budget(report: SupervisorReport) -> None:
    # Bound strings before sorting or JSON escaping allocates copies.
    if len(report.outcomes) + len(report.unexpected) > MAX_EXPECTED_NODEIDS * 2:
        raise SupervisorError("Report item cap exceeded")
    total = 0

    def account(value: str) -> None:
        nonlocal total
        if not isinstance(value, str) or len(value) > MAX_REPORT_BYTES:
            raise SupervisorError("Invalid report string")
        for char in value:
            point = ord(char)
            if point > 0xffff:
                total += 12
            elif char in "\b\f\n\r\t":
                total += 2
            elif point < 32 or point > 126:
                total += 6
            elif char in ('"', chr(92)):
                total += 2
            else:
                total += 1
            if total > MAX_REPORT_BYTES:
                raise SupervisorError("Report exceeds MAX_REPORT_BYTES")

    for key, value in report.outcomes.items():
        account(key)
        account(value)
    for value in report.unexpected:
        account(value)
    if report.error is not None:
        account(report.error)


def read_results_json(fileobj: BinaryIO, expected_nodeids: list[str]) -> str:
    """Evaluate a stream and return the deterministic JSON report string."""
    return evaluate_stream(fileobj, expected_nodeids).to_json()


def open_regular_file_ro(path: str | os.PathLike[str]) -> BinaryIO:
    """Open a regular file read-only without following symlinks or blocking on FIFOs."""
    try:
        validate_path(path)
        return os.fdopen(open_regular(path, MAX_STREAM_BYTES), "rb")
    except UnsafePathError as exc:
        raise UnsafeFileError("Unsafe regular input path") from exc
    except (OSError, TypeError, ValueError) as exc:
        raise SupervisorError("Unable to open regular input file") from exc


def read_results_from_file(
    path: str | os.PathLike[str], expected_nodeids: list[str]
) -> SupervisorReport:
    """Safely open a regular result file (no symlinks/FIFOs/devices) and evaluate it."""
    validated = _validate_expected_nodeids(expected_nodeids)
    with open_regular_file_ro(path) as stream:
        return evaluate_stream(stream, validated)


def write_report_atomic(path: str | os.PathLike[str], report: SupervisorReport) -> None:
    """Atomically write a deterministic JSON report to a regular file path."""
    try:
        validate_path(path)
    except (TypeError, ValueError) as exc:
        raise SupervisorError("Invalid destination path") from exc
    payload = report.to_json().encode("utf-8")
    try:
        atomic_write(path, payload)
    except UnsafePathError as exc:
        raise UnsafeFileError("Unsafe report destination") from exc
    except OSError as exc:
        raise SupervisorError("Atomic report write failed") from exc
