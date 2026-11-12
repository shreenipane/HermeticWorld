"""Supervisor stream reader, outcome resolver, and deterministic JSON reporter."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import fcntl
import json
import os
import stat
from typing import Any, BinaryIO

from hermetic_grader_records.record import (
    EndRecord,
    FinishRecord,
    HermeticGraderError,
    MAX_NODEID_LEN,
    PrematureEOFError,
    RecordError,
    StartRecord,
    iter_records,
)

MAX_EXPECTED_NODEIDS: int = 100_000
MAX_REPORT_BYTES: int = 16 * 1024 * 1024  # 16 MiB
WRITE_CHUNK_SIZE: int = 65536
MAX_WRITE_ITERATIONS: int = (MAX_REPORT_BYTES // WRITE_CHUNK_SIZE) + 16
MAX_TEMP_ATTEMPTS: int = 64

_TEMP_COUNTER: int = 0


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
                break
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
    return json.dumps(report.to_dict(), sort_keys=True, indent=2, allow_nan=False) + "\n"


def read_results_json(fileobj: BinaryIO, expected_nodeids: list[str]) -> str:
    """Evaluate a stream and return the deterministic JSON report string."""
    return evaluate_stream(fileobj, expected_nodeids).to_json()


def open_regular_file_ro(path: str | os.PathLike[str]) -> BinaryIO:
    """Open a regular file read-only without following symlinks or blocking on FIFOs."""
    try:
        raw_path = os.fspath(path)
    except TypeError as exc:
        raise SupervisorError("Invalid file path") from exc

    if not raw_path:
        raise SupervisorError("Empty file path")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK

    try:
        fd = os.open(raw_path, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise UnsafeFileError("Refusing symlink when opening regular file") from exc
        raise SupervisorError("Failed to open input file") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UnsafeFileError("Refusing non-regular file (FIFO, device, directory, or socket)")

        if hasattr(fcntl, "F_GETFL") and hasattr(fcntl, "F_SETFL") and hasattr(os, "O_NONBLOCK"):
            cur_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, cur_flags & ~os.O_NONBLOCK)

        return os.fdopen(fd, "rb")
    except Exception as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        if isinstance(exc, SupervisorError):
            raise
        raise SupervisorError("Failed to validate regular input file") from exc


def read_results_from_file(
    path: str | os.PathLike[str], expected_nodeids: list[str]
) -> SupervisorReport:
    """Safely open a regular result file (no symlinks/FIFOs/devices) and evaluate it."""
    with open_regular_file_ro(path) as stream:
        return evaluate_stream(stream, expected_nodeids)


def write_report_atomic(path: str | os.PathLike[str], report: SupervisorReport) -> None:
    """Atomically write a deterministic JSON report to a regular file path."""
    global _TEMP_COUNTER

    try:
        raw_path = os.fspath(path)
    except TypeError as exc:
        raise SupervisorError("Invalid destination path") from exc

    if isinstance(raw_path, bytes):
        raise SupervisorError("Destination path must be str")
    if not raw_path:
        raise SupervisorError("Empty destination path")

    payload = report.to_json().encode("utf-8")
    if len(payload) > MAX_REPORT_BYTES:
        raise SupervisorError("Report exceeds MAX_REPORT_BYTES")

    try:
        dest_st = os.lstat(raw_path)
    except FileNotFoundError:
        dest_st = None
    except OSError as exc:
        raise SupervisorError("Failed to inspect destination path") from exc

    if dest_st is not None:
        if stat.S_ISLNK(dest_st.st_mode):
            raise UnsafeFileError("Refusing to overwrite symlink")
        if not stat.S_ISREG(dest_st.st_mode):
            raise UnsafeFileError("Refusing to overwrite non-regular file")

    parent_dir = os.path.dirname(raw_path) or "."
    try:
        parent_st = os.lstat(parent_dir)
    except OSError as exc:
        raise SupervisorError("Parent directory does not exist") from exc

    if stat.S_ISLNK(parent_st.st_mode) or not stat.S_ISDIR(parent_st.st_mode):
        raise UnsafeFileError("Refusing symlink or non-directory parent")

    pid = os.getpid()
    open_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )

    for attempt in range(MAX_TEMP_ATTEMPTS):
        _TEMP_COUNTER += 1
        tmp_name = f".tmp.hgr.{pid}.{_TEMP_COUNTER}.{attempt}"
        tmp_path = os.path.join(parent_dir, tmp_name)

        try:
            fd = os.open(tmp_path, open_flags, 0o600)
        except FileExistsError:
            continue
        except OSError as exc:
            raise SupervisorError("Failed to create temporary report file") from exc

        try:
            tmp_st = os.fstat(fd)
            if not stat.S_ISREG(tmp_st.st_mode):
                raise UnsafeFileError("Temporary file is not a regular file")

            view = memoryview(payload)
            offset = 0
            for _ in range(MAX_WRITE_ITERATIONS):
                if offset >= len(payload):
                    break
                chunk = view[offset : offset + WRITE_CHUNK_SIZE]
                written = os.write(fd, chunk)
                if written <= 0:
                    raise SupervisorError("Zero-byte write while saving report")
                offset += written
            else:
                raise SupervisorError("Exceeded MAX_WRITE_ITERATIONS while saving report")

            os.fsync(fd)
            os.close(fd)
            fd = -1

            os.replace(tmp_path, raw_path)

            # Best-effort directory fsync for crash durability
            dir_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_DIRECTORY"):
                dir_flags |= os.O_DIRECTORY
            try:
                dir_fd = os.open(parent_dir, dir_flags)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
            return
        except Exception as exc:
            if fd != -1:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            if isinstance(exc, SupervisorError):
                raise
            raise SupervisorError("Atomic report write failed") from exc

    raise SupervisorError("Exhausted MAX_TEMP_ATTEMPTS creating temporary file")
