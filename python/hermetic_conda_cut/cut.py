"""Core validation, timestamp filtering, and atomic I/O for hermetic_conda_cut."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
import re
import stat
from typing import Any

DEFAULT_REPODATA_CAP_BYTES = 512 * 1024 * 1024
MAX_PACKAGE_RECORDS = 1_000_000
MAX_REMOVED_ENTRIES = 250_000
MAX_JSON_DEPTH = 16
MAX_JSON_TOKENS = 20_000_000
MAX_OBJECT_KEYS = 1_000_000
MAX_STRING_LEN = 4096
MAX_TEMP_ATTEMPTS = 128
READ_CHUNK_BYTES = 65_536

# Unix timestamps in seconds are below 10**11 until year 5138; conda timestamps must be in ms.
MIN_CONDA_TIMESTAMP_MS = 10**11
MAX_CONDA_TIMESTAMP_MS = 10**15

_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_RFC3339_RE = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z$",
    flags=re.ASCII,
)


class HermeticCondaCutError(Exception):
    """Base typed error for hermetic_conda_cut."""

    code: str = "HERMETIC_CONDA_CUT_ERROR"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class CapExceededError(HermeticCondaCutError):
    code: str = "CAP_EXCEEDED"


class FileSafetyError(HermeticCondaCutError):
    code: str = "FILE_SAFETY_ERROR"


class JsonParseError(HermeticCondaCutError):
    code: str = "JSON_PARSE_ERROR"


class ValidationError(HermeticCondaCutError):
    code: str = "VALIDATION_ERROR"


class DateParseError(HermeticCondaCutError):
    code: str = "DATE_PARSE_ERROR"


@dataclass(frozen=True)
class CondaCutReport:
    kept: int
    dropped_after_cutoff: int
    unknown: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kept": self.kept,
            "dropped_after_cutoff": self.dropped_after_cutoff,
            "unknown": list(self.unknown),
        }


def parse_rfc3339_utc_nanos(value: str) -> int:
    if not isinstance(value, str) or len(value) > 40:
        raise DateParseError("Invalid RFC 3339 UTC timestamp string")
    match = _RFC3339_RE.fullmatch(value)
    if match is None:
        raise DateParseError("Timestamp must be strict RFC 3339 UTC")
    year = int(match.group(1))
    month = int(match.group(2))
    day = int(match.group(3))
    hour = int(match.group(4))
    minute = int(match.group(5))
    second = int(match.group(6))
    frac = match.group(7)
    try:
        dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError as exc:
        raise DateParseError("Calendar date/time out of range") from exc
    epoch_seconds = (dt - _EPOCH_UTC) // timedelta(seconds=1)
    nanos = int(frac.ljust(9, "0")) if frac is not None else 0
    return epoch_seconds * 1_000_000_000 + nanos


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


def write_file_atomic(target_path: str | os.PathLike[str], content: bytes) -> None:
    target_str = os.fspath(target_path)
    try:
        st = os.lstat(target_str)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise FileSafetyError("Refusing to overwrite symlink or non-regular destination")
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise FileSafetyError("Cannot inspect destination path") from exc

    parent = os.path.dirname(target_str) or "."
    base = os.path.basename(target_str)
    if not base or base in (".", ".."):
        raise FileSafetyError("Invalid destination filename")

    pid = os.getpid()
    open_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    tmp_path: str | None = None
    fd: int | None = None

    for attempt in range(MAX_TEMP_ATTEMPTS):
        candidate = os.path.join(parent, f".{base}.tmp.{pid}.{attempt}")
        try:
            fd = os.open(candidate, open_flags, 0o644)
            tmp_path = candidate
            break
        except FileExistsError:
            continue
        except OSError as exc:
            raise FileSafetyError("Unable to create temporary file in destination directory") from exc

    if fd is None or tmp_path is None:
        raise FileSafetyError("Exhausted attempts creating temporary file")

    try:
        view = memoryview(content)
        written = 0
        total_len = len(content)
        max_writes = (total_len // READ_CHUNK_BYTES) + 4
        for _ in range(max_writes):
            if written >= total_len:
                break
            try:
                n = os.write(fd, view[written : written + READ_CHUNK_BYTES])
            except OSError as exc:
                raise FileSafetyError("Failed writing to temporary file") from exc
            if n <= 0:
                raise FileSafetyError("Short write to temporary file")
            written += n
        if written != total_len:
            raise FileSafetyError("Incomplete write to temporary file")
        try:
            os.fsync(fd)
        except OSError as exc:
            raise FileSafetyError("Failed fsync on temporary file") from exc
        os.close(fd)
        fd = None
        try:
            os.replace(tmp_path, target_str)
        except OSError as exc:
            raise FileSafetyError("Atomic rename failed") from exc
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _validate_str(val: Any, field_name: str, max_len: int = MAX_STRING_LEN) -> str:
    if not isinstance(val, str):
        raise ValidationError(f"Field '{field_name}' must be a string")
    if len(val) == 0 or len(val) > max_len:
        raise ValidationError(f"Field '{field_name}' length out of bounds")
    if "\x00" in val:
        raise ValidationError(f"Field '{field_name}' must not contain NUL bytes")
    return val


def _validate_record_and_extract_ms(filename: str, record: Any) -> int | None:
    if not isinstance(record, dict):
        raise ValidationError(f"Package record for '{filename}' must be a JSON object")
    _validate_str(record.get("name"), "record.name")
    _validate_str(record.get("version"), "record.version")
    _validate_str(record.get("build"), "record.build")

    if "timestamp" not in record or record["timestamp"] is None:
        return None
    ts_ms = record["timestamp"]
    if isinstance(ts_ms, bool) or not isinstance(ts_ms, int):
        raise ValidationError(f"Record '{filename}' timestamp must be integer milliseconds")
    if ts_ms < MIN_CONDA_TIMESTAMP_MS or ts_ms > MAX_CONDA_TIMESTAMP_MS:
        raise ValidationError(
            f"Record '{filename}' timestamp out of valid millisecond range (>= 10**11 required)"
        )
    return ts_ms


def cut_repodata(
    repodata: Any,
    cutoff: str,
) -> tuple[dict[str, Any], CondaCutReport]:
    """Filter conda repodata packages and packages.conda at the cutoff timestamp."""
    cutoff_nanos = parse_rfc3339_utc_nanos(cutoff)

    if not isinstance(repodata, dict):
        raise ValidationError("Repodata root must be a JSON object")
    if "info" not in repodata or not isinstance(repodata["info"], dict):
        raise ValidationError("Repodata must include an 'info' JSON object")
    if "packages" not in repodata or not isinstance(repodata["packages"], dict):
        raise ValidationError("Repodata must include a 'packages' JSON object")
    if "packages.conda" not in repodata or not isinstance(repodata["packages.conda"], dict):
        raise ValidationError("Repodata must include a 'packages.conda' JSON object")

    total_records = len(repodata["packages"]) + len(repodata["packages.conda"])
    if total_records > MAX_PACKAGE_RECORDS:
        raise CapExceededError("Total package records exceed MAX_PACKAGE_RECORDS")

    if "removed" in repodata:
        removed_val = repodata["removed"]
        if not isinstance(removed_val, list):
            raise ValidationError("Repodata 'removed' must be a JSON array")
        if len(removed_val) > MAX_REMOVED_ENTRIES:
            raise CapExceededError("Repodata 'removed' array exceeds MAX_REMOVED_ENTRIES")
        for item in removed_val:
            _validate_str(item, "removed[]")

    kept_count = 0
    dropped_after_count = 0
    unknown_filenames: list[str] = []

    out_repodata = copy.deepcopy(repodata)

    for map_key in ("packages", "packages.conda"):
        raw_map: dict[str, Any] = repodata[map_key]
        kept_map: dict[str, Any] = {}
        for filename in sorted(raw_map.keys()):
            _validate_str(filename, f"{map_key}.filename")
            record = raw_map[filename]
            ts_ms = _validate_record_and_extract_ms(filename, record)
            if ts_ms is None:
                unknown_filenames.append(filename)
                continue
            record_nanos = ts_ms * 1_000_000
            if record_nanos <= cutoff_nanos:
                kept_map[filename] = copy.deepcopy(record)
                kept_count += 1
            else:
                dropped_after_count += 1
        out_repodata[map_key] = kept_map

    # Rule 2: Keep every other key of kept records unchanged; keep "info" unchanged.
    # Drop "removed" entries newer than cutoff is NOT applicable: keep "removed" unchanged
    # because 'removed' contains channel-level yank/hiding directives without timestamps.
    report = CondaCutReport(
        kept=kept_count,
        dropped_after_cutoff=dropped_after_count,
        unknown=sorted(unknown_filenames),
    )
    return out_repodata, report


def cut_repodata_files(
    repodata_path: str | os.PathLike[str],
    cutoff: str,
    out_path: str | os.PathLike[str],
    report_path: str | os.PathLike[str],
    repodata_cap_bytes: int = DEFAULT_REPODATA_CAP_BYTES,
) -> CondaCutReport:
    raw = read_regular_file_bounded(repodata_path, max_bytes=repodata_cap_bytes)
    data = parse_json_bytes(raw, max_bytes=repodata_cap_bytes)
    cut_data, report = cut_repodata(data, cutoff=cutoff)

    out_bytes = json.dumps(
        cut_data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    rep_bytes = json.dumps(
        report.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")

    write_file_atomic(out_path, out_bytes)
    write_file_atomic(report_path, rep_bytes)
    return report
