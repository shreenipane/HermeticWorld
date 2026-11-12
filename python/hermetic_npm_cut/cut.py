"""Core SemVer 2.0.0 comparator, npm packument cutoff filter, and atomic I/O."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
import re
import stat
from typing import Any

DEFAULT_PACKUMENT_CAP_BYTES = 64 * 1024 * 1024
MAX_VERSIONS = 100_000
MAX_TAGS = 10_000
MAX_JSON_DEPTH = 24
MAX_JSON_TOKENS = 8_000_000
MAX_OBJECT_KEYS = 250_000
MAX_STRING_LEN = 256 * 1024
MAX_VERSION_LEN = 256
MAX_TEMP_ATTEMPTS = 128
READ_CHUNK_BYTES = 65_536

_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_RFC3339_RE = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z$",
    flags=re.ASCII,
)
_SEMVER_CORE_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$", flags=re.ASCII)
_SEMVER_IDENT_RE = re.compile(r"^[0-9A-Za-z-]+$", flags=re.ASCII)
_NUMERIC_IDENT_RE = re.compile(r"^(0|[1-9][0-9]*)$", flags=re.ASCII)
_ALL_DIGITS_RE = re.compile(r"^[0-9]+$", flags=re.ASCII)


class HermeticNpmCutError(Exception):
    """Base typed error for hermetic_npm_cut."""

    code: str = "HERMETIC_NPM_CUT_ERROR"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class CapExceededError(HermeticNpmCutError):
    code: str = "CAP_EXCEEDED"


class FileSafetyError(HermeticNpmCutError):
    code: str = "FILE_SAFETY_ERROR"


class JsonParseError(HermeticNpmCutError):
    code: str = "JSON_PARSE_ERROR"


class ValidationError(HermeticNpmCutError):
    code: str = "VALIDATION_ERROR"


class DateParseError(HermeticNpmCutError):
    code: str = "DATE_PARSE_ERROR"


@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[int | str, ...] | None
    build: tuple[str, ...] | None


@dataclass(frozen=True)
class NpmCutReport:
    kept: int
    dropped_after_cutoff: int
    unknown: list[str]
    tags_dropped: list[str]
    latest: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kept": self.kept,
            "dropped_after_cutoff": self.dropped_after_cutoff,
            "unknown": list(self.unknown),
            "tags_dropped": list(self.tags_dropped),
            "latest": self.latest,
        }


def parse_semver(version: str) -> SemVer | None:
    """Strictly parse a SemVer 2.0.0 version string; return None if invalid."""
    if not isinstance(version, str) or len(version) == 0 or len(version) > MAX_VERSION_LEN:
        return None
    if not version.isascii() or "\x00" in version or any(c.isspace() for c in version):
        return None

    build_part: str | None = None
    rest = version
    if "+" in rest:
        rest, build_part = rest.split("+", 1)
        if not build_part:
            return None

    prerelease_part: str | None = None
    if "-" in rest:
        rest, prerelease_part = rest.split("-", 1)
        if not prerelease_part:
            return None

    core_match = _SEMVER_CORE_RE.fullmatch(rest)
    if core_match is None:
        return None
    major = int(core_match.group(1))
    minor = int(core_match.group(2))
    patch = int(core_match.group(3))

    prerelease_tuple: tuple[int | str, ...] | None = None
    if prerelease_part is not None:
        raw_ids = prerelease_part.split(".")
        parsed_ids: list[int | str] = []
        for ident in raw_ids:
            if not ident or _SEMVER_IDENT_RE.fullmatch(ident) is None:
                return None
            if _ALL_DIGITS_RE.fullmatch(ident) is not None:
                if _NUMERIC_IDENT_RE.fullmatch(ident) is None:
                    # Numeric prerelease identifiers MUST NOT include leading zeroes
                    return None
                parsed_ids.append(int(ident))
            else:
                parsed_ids.append(ident)
        prerelease_tuple = tuple(parsed_ids)

    build_tuple: tuple[str, ...] | None = None
    if build_part is not None:
        raw_builds = build_part.split(".")
        for b_ident in raw_builds:
            if not b_ident or _SEMVER_IDENT_RE.fullmatch(b_ident) is None:
                return None
        build_tuple = tuple(raw_builds)

    return SemVer(
        major=major,
        minor=minor,
        patch=patch,
        prerelease=prerelease_tuple,
        build=build_tuple,
    )


def compare_semver(a: SemVer, b: SemVer) -> int:
    """Compare two SemVer 2.0.0 instances: return -1 if a < b, 0 if a == b, 1 if a > b."""
    core_a = (a.major, a.minor, a.patch)
    core_b = (b.major, b.minor, b.patch)
    if core_a < core_b:
        return -1
    if core_a > core_b:
        return 1

    # Normal version has higher precedence than a pre-release version
    if a.prerelease is None and b.prerelease is None:
        return 0
    if a.prerelease is None:
        return 1
    if b.prerelease is None:
        return -1

    min_len = min(len(a.prerelease), len(b.prerelease))
    for i in range(min_len):
        id_a = a.prerelease[i]
        id_b = b.prerelease[i]
        if type(id_a) is type(id_b):
            if id_a < id_b:  # type: ignore[operator]
                return -1
            if id_a > id_b:  # type: ignore[operator]
                return 1
        else:
            # Numeric identifiers always have lower precedence than non-numeric identifiers
            if isinstance(id_a, int):
                return -1
            return 1

    if len(a.prerelease) < len(b.prerelease):
        return -1
    if len(a.prerelease) > len(b.prerelease):
        return 1
    return 0


def parse_rfc3339_utc_nanos(value: str) -> int:
    """Strictly parse RFC 3339 UTC string with trailing 'Z' to integer nanoseconds since epoch."""
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
    open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
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
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise


def _validate_str(val: Any, field: str, max_len: int = MAX_STRING_LEN) -> str:
    if not isinstance(val, str):
        raise ValidationError(f"Field '{field}' must be a string")
    if len(val) == 0 or len(val) > max_len:
        raise ValidationError(f"Field '{field}' length out of bounds")
    if "\x00" in val:
        raise ValidationError(f"Field '{field}' must not contain NUL bytes")
    return val


def cut_packument(
    packument: Any,
    cutoff: str,
) -> tuple[dict[str, Any], NpmCutReport]:
    """Filter an npm registry packument at cutoff and recompute time, dist-tags, and metadata."""
    cutoff_nanos = parse_rfc3339_utc_nanos(cutoff)

    if not isinstance(packument, dict):
        raise ValidationError("Packument root must be a JSON object")
    pkg_name = _validate_str(packument.get("name"), "name", max_len=512)

    if "versions" not in packument or not isinstance(packument["versions"], dict):
        raise ValidationError("Packument must include 'versions' object")
    if len(packument["versions"]) > MAX_VERSIONS:
        raise CapExceededError("Packument 'versions' exceeds MAX_VERSIONS")

    if "time" not in packument or not isinstance(packument["time"], dict):
        raise ValidationError("Packument must include 'time' object")
    if len(packument["time"]) > MAX_VERSIONS + 16:
        raise CapExceededError("Packument 'time' exceeds cap")

    raw_dist_tags = packument.get("dist-tags", {})
    if not isinstance(raw_dist_tags, dict):
        raise ValidationError("Packument 'dist-tags' must be a JSON object")
    if len(raw_dist_tags) > MAX_TAGS:
        raise CapExceededError("Packument 'dist-tags' exceeds MAX_TAGS")
    for tag_k, tag_v in raw_dist_tags.items():
        _validate_str(tag_k, "dist-tags.key", max_len=256)
        _validate_str(tag_v, "dist-tags.value", max_len=MAX_VERSION_LEN)

    raw_versions: dict[str, Any] = packument["versions"]
    raw_time: dict[str, Any] = packument["time"]

    kept_versions: dict[str, Any] = {}
    kept_times_str: dict[str, str] = {}
    kept_times_nanos: dict[str, int] = {}
    dropped_after_count = 0
    unknown_versions: list[str] = []

    for ver in sorted(raw_versions.keys()):
        _validate_str(ver, "versions.key", max_len=MAX_VERSION_LEN)
        manifest = raw_versions[ver]
        if not isinstance(manifest, dict):
            raise ValidationError(f"Manifest for version '{ver}' must be a JSON object")

        if ver not in raw_time or raw_time[ver] is None:
            unknown_versions.append(ver)
            continue

        ver_time_str = raw_time[ver]
        ver_nanos = parse_rfc3339_utc_nanos(ver_time_str)
        if ver_nanos <= cutoff_nanos:
            kept_versions[ver] = copy.deepcopy(manifest)
            kept_times_str[ver] = ver_time_str
            kept_times_nanos[ver] = ver_nanos
        else:
            dropped_after_count += 1

    # Recompute "time": keep only kept versions, set created to earliest and modified to latest.
    recomputed_time: dict[str, str] = {}
    if kept_versions:
        earliest_ver = min(kept_versions.keys(), key=lambda v: (kept_times_nanos[v], v))
        latest_time_ver = max(kept_versions.keys(), key=lambda v: (kept_times_nanos[v], v))
        recomputed_time["created"] = kept_times_str[earliest_ver]
        recomputed_time["modified"] = kept_times_str[latest_time_ver]
        for ver in sorted(kept_versions.keys()):
            recomputed_time[ver] = kept_times_str[ver]

    # Select highest kept stable SemVer 2.0.0 version for "latest"
    best_latest_ver: str | None = None
    best_latest_sv: SemVer | None = None
    for ver in sorted(kept_versions.keys()):
        sv = parse_semver(ver)
        if sv is None or sv.prerelease is not None:
            continue
        if best_latest_sv is None or compare_semver(sv, best_latest_sv) > 0:
            best_latest_sv = sv
            best_latest_ver = ver

    # Recompute dist-tags
    recomputed_tags: dict[str, str] = {}
    tags_dropped: list[str] = []
    for tag in sorted(raw_dist_tags.keys()):
        if tag == "latest":
            continue
        target_ver = raw_dist_tags[tag]
        if target_ver in kept_versions:
            recomputed_tags[tag] = target_ver
        else:
            tags_dropped.append(tag)

    if best_latest_ver is not None:
        recomputed_tags["latest"] = best_latest_ver
    elif "latest" in raw_dist_tags:
        tags_dropped.append("latest")

    tags_dropped.sort()

    out_packument = copy.deepcopy(packument)
    out_packument["name"] = pkg_name
    out_packument["versions"] = kept_versions
    out_packument["time"] = recomputed_time
    out_packument["dist-tags"] = recomputed_tags

    # Always strip post-cutoff leak keys "users" and "_rev"; keep "_id" and "name"
    out_packument.pop("users", None)
    out_packument.pop("_rev", None)

    # Replace top-level "readme" and "readmeFilename" with kept latest version's values if present
    out_packument.pop("readme", None)
    out_packument.pop("readmeFilename", None)
    if best_latest_ver is not None:
        latest_manifest = kept_versions[best_latest_ver]
        if isinstance(latest_manifest.get("readme"), str):
            out_packument["readme"] = latest_manifest["readme"]
        if isinstance(latest_manifest.get("readmeFilename"), str):
            out_packument["readmeFilename"] = latest_manifest["readmeFilename"]

    report = NpmCutReport(
        kept=len(kept_versions),
        dropped_after_cutoff=dropped_after_count,
        unknown=sorted(unknown_versions),
        tags_dropped=sorted(tags_dropped),
        latest=best_latest_ver,
    )
    return out_packument, report


def cut_packument_files(
    packument_path: str | os.PathLike[str],
    cutoff: str,
    out_path: str | os.PathLike[str],
    report_path: str | os.PathLike[str],
    packument_cap_bytes: int = DEFAULT_PACKUMENT_CAP_BYTES,
) -> NpmCutReport:
    raw = read_regular_file_bounded(packument_path, max_bytes=packument_cap_bytes)
    data = parse_json_bytes(raw, max_bytes=packument_cap_bytes)
    cut_data, report = cut_packument(data, cutoff=cutoff)

    out_bytes = json.dumps(
        cut_data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    rep_bytes = json.dumps(
        report.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")

    write_file_atomic(out_path, out_bytes)
    write_file_atomic(report_path, rep_bytes)
    return report
