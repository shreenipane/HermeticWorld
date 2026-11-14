"""Core SemVer 2.0.0 comparator, npm packument cutoff filter, and atomic I/O."""

from __future__ import annotations

import copy
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import math
import os
import re
import stat
from typing import Any

from hermetic_safe_io import (
    atomic_write, atomic_write_at, open_parent, open_regular, open_regular_at, validate_path,
)

DEFAULT_PACKUMENT_CAP_BYTES = 64 * 1024 * 1024
MAX_VERSIONS = 100_000
MAX_TAGS = 10_000
MAX_JSON_DEPTH = 24
MAX_JSON_TOKENS = 8_000_000
MAX_OBJECT_KEYS = 250_000
MAX_STRING_LEN = 256 * 1024
MAX_VERSION_LEN = 256
MAX_INTEGER_BITS = 4096
MAX_OPEN_SIZE_BYTES = 1 << 62
READ_CHUNK_BYTES = 65_536

# "time" keys that describe the whole package, never a single version.
_RESERVED_TIME_KEYS = frozenset({"created", "modified", "unpublished"})

# Top-level keys the registry derives from the newest publish (post-cutoff state). Like
# "readme" (rule 4) they are replaced by the kept latest version's own value, else removed.
LATEST_DERIVED_KEYS = (
    "readme",
    "readmeFilename",
    "description",
    "keywords",
    "author",
    "contributors",
    "maintainers",
    "repository",
    "homepage",
    "bugs",
    "license",
)

# Manifest keys the registry can mutate after a version was published, so their value at
# the cutoff is unverifiable: dropped from every kept manifest (fail closed).
POST_PUBLISH_MANIFEST_KEYS = ("deprecated",)

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


def _validate_json_tree(value: Any, max_bytes: int, *, snapshot: bool = False) -> Any:
    """Bound direct library inputs before sorting or copying any nested manifest.

    Iterator frames keep auxiliary memory proportional to MAX_JSON_DEPTH. The
    byte budget includes every occurrence, including shared nodes.
    Cycles therefore reach the depth cap instead of reaching deepcopy/encoding.
    When requested, copy containers during validation so later consumers never
    revisit caller-owned nodes that could have changed after their checks.
    """
    captured: list[Any] = []
    frames = [(iter(((value, captured, None),)), 0)]
    tokens = 0
    size = 0
    while frames:
        iterator, depth = frames[-1]
        try:
            item, destination, key = next(iterator)
        except StopIteration:
            frames.pop()
            continue
        except RuntimeError:
            raise ValidationError("JSON object changed during validation") from None
        tokens += 1
        if tokens > MAX_JSON_TOKENS:
            raise CapExceededError("JSON token count exceeds cap")
        kind = type(item)
        retained = item
        if kind in (dict, list):
            if depth >= MAX_JSON_DEPTH:
                raise CapExceededError("JSON nesting depth exceeds cap")
            retained = ({} if kind is dict else []) if snapshot else item
            if kind is dict:
                if len(item) > MAX_OBJECT_KEYS:
                    raise CapExceededError("JSON object key count exceeds cap")
                def members(mapping, target):
                    for key, member in mapping.items():
                        if type(key) is not str:
                            raise ValidationError("JSON object keys must be strings")
                        if "\0" in key:
                            raise ValidationError("NUL byte not allowed in JSON key")
                        yield key, None, None
                        yield member, target, key
                children = members(item, retained if snapshot else None)
            else:
                def elements(sequence, target):
                    for member in sequence:
                        yield member, target, None
                children = elements(item, retained if snapshot else None)
            size += 2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0)
            frames.append((children, depth + 1))
        else:
            if kind is str:
                if len(item) > MAX_STRING_LEN:
                    raise CapExceededError("JSON string length exceeds cap")
            elif kind is int:
                if item.bit_length() > MAX_INTEGER_BITS:
                    raise CapExceededError("JSON integer size exceeds cap")
            elif kind is float:
                if not math.isfinite(item):
                    raise ValidationError("Non-finite JSON number rejected")
            elif kind not in (bool, type(None)):
                raise ValidationError("Non-JSON value rejected")
            try:
                size += len(json.dumps(item, ensure_ascii=False, allow_nan=False).encode("utf-8"))
            except UnicodeEncodeError:
                raise ValidationError("JSON contains text that is not valid Unicode") from None
        if size > max_bytes:
            raise CapExceededError("JSON tree exceeds byte cap")
        if destination is not None:
            if type(destination) is list:
                destination.append(retained)
            else:
                destination[key] = retained
    return captured[0]


def parse_json_bytes(raw: bytes, max_bytes: int) -> Any:
    if type(raw) is not bytes:
        raise ValidationError("JSON input must be bytes")
    if type(max_bytes) is not int or not 0 <= max_bytes <= DEFAULT_PACKUMENT_CAP_BYTES:
        raise ValidationError("JSON byte cap is out of bounds")
    if len(raw) > max_bytes:
        raise CapExceededError("JSON payload exceeds byte cap")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JsonParseError("Invalid UTF-8 in JSON input") from exc
    _precheck_json_structure(text, max_depth=MAX_JSON_DEPTH, max_tokens=MAX_JSON_TOKENS)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_pairs_hook,
            parse_constant=_reject_constant,
        )
        _validate_json_tree(value, max_bytes)
        return value
    except (CapExceededError, JsonParseError, ValidationError):
        raise
    except RecursionError as exc:
        raise CapExceededError("JSON nesting depth exceeded") from exc
    except ValueError as exc:
        raise JsonParseError("Malformed JSON document") from exc


def read_regular_file_bounded(path: str | os.PathLike[str], max_bytes: int,
                              *, directory: int | None = None,
                              expected: os.stat_result | None = None) -> bytes:
    """Read a pinned regular inode without following any symlink or blocking on a FIFO."""
    if type(max_bytes) is not int or max_bytes < 0:
        raise ValidationError("Byte cap must be a non-negative integer")
    try:
        # The cap is enforced below so that an oversized file maps to CapExceededError.
        if directory is None:
            fd = open_regular(path, MAX_OPEN_SIZE_BYTES)
        else:
            fd = open_regular_at(directory, os.fspath(path), MAX_OPEN_SIZE_BYTES, expected=expected)
    except (OSError, ValueError, TypeError):
        raise FileSafetyError("Refusing to open file (missing, symlink, non-regular, or OS error)") from None
    try:
        try:
            st = os.fstat(fd)
        except OSError:
            raise FileSafetyError("Unable to stat file descriptor") from None
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
            except OSError:
                raise FileSafetyError("Error reading file") from None
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
    """Atomically publish bytes: temp file in the pinned parent, fsync, rename, dir fsync."""
    if not isinstance(content, bytes):
        raise ValidationError("Output content must be bytes")
    try:
        atomic_write(target_path, content)
    except (OSError, ValueError, TypeError):
        raise FileSafetyError("Unable to write destination atomically") from None


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
    packument = _validate_json_tree(packument, DEFAULT_PACKUMENT_CAP_BYTES, snapshot=True)

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
            raise ValidationError("Version manifest must be a JSON object")

        if ver in _RESERVED_TIME_KEYS or ver not in raw_time or raw_time[ver] is None:
            # A reserved "time" key is package-level, not this version's publish time.
            unknown_versions.append(ver)
            continue

        ver_time_str = raw_time[ver]
        ver_nanos = parse_rfc3339_utc_nanos(ver_time_str)
        if ver_nanos <= cutoff_nanos:
            kept_manifest = copy.deepcopy(manifest)
            for mutable_key in POST_PUBLISH_MANIFEST_KEYS:
                kept_manifest.pop(mutable_key, None)
            kept_versions[ver] = kept_manifest
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

    # Recompute dist-tags. A packument carries no tag history: a tag's name and
    # target can be set after the cutoff even when it points at an admitted
    # version (e.g. "added-after-cutoff-2026" -> a 2020 release). Owner decision
    # (2026-11-14): drop every tag except "latest", which is recomputed from the
    # admitted versions alone.
    recomputed_tags: dict[str, str] = {}
    tags_dropped: list[str] = sorted(tag for tag in raw_dist_tags if tag != "latest")

    if best_latest_ver is not None:
        recomputed_tags["latest"] = best_latest_ver
    elif "latest" in raw_dist_tags:
        tags_dropped.append("latest")

    tags_dropped.sort()

    # Build the output from an allow-list (fail closed): every top-level key not listed
    # here ("users", "_rev", "_attachments", unknown registry keys) may carry post-cutoff
    # state and is dropped. "_id" and "name" are kept (rule 4).
    out_packument: dict[str, Any] = {
        "name": pkg_name,
        "versions": kept_versions,
        "time": recomputed_time,
        "dist-tags": recomputed_tags,
    }
    if "_id" in packument:
        out_packument["_id"] = _validate_str(packument["_id"], "_id", max_len=512)

    # Rule 4: "readme", "readmeFilename" and the other latest-derived keys are replaced by
    # the kept latest version's own values if present, else removed.
    if best_latest_ver is not None:
        latest_manifest = kept_versions[best_latest_ver]
        for derived_key in LATEST_DERIVED_KEYS:
            if derived_key in latest_manifest:
                out_packument[derived_key] = copy.deepcopy(latest_manifest[derived_key])

    report = NpmCutReport(
        kept=len(kept_versions),
        dropped_after_cutoff=dropped_after_count,
        unknown=sorted(unknown_versions),
        tags_dropped=sorted(tags_dropped),
        latest=best_latest_ver,
    )
    return out_packument, report


def canonical_json_bytes(value: Any) -> bytes:
    """Canonical JSON (sorted keys, compact, UTF-8); unencodable text is a typed error."""
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except UnicodeEncodeError as exc:
        # json accepts "\ud800" escapes; a lone surrogate has no UTF-8 encoding.
        raise ValidationError("Packument contains text that is not valid Unicode") from exc


def cut_packument_files(
    packument_path: str | os.PathLike[str],
    cutoff: str,
    out_path: str | os.PathLike[str],
    report_path: str | os.PathLike[str],
    packument_cap_bytes: int = DEFAULT_PACKUMENT_CAP_BYTES,
) -> NpmCutReport:
    parse_rfc3339_utc_nanos(cutoff)
    if (type(packument_cap_bytes) is not int
            or not 0 <= packument_cap_bytes <= DEFAULT_PACKUMENT_CAP_BYTES):
        raise ValidationError("Packument byte cap is out of bounds")
    try:
        paths = [validate_path(path)[0] for path in (packument_path, out_path, report_path)]
    except (OSError, ValueError, TypeError):
        raise ValidationError("Invalid packument or publication path") from None
    if len({os.path.abspath(path) for path in paths}) != len(paths):
        raise ValidationError("Input, output and report paths must be distinct")
    with ExitStack() as handles:
        try:
            destinations = []
            inspected = []
            names = set()
            inodes = set()
            # Inspect every destination before publication, and retain its parent
            # handle so later directory renames cannot redirect either write.
            for path in paths:
                directory, leaf = open_parent(path)
                handles.callback(os.close, directory)
                parent = os.fstat(directory)
                identity = (parent.st_dev, parent.st_ino, leaf)
                if identity in names:
                    raise ValidationError("Input, output and report paths must be distinct")
                names.add(identity)
                try:
                    existing = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    existing = None
                if existing is not None:
                    if not stat.S_ISREG(existing.st_mode):
                        raise FileSafetyError("Publication requires regular files")
                    inode = (existing.st_dev, existing.st_ino)
                    if inode in inodes:
                        raise ValidationError("Input, output and report paths must be distinct")
                    inodes.add(inode)
                destinations.append((directory, leaf))
                inspected.append(existing)
        except (OSError, ValueError, TypeError):
            raise FileSafetyError("Unable to prepare publication safely") from None

        if inspected[0] is None:
            raise FileSafetyError("Input must exist during preflight")
        input_directory, input_leaf = destinations[0]
        raw = read_regular_file_bounded(input_leaf, max_bytes=packument_cap_bytes,
                                        directory=input_directory, expected=inspected[0])
        data = parse_json_bytes(raw, max_bytes=packument_cap_bytes)
        cut_data, report = cut_packument(data, cutoff=cutoff)
        out_bytes = canonical_json_bytes(cut_data)
        rep_bytes = canonical_json_bytes(report.to_dict())
        try:
            for (directory, leaf), content in zip(destinations[1:], (out_bytes, rep_bytes)):
                atomic_write_at(directory, leaf, content)
        except (OSError, ValueError, TypeError):
            raise FileSafetyError("Unable to write destination atomically") from None
        return report
