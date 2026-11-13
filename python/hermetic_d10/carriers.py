
"""Date carrier extractors, bounded parsers, and timestamp classifiers for Detector D10.

In-scope carriers:
  - ZIP/JAR/WHL member DOS timestamps (compared conservatively against T_clock + 14h,
    since MS-DOS timestamps record local wall-clock time without a timezone and UTC+14:00
    is the maximum positive timezone offset on Earth), from both the central directory
    and each member's local file header (the two copies can differ).
  - ZIP/JAR/WHL timestamp extra fields, central and local: extended timestamp (0x5455,
    whose atime/ctime exist only in the local header), Info-ZIP Unix (0x5855), PKWARE
    Unix (0x000D) and NTFS (0x000A).
  - ZIP archives found by their end-of-central-directory record (zipapps, self-extracting
    archives) even when the file does not start with a ZIP signature.
  - TAR member modification times (mtime), plus pax atime/ctime records.
  - GZIP header MTIME (RFC 1952).
  - Python wheel and egg METADATA / PKG-INFO date-bearing RFC 822 header fields.
  - JAR META-INF/MANIFEST.MF "Created-By" / "Build-Date"-style entries with parseable dates.
  - Python .pyc headers in PEP 552 timestamp invalidation mode (flags == 0, bytes 8..12).

Out of scope (intentionally ignored):
  - npm package.json "time"-like fields.
"""

from __future__ import annotations

import bz2
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.parser import HeaderParser
from email.utils import parsedate_to_datetime
import io
import lzma
from pathlib import PurePosixPath
import re
import stat
import struct
import tarfile
import zipfile
import zlib

# Named safety and resource caps
MAX_FILES: int = 10_000
MAX_TOTAL_BYTES_READ: int = 256 * 1024 * 1024  # 256 MiB across an entire tree scan
MAX_FILE_BYTES: int = 32 * 1024 * 1024         # 32 MiB per regular file on disk
MAX_DECOMPRESSED_BYTES: int = 32 * 1024 * 1024 # 32 MiB per archive / decompressed stream
MAX_ARCHIVE_MEMBERS: int = 10_000              # Max members inspected per zip/tar archive
MAX_NESTING_DEPTH: int = 3                     # Max archive nesting depth (e.g. zip in tar in gzip)
MAX_METADATA_BYTES: int = 1 * 1024 * 1024      # 1 MiB cap for METADATA / PKG-INFO / MANIFEST.MF
MAX_METADATA_LINES: int = 5_000                # Max lines parsed in text metadata headers
MAX_EXTRA_FIELD_BYTES: int = 65_536            # 64 KiB max ZIP extra field block
READ_CHUNK_SIZE: int = 65_536                  # 64 KiB streaming read chunk size
MAX_DIR_DEPTH: int = 64                        # Max filesystem directory recursion depth
MAX_DIR_ENTRIES: int = 100_000                 # Max entries listed from one directory
MAX_TREE_ENTRIES: int = 1_000_000              # Max entries visited across a tree scan
MAX_COMPRESSED_STREAMS: int = 1_024            # Max concatenated bz2/xz streams per payload
ZIP_EOCD_SEARCH_BYTES: int = 65_557            # EOCD record (22) + max comment (65535)

# Timestamp evaluation constants
DOS_TIMEZONE_SLACK_HOURS: int = 14
PLAUSIBLE_MIN_YEAR: int = 1980
PLAUSIBLE_MAX_YEAR: int = 2100

PLAUSIBLE_MIN: datetime = datetime(PLAUSIBLE_MIN_YEAR, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
PLAUSIBLE_MAX: datetime = datetime(PLAUSIBLE_MAX_YEAR, 12, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)
DOS_SLACK: timedelta = timedelta(hours=DOS_TIMEZONE_SLACK_HOURS)

_ZIP_MAGICS: tuple[bytes, ...] = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_GZIP_MAGIC: bytes = b"\x1f\x8b"
_BZ2_MAGIC: bytes = b"BZh"
_XZ_MAGIC: bytes = b"\xfd7zXZ\x00"

_PKG_DATE_EXACT_KEYS: frozenset[str] = frozenset({
    "date",
    "build-date",
    "built-date",
    "build-time",
    "build-timestamp",
    "created-date",
    "creation-date",
    "release-date",
    "upload-date",
    "timestamp",
})

_MANIFEST_EXACT_KEYS: frozenset[str] = frozenset({
    "created-by",
    "built-by",
    "bnd-lastmodified",
})

_ISO_DATE_ONLY_RE = re.compile(r"^(\d{4})[-/](\d{2})[-/](\d{2})$")
_ISO_DATETIME_RE = re.compile(
    r"^(\d{4})[-/](\d{2})[-/](\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,6}))?)?"
    r"(?:(Z|z)|([+-]\d{2}):?(\d{2}))?$"
)
_EMBEDDED_DATE_RE = re.compile(
    r"\d{4}[-/]\d{2}[-/]\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|z|[+-]\d{2}:?\d{2})?)?"
)
_FOUR_DIGIT_YEAR_RE = re.compile(r"\b\d{4}\b")


class HermeticD10Error(Exception):
    """Base typed exception for all Detector D10 errors."""


class CapExceededError(HermeticD10Error):
    """Raised when a file, byte, member, decompression, or nesting cap is exceeded."""


class UnsafeFileError(HermeticD10Error):
    """Raised when a symlink, non-regular file, or unsafe path is encountered."""


class MalformedArchiveError(HermeticD10Error):
    """Raised when an archive or binary header is truncated or structurally invalid."""


class InvalidTimestampError(HermeticD10Error):
    """Raised when a timestamp string (such as --t-clock) is not valid RFC 3339."""


@dataclass(frozen=True)
class ScanCaps:
    """Configurable resource caps defaulting to the module's named constants."""

    max_files: int = MAX_FILES
    max_total_bytes_read: int = MAX_TOTAL_BYTES_READ
    max_file_bytes: int = MAX_FILE_BYTES
    max_decompressed_bytes: int = MAX_DECOMPRESSED_BYTES
    max_archive_members: int = MAX_ARCHIVE_MEMBERS
    max_nesting_depth: int = MAX_NESTING_DEPTH
    max_metadata_bytes: int = MAX_METADATA_BYTES
    max_metadata_lines: int = MAX_METADATA_LINES
    max_extra_field_bytes: int = MAX_EXTRA_FIELD_BYTES
    read_chunk_size: int = READ_CHUNK_SIZE
    max_dir_depth: int = MAX_DIR_DEPTH
    max_dir_entries: int = MAX_DIR_ENTRIES
    max_tree_entries: int = MAX_TREE_ENTRIES


@dataclass(frozen=True)
class Finding:
    """Single timestamp discovery from an archive or package metadata carrier."""

    path: str
    member_chain: list[str]
    carrier: str
    found_date: str
    severity: str
    implausible: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "member_chain": list(self.member_chain),
            "carrier": self.carrier,
            "found_date": self.found_date,
            "severity": self.severity,
            "implausible": self.implausible,
            "note": self.note,
        }


@dataclass(frozen=True)
class Refusal:
    """Record of an entry or archive refused due to safety rules or resource caps."""

    path: str
    member_chain: list[str]
    error_type: str
    reason: str
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "member_chain": list(self.member_chain),
            "error_type": self.error_type,
            "reason": self.reason,
            "detail": self.detail,
        }


def parse_rfc3339_utc(value: str) -> datetime:
    """Parse an RFC 3339 timestamp string and normalize to UTC."""
    if not isinstance(value, str) or not value.strip():
        raise InvalidTimestampError("RFC 3339 timestamp must be a non-empty string.")
    text = value.strip()
    if "T" not in text and "t" not in text and " " not in text:
        raise InvalidTimestampError(f"Timestamp missing time component: {value!r}")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise InvalidTimestampError(f"Invalid RFC 3339 timestamp {value!r}: {exc}") from exc
    if dt.tzinfo is None:
        raise InvalidTimestampError(f"RFC 3339 timestamp must include timezone offset: {value!r}")
    return dt.astimezone(timezone.utc)


def format_rfc3339_utc(dt: datetime) -> str:
    """Format a timezone-aware datetime as canonical RFC 3339 UTC."""
    utc_dt = dt.astimezone(timezone.utc)
    if utc_dt.microsecond == 0:
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return utc_dt.isoformat().replace("+00:00", "Z")


def evaluate_timestamp(
    dt: datetime,
    t_clock: datetime,
    *,
    is_dos: bool = False,
) -> tuple[str, bool, str]:
    """Classify a UTC timestamp against T_clock and plausibility bounds.

    Returns (severity, implausible, note).
    """
    utc_dt = dt.astimezone(timezone.utc)
    utc_clock = t_clock.astimezone(timezone.utc)

    if utc_dt < PLAUSIBLE_MIN or utc_dt > PLAUSIBLE_MAX:
        note = (
            "Date is outside plausible bounds (1980-01-01 to 2100-12-31); "
            "reported as implausible (info), not gated."
        )
        if is_dos:
            note += (
                " DOS timestamps have no timezone and are conservatively "
                "compared against T_clock + 14h (UTC+14 maximum offset)."
            )
        return "info", True, note

    if is_dos:
        effective_cutoff = utc_clock + DOS_SLACK
        note = (
            "DOS timestamps have no timezone; compared conservatively against "
            "T_clock + 14h (UTC+14 maximum timezone offset)."
        )
    else:
        effective_cutoff = utc_clock
        note = ""

    if utc_dt > effective_cutoff:
        return "gate", False, note
    return "info", False, note


def parse_flexible_date(raw: str, *, allow_epoch: bool = False) -> datetime | None:
    """Parse common metadata/manifest date strings into a UTC datetime, or None."""
    text = raw.strip()
    if not text:
        return None

    if allow_epoch and text.isdigit():
        if len(text) == 10:
            try:
                return datetime.fromtimestamp(int(text), tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
        if len(text) == 13:
            try:
                return datetime.fromtimestamp(int(text) / 1000.0, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
        return None

    m_date = _ISO_DATE_ONLY_RE.match(text)
    if m_date:
        yr, mo, dy = int(m_date.group(1)), int(m_date.group(2)), int(m_date.group(3))
        try:
            return datetime(yr, mo, dy, 0, 0, 0, tzinfo=timezone.utc)
        except ValueError:
            return None

    m_dt = _ISO_DATETIME_RE.match(text)
    if m_dt:
        yr = int(m_dt.group(1))
        mo = int(m_dt.group(2))
        dy = int(m_dt.group(3))
        hr = int(m_dt.group(4))
        mi = int(m_dt.group(5))
        sc = int(m_dt.group(6) or 0)
        us_str = m_dt.group(7)
        us = int(us_str.ljust(6, "0")) if us_str else 0
        z_flag = m_dt.group(8)
        off_h = m_dt.group(9)
        off_m = m_dt.group(10)
        if z_flag is not None or (off_h is None and off_m is None):
            tz: timezone = timezone.utc
        else:
            sign = -1 if off_h.startswith("-") else 1
            delta = timedelta(hours=abs(int(off_h)), minutes=int(off_m)) * sign
            tz = timezone(delta)
        try:
            return datetime(yr, mo, dy, hr, mi, sc, us, tzinfo=tz).astimezone(timezone.utc)
        except (ValueError, OverflowError):
            return None

    if _FOUR_DIGIT_YEAR_RE.search(text):
        try:
            parsed = parsedate_to_datetime(text)
            if parsed is not None:
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError, IndexError, OverflowError):
            pass

    return None


def _make_finding(
    path: str,
    member_chain: list[str],
    carrier: str,
    dt: datetime,
    t_clock: datetime,
    *,
    is_dos: bool = False,
) -> Finding:
    severity, implausible, note = evaluate_timestamp(dt, t_clock, is_dos=is_dos)
    return Finding(
        path=path,
        member_chain=list(member_chain),
        carrier=carrier,
        found_date=format_rfc3339_utc(dt),
        severity=severity,
        implausible=implausible,
        note=note,
    )


def _read_stream_bounded(
    stream: io.BufferedReader | io.BytesIO | object,
    max_bytes: int,
    chunk_size: int,
    label: str,
) -> bytes:
    """Read from a binary stream in bounded chunks up to max_bytes."""
    buf = bytearray()
    while True:
        remaining = max_bytes - len(buf)
        to_read = min(chunk_size, remaining + 1)
        chunk = stream.read(to_read)  # type: ignore[attr-defined]
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise CapExceededError(f"{label} exceeded byte cap ({max_bytes} bytes).")
    return bytes(buf)


def inspect_pyc_bytes(
    rel_path: str,
    member_chain: list[str],
    data: bytes,
    t_clock: datetime,
) -> list[Finding]:
    """Inspect a Python .pyc file header for PEP 552 timestamp mode (flags == 0)."""
    if len(data) < 16 or data[2:4] != b"\r\n":
        raise MalformedArchiveError("Truncated or invalid .pyc header.")
    (flags,) = struct.unpack_from("<I", data, 4)
    if flags != 0:
        # PEP 552 hash-based invalidation mode (bytes 8..16 hold a SipHash, not a timestamp).
        return []
    (ts,) = struct.unpack_from("<I", data, 8)
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return [_make_finding(rel_path, member_chain, "pyc_timestamp", dt, t_clock)]


def inspect_pkg_metadata_bytes(
    rel_path: str,
    member_chain: list[str],
    data: bytes,
    t_clock: datetime,
    caps: ScanCaps,
) -> list[Finding]:
    """Inspect wheel/egg METADATA or PKG-INFO RFC 822 headers for date fields."""
    if len(data) > caps.max_metadata_bytes:
        raise CapExceededError(
            f"Package metadata size ({len(data)}) exceeds cap ({caps.max_metadata_bytes})."
        )
    text = data.decode("utf-8", errors="replace")
    header_lines: list[str] = []
    for idx, line in enumerate(text.splitlines()):
        if idx >= caps.max_metadata_lines:
            raise CapExceededError(
                f"Package metadata header line count exceeds cap ({caps.max_metadata_lines})."
            )
        if line == "":
            break
        header_lines.append(line)

    if not header_lines:
        return []

    msg = HeaderParser().parsestr("\n".join(header_lines), headersonly=True)
    findings: list[Finding] = []
    for key, val in msg.items():
        key_lower = key.strip().lower()
        is_date_key = (
            key_lower in _PKG_DATE_EXACT_KEYS
            or key_lower.endswith(("-date", "-time", "-timestamp"))
        )
        if not is_date_key:
            continue
        allow_epoch = "timestamp" in key_lower
        dt = parse_flexible_date(val, allow_epoch=allow_epoch)
        if dt is not None:
            findings.append(_make_finding(rel_path, member_chain, "pkg_metadata", dt, t_clock))
    return findings


def inspect_jar_manifest_bytes(
    rel_path: str,
    member_chain: list[str],
    data: bytes,
    t_clock: datetime,
    caps: ScanCaps,
) -> list[Finding]:
    """Inspect JAR META-INF/MANIFEST.MF for Created-By/Build-Date-style date entries."""
    if len(data) > caps.max_metadata_bytes:
        raise CapExceededError(
            f"JAR manifest size ({len(data)}) exceeds cap ({caps.max_metadata_bytes})."
        )
    text = data.decode("utf-8", errors="replace")
    unfolded: list[str] = []
    for idx, raw_line in enumerate(text.splitlines()):
        if idx >= caps.max_metadata_lines:
            raise CapExceededError(
                f"JAR manifest line count exceeds cap ({caps.max_metadata_lines})."
            )
        if raw_line.startswith(" ") and unfolded:
            unfolded[-1] += raw_line[1:]
        else:
            unfolded.append(raw_line)

    findings: list[Finding] = []
    for line in unfolded:
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key_lower = key.strip().lower()
        val_stripped = val.strip()
        if not val_stripped:
            continue

        is_candidate = (
            key_lower in _MANIFEST_EXACT_KEYS
            or key_lower.endswith(("-date", "-time", "-timestamp", "-lastmodified"))
            or "date" in key_lower
            or "timestamp" in key_lower
        )
        if not is_candidate:
            continue

        allow_epoch = "timestamp" in key_lower or "lastmodified" in key_lower
        dt = parse_flexible_date(val_stripped, allow_epoch=allow_epoch)
        if dt is None and key_lower in {"created-by", "built-by"}:
            for match in _EMBEDDED_DATE_RE.finditer(val_stripped):
                dt = parse_flexible_date(match.group(0), allow_epoch=False)
                if dt is not None:
                    break
        if dt is not None:
            findings.append(_make_finding(rel_path, member_chain, "jar_manifest", dt, t_clock))
    return findings


_NTFS_EPOCH_OFFSET_SECONDS: int = 11_644_473_600  # 1601-01-01 to 1970-01-01


def _unix_ts_to_dt(ts: int) -> datetime | None:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _filetime_to_dt(filetime: int) -> datetime | None:
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime // 10)
    except (OverflowError, ValueError):
        return None


def _zip_extra_timestamps(extra: bytes, caps: ScanCaps) -> list[tuple[str, datetime]]:
    """Return (carrier, datetime) for every timestamp in a ZIP extra-field block."""
    found: list[tuple[str, datetime]] = []
    limit = min(len(extra), caps.max_extra_field_bytes)
    pos = 0
    while pos + 4 <= limit:
        header_id, data_size = struct.unpack_from("<HH", extra, pos)
        pos += 4
        if pos + data_size > limit:
            break
        end = pos + data_size
        stamps: list[tuple[str, int | None, datetime | None]] = []
        if header_id == 0x5455 and data_size >= 1:
            flags = extra[pos]
            cursor = pos + 1
            for bit, carrier in (
                (0x01, "zip_ext_timestamp"),
                (0x02, "zip_ext_timestamp_atime"),
                (0x04, "zip_ext_timestamp_ctime"),
            ):
                if (flags & bit) and cursor + 4 <= end:
                    (value,) = struct.unpack_from("<I", extra, cursor)
                    cursor += 4
                    stamps.append((carrier, value, None))
        elif header_id in (0x5855, 0x000D) and data_size >= 8:
            # Info-ZIP Unix (old) and PKWARE Unix: atime then mtime, 32-bit Unix seconds.
            atime, mtime = struct.unpack_from("<II", extra, pos)
            stamps.append(("zip_unix_extra_atime", atime, None))
            stamps.append(("zip_unix_extra_mtime", mtime, None))
        elif header_id == 0x000A and data_size >= 4:
            cursor = pos + 4  # reserved
            while cursor + 4 <= end:
                tag, tag_size = struct.unpack_from("<HH", extra, cursor)
                cursor += 4
                if cursor + tag_size > end:
                    break
                if tag == 0x0001 and tag_size >= 24:
                    mtime, atime, ctime = struct.unpack_from("<QQQ", extra, cursor)
                    stamps.append(("zip_ntfs_mtime", None, _filetime_to_dt(mtime)))
                    stamps.append(("zip_ntfs_atime", None, _filetime_to_dt(atime)))
                    stamps.append(("zip_ntfs_ctime", None, _filetime_to_dt(ctime)))
                cursor += tag_size
        for carrier, unix_value, direct in stamps:
            dt = direct if unix_value is None else _unix_ts_to_dt(unix_value)
            if dt is not None:
                found.append((carrier, dt))
        pos = end
    return found


def _parse_zip_extra_0x5455(
    rel_path: str,
    member_chain: list[str],
    extra: bytes,
    t_clock: datetime,
    caps: ScanCaps,
) -> list[Finding]:
    """Parse ZIP timestamp extra fields (0x5455 and the other timestamp-bearing IDs)."""
    return [
        _make_finding(rel_path, member_chain, carrier, dt, t_clock)
        for carrier, dt in _zip_extra_timestamps(extra, caps)
    ]


def _dos_fields_to_dt(dos_time: int, dos_date: int) -> datetime | None:
    yr = (dos_date >> 9) + 1980
    mo = (dos_date >> 5) & 0x0F
    dy = dos_date & 0x1F
    hr = dos_time >> 11
    mi = (dos_time >> 5) & 0x3F
    sc = (dos_time & 0x1F) * 2
    try:
        return datetime(yr, mo, dy, hr, mi, sc, tzinfo=timezone.utc)
    except ValueError:
        return None


def _zip_local_header(data: bytes, offset: int) -> tuple[int, int, bytes]:
    """Return (dos_time, dos_date, extra) from the local file header at ``offset``."""
    if offset < 0 or offset + 30 > len(data) or data[offset : offset + 4] != b"PK\x03\x04":
        raise MalformedArchiveError("ZIP member local file header missing or truncated.")
    dos_time, dos_date = struct.unpack_from("<HH", data, offset + 10)
    name_len, extra_len = struct.unpack_from("<HH", data, offset + 26)
    extra_start = offset + 30 + name_len
    extra_end = extra_start + extra_len
    if extra_end > len(data):
        raise MalformedArchiveError("ZIP member local extra field truncated.")
    return dos_time, dos_date, data[extra_start:extra_end]


def _has_zip_eocd(data: bytes) -> bool:
    return data.rfind(b"PK\x05\x06", max(0, len(data) - ZIP_EOCD_SEARCH_BYTES)) != -1


def _is_zip_bytes(filename: str, data: bytes) -> bool:
    if len(data) >= 4 and data[:4] in _ZIP_MAGICS:
        return True
    lower = filename.lower()
    return lower.endswith((".zip", ".jar", ".whl", ".egg")) and len(data) > 0


def _is_gzip_bytes(filename: str, data: bytes) -> bool:
    if len(data) >= 2 and data[:2] == _GZIP_MAGIC:
        return True
    lower = filename.lower()
    return lower.endswith((".gz", ".tgz", ".svgz")) and len(data) > 0


def _is_tar_bytes(filename: str, data: bytes) -> bool:
    if len(data) >= 263 and data[257:262] == b"ustar":
        return True
    return filename.lower().endswith(".tar") and len(data) > 0


def _is_bz2_bytes(filename: str, data: bytes) -> bool:
    if len(data) >= 3 and data[:3] == _BZ2_MAGIC:
        return True
    return filename.lower().endswith((".bz2", ".tbz2")) and len(data) > 0


def _is_xz_bytes(filename: str, data: bytes) -> bool:
    if len(data) >= 6 and data[:6] == _XZ_MAGIC:
        return True
    return filename.lower().endswith((".xz", ".txz")) and len(data) > 0


def _derive_gzip_inner_name(outer_name: str, data: bytes, member_index: int) -> str:
    """Determine a deterministic inner member name for a gzip payload."""
    if len(data) >= 10 and data[:2] == _GZIP_MAGIC:
        flg = data[3]
        pos = 10
        if flg & 0x04:  # FEXTRA
            if pos + 2 <= len(data):
                (xlen,) = struct.unpack_from("<H", data, pos)
                pos += 2 + xlen
        if flg & 0x08:  # FNAME
            end = data.find(b"\x00", pos, min(len(data), pos + 1024))
            if end != -1 and end > pos:
                raw_name = data[pos:end].decode("latin-1", errors="replace").lstrip("/")
                if raw_name:
                    return raw_name if member_index == 0 else f"{raw_name}#{member_index}"

    base = PurePosixPath(outer_name).name
    lower = base.lower()
    if lower.endswith(".tgz"):
        derived = base[:-4] + ".tar"
    elif lower.endswith(".gz") and len(base) > 3:
        derived = base[:-3]
    else:
        derived = "<gzip>"
    return derived if member_index == 0 else f"{derived}#{member_index}"


def inspect_zip_bytes(
    rel_path: str,
    member_chain: list[str],
    data: bytes,
    t_clock: datetime,
    caps: ScanCaps,
    depth: int,
) -> list[Finding]:
    """Inspect a ZIP/JAR/WHL archive for DOS timestamps, 0x5455 fields, and nested content."""
    if depth > caps.max_nesting_depth:
        raise CapExceededError(
            f"Archive nesting depth ({depth}) exceeds cap ({caps.max_nesting_depth})."
        )
    try:
        zf = zipfile.ZipFile(io.BytesIO(data), mode="r")
    except (
        zipfile.BadZipFile,
        OSError,
        EOFError,
        struct.error,
        ValueError,
        NotImplementedError,
    ) as exc:
        raise MalformedArchiveError(f"Invalid ZIP archive: {type(exc).__name__}") from exc

    findings: list[Finding] = []
    total_decompressed = 0
    with zf:
        infolist = zf.infolist()
        if len(infolist) > caps.max_archive_members:
            raise CapExceededError(
                f"ZIP member count ({len(infolist)}) exceeds cap ({caps.max_archive_members})."
            )
        for idx, info in enumerate(infolist):
            if idx >= caps.max_archive_members:
                raise CapExceededError(
                    f"ZIP member count exceeds cap ({caps.max_archive_members})."
                )
            cur_chain = member_chain + [info.filename]

            # 1. DOS timestamp (central directory / local header)
            yr, mo, dy, hr, mi, sc = info.date_time
            if (yr, mo, dy, hr, mi, sc) != (1980, 0, 0, 0, 0, 0):
                try:
                    dos_dt = datetime(yr, mo, dy, hr, mi, sc, tzinfo=timezone.utc)
                    findings.append(
                        _make_finding(
                            rel_path,
                            cur_chain,
                            "zip_dos_timestamp",
                            dos_dt,
                            t_clock,
                            is_dos=True,
                        )
                    )
                except ValueError:
                    pass

            # 2. Timestamp extra fields from the central directory
            seen_stamps: set[tuple[str, str]] = set()
            if info.extra:
                for carrier, dt in _zip_extra_timestamps(info.extra, caps):
                    seen_stamps.add((carrier, format_rfc3339_utc(dt)))
                    findings.append(_make_finding(rel_path, cur_chain, carrier, dt, t_clock))

            # 3. The local file header carries its own DOS time and extra block; Info-ZIP
            #    writes atime/ctime only there. Report whatever the central copy lacks.
            local_time, local_date, local_extra = _zip_local_header(data, info.header_offset)
            local_dos = _dos_fields_to_dt(local_time, local_date)
            if local_dos is not None and (
                local_dos.year,
                local_dos.month,
                local_dos.day,
                local_dos.hour,
                local_dos.minute,
                local_dos.second,
            ) != tuple(info.date_time):
                findings.append(
                    _make_finding(
                        rel_path,
                        cur_chain,
                        "zip_local_dos_timestamp",
                        local_dos,
                        t_clock,
                        is_dos=True,
                    )
                )
            for carrier, dt in _zip_extra_timestamps(local_extra, caps):
                key = (carrier, format_rfc3339_utc(dt))
                if key not in seen_stamps:
                    seen_stamps.add(key)
                    findings.append(_make_finding(rel_path, cur_chain, carrier, dt, t_clock))

            # Skip directories and symlink entries inside ZIP
            if info.is_dir():
                continue
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(unix_mode):
                continue

            # Pre-check declared uncompressed size against decompression cap
            if info.file_size < 0 or info.file_size > caps.max_decompressed_bytes:
                raise CapExceededError(
                    f"ZIP member {info.filename!r} uncompressed size ({info.file_size}) "
                    f"exceeds cap ({caps.max_decompressed_bytes})."
                )
            if total_decompressed + info.file_size > caps.max_decompressed_bytes:
                raise CapExceededError(
                    f"Cumulative ZIP decompressed size exceeds cap ({caps.max_decompressed_bytes})."
                )

            remaining_budget = caps.max_decompressed_bytes - total_decompressed
            try:
                with zf.open(info, mode="r") as member_fp:
                    member_bytes = _read_stream_bounded(
                        member_fp,
                        remaining_budget,
                        caps.read_chunk_size,
                        f"ZIP member {info.filename!r}",
                    )
            except (
                zipfile.BadZipFile,
                zlib.error,
                lzma.LZMAError,
                EOFError,
                OSError,
                RuntimeError,
                ValueError,
                NotImplementedError,
            ) as exc:
                raise MalformedArchiveError(
                    f"Corrupt or unsupported ZIP member {info.filename!r}: {type(exc).__name__}"
                ) from exc

            total_decompressed += len(member_bytes)
            findings.extend(
                inspect_payload_bytes(
                    rel_path=rel_path,
                    filename=info.filename,
                    member_chain=cur_chain,
                    data=member_bytes,
                    t_clock=t_clock,
                    caps=caps,
                    depth=depth,
                )
            )
    return findings


def _tar_time_to_dt(value: float) -> datetime | None:
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def inspect_tar_bytes(
    rel_path: str,
    member_chain: list[str],
    data: bytes,
    t_clock: datetime,
    caps: ScanCaps,
    depth: int,
) -> list[Finding]:
    """Inspect a TAR archive for member mtimes and nested regular file members."""
    if depth > caps.max_nesting_depth:
        raise CapExceededError(
            f"Archive nesting depth ({depth}) exceeds cap ({caps.max_nesting_depth})."
        )
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        raise MalformedArchiveError(f"Invalid TAR archive: {exc}") from exc

    findings: list[Finding] = []
    total_extracted = 0
    with tf:
        member_count = 0
        while True:
            try:
                member = tf.next()
            except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
                raise MalformedArchiveError(f"Corrupt TAR stream: {exc}") from exc
            if member is None:
                break
            member_count += 1
            if member_count > caps.max_archive_members:
                raise CapExceededError(
                    f"TAR member count ({member_count}) exceeds cap ({caps.max_archive_members})."
                )

            cur_chain = member_chain + [member.name]
            mtime_dt = _tar_time_to_dt(member.mtime)
            if mtime_dt is None:
                raise MalformedArchiveError(
                    f"TAR member {member.name!r} has an unrepresentable mtime."
                )
            findings.append(_make_finding(rel_path, cur_chain, "tar_mtime", mtime_dt, t_clock))
            for pax_key in ("atime", "ctime"):
                raw_value = member.pax_headers.get(pax_key)
                if raw_value is None:
                    continue
                try:
                    pax_dt = _tar_time_to_dt(float(raw_value))
                except (TypeError, ValueError):
                    pax_dt = None
                if pax_dt is None:
                    raise MalformedArchiveError(
                        f"TAR member {member.name!r} has an unrepresentable pax {pax_key}."
                    )
                findings.append(
                    _make_finding(rel_path, cur_chain, f"tar_pax_{pax_key}", pax_dt, t_clock)
                )

            # Only inspect regular file payloads; never extract symlinks, hardlinks, FIFOs, or devices.
            if not member.isfile():
                continue

            if member.size < 0 or member.size > caps.max_decompressed_bytes:
                raise CapExceededError(
                    f"TAR member {member.name!r} size ({member.size}) "
                    f"exceeds cap ({caps.max_decompressed_bytes})."
                )
            if total_extracted + member.size > caps.max_decompressed_bytes:
                raise CapExceededError(
                    f"Cumulative TAR extracted size exceeds cap ({caps.max_decompressed_bytes})."
                )

            remaining_budget = caps.max_decompressed_bytes - total_extracted
            try:
                extracted_fp = tf.extractfile(member)
                if extracted_fp is None:
                    continue
                with extracted_fp:
                    member_bytes = _read_stream_bounded(
                        extracted_fp,
                        remaining_budget,
                        caps.read_chunk_size,
                        f"TAR member {member.name!r}",
                    )
            except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
                raise MalformedArchiveError(
                    f"Corrupt TAR member {member.name!r}: {type(exc).__name__}"
                ) from exc
            total_extracted += len(member_bytes)
            findings.extend(
                inspect_payload_bytes(
                    rel_path=rel_path,
                    filename=member.name,
                    member_chain=cur_chain,
                    data=member_bytes,
                    t_clock=t_clock,
                    caps=caps,
                    depth=depth,
                )
            )
    return findings


# Header bytes inspected for the FNAME field: fixed header, FEXTRA length and body, name cap.
_GZIP_NAME_HEADER_PROBE = 10 + 2 + 0xFFFF + 1024


def inspect_gzip_bytes(
    rel_path: str,
    outer_name: str,
    member_chain: list[str],
    data: bytes,
    t_clock: datetime,
    caps: ScanCaps,
    depth: int,
) -> list[Finding]:
    """Inspect GZIP header MTIME(s) and bounded decompressed payload."""
    if depth > caps.max_nesting_depth:
        raise CapExceededError(
            f"Archive nesting depth ({depth}) exceeds cap ({caps.max_nesting_depth})."
        )
    if len(data) < 10 or data[:2] != _GZIP_MAGIC:
        raise MalformedArchiveError("Truncated or invalid GZIP header.")

    findings: list[Finding] = []
    offset = 0
    stream_idx = 0
    view = memoryview(data)
    # The decompression cap is archive-wide: it is shared by every concatenated stream.
    total_out = 0

    while offset < len(data):
        if stream_idx >= caps.max_archive_members:
            raise CapExceededError(
                f"Concatenated GZIP stream count exceeds cap ({caps.max_archive_members})."
            )
        remaining_slice = view[offset:]
        if len(remaining_slice) < 10 or bytes(remaining_slice[:2]) != _GZIP_MAGIC:
            raise MalformedArchiveError("Invalid concatenated GZIP member header.")

        (mtime_ts,) = struct.unpack_from("<I", remaining_slice, 4)
        cur_chain = (
            member_chain
            if stream_idx == 0
            else member_chain + [f"<gzip-stream-{stream_idx}>"]
        )
        if mtime_ts != 0:
            dt = datetime.fromtimestamp(mtime_ts, tz=timezone.utc)
            findings.append(_make_finding(rel_path, cur_chain, "gzip_mtime", dt, t_clock))

        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out_buf = bytearray()
        pos = 0
        try:
            while pos < len(remaining_slice) and not decompressor.eof:
                chunk = remaining_slice[pos : pos + caps.read_chunk_size]
                pos += len(chunk)
                remaining_budget = caps.max_decompressed_bytes - total_out - len(out_buf)
                if remaining_budget <= 0:
                    raise CapExceededError(
                        f"GZIP decompressed output exceeds cap ({caps.max_decompressed_bytes})."
                    )
                piece = decompressor.decompress(chunk, max_length=remaining_budget)
                out_buf.extend(piece)
                if (
                    decompressor.unconsumed_tail
                    and total_out + len(out_buf) >= caps.max_decompressed_bytes
                ):
                    raise CapExceededError(
                        f"GZIP decompressed output exceeds cap ({caps.max_decompressed_bytes})."
                    )
            if not decompressor.eof:
                remaining_budget = caps.max_decompressed_bytes - total_out - len(out_buf)
                if remaining_budget <= 0:
                    raise CapExceededError(
                        f"GZIP decompressed output exceeds cap ({caps.max_decompressed_bytes})."
                    )
                out_buf.extend(decompressor.flush(remaining_budget))
        except zlib.error as exc:
            raise MalformedArchiveError(f"Corrupt GZIP deflate stream: {exc}") from exc

        if not decompressor.eof:
            raise MalformedArchiveError("Truncated GZIP stream (missing trailer).")

        consumed = pos - len(decompressor.unused_data)
        if consumed <= 0:
            raise MalformedArchiveError("GZIP decompressor made zero progress.")
        offset += consumed
        total_out += len(out_buf)

        inner_name = _derive_gzip_inner_name(
            outer_name, bytes(remaining_slice[:_GZIP_NAME_HEADER_PROBE]), stream_idx
        )
        inner_chain = member_chain + [inner_name]
        findings.extend(
            inspect_payload_bytes(
                rel_path=rel_path,
                filename=inner_name,
                member_chain=inner_chain,
                data=bytes(out_buf),
                t_clock=t_clock,
                caps=caps,
                depth=depth,
            )
        )
        stream_idx += 1

    return findings


def _decompress_streams_bounded(
    data: bytes,
    caps: ScanCaps,
    label: str,
    make_decompressor: object,
    errors: tuple[type[BaseException], ...],
    *,
    skip_null_padding: bool = False,
) -> bytes:
    """Decompress every concatenated stream in ``data`` within the decompression cap."""
    out_buf = bytearray()
    pending = data
    try:
        for _ in range(MAX_COMPRESSED_STREAMS):
            decompressor = make_decompressor()  # type: ignore[operator]
            pos = 0
            while pos < len(pending) and not decompressor.eof:
                chunk = pending[pos : pos + caps.read_chunk_size]
                pos += len(chunk)
                remaining_budget = caps.max_decompressed_bytes - len(out_buf)
                if remaining_budget <= 0:
                    raise CapExceededError(
                        f"{label} decompressed output exceeds cap ({caps.max_decompressed_bytes})."
                    )
                piece = decompressor.decompress(chunk, max_length=remaining_budget)
                out_buf.extend(piece)
                # Drain output held back by max_length before feeding more input.
                while not decompressor.eof and not decompressor.needs_input:
                    remaining_budget = caps.max_decompressed_bytes - len(out_buf)
                    if remaining_budget <= 0:
                        raise CapExceededError(
                            f"{label} decompressed output exceeds cap "
                            f"({caps.max_decompressed_bytes})."
                        )
                    piece = decompressor.decompress(b"", max_length=remaining_budget)
                    if not piece:
                        break
                    out_buf.extend(piece)
            if not decompressor.eof:
                raise MalformedArchiveError(f"Truncated {label} stream.")
            # Bytes after the end of this stream: the decompressor's unused input plus
            # any input that was never fed to it.
            pending = decompressor.unused_data + bytes(pending[pos:])
            if skip_null_padding:
                # xz permits NUL stream padding between and after streams.
                pending = pending.lstrip(b"\x00")
            if not pending:
                return bytes(out_buf)
        raise CapExceededError(
            f"Concatenated {label} stream count exceeds cap ({MAX_COMPRESSED_STREAMS})."
        )
    except errors as exc:
        raise MalformedArchiveError(f"Corrupt {label} stream: {type(exc).__name__}") from exc


def _decompress_bz2_bounded(data: bytes, caps: ScanCaps) -> bytes:
    return _decompress_streams_bounded(
        data, caps, "BZ2", bz2.BZ2Decompressor, (OSError, EOFError, ValueError)
    )


def _decompress_xz_bounded(data: bytes, caps: ScanCaps) -> bytes:
    return _decompress_streams_bounded(
        data,
        caps,
        "XZ",
        lzma.LZMADecompressor,
        (lzma.LZMAError, EOFError, ValueError),
        skip_null_padding=True,
    )


def inspect_payload_bytes(
    rel_path: str,
    filename: str,
    member_chain: list[str],
    data: bytes,
    t_clock: datetime,
    caps: ScanCaps,
    depth: int,
) -> list[Finding]:
    """Dispatch a file or extracted member payload to matching date carrier inspectors."""
    posix_lower = PurePosixPath(filename).as_posix().lower()
    basename_lower = PurePosixPath(filename).name.lower()

    if basename_lower.endswith(".pyc"):
        return inspect_pyc_bytes(rel_path, member_chain, data, t_clock)

    if (
        basename_lower in {"metadata", "pkg-info"}
        or basename_lower.endswith(".egg-info")
    ):
        return inspect_pkg_metadata_bytes(rel_path, member_chain, data, t_clock, caps)

    if posix_lower.endswith("meta-inf/manifest.mf") or posix_lower == "manifest.mf":
        return inspect_jar_manifest_bytes(rel_path, member_chain, data, t_clock, caps)

    if _is_gzip_bytes(filename, data):
        return inspect_gzip_bytes(
            rel_path=rel_path,
            outer_name=filename,
            member_chain=member_chain,
            data=data,
            t_clock=t_clock,
            caps=caps,
            depth=depth + 1,
        )

    if _is_bz2_bytes(filename, data):
        if depth + 1 > caps.max_nesting_depth:
            raise CapExceededError(
                f"Archive nesting depth ({depth + 1}) exceeds cap ({caps.max_nesting_depth})."
            )
        decompressed = _decompress_bz2_bounded(data, caps)
        inner_name = filename[:-4] if basename_lower.endswith(".bz2") else "<bz2>"
        return inspect_payload_bytes(
            rel_path=rel_path,
            filename=inner_name,
            member_chain=member_chain + [inner_name],
            data=decompressed,
            t_clock=t_clock,
            caps=caps,
            depth=depth + 1,
        )

    if _is_xz_bytes(filename, data):
        if depth + 1 > caps.max_nesting_depth:
            raise CapExceededError(
                f"Archive nesting depth ({depth + 1}) exceeds cap ({caps.max_nesting_depth})."
            )
        decompressed = _decompress_xz_bounded(data, caps)
        inner_name = filename[:-3] if basename_lower.endswith(".xz") else "<xz>"
        return inspect_payload_bytes(
            rel_path=rel_path,
            filename=inner_name,
            member_chain=member_chain + [inner_name],
            data=decompressed,
            t_clock=t_clock,
            caps=caps,
            depth=depth + 1,
        )

    if _is_zip_bytes(filename, data):
        return inspect_zip_bytes(
            rel_path=rel_path,
            member_chain=member_chain,
            data=data,
            t_clock=t_clock,
            caps=caps,
            depth=depth + 1,
        )

    if _is_tar_bytes(filename, data):
        return inspect_tar_bytes(
            rel_path=rel_path,
            member_chain=member_chain,
            data=data,
            t_clock=t_clock,
            caps=caps,
            depth=depth + 1,
        )

    if _has_zip_eocd(data):
        # A ZIP with a prefix (zipapp shebang, self-extractor stub) has no leading
        # signature. Only a payload that actually opens as a ZIP is inspected; other
        # bytes that merely contain the EOCD signature are ordinary data.
        try:
            zipfile.ZipFile(io.BytesIO(data), mode="r").close()
        except Exception:  # noqa: BLE001
            return []
        # zipfile reports header offsets including the prefix, so local headers
        # are located in ``data`` as is.
        return inspect_zip_bytes(
            rel_path=rel_path,
            member_chain=member_chain,
            data=data,
            t_clock=t_clock,
            caps=caps,
            depth=depth + 1,
        )

    return []


