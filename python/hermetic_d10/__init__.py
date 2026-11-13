
"""Hermetic World Detector D10: post-cutoff timestamp scanner for archives and package metadata."""

from __future__ import annotations

from hermetic_d10.carriers import (
    DOS_TIMEZONE_SLACK_HOURS,
    MAX_ARCHIVE_MEMBERS,
    MAX_DECOMPRESSED_BYTES,
    MAX_DIR_DEPTH,
    MAX_EXTRA_FIELD_BYTES,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_METADATA_BYTES,
    MAX_METADATA_LINES,
    MAX_NESTING_DEPTH,
    MAX_TOTAL_BYTES_READ,
    PLAUSIBLE_MAX_YEAR,
    PLAUSIBLE_MIN_YEAR,
    READ_CHUNK_SIZE,
    CapExceededError,
    Finding,
    HermeticD10Error,
    InvalidTimestampError,
    MalformedArchiveError,
    Refusal,
    ScanCaps,
    UnsafeFileError,
    format_rfc3339_utc,
    parse_rfc3339_utc,
)
from hermetic_d10.scan import ScanResult, scan_file, scan_tree

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "DOS_TIMEZONE_SLACK_HOURS",
    "MAX_ARCHIVE_MEMBERS",
    "MAX_DECOMPRESSED_BYTES",
    "MAX_DIR_DEPTH",
    "MAX_EXTRA_FIELD_BYTES",
    "MAX_FILE_BYTES",
    "MAX_FILES",
    "MAX_METADATA_BYTES",
    "MAX_METADATA_LINES",
    "MAX_NESTING_DEPTH",
    "MAX_TOTAL_BYTES_READ",
    "PLAUSIBLE_MAX_YEAR",
    "PLAUSIBLE_MIN_YEAR",
    "READ_CHUNK_SIZE",
    "CapExceededError",
    "Finding",
    "HermeticD10Error",
    "InvalidTimestampError",
    "MalformedArchiveError",
    "Refusal",
    "ScanCaps",
    "ScanResult",
    "UnsafeFileError",
    "format_rfc3339_utc",
    "parse_rfc3339_utc",
    "scan_file",
    "scan_tree",
]


