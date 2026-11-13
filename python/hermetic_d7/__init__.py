
"""Hermetic World Detector D7: deep audit comparison of shipped vs rebuilt artifacts."""

from __future__ import annotations

from hermetic_d7.compare import (
    build_error_report,
    build_unified_diff,
    compare_artifacts,
    format_report_json,
)
from hermetic_d7.normalise import (
    MAX_ARCHIVE_MEMBERS,
    MAX_DIFF_INPUT_LINES,
    MAX_DIFF_LINES,
    MAX_MEMBER_BYTES,
    MAX_METADATA_LINES,
    MAX_NESTING_DEPTH,
    MAX_READ_CHUNKS,
    MAX_RECORD_LINES,
    MAX_TEXT_DIFF_BYTES,
    MAX_TOTAL_DECOMPRESSED_BYTES,
    PYC_HEADER_SIZE,
    READ_CHUNK_SIZE,
    CliUsageError,
    HermeticD7Error,
    InvalidArtifactError,
    NormalisedMember,
    ResourceLimitError,
    ResourceLimits,
    SecurityViolationError,
    load_artifact,
    normalise_executable,
    normalise_member_bytes,
    normalise_metadata,
    normalise_pyc,
    normalise_record,
    validate_member_path,
)

__version__ = "0.1.0"

__all__ = [
    "CliUsageError",
    "HermeticD7Error",
    "InvalidArtifactError",
    "MAX_ARCHIVE_MEMBERS",
    "MAX_DIFF_INPUT_LINES",
    "MAX_DIFF_LINES",
    "MAX_MEMBER_BYTES",
    "MAX_METADATA_LINES",
    "MAX_NESTING_DEPTH",
    "MAX_READ_CHUNKS",
    "MAX_RECORD_LINES",
    "MAX_TEXT_DIFF_BYTES",
    "MAX_TOTAL_DECOMPRESSED_BYTES",
    "NormalisedMember",
    "PYC_HEADER_SIZE",
    "READ_CHUNK_SIZE",
    "ResourceLimitError",
    "ResourceLimits",
    "SecurityViolationError",
    "__version__",
    "build_error_report",
    "build_unified_diff",
    "compare_artifacts",
    "format_report_json",
    "load_artifact",
    "normalise_executable",
    "normalise_member_bytes",
    "normalise_metadata",
    "normalise_pyc",
    "normalise_record",
    "validate_member_path",
]


