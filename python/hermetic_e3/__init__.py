
"""Hermetic World Experiment E3 evaluation package.

Evaluates leak-scanner ("sealcheck") findings against ground-truth leaks
(seeded and real) using deterministic matching, integer per-mille metrics,
task-level percentile bootstrap confidence intervals, and exit-criterion checks.
"""

from __future__ import annotations

__all__ = [
    "MAX_FILE_BYTES",
    "READ_CHUNK_BYTES",
    "MAX_READ_CHUNKS",
    "MAX_ENTRIES",
    "MAX_OBJECT_KEYS",
    "MAX_STRING_LEN",
    "MAX_LINE_NUMBER",
    "DEFAULT_BOOTSTRAP_ITERATIONS",
    "MAX_BOOTSTRAP_ITERATIONS",
    "MAX_CLI_ARGS",
    "MAX_VALIDATION_DEPTH",
    "PERMILLE_SCALE",
    "HermeticE3Error",
    "FileSecurityError",
    "SizeLimitError",
    "JsonFormatError",
    "DuplicateKeyError",
    "SchemaValidationError",
    "RangeError",
    "CliArgumentError",
    "Leak",
    "Finding",
    "MatchResult",
    "ScopeMetrics",
    "PercentileRange",
    "ConfidenceInterval",
    "ExitCriterionResult",
    "EvaluationReport",
    "load_ground_truth",
    "load_findings",
    "parse_ground_truth",
    "parse_findings",
    "ranges_overlap",
    "match_findings",
    "to_permille_floor",
    "compute_all_metrics",
    "bootstrap_confidence_interval",
    "evaluate_exit_criterion",
    "evaluate",
]

# Named constant caps bounding every file read, validation pass, and loop.
MAX_FILE_BYTES: int = 16 * 1024 * 1024  # 16 MiB
READ_CHUNK_BYTES: int = 64 * 1024  # 64 KiB
MAX_READ_CHUNKS: int = (MAX_FILE_BYTES // READ_CHUNK_BYTES) + 2
MAX_ENTRIES: int = 200_000
MAX_OBJECT_KEYS: int = 32
MAX_STRING_LEN: int = 65_536
MAX_LINE_NUMBER: int = 100_000_000
DEFAULT_BOOTSTRAP_ITERATIONS: int = 1_000
MAX_BOOTSTRAP_ITERATIONS: int = 100_000
MAX_CLI_ARGS: int = 64
MAX_VALIDATION_DEPTH: int = 16
PERMILLE_SCALE: int = 1_000


class HermeticE3Error(Exception):
    """Base typed error for all Hermetic E3 failures."""

    error_code: str = "HERMETIC_E3_ERROR"


class FileSecurityError(HermeticE3Error):
    """Raised when a file cannot be opened safely (missing, symlink, non-regular)."""

    error_code: str = "FILE_SECURITY_ERROR"


class SizeLimitError(HermeticE3Error):
    """Raised when a file or collection exceeds a hard size or entry cap."""

    error_code: str = "SIZE_LIMIT_ERROR"


class JsonFormatError(HermeticE3Error):
    """Raised when input bytes are not valid UTF-8 or valid strict JSON."""

    error_code: str = "JSON_FORMAT_ERROR"


class DuplicateKeyError(JsonFormatError):
    """Raised when a JSON object contains duplicate keys."""

    error_code: str = "DUPLICATE_KEY_ERROR"


class SchemaValidationError(HermeticE3Error):
    """Raised when parsed JSON violates the strict ground-truth or findings schema."""

    error_code: str = "SCHEMA_VALIDATION_ERROR"


class RangeError(HermeticE3Error):
    """Raised when a numeric parameter falls outside its allowed integer bounds."""

    error_code: str = "RANGE_ERROR"


class CliArgumentError(HermeticE3Error):
    """Raised when command-line arguments are missing, malformed, or out of range."""

    error_code: str = "CLI_ARGUMENT_ERROR"


from hermetic_e3.match import (  # noqa: E402
    Finding,
    Leak,
    MatchResult,
    load_findings,
    load_ground_truth,
    match_findings,
    parse_findings,
    parse_ground_truth,
    ranges_overlap,
)
from hermetic_e3.metrics import (  # noqa: E402
    ConfidenceInterval,
    EvaluationReport,
    ExitCriterionResult,
    PercentileRange,
    ScopeMetrics,
    bootstrap_confidence_interval,
    compute_all_metrics,
    evaluate,
    evaluate_exit_criterion,
    to_permille_floor,
)


