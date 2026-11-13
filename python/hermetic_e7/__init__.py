
"""Hermetic World Experiment E7: deterministic sealing and reproducibility diffing."""

from hermetic_e7.compare import (
    ComparisonReport,
    ImageLocalisation,
    JsonLocalisation,
    ModeDiff,
    SizeHashDiff,
    SuspectedCause,
    TextLocalisation,
    classify_file,
    compare_worlds,
    format_report,
)
from hermetic_e7.tree import (
    CapExceededError,
    HermeticError,
    UnsupportedEntryError,
    WorldPathError,
    build_manifest,
    canonical_manifest_bytes,
)

__all__ = [
    "CapExceededError",
    "ComparisonReport",
    "HermeticError",
    "ImageLocalisation",
    "JsonLocalisation",
    "ModeDiff",
    "SizeHashDiff",
    "SuspectedCause",
    "TextLocalisation",
    "UnsupportedEntryError",
    "WorldPathError",
    "build_manifest",
    "canonical_manifest_bytes",
    "classify_file",
    "compare_worlds",
    "format_report",
]


