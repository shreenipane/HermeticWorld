"""Hermetic World Layer 2 ecosystem baseline package (TR-PKG-4).

Provides:
- Validated, capped baseline specification for a cutoff month.
- Bounded transitive closure planner with deterministic output and cycle handling.
- Content-addressed store builder compatible with hermetic_pkgindex store.py,
  verifying every SHA-256 and enforcing baseline immutability.
- Storage footprint measurement per ecosystem and per package.
"""

from __future__ import annotations

from .builder import BaselineBuilder, Fetcher, OfflineFixtureFetcher, is_store_frozen
from .errors import (
    CapExceededError,
    DepthCapExceededError,
    HashMismatchError,
    PackageCountCapExceededError,
    PkgBaseError,
    ResolutionError,
    SpecValidationError,
    StoreImmutableError,
    StoreIOError,
    TotalBytesCapExceededError,
    UnsafePathError,
)
from .planner import (
    MAX_CLOSURE_DEPTH,
    MAX_PACKAGE_COUNT,
    MAX_QUEUE_ITERATIONS,
    MAX_TOTAL_BYTES,
    Plan,
    Planner,
    UnresolvedPackage,
)
from .resolver import (
    OfflineFixtureResolver,
    ResolvedFile,
    ResolvedRelease,
    Resolver,
    parse_rfc3339_nanos,
)
from .spec import (
    CANONICAL_FIXED_TOOLS,
    MAX_ECOSYSTEMS,
    MAX_FILE_BYTES,
    MAX_FILENAME_BYTES,
    MAX_FIXED_TOOLS,
    MAX_SPEC_BYTES,
    MAX_TOP_N,
    BaselineSpec,
    normalize_project_name,
    parse_cutoff_month,
    parse_spec,
    parse_top_packages_file,
    validate_distribution_filename,
)
from .storage import StorageReport

__all__ = [
    "BaselineBuilder",
    "BaselineSpec",
    "CANONICAL_FIXED_TOOLS",
    "CapExceededError",
    "DepthCapExceededError",
    "Fetcher",
    "HashMismatchError",
    "MAX_CLOSURE_DEPTH",
    "MAX_ECOSYSTEMS",
    "MAX_FILE_BYTES",
    "MAX_FILENAME_BYTES",
    "MAX_FIXED_TOOLS",
    "MAX_PACKAGE_COUNT",
    "MAX_QUEUE_ITERATIONS",
    "MAX_SPEC_BYTES",
    "MAX_TOP_N",
    "MAX_TOTAL_BYTES",
    "OfflineFixtureFetcher",
    "OfflineFixtureResolver",
    "PackageCountCapExceededError",
    "PkgBaseError",
    "Plan",
    "Planner",
    "ResolutionError",
    "ResolvedFile",
    "ResolvedRelease",
    "Resolver",
    "SpecValidationError",
    "StorageReport",
    "StoreImmutableError",
    "StoreIOError",
    "TotalBytesCapExceededError",
    "UnresolvedPackage",
    "UnsafePathError",
    "is_store_frozen",
    "normalize_project_name",
    "parse_cutoff_month",
    "parse_rfc3339_nanos",
    "parse_spec",
    "parse_top_packages_file",
    "validate_distribution_filename",
]
