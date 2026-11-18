"""Offline cutoff filters for crates.io sparse indexes and Go proxy metadata.

The exported filters transform bounded bytes without file or network operations.
The mirror submodule verifies acquisition blobs and publishes admitted metadata
and artifacts into a frozen offline WorldServer store. No source is fetched.
"""

from .cut import CutError, CutReport, cut_crates_index, cut_go_versions
from .provenance import (
    ProvenanceError,
    compute_go_mod_h1,
    compute_go_zip_h1,
    format_go_sum,
    format_sumdb_lookup,
    verify_go_provenance,
)
from .pypi import PyPIIndex, cut_pypi_json, cut_pypi_simple
from .resolver import (
    CutoffResolver,
    ResolutionError,
    ResolutionPlan,
    ResolvedDependency,
    ResolvedPackage,
    parse_version_req,
    satisfies_req,
)

__all__ = [
    "CutError",
    "CutReport",
    "CutoffResolver",
    "ProvenanceError",
    "PyPIIndex",
    "ResolutionError",
    "ResolutionPlan",
    "ResolvedDependency",
    "ResolvedPackage",
    "compute_go_mod_h1",
    "compute_go_zip_h1",
    "cut_crates_index",
    "cut_go_versions",
    "cut_pypi_json",
    "cut_pypi_simple",
    "format_go_sum",
    "format_sumdb_lookup",
    "parse_version_req",
    "satisfies_req",
    "verify_go_provenance",
]
