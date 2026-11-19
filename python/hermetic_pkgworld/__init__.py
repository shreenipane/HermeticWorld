"""Hermetic World package evidence component for WorldManifest.

Computes PackagesRecord {closure_root, baseline_month, baseline_root}
over Layer-1 frozen closures (hermetic_pkgrec freeze) and Layer-2 baseline stores (hermetic_pkgbase).
"""

from __future__ import annotations

from hermetic_pkgworld.constants import (
    PKG_EMPTY_TAG,
    PKG_LEAF_TAG,
    PKG_NODE_TAG,
)
from hermetic_pkgworld.errors import (
    BaselineError,
    ClosureError,
    CutoffMismatchError,
    IntegrityError,
    PkgWorldError,
    SafeIOError,
)
from hermetic_pkgworld.evidence import (
    canonical_json_bytes,
    compute_baseline_root,
    compute_closure_root,
    compute_leaf_hash,
    compute_merkle_root,
    compute_package_evidence,
)

__all__ = [
    "BaselineError",
    "ClosureError",
    "CutoffMismatchError",
    "IntegrityError",
    "PKG_EMPTY_TAG",
    "PKG_LEAF_TAG",
    "PKG_NODE_TAG",
    "PkgWorldError",
    "SafeIOError",
    "canonical_json_bytes",
    "compute_baseline_root",
    "compute_closure_root",
    "compute_leaf_hash",
    "compute_merkle_root",
    "compute_package_evidence",
]
