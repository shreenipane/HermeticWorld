"""Hermetic slice package for cutoff computation and repository sealing."""

from hermetic_slice.cutoffs import (
    Cutoffs,
    DiscardedDate,
    FixCommit,
    compute_cutoffs,
    ensure_utc,
)
from hermetic_slice.gitutil import GitError, run_git
from hermetic_slice.repo_sealer import (
    SealReport,
    UnsupportedRepoError,
    VerificationError,
    seal_repo,
    verify_sealed_repo,
)

__all__ = [
    "Cutoffs",
    "DiscardedDate",
    "FixCommit",
    "GitError",
    "SealReport",
    "UnsupportedRepoError",
    "VerificationError",
    "compute_cutoffs",
    "ensure_utc",
    "run_git",
    "seal_repo",
    "verify_sealed_repo",
]
