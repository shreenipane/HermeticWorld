"""Typed exceptions for hermetic_pkgworld."""

from __future__ import annotations


class PkgWorldError(Exception):
    """Base error for all hermetic_pkgworld operations."""


class ClosureError(PkgWorldError):
    """Raised when the Layer-1 frozen closure is invalid, incomplete, or corrupted."""


class BaselineError(PkgWorldError):
    """Raised when the Layer-2 baseline plan/store is invalid, unfrozen, or corrupted."""


class IntegrityError(PkgWorldError):
    """Raised when a distribution file digest or manifest verification fails."""


class CutoffMismatchError(PkgWorldError):
    """Raised when baseline cutoff month does not match the package cutoff."""


class SafeIOError(PkgWorldError):
    """Raised when an unsafe path, symlink, or special file is encountered."""
