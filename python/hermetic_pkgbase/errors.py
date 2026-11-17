"""Typed exceptions for hermetic_pkgbase.

All failures raise a typed subclass of PkgBaseError. No unhandled
or raw exceptions escape to callers.
"""

from __future__ import annotations

from hermetic_safe_io import UnsafePathError as BaseUnsafePathError


class PkgBaseError(Exception):
    """Base exception for all hermetic_pkgbase errors."""


class SpecValidationError(PkgBaseError):
    """Raised when a baseline spec violates validation rules or format constraints."""


class CapExceededError(PkgBaseError):
    """Raised when a named cap or limit is exceeded."""


class DepthCapExceededError(CapExceededError):
    """Raised when dependency resolution depth exceeds the maximum allowed depth."""


class PackageCountCapExceededError(CapExceededError):
    """Raised when resolved package count exceeds the maximum allowed count."""


class TotalBytesCapExceededError(CapExceededError):
    """Raised when total resolved artifact bytes exceed the maximum allowed cap."""


class ResolutionError(PkgBaseError):
    """Raised when an error occurs during dependency resolution."""


class HashMismatchError(PkgBaseError):
    """Raised when fetched artifact content does not match the expected SHA-256 digest."""


class StoreImmutableError(PkgBaseError):
    """Raised when an operation attempts to modify or rebuild a frozen baseline store."""


class StoreIOError(PkgBaseError):
    """Raised when filesystem operations on the baseline store fail."""


class UnsafePathError(StoreIOError, BaseUnsafePathError):
    """Raised when a path is unsafe, contains symlinks, or traverses outside the store root."""
