"""Typed exceptions for hermetic_pkgrec."""

from __future__ import annotations


class PkgRecError(Exception):
    """Base typed exception for all hermetic_pkgrec operations."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class CutoffError(PkgRecError):
    """Raised when a cutoff date or timestamp is malformed or invalid."""


class ProjectOverFileCapError(PkgRecError):
    """Raised when a project contains more files than MAX_FILES_PER_PROJECT."""


class UpstreamError(PkgRecError):
    """Base exception for errors communicating with an upstream package index."""


class InsecureUpstreamError(UpstreamError):
    """Raised when an upstream URL uses non-HTTPS protocol outside test fixtures."""


class CrossHostRedirectError(UpstreamError):
    """Raised when an upstream server attempts to redirect across host boundaries."""


class UpstreamTimeoutError(UpstreamError):
    """Raised when an upstream request exceeds socket or read timeouts."""


class UpstreamResponseTooLargeError(UpstreamError):
    """Raised when an upstream response exceeds configured byte caps."""


class UpstreamHttpError(UpstreamError):
    """Raised when an upstream returns an unexpected HTTP error code."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"Upstream returned status {status_code}: {message}")
        self.status_code = status_code


class HashMismatchError(PkgRecError):
    """Raised when the SHA-256 of a fetched file does not match the index declaration."""


class OversizeFileError(PkgRecError):
    """Raised when a fetched or processed distribution file exceeds configured size limits."""


class ManifestError(PkgRecError):
    """Raised when a manifest file is missing, corrupted, or violates the schema."""


class StoreError(PkgRecError):
    """Base exception for store operations."""


class StoreLimitError(StoreError):
    """Raised when a store directory entry cap or file size cap is exceeded."""


class SymlinkError(StoreError):
    """Raised when a symbolic link is encountered in a strictly inspected location."""


class PathTraversalError(StoreError):
    """Raised when an unsafe path component (e.g. '..', NUL, backslash) is detected."""


class FreezeError(PkgRecError):
    """Base exception for index freezing operations."""


class ExistingFrozenRootError(FreezeError):
    """Raised when attempting to modify or overwrite an existing frozen root directory."""
