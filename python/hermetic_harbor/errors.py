"""Typed error classes for the sealed Harbor backend (TR-HB-1).

Diagnostics carry fixed descriptive messages and never include host paths,
host timestamps, usernames, or host network identities.
"""

from __future__ import annotations


class HarborError(Exception):
    """Base error for all Hermetic Harbor backend failures."""


class HarborDependencyError(HarborError):
    """The required harbor framework dependency is missing or incompatible."""


class HarborRegistrationError(HarborError):
    """Registration into the Harbor environment factory failed."""


class HarborConfigError(HarborError):
    """Task or environment configuration failed validation."""


class HarborExecutionError(HarborError):
    """Command execution inside the environment failed or timed out."""


class HarborSecurityError(HarborError):
    """A path escape, symlink, unsupported file type or security violation was detected."""


class HarborExtractionError(HarborError):
    """ExtractorVM artifact extraction failed or produced invalid records."""


class HarborVerificationError(HarborError):
    """GraderVM verifier execution failed or produced an unparseable result."""
