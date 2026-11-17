"""Storage measurement for Hermetic World Layer 2 baselines.

Computes and reports total bytes, bytes per ecosystem, and bytes per package
to measure Layer 2 storage footprint per architectural requirements.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from .resolver import ResolvedFile


@dataclass(frozen=True, slots=True)
class StorageReport:
    """Storage footprint report for resolved Layer 2 baseline artifacts."""

    total_bytes: int
    by_ecosystem: dict[str, int]
    by_package: dict[str, int]
    file_count: int
    package_count: int

    @classmethod
    def from_files(cls, files: Sequence[ResolvedFile]) -> StorageReport:
        """Calculate storage breakdown from a sequence of resolved files."""
        total = 0
        by_eco: dict[str, int] = {}
        by_pkg: dict[str, int] = {}
        seen_packages: set[str] = set()

        for f in files:
            total += f.size_bytes
            by_eco[f.ecosystem] = by_eco.get(f.ecosystem, 0) + f.size_bytes
            by_pkg[f.project] = by_pkg.get(f.project, 0) + f.size_bytes
            seen_packages.add(f.project)

        # Sort dictionaries deterministically
        sorted_eco = {k: by_eco[k] for k in sorted(by_eco.keys())}
        sorted_pkg = {k: by_pkg[k] for k in sorted(by_pkg.keys())}

        return cls(
            total_bytes=total,
            by_ecosystem=sorted_eco,
            by_package=sorted_pkg,
            file_count=len(files),
            package_count=len(seen_packages),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert storage report to a dictionary."""
        return {
            "by_ecosystem": dict(self.by_ecosystem),
            "by_package": dict(self.by_package),
            "file_count": self.file_count,
            "package_count": self.package_count,
            "total_bytes": self.total_bytes,
        }
