"""Pluggable resolver interface and offline fixture resolver for hermetic_pkgbase.

Knows dependency metadata, file checksums, sizes, and upload times.
Only releases and files uploaded strictly before the cutoff timestamp
are eligible for admission into the Layer 2 baseline.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass, field
import datetime
import re
from typing import Any, Protocol, Sequence

from .errors import ResolutionError
from .spec import normalize_project_name

_RFC3339_RE = re.compile(
    r"^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2}))$"
)
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_NS_PER_SEC: int = 1_000_000_000


def parse_rfc3339_nanos(value: str) -> int:
    """Parse an RFC 3339 UTC timestamp into integer epoch nanoseconds."""
    if not isinstance(value, str) or len(value) > 64:
        raise ResolutionError(f"Invalid timestamp string: {value!r}")
    match = _RFC3339_RE.fullmatch(value)
    if not match:
        raise ResolutionError(f"Timestamp does not conform to RFC 3339: {value!r}")

    year, month, day, hour, minute, second = (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
        int(match.group(4)),
        int(match.group(5)),
        int(match.group(6)),
    )
    frac_str = match.group(7) or ""
    offset_sign = match.group(8)

    offset_sec = 0
    if offset_sign is not None:
        off_h = int(match.group(9))
        off_m = int(match.group(10))
        if off_h > 23 or off_m > 59:
            raise ResolutionError("Invalid UTC offset in timestamp.")
        total_off = off_h * 3600 + off_m * 60
        offset_sec = total_off if offset_sign == "+" else -total_off

    if year < 1970 or year > 9999:
        raise ResolutionError(f"Timestamp year out of range: {year}")
    try:
        dt = datetime.date(year, month, day)
    except ValueError as exc:
        raise ResolutionError(f"Invalid calendar date in timestamp: {exc}") from exc

    if hour > 23 or minute > 59 or second > 59:
        raise ResolutionError("Invalid time component in timestamp.")

    sec = calendar.timegm((dt.year, dt.month, dt.day, hour, minute, second, 0, 0, 0)) - offset_sec
    frac_ns = int(frac_str.ljust(9, "0")) if frac_str else 0
    return sec * _NS_PER_SEC + frac_ns


@dataclass(frozen=True, slots=True)
class ResolvedFile:
    """Metadata for an individual distribution file verified at the cutoff."""

    filename: str
    sha256: str
    upload_time: str
    size_bytes: int
    upload_time_ns: int
    project: str
    ecosystem: str = "pypi"
    requires_python: str | None = None
    yanked: bool | str = False

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ecosystem": self.ecosystem,
            "filename": self.filename,
            "project": self.project,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "upload-time": self.upload_time,
        }
        if self.requires_python is not None:
            result["requires-python"] = self.requires_python
        if self.yanked:
            result["yanked"] = self.yanked
        return result


@dataclass(frozen=True, slots=True)
class ResolvedRelease:
    """Resolved package release containing admitted pre-cutoff distribution files."""

    project: str
    version: str
    upload_time: str
    upload_time_ns: int
    files: tuple[ResolvedFile, ...]
    dependencies: tuple[str, ...]
    ecosystem: str = "pypi"


class Resolver(Protocol):
    """Protocol for resolving package releases and dependencies at a given cutoff."""

    def resolve_package(
        self,
        project: str,
        cutoff_epoch_ns: int,
        ecosystem: str = "pypi",
    ) -> ResolvedRelease | None:
        """Resolve the latest release of `project` strictly uploaded before `cutoff_epoch_ns`.

        Returns None if the package does not exist or has no files uploaded before the cutoff.
        """
        ...


class OfflineFixtureResolver:
    """In-memory offline resolver populated with fixture metadata for tests."""

    def __init__(self, packages: dict[str, Any]) -> None:
        self._packages: dict[str, list[dict[str, Any]]] = {}
        if not isinstance(packages, dict):
            raise ResolutionError("Packages fixture must be a dictionary.")

        for raw_name, raw_releases in packages.items():
            norm_name = normalize_project_name(raw_name)
            if not isinstance(raw_releases, list):
                raise ResolutionError(f"Releases for {raw_name} must be a list.")
            self._packages[norm_name] = raw_releases

    def resolve_package(
        self,
        project: str,
        cutoff_epoch_ns: int,
        ecosystem: str = "pypi",
    ) -> ResolvedRelease | None:
        """Find the latest release uploaded strictly before cutoff_epoch_ns."""
        norm_name = normalize_project_name(project)
        release_entries = self._packages.get(norm_name)
        if not release_entries:
            return None

        admissible_releases: list[ResolvedRelease] = []

        for rel in release_entries:
            if not isinstance(rel, dict):
                raise ResolutionError(f"Release entry for {norm_name} must be a dictionary.")
            version = str(rel.get("version", ""))
            rel_upload_time = rel.get("upload_time")
            if not rel_upload_time or not isinstance(rel_upload_time, str):
                raise ResolutionError("unknown upload time")
            try:
                rel_upload_ns = parse_rfc3339_nanos(rel_upload_time)
            except ResolutionError:
                raise ResolutionError("unknown upload time")

            # Check if release itself was before cutoff
            if rel_upload_ns >= cutoff_epoch_ns:
                continue

            # Files for this release
            raw_files = rel.get("files", [])
            if not isinstance(raw_files, list):
                raise ResolutionError(f"Files for release {version} must be a list.")
            admissible_files: list[ResolvedFile] = []

            for f in raw_files:
                if not isinstance(f, dict):
                    raise ResolutionError(f"File metadata in release {version} must be a dictionary.")
                filename = str(f.get("filename", ""))
                sha256 = str(f.get("sha256", "")).lower()
                if not _SHA256_HEX_RE.match(sha256):
                    raise ResolutionError(f"Invalid SHA-256 for file {filename}: {sha256}")

                raw_size = f.get("size_bytes", 0)
                if not isinstance(raw_size, int) or isinstance(raw_size, bool):
                    try:
                        size_bytes = int(raw_size)
                    except (ValueError, TypeError) as exc:
                        raise ResolutionError(
                            f"Invalid non-integer size_bytes for file {filename}: {raw_size!r}"
                        ) from exc
                else:
                    size_bytes = raw_size
                if size_bytes < 0:
                    raise ResolutionError(f"Negative size_bytes for file {filename}: {size_bytes}")

                file_upload_time = f.get("upload_time") or rel_upload_time
                if not file_upload_time or not isinstance(file_upload_time, str):
                    raise ResolutionError("unknown upload time")
                try:
                    file_upload_ns = parse_rfc3339_nanos(file_upload_time)
                except ResolutionError:
                    raise ResolutionError("unknown upload time")

                # "first second of the cutoff month: only files uploaded before it"
                if file_upload_ns < cutoff_epoch_ns:
                    admissible_files.append(
                        ResolvedFile(
                            filename=filename,
                            sha256=sha256,
                            upload_time=file_upload_time,
                            upload_time_ns=file_upload_ns,
                            size_bytes=size_bytes,
                            project=norm_name,
                            ecosystem=ecosystem,
                            requires_python=f.get("requires_python") or f.get("requires-python"),
                            yanked=f.get("yanked", False),
                        )
                    )

            if not admissible_files:
                # No files for this release were uploaded before the cutoff
                continue

            deps: list[str] = []
            for dep in rel.get("dependencies", []):
                if isinstance(dep, str):
                    deps.append(normalize_project_name(dep))

            admissible_releases.append(
                ResolvedRelease(
                    project=norm_name,
                    version=version,
                    upload_time=rel_upload_time,
                    upload_time_ns=rel_upload_ns,
                    files=tuple(admissible_files),
                    dependencies=tuple(deps),
                    ecosystem=ecosystem,
                )
            )

        if not admissible_releases:
            return None

        # Sort candidate releases by upload_time_ns descending to select latest before cutoff
        admissible_releases.sort(key=lambda r: (r.upload_time_ns, r.version), reverse=True)
        return admissible_releases[0]
