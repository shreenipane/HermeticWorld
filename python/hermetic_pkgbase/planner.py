"""Transitive closure planner for Hermetic World Layer 2 baselines.

Given a BaselineSpec and a Resolver, computes the transitive closure at the cutoff
(first second of the cutoff month: only files uploaded strictly before it).
Enforces deterministic ordering, cycle handling, and named caps on depth,
package count, and total storage bytes.
Outputs a canonical-JSON plan listing every file and unresolvable packages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Sequence

from .errors import (
    CapExceededError,
    DepthCapExceededError,
    PackageCountCapExceededError,
    ResolutionError,
    TotalBytesCapExceededError,
)
from .resolver import ResolvedFile, ResolvedRelease, Resolver, parse_rfc3339_nanos
from .spec import BaselineSpec, MAX_FILE_BYTES, normalize_project_name, validate_distribution_filename
from .storage import StorageReport

MAX_CLOSURE_DEPTH: int = 64
MAX_PACKAGE_COUNT: int = 10_000
MAX_TOTAL_BYTES: int = 100 * 1024 * 1024 * 1024  # 100 GiB
MAX_QUEUE_ITERATIONS: int = 100_000
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class UnresolvedPackage:
    """A package that could not be resolved at the cutoff (listed, not guessed)."""

    project: str
    ecosystem: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "project": self.project,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class Plan:
    """Deterministic, canonical plan for building a Layer 2 baseline."""

    spec: BaselineSpec
    files: tuple[ResolvedFile, ...]
    unresolved: tuple[UnresolvedPackage, ...]
    storage: StorageReport
    resolved_projects: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Convert plan to a plain dictionary without host paths or host time."""
        return {
            "cutoff_month": self.spec.cutoff_month,
            "cutoff_timestamp": self.spec.cutoff_timestamp,
            "files": [f.to_dict() for f in self.files],
            "resolved_projects": list(self.resolved_projects),
            "storage": self.storage.to_dict(),
            "unresolved": [u.to_dict() for u in self.unresolved],
        }

    def to_canonical_json(self) -> str:
        """Render canonical JSON representation with sorted keys and 2-space indentation."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


class Planner:
    """Computes the bounded transitive closure for a baseline specification."""

    def __init__(
        self,
        *,
        max_depth: int = MAX_CLOSURE_DEPTH,
        max_packages: int = MAX_PACKAGE_COUNT,
        max_total_bytes: int = MAX_TOTAL_BYTES,
    ) -> None:
        if max_depth <= 0 or max_depth > MAX_CLOSURE_DEPTH:
            raise CapExceededError(f"max_depth {max_depth} out of valid bounds (1-{MAX_CLOSURE_DEPTH})")
        if max_packages <= 0 or max_packages > MAX_PACKAGE_COUNT:
            raise CapExceededError(f"max_packages {max_packages} out of valid bounds (1-{MAX_PACKAGE_COUNT})")
        if max_total_bytes <= 0 or max_total_bytes > MAX_TOTAL_BYTES:
            raise CapExceededError(f"max_total_bytes out of valid bounds (1-{MAX_TOTAL_BYTES})")

        self.max_depth = max_depth
        self.max_packages = max_packages
        self.max_total_bytes = max_total_bytes

    def plan(self, spec: BaselineSpec, resolver: Resolver) -> Plan:
        """Compute the transitive closure at the cutoff and generate the plan."""
        cutoff_ns = spec.cutoff_epoch_ns

        # Track resolved releases and unresolvables
        resolved_releases: dict[str, ResolvedRelease] = {}
        unresolved_map: dict[str, UnresolvedPackage] = {}
        visited: set[str] = set()

        # Seed packages from fixed tools and top packages
        seed_projects = spec.get_seed_packages(ecosystem="pypi")

        # FIFO queue: (project_name, depth, ecosystem)
        queue: list[tuple[str, int, str]] = [
            (norm_name, 0, "pypi") for norm_name in seed_projects
        ]

        running_bytes = 0
        loop_count = 0

        while queue:
            loop_count += 1
            if loop_count > MAX_QUEUE_ITERATIONS:
                raise CapExceededError(
                    f"Queue iteration limit ({MAX_QUEUE_ITERATIONS}) exceeded during planning."
                )

            current_project, current_depth, ecosystem = queue.pop(0)

            # Cycle and duplicate detection
            if current_project in visited:
                continue
            visited.add(current_project)

            # Depth cap check
            if current_depth > self.max_depth:
                raise DepthCapExceededError(
                    f"Dependency depth cap of {self.max_depth} exceeded at package {current_project!r}."
                )

            # Resolve release at the cutoff (untrusted, pluggable interface)
            try:
                release = resolver.resolve_package(
                    current_project,
                    cutoff_ns,
                    ecosystem=ecosystem,
                )
            except ResolutionError as exc:
                msg = str(exc)
                reason = "unknown upload time" if "unknown upload time" in msg else msg
                unresolved_map[current_project] = UnresolvedPackage(
                    project=current_project,
                    ecosystem=ecosystem,
                    reason=reason,
                )
                continue
            except Exception as exc:
                unresolved_map[current_project] = UnresolvedPackage(
                    project=current_project,
                    ecosystem=ecosystem,
                    reason=f"Resolver error: {exc}",
                )
                continue

            if release is None:
                # Package could not be resolved at the cutoff: listed, not guessed.
                unresolved_map[current_project] = UnresolvedPackage(
                    project=current_project,
                    ecosystem=ecosystem,
                    reason="No admissible release or files available before cutoff.",
                )
                continue

            # Re-validate release returned by resolver
            if (
                not hasattr(release, "project")
                or not hasattr(release, "upload_time_ns")
                or not hasattr(release, "files")
            ):
                unresolved_map[current_project] = UnresolvedPackage(
                    project=current_project,
                    ecosystem=ecosystem,
                    reason="Invalid release object returned by resolver.",
                )
                continue

            # Project name must equal requested normalized name
            if release.project != current_project:
                unresolved_map[current_project] = UnresolvedPackage(
                    project=current_project,
                    ecosystem=ecosystem,
                    reason=f"Mismatched project name: expected {current_project!r}, got {release.project!r}",
                )
                continue

            # Release upload time check
            if not isinstance(release.upload_time_ns, int) or getattr(release, "upload_time", None) in (None, ""):
                unresolved_map[current_project] = UnresolvedPackage(
                    project=current_project,
                    ecosystem=ecosystem,
                    reason="unknown upload time",
                )
                continue
            try:
                rel_parsed_ns = parse_rfc3339_nanos(release.upload_time)
            except ResolutionError:
                unresolved_map[current_project] = UnresolvedPackage(
                    project=current_project,
                    ecosystem=ecosystem,
                    reason="unknown upload time",
                )
                continue
            if rel_parsed_ns != release.upload_time_ns:
                unresolved_map[current_project] = UnresolvedPackage(
                    project=current_project,
                    ecosystem=ecosystem,
                    reason=f"Release upload time {release.upload_time!r} does not match upload_time_ns ({release.upload_time_ns} ns).",
                )
                continue
            if release.upload_time_ns >= cutoff_ns:
                unresolved_map[current_project] = UnresolvedPackage(
                    project=current_project,
                    ecosystem=ecosystem,
                    reason=f"Release upload time ({release.upload_time_ns} ns) is not strictly before cutoff ({cutoff_ns} ns).",
                )
                continue

            # Files non-empty sequence check
            if not isinstance(release.files, (tuple, list)) or not release.files:
                unresolved_map[current_project] = UnresolvedPackage(
                    project=current_project,
                    ecosystem=ecosystem,
                    reason="Release has no files.",
                )
                continue

            # Re-validate every file in the release
            file_refusal_reason: str | None = None
            for f in release.files:
                if (
                    not hasattr(f, "filename")
                    or not hasattr(f, "sha256")
                    or not hasattr(f, "size_bytes")
                    or not hasattr(f, "upload_time_ns")
                ):
                    file_refusal_reason = "Invalid file object in release."
                    break

                if getattr(f, "project", None) != current_project:
                    file_refusal_reason = (
                        f"Mismatched file project: expected {current_project!r}, "
                        f"got {getattr(f, 'project', None)!r}"
                    )
                    break

                if not isinstance(f.upload_time_ns, int) or getattr(f, "upload_time", None) in (None, ""):
                    file_refusal_reason = "unknown upload time"
                    break

                try:
                    f_parsed_ns = parse_rfc3339_nanos(f.upload_time)
                except ResolutionError:
                    file_refusal_reason = "unknown upload time"
                    break

                if f_parsed_ns != f.upload_time_ns:
                    file_refusal_reason = (
                        f"File {f.filename!r} upload time {f.upload_time!r} does not match upload_time_ns ({f.upload_time_ns} ns)."
                    )
                    break

                if f.upload_time_ns >= cutoff_ns:
                    file_refusal_reason = (
                        f"File {f.filename!r} upload time ({f.upload_time_ns} ns) "
                        f"is not strictly before cutoff ({cutoff_ns} ns)."
                    )
                    break

                if not isinstance(f.sha256, str) or not _SHA256_HEX_RE.fullmatch(f.sha256):
                    file_refusal_reason = f"Invalid sha256 digest for file {f.filename!r}: {getattr(f, 'sha256', None)!r}"
                    break

                if (
                    not isinstance(f.size_bytes, int)
                    or isinstance(f.size_bytes, bool)
                    or f.size_bytes < 0
                    or f.size_bytes > MAX_FILE_BYTES
                ):
                    file_refusal_reason = f"Invalid size_bytes for file {f.filename!r}: {getattr(f, 'size_bytes', None)!r}"
                    break

                try:
                    validate_distribution_filename(f.filename)
                except ValueError as exc:
                    file_refusal_reason = f"Invalid filename for file {getattr(f, 'filename', None)!r}: {exc}"
                    break

            if file_refusal_reason is not None:
                unresolved_map[current_project] = UnresolvedPackage(
                    project=current_project,
                    ecosystem=ecosystem,
                    reason=file_refusal_reason,
                )
                continue

            # Package count cap check
            if len(resolved_releases) + 1 > self.max_packages:
                raise PackageCountCapExceededError(
                    f"Package count cap of {self.max_packages} exceeded."
                )

            # Total bytes cap check
            rel_bytes = sum(f.size_bytes for f in release.files)
            if running_bytes + rel_bytes > self.max_total_bytes:
                raise TotalBytesCapExceededError(
                    f"Total artifact storage cap of {self.max_total_bytes} bytes exceeded."
                )
            running_bytes += rel_bytes

            resolved_releases[current_project] = release

            # Queue dependencies deterministically
            for dep in sorted(release.dependencies):
                norm_dep = normalize_project_name(dep)
                if norm_dep not in visited:
                    queue.append((norm_dep, current_depth + 1, ecosystem))

        # Flatten and sort all files deterministically by (project, filename)
        all_files: list[ResolvedFile] = []
        for release in resolved_releases.values():
            all_files.extend(release.files)
        all_files.sort(key=lambda f: (f.project, f.filename))

        # Sort unresolved packages deterministically
        sorted_unresolved = [
            unresolved_map[k] for k in sorted(unresolved_map.keys())
        ]

        # Sorted resolved projects
        sorted_projects = tuple(sorted(resolved_releases.keys()))

        # Compute storage report
        storage = StorageReport.from_files(all_files)

        return Plan(
            spec=spec,
            files=tuple(all_files),
            unresolved=tuple(sorted_unresolved),
            storage=storage,
            resolved_projects=sorted_projects,
        )
