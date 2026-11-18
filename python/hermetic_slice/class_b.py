"""Class B environment rebuild with repo_only fallback and labelling (TRD §4.3, §1.3, §15.2)."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Sequence

from hermetic_apt_snapshot.select import parse_rfc3339_utc_nanos
from hermetic_pkgbase.resolver import Resolver

MAX_PACKAGES: int = 10_000
MAX_NAME_LEN: int = 128
MAX_VERSION_LEN: int = 64
MAX_REASON_LEN: int = 256

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]*$")


class ClassBError(Exception):
    """Raised on invalid Class B input or configuration."""


@dataclass(frozen=True, slots=True)
class ClassBRebuildResult:
    """Deterministic result of Class B environment rebuild and labelling."""

    seal_level: str  # "strict" or "repo_only"
    class_b_status: str  # "rebuilt_strict" or "fallback_repo_only"
    fallback_reason: str | None
    rebuilt_packages: tuple[dict[str, str], ...]
    d5b_warning_list: tuple[str, ...] | None  # None in strict mode; sorted tuple in repo_only
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return canonical dictionary representation without host paths or host time."""
        result: dict[str, Any] = {
            "seal_level": self.seal_level,
            "class_b_status": self.class_b_status,
            "rebuilt_packages": [dict(p) for p in self.rebuilt_packages],
            "warnings": list(self.warnings),
        }
        if self.fallback_reason is not None:
            reason = self.fallback_reason
            if reason.startswith("class_b_rebuild_failed: resolver error for "):
                parts = reason.split(": ")
                if len(parts) >= 2:
                    reason = f"{parts[0]}: {parts[1]}"
            if len(reason) > MAX_REASON_LEN:
                reason = reason[:MAX_REASON_LEN]
            result["fallback_reason"] = reason
        if self.d5b_warning_list is not None:
            result["d5b_warning_list"] = list(self.d5b_warning_list)
        return result


def _validate_package_entry(entry: Any) -> dict[str, str]:
    if not isinstance(entry, dict):
        raise ClassBError("Package entry must be a dictionary")
    name = entry.get("name")
    if not isinstance(name, str) or not (0 < len(name) <= MAX_NAME_LEN) or _NAME_RE.fullmatch(name) is None:
        raise ClassBError(f"Invalid package name: {name!r}")
    version = entry.get("version")
    if not isinstance(version, str) or not (0 < len(version) <= MAX_VERSION_LEN) or _VERSION_RE.fullmatch(version) is None:
        raise ClassBError(f"Invalid package version: {version!r}")
    ecosystem = entry.get("ecosystem", "pypi")
    if not isinstance(ecosystem, str) or len(ecosystem) > 32:
        raise ClassBError("Invalid ecosystem name")
    upload_time = entry.get("upload_time")
    if upload_time is not None and (not isinstance(upload_time, str) or len(upload_time) > 40):
        raise ClassBError("Invalid upload_time")

    clean = {"name": name, "version": version, "ecosystem": ecosystem}
    if upload_time:
        clean["upload_time"] = upload_time
    return clean


def rebuild_class_b_environment(
    installed_packages: Sequence[dict[str, Any]],
    cutoff: str,
    *,
    target_mode: str = "strict",
    resolver: Resolver | None = None,
) -> ClassBRebuildResult:
    """Rebuild Class B third-party packages at the cutoff, falling back to repo_only if unresolvable.

    In strict mode:
    - Verifies or rebuilds each package to a release uploaded at or before the cutoff.
    - If any package cannot be resolved at or before the cutoff, falls back to 'repo_only'.
    - On fallback, seal_level becomes 'repo_only', fallback_reason is recorded, and
      post-cutoff packages are collected into d5b_warning_list (strictly None in strict mode).

    In repo_only mode:
    - Never attempts strict resolution.
    - Inspects installed packages against the cutoff and lists any newer ones as warnings.
    """
    if target_mode not in ("strict", "repo_only"):
        raise ClassBError(f"Invalid target_mode: {target_mode!r}; expected 'strict' or 'repo_only'")

    if not isinstance(installed_packages, (list, tuple)):
        raise ClassBError("installed_packages must be a list or tuple")
    if len(installed_packages) > MAX_PACKAGES:
        raise ClassBError(f"Package count exceeds limit of {MAX_PACKAGES}")

    try:
        cutoff_nanos = parse_rfc3339_utc_nanos(cutoff)
    except Exception as exc:
        raise ClassBError(f"Invalid cutoff timestamp: {cutoff!r}") from exc
    cutoff_date = cutoff[:10]

    validated_packages = [_validate_package_entry(pkg) for pkg in installed_packages]

    def build_repo_only_warnings() -> tuple[list[str], list[str]]:
        d5b_warnings: list[str] = []
        human_warnings: list[str] = []
        for pkg in validated_packages:
            upload_time = pkg.get("upload_time")
            up_nanos: int | None = None
            if upload_time:
                try:
                    up_nanos = parse_rfc3339_utc_nanos(upload_time)
                except Exception:
                    up_nanos = None

            if up_nanos is not None:
                if up_nanos > cutoff_nanos:
                    pkg_str = f"{pkg['name']}=={pkg['version']}"
                    d5b_warnings.append(pkg_str)
                    up_date = upload_time[:10]
                    human_warnings.append(
                        f"{pkg['name']} {pkg['version']} installed (uploaded {up_date}) is newer than T_world {cutoff_date} (repo_only: listed, not rebuilt)"
                    )
            else:
                pkg_str = f"{pkg['name']}=={pkg['version']}"
                d5b_warnings.append(pkg_str)
                human_warnings.append(
                    f"{pkg['name']} {pkg['version']} installed upload time could not be verified (repo_only: listed, not rebuilt)"
                )
        return sorted(set(d5b_warnings)), sorted(human_warnings)

    if target_mode == "repo_only":
        d5b_list, warnings = build_repo_only_warnings()
        return ClassBRebuildResult(
            seal_level="repo_only",
            class_b_status="fallback_repo_only",
            fallback_reason=None,
            rebuilt_packages=tuple(dict(p) for p in validated_packages),
            d5b_warning_list=tuple(d5b_list),
            warnings=tuple(warnings),
        )

    # target_mode == "strict"
    rebuilt: list[dict[str, str]] = []
    fallback_reason: str | None = None

    for pkg in validated_packages:
        name = pkg["name"]
        ver = pkg["version"]
        eco = pkg.get("ecosystem", "pypi")
        upload_time = pkg.get("upload_time")

        is_already_at_cutoff = False
        up_nanos: int | None = None
        if upload_time:
            try:
                up_nanos = parse_rfc3339_utc_nanos(upload_time)
                if up_nanos <= cutoff_nanos:
                    is_already_at_cutoff = True
            except Exception:
                up_nanos = None

        if is_already_at_cutoff:
            rebuilt.append(dict(pkg))
            continue

        # Package needs rebuild at cutoff
        if resolver is None:
            if up_nanos is not None and up_nanos > cutoff_nanos:
                fallback_reason = f"class_b_rebuild_failed: package {name} {ver} is newer than cutoff and no resolver provided"
            else:
                fallback_reason = f"class_b_rebuild_failed: package {name} {ver} upload time could not be verified and no resolver provided"
            break

        try:
            resolved_release = resolver.resolve_package(name, cutoff_nanos + 1, ecosystem=eco)
        except OSError:
            fallback_reason = f"class_b_rebuild_failed: resolver error for {name}"
            break
        except Exception as exc:
            exc_str = str(exc)
            if "/" in exc_str or "\\" in exc_str or len(exc_str) > 64:
                fallback_reason = f"class_b_rebuild_failed: resolver error for {name}"
            else:
                fallback_reason = f"class_b_rebuild_failed: resolver error for {name}: {exc_str}"
            break

        if resolved_release is None:
            fallback_reason = f"class_b_rebuild_failed: no pre-cutoff release found for {name}"
            break

        # Succeeded in resolving package at cutoff
        rebuilt.append({
            "name": resolved_release.project,
            "version": resolved_release.version,
            "ecosystem": eco,
            "upload_time": resolved_release.upload_time,
        })

    if fallback_reason is not None:
        # Fallback to repo_only
        d5b_list, warnings = build_repo_only_warnings()
        return ClassBRebuildResult(
            seal_level="repo_only",
            class_b_status="fallback_repo_only",
            fallback_reason=fallback_reason,
            rebuilt_packages=tuple(dict(p) for p in validated_packages),
            d5b_warning_list=tuple(d5b_list),
            warnings=tuple(warnings),
        )

    # Strict rebuild succeeded
    return ClassBRebuildResult(
        seal_level="strict",
        class_b_status="rebuilt_strict",
        fallback_reason=None,
        rebuilt_packages=tuple(rebuilt),
        d5b_warning_list=None,
        warnings=(),
    )
