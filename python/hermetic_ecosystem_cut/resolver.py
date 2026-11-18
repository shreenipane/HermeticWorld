"""Cutoff-aware dependency resolver and closure recorder for Hermetic World.

Supports npm, crates.io, and Go modules. Enforces strict cutoff dates, traverses
transitive closures including build dependencies (e.g. Cargo build deps, npm
devDependencies), prevents infinite loops on circular dependencies, bounds all
traversal by named caps, and produces deterministic recipe structures for
hermetic_ecosystem_cut.mirror.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, Callable, Sequence

from hermetic_npm_cut.cut import (
    SemVer,
    compare_semver,
    parse_rfc3339_utc_nanos,
    parse_semver,
)

from .cut import CutError, _time, cut_crates_index, cut_go_versions
from .provenance import compute_go_mod_h1, compute_go_zip_h1

MAX_CLOSURE_PACKAGES: int = 1000
MAX_CLOSURE_DEPTH: int = 32
MAX_REQ_BYTES: int = 512
MAX_RESOLVER_ITERATIONS: int = 10_000


class ResolutionError(CutError):
    """Sanitized failure for cutoff-aware resolution or recording."""


@dataclass(frozen=True, slots=True)
class VersionConstraint:
    """A single version constraint comparison."""
    op: str  # '=', '!=', '>', '>=', '<', '<='
    version: SemVer

    def matches(self, sv: SemVer) -> bool:
        cmp = compare_semver(sv, self.version)
        if self.op in ("=", "=="):
            return cmp == 0
        if self.op == "!=":
            return cmp != 0
        if self.op == ">":
            return cmp > 0
        if self.op == ">=":
            return cmp >= 0
        if self.op == "<":
            return cmp < 0
        if self.op == "<=":
            return cmp <= 0
        return False


def _parse_simple_constraint(text: str, ecosystem: str = "npm") -> list[VersionConstraint]:
    """Parse caret, tilde, wildcards, or comparison operators into constraints."""
    text = text.strip()
    if not text or text in ("*", "x", "X"):
        return []

    # Ecosystem-specific preprocessing
    if ecosystem == "crates":
        # In Cargo, bare version requirement 1.2.3 is an abbreviation for ^1.2.3
        if re.fullmatch(r"^\d+(?:\.\d+)*(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$", text):
            text = "^" + text
    elif ecosystem == "go":
        # In Go, strip leading 'v' and bare version indicates minimum version >=
        text = re.sub(r'^(>=|<=|==|!=|>|<|=)\s*v', r'\1', text)
        if text.startswith("v") and len(text) > 1 and text[1].isdigit():
            text = text[1:]
        if re.fullmatch(r"^\d+(?:\.\d+)*(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$", text):
            sv = parse_semver(text)
            if sv is not None:
                return [VersionConstraint(">=", sv)]

    # Handle caret: ^1.2.3
    if text.startswith("^"):
        sv = parse_semver(text[1:].lstrip())
        if sv is None:
            raise ResolutionError("Invalid SemVer in caret constraint")
        lower = VersionConstraint(">=", sv)
        if sv.major > 0:
            upper_sv = SemVer(sv.major + 1, 0, 0, None, None)
        elif sv.minor > 0:
            upper_sv = SemVer(0, sv.minor + 1, 0, None, None)
        else:
            upper_sv = SemVer(0, 0, sv.patch + 1, None, None)
        upper = VersionConstraint("<", upper_sv)
        return [lower, upper]

    # Handle tilde: ~1.2.3
    if text.startswith("~"):
        sv = parse_semver(text[1:].lstrip())
        if sv is None:
            raise ResolutionError("Invalid SemVer in tilde constraint")
        lower = VersionConstraint(">=", sv)
        upper_sv = SemVer(sv.major, sv.minor + 1, 0, None, None)
        upper = VersionConstraint("<", upper_sv)
        return [lower, upper]

    # Comparison operators
    for op in (">=", "<=", "==", "!=", ">", "<", "="):
        if text.startswith(op):
            ver_part = text[len(op):].lstrip()
            sv = parse_semver(ver_part)
            if sv is None:
                raise ResolutionError(f"Invalid SemVer in constraint: {text}")
            return [VersionConstraint(op, sv)]

    # Exact version without operator
    sv = parse_semver(text)
    if sv is not None:
        return [VersionConstraint("=", sv)]

    # Wildcards like 1.x, 1.X, 1.*, 1.2.x, 1.2.X, 1.2.*
    parts = text.split(".")
    if len(parts) == 2 and parts[1].lower() in ("x", "*") and parts[0].isdigit():
        major = int(parts[0])
        return [VersionConstraint(">=", SemVer(major, 0, 0, None, None)),
                VersionConstraint("<", SemVer(major + 1, 0, 0, None, None))]
    if len(parts) == 3 and parts[2].lower() in ("x", "*") and parts[0].isdigit() and parts[1].isdigit():
        major = int(parts[0])
        minor = int(parts[1])
        return [VersionConstraint(">=", SemVer(major, minor, 0, None, None)),
                VersionConstraint("<", SemVer(major, minor + 1, 0, None, None))]
    if len(parts) == 1 and parts[0].isdigit():
        major = int(parts[0])
        return [VersionConstraint(">=", SemVer(major, 0, 0, None, None)),
                VersionConstraint("<", SemVer(major + 1, 0, 0, None, None))]
    if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
        major = int(parts[0])
        minor = int(parts[1])
        return [VersionConstraint(">=", SemVer(major, minor, 0, None, None)),
                VersionConstraint("<", SemVer(major, minor + 1, 0, None, None))]

    raise ResolutionError(f"Unsupported version constraint: {text}")


def parse_version_req(req_str: str, ecosystem: str = "npm") -> list[VersionConstraint]:
    """Parse composite version requirement (comma or space separated)."""
    if len(req_str.encode("utf-8")) > MAX_REQ_BYTES:
        raise ResolutionError("Version requirement string exceeds byte limit")
    req_str = req_str.strip()
    if not req_str or req_str == "*":
        return []
    # Split on commas first, then spaces if multiple terms
    parts: list[str] = []
    for chunk in req_str.split(","):
        for sub in chunk.split():
            sub = sub.strip()
            if sub:
                parts.append(sub)

    constraints: list[VersionConstraint] = []
    for part in parts:
        constraints.extend(_parse_simple_constraint(part, ecosystem=ecosystem))
    return constraints


def satisfies_req(version_str: str, req_str: str, ecosystem: str = "npm") -> bool:
    """Check if version_str satisfies req_str under ecosystem rules."""
    v_cand = version_str.strip()
    if ecosystem == "go" or v_cand.startswith("v"):
        v_cand = v_cand.removeprefix("v")
    sv = parse_semver(v_cand)
    if sv is None:
        return False

    req_clean = req_str.strip()
    if ecosystem == "go":
        req_clean = re.sub(r'(>=|<=|==|!=|>|<|=)\s*v', r'\1', req_clean)
        if req_clean.startswith("v") and len(req_clean) > 1 and req_clean[1].isdigit():
            req_clean = req_clean[1:]

    # In npm, exclude prereleases unless requirement explicitly mentions a prerelease
    if ecosystem == "npm" and sv.prerelease is not None:
        if "-" not in req_clean:
            return False

    constraints = parse_version_req(req_clean, ecosystem=ecosystem)
    if ecosystem == "npm" and sv.prerelease is not None:
        opted_in = any(
            c.version.prerelease is not None and
            (c.version.major, c.version.minor, c.version.patch) == (sv.major, sv.minor, sv.patch)
            for c in constraints
        )
        if not opted_in:
            return False

    for c in constraints:
        if not c.matches(sv):
            return False
    return True


@dataclass(frozen=True, slots=True)
class ResolvedDependency:
    name: str
    version: str
    kind: str  # 'normal', 'build', 'dev'
    optional: bool = False


@dataclass(frozen=True, slots=True)
class ResolvedPackage:
    ecosystem: str
    name: str
    version: str
    upload_time: str
    dependencies: tuple[ResolvedDependency, ...]
    artifacts: dict[str, str]  # key -> sha256 blob digest
    metadata_digest: str
    info_digest: str | None = None  # for Go
    tag_history_digest: str | None = None  # for npm
    sums_digest: str | None = None  # for Go


@dataclass(frozen=True, slots=True)
class UnresolvedPackage:
    name: str
    requirement: str
    reason: str


@dataclass(frozen=True, slots=True)
class ResolutionPlan:
    cutoff: str
    ecosystem: str
    packages: tuple[ResolvedPackage, ...]
    build_dependencies: tuple[str, ...]
    runtime_dependencies: tuple[str, ...]
    unresolved: tuple[UnresolvedPackage, ...]
    blobs: dict[str, bytes] = field(default_factory=dict)

    def to_recipe(self) -> dict[str, Any]:
        """Convert the resolution plan into a mirror.build_mirror recipe dict."""
        grouped: dict[tuple[str, str], list[ResolvedPackage]] = {}
        for pkg in self.packages:
            grouped.setdefault((pkg.ecosystem, pkg.name), []).append(pkg)

        recipe_packages: list[dict[str, Any]] = []
        for (eco, name), pkgs in grouped.items():
            combined_artifacts: dict[str, str] = {}
            combined_infos: dict[str, str] = {}
            for p in pkgs:
                combined_artifacts.update(p.artifacts)
                if p.info_digest is not None:
                    combined_infos[p.version] = p.info_digest

            if len(pkgs) == 1:
                pkg = pkgs[0]
                entry: dict[str, Any] = {
                    "ecosystem": pkg.ecosystem,
                    "name": pkg.name,
                    "metadata": pkg.metadata_digest,
                    "artifacts": dict(sorted(combined_artifacts.items())),
                }
                if pkg.ecosystem == "go" and combined_infos:
                    entry["infos"] = combined_infos
                    if pkg.sums_digest is not None:
                        entry["sums"] = pkg.sums_digest
                        entry["sumdb"] = True
                elif pkg.ecosystem == "npm" and pkg.tag_history_digest is not None:
                    entry["tag_history"] = pkg.tag_history_digest
            else:
                if eco == "crates":
                    meta_bytes = b"".join(self.blobs.get(p.metadata_digest, b"") for p in pkgs)
                    meta_d = hashlib.sha256(meta_bytes).hexdigest()
                    self.blobs[meta_d] = meta_bytes
                    entry = {
                        "ecosystem": "crates",
                        "name": name,
                        "metadata": meta_d,
                        "artifacts": dict(sorted(combined_artifacts.items())),
                    }
                elif eco == "go":
                    def _go_sort_key(v: str):
                        sv = parse_semver(v.removeprefix("v"))
                        return (sv.major, sv.minor, sv.patch, sv.prerelease is None) if sv else (0, 0, 0, False)
                    sorted_vers = sorted([p.version for p in pkgs], key=_go_sort_key)
                    meta_bytes = "\n".join(sorted_vers).encode("utf-8") + b"\n"
                    meta_d = hashlib.sha256(meta_bytes).hexdigest()
                    self.blobs[meta_d] = meta_bytes
                    combined_sums: dict[str, str] = {}
                    for p in pkgs:
                        if p.sums_digest and p.sums_digest in self.blobs:
                            try:
                                combined_sums.update(json.loads(self.blobs[p.sums_digest]))
                            except Exception:
                                pass
                    sums_d = None
                    if combined_sums:
                        sums_bytes = json.dumps(combined_sums, sort_keys=True, separators=(",", ":")).encode("utf-8")
                        sums_d = hashlib.sha256(sums_bytes).hexdigest()
                        self.blobs[sums_d] = sums_bytes
                    entry = {
                        "ecosystem": "go",
                        "name": name,
                        "metadata": meta_d,
                        "artifacts": dict(sorted(combined_artifacts.items())),
                        "infos": combined_infos,
                    }
                    if sums_d:
                        entry["sums"] = sums_d
                        entry["sumdb"] = True
                else:  # npm
                    combined_versions: dict[str, Any] = {}
                    combined_times: dict[str, Any] = {}
                    def _npm_sort_key(p: ResolvedPackage):
                        sv = parse_semver(p.version)
                        return (sv.major, sv.minor, sv.patch, sv.prerelease is None) if sv else (0, 0, 0, False)
                    latest_p = max(pkgs, key=_npm_sort_key)
                    for p in pkgs:
                        if p.metadata_digest in self.blobs:
                            try:
                                raw_meta = json.loads(self.blobs[p.metadata_digest])
                                combined_versions.update(raw_meta.get("versions", {}))
                                combined_times.update(raw_meta.get("time", {}))
                            except Exception:
                                pass
                    meta_dict = {
                        "name": name,
                        "versions": combined_versions,
                        "time": combined_times,
                        "dist-tags": {"latest": latest_p.version},
                    }
                    meta_bytes = json.dumps(meta_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    meta_d = hashlib.sha256(meta_bytes).hexdigest()
                    self.blobs[meta_d] = meta_bytes
                    entry = {
                        "ecosystem": "npm",
                        "name": name,
                        "metadata": meta_d,
                        "artifacts": dict(sorted(combined_artifacts.items())),
                    }
                    for p in pkgs:
                        if p.tag_history_digest:
                            entry["tag_history"] = p.tag_history_digest
                            break
            recipe_packages.append(entry)

        recipe_packages.sort(key=lambda p: (p["ecosystem"], p["name"]))
        return {
            "cutoff": self.cutoff,
            "packages": recipe_packages,
        }


class CutoffResolver:
    """Performs cutoff-aware resolution across npm, crates.io, and Go modules."""

    def __init__(
        self,
        cutoff: str,
        *,
        include_build_dependencies: bool = True,
        max_packages: int = MAX_CLOSURE_PACKAGES,
        max_depth: int = MAX_CLOSURE_DEPTH,
    ) -> None:
        _time(cutoff)
        self.cutoff = cutoff
        self.cutoff_nanos = parse_rfc3339_utc_nanos(cutoff)
        self.include_build_dependencies = include_build_dependencies
        self.max_packages = max_packages
        self.max_depth = max_depth
        self.blobs: dict[str, bytes] = {}

    def resolve(
        self,
        ecosystem: str,
        root_requirements: dict[str, str],
        package_provider: Callable[[str], dict[str, Any] | None],
    ) -> ResolutionPlan:
        """Resolve transitive closure for root_requirements using package_provider.

        package_provider(name) returns a package metadata dict containing:
          - for crates: 'index_lines' (list of raw records or strings) and 'artifacts' (vers -> bytes)
          - for npm: 'packument' (dict) and 'artifacts' (vers -> bytes), optional 'tag_history'
          - for go: 'list' (bytes/str), 'infos' (dict of vers -> dict/bytes), 'artifacts' (dict)
        """
        if ecosystem not in ("crates", "npm", "go"):
            raise ResolutionError(f"Unsupported ecosystem: {ecosystem}")

        self.blobs = {}
        resolved: dict[tuple[str, str], ResolvedPackage] = {}
        unresolved: list[UnresolvedPackage] = []
        build_deps: set[str] = set()
        runtime_deps: set[str] = set()
        expanded: set[tuple[str, str, bool]] = set()

        # Queue items: (name, req_str, depth, is_build_dep)
        queue: list[tuple[str, str, int, bool]] = [
            (name, req, 0, False) for name, req in sorted(root_requirements.items())
        ]

        iterations = 0
        while queue:
            iterations += 1
            if iterations > MAX_RESOLVER_ITERATIONS:
                raise ResolutionError("Closure exceeds maximum resolver iteration limit")
            name, req, depth, is_build = queue.pop(0)

            if depth > self.max_depth:
                raise ResolutionError("Closure exceeds maximum depth limit")

            pkg_data = package_provider(name)
            if pkg_data is None:
                unresolved.append(UnresolvedPackage(name, req, "package_not_found"))
                continue

            if ecosystem == "crates":
                res_pkg, reason = self._resolve_crate(name, req, pkg_data)
            elif ecosystem == "npm":
                res_pkg, reason = self._resolve_npm(name, req, pkg_data)
            else:
                res_pkg, reason = self._resolve_go(name, req, pkg_data)

            if res_pkg is None:
                unresolved.append(UnresolvedPackage(name, req, reason or "no_admitted_version_satisfies_req"))
                continue

            if is_build:
                build_deps.add(name)
            else:
                runtime_deps.add(name)

            key = (name, res_pkg.version)
            if key not in resolved:
                if len(resolved) >= self.max_packages:
                    raise ResolutionError("Closure exceeds maximum package count limit")
                resolved[key] = res_pkg

            scope_key = (name, res_pkg.version, is_build)
            if scope_key in expanded:
                continue
            expanded.add(scope_key)
            if not is_build:
                expanded.add((name, res_pkg.version, True))

            # Queue dependencies
            for dep in res_pkg.dependencies:
                dep_is_build = dep.kind == "build"
                if dep_is_build and not self.include_build_dependencies:
                    continue
                next_is_build = is_build or dep_is_build
                if (dep.name, dep.version, next_is_build) not in expanded:
                    queue.append((dep.name, dep.version, depth + 1, next_is_build))

        sorted_packages = tuple(resolved[k] for k in sorted(resolved.keys()))
        return ResolutionPlan(
            cutoff=self.cutoff,
            ecosystem=ecosystem,
            packages=sorted_packages,
            build_dependencies=tuple(sorted(build_deps)),
            runtime_dependencies=tuple(sorted(runtime_deps)),
            unresolved=tuple(unresolved),
            blobs=dict(self.blobs),
        )

    def _resolve_crate(self, name: str, req: str, data: dict[str, Any]) -> tuple[ResolvedPackage | None, str | None]:
        raw_lines = data.get("index_lines", [])
        raw_artifacts = data.get("artifacts", {})
        admitted_records = []
        for item in raw_lines:
            rec = json.loads(item) if isinstance(item, (str, bytes)) else item
            date = rec.get("pubtime")
            if date and parse_rfc3339_utc_nanos(date) <= self.cutoff_nanos:
                vers = rec["vers"]
                if satisfies_req(vers, req, ecosystem="crates"):
                    sv = parse_semver(vers)
                    if sv is not None:
                        admitted_records.append((rec, sv))

        if not admitted_records:
            return None, "no_admitted_version_satisfies_req"

        # Choose highest version
        admitted_records.sort(
            key=lambda pair: (pair[1].major, pair[1].minor, pair[1].patch, pair[1].prerelease is None)
        )
        best_rec = admitted_records[-1][0]
        version = best_rec["vers"]

        if version not in raw_artifacts:
            return None, "missing_artifact"

        deps: list[ResolvedDependency] = []
        for dep in best_rec.get("deps", []):
            kind = dep.get("kind") or "normal"
            deps.append(ResolvedDependency(dep["name"], dep["req"], kind, dep.get("optional", False)))

        # Format metadata
        clean_rec = dict(best_rec)
        clean_rec["yanked"] = False
        meta_bytes = json.dumps(clean_rec, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        meta_digest = hashlib.sha256(meta_bytes).hexdigest()
        self.blobs[meta_digest] = meta_bytes

        art_bytes = raw_artifacts[version]
        art_digest = hashlib.sha256(art_bytes).hexdigest()

        return ResolvedPackage(
            ecosystem="crates",
            name=name,
            version=version,
            upload_time=best_rec["pubtime"],
            dependencies=tuple(deps),
            artifacts={version: art_digest},
            metadata_digest=meta_digest,
        ), None

    def _resolve_npm(self, name: str, req: str, data: dict[str, Any]) -> tuple[ResolvedPackage | None, str | None]:
        packument = data.get("packument", {})
        raw_artifacts = data.get("artifacts", {})
        tag_history = data.get("tag_history")
        versions = packument.get("versions", {})
        times = packument.get("time", {})

        admitted_versions: list[tuple[str, SemVer, str]] = []
        for ver, manifest in versions.items():
            date = times.get(ver)
            if date and parse_rfc3339_utc_nanos(date) <= self.cutoff_nanos:
                if satisfies_req(ver, req, ecosystem="npm"):
                    sv = parse_semver(ver)
                    if sv:
                        admitted_versions.append((ver, sv, date))

        if not admitted_versions:
            return None, "no_admitted_version_satisfies_req"

        admitted_versions.sort(key=lambda t: (t[1].major, t[1].minor, t[1].patch, t[1].prerelease is None))
        version, _, date = admitted_versions[-1]
        manifest = versions[version]

        if version not in raw_artifacts:
            return None, "missing_artifact"

        deps: list[ResolvedDependency] = []
        for dep_name, dep_req in sorted(manifest.get("dependencies", {}).items()):
            deps.append(ResolvedDependency(dep_name, dep_req, "normal"))
        if self.include_build_dependencies:
            for dep_name, dep_req in sorted(manifest.get("devDependencies", {}).items()):
                deps.append(ResolvedDependency(dep_name, dep_req, "build"))

        meta_bytes = json.dumps(
            {"name": name, "versions": {version: manifest}, "time": {version: date}, "dist-tags": {"latest": version}},
            sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        meta_digest = hashlib.sha256(meta_bytes).hexdigest()
        self.blobs[meta_digest] = meta_bytes

        art_bytes = raw_artifacts[version]
        art_digest = hashlib.sha256(art_bytes).hexdigest()

        th_digest = None
        if tag_history:
            th_bytes = json.dumps(tag_history, sort_keys=True, separators=(",", ":")).encode("utf-8")
            th_digest = hashlib.sha256(th_bytes).hexdigest()
            self.blobs[th_digest] = th_bytes

        return ResolvedPackage(
            ecosystem="npm",
            name=name,
            version=version,
            upload_time=date,
            dependencies=tuple(deps),
            artifacts={version: art_digest},
            metadata_digest=meta_digest,
            tag_history_digest=th_digest,
        ), None

    def _resolve_go(self, name: str, req: str, data: dict[str, Any]) -> tuple[ResolvedPackage | None, str | None]:
        raw_list = data.get("list", "")
        if isinstance(raw_list, bytes):
            raw_list = raw_list.decode("utf-8")
        infos = data.get("infos", {})
        raw_artifacts = data.get("artifacts", {})

        admitted_versions: list[tuple[str, SemVer, str]] = []
        for line in raw_list.splitlines():
            ver = line.strip()
            if not ver:
                continue
            info = infos.get(ver)
            if info:
                info_dict = json.loads(info) if isinstance(info, (str, bytes)) else info
                # Verify source info record Version matches ver
                if info_dict.get("Version") == ver:
                    date = info_dict.get("Time")
                    if date and parse_rfc3339_utc_nanos(date) <= self.cutoff_nanos:
                        if satisfies_req(ver, req, ecosystem="go"):
                            sv = parse_semver(ver.removeprefix("v"))
                            if sv:
                                admitted_versions.append((ver, sv, date))

        if not admitted_versions:
            return None, "no_admitted_version_satisfies_req"

        admitted_versions.sort(key=lambda t: (t[1].major, t[1].minor, t[1].patch, t[1].prerelease is None))
        # go.mod requirements are minimums and Go's minimal version selection uses
        # the required version itself, so record the lowest admitted match (the
        # recipe keeps every required version; the go tool picks the maximum).
        version, _, date = admitted_versions[0]

        # Artifacts: .mod and .zip
        mod_key = f"{version}.mod"
        zip_key = f"{version}.zip"
        if mod_key not in raw_artifacts or zip_key not in raw_artifacts:
            return None, "missing_artifact"

        mod_bytes = raw_artifacts[mod_key]
        zip_bytes = raw_artifacts[zip_key]
        mod_sha = hashlib.sha256(mod_bytes).hexdigest()
        zip_sha = hashlib.sha256(zip_bytes).hexdigest()

        # Parse go.mod dependencies supporting single-line require and require ( ... ) blocks
        deps: list[ResolvedDependency] = []
        in_require_block = False
        for raw_mod_line in mod_bytes.decode("utf-8", errors="replace").splitlines():
            clean_line = raw_mod_line.split("//")[0].strip()
            if not clean_line:
                continue
            if in_require_block:
                if clean_line.startswith(")"):
                    in_require_block = False
                    continue
                parts = clean_line.split()
                if len(parts) >= 2:
                    deps.append(ResolvedDependency(parts[0], parts[1], "normal"))
            elif clean_line.startswith("require "):
                body = clean_line.removeprefix("require").strip()
                if body.startswith("("):
                    in_require_block = True
                    continue
                parts = body.split()
                if len(parts) >= 2:
                    deps.append(ResolvedDependency(parts[0], parts[1], "normal"))
            elif clean_line == "require (" or clean_line.startswith("require("):
                in_require_block = True

        meta_bytes = (version + "\n").encode("utf-8")
        meta_digest = hashlib.sha256(meta_bytes).hexdigest()
        self.blobs[meta_digest] = meta_bytes

        info_bytes = json.dumps({"Version": version, "Time": date}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        info_digest = hashlib.sha256(info_bytes).hexdigest()
        self.blobs[info_digest] = info_bytes

        # Go h1 sums
        sums_digest = None
        if zip_bytes.startswith(b"PK\x03\x04"):
            zip_h1 = compute_go_zip_h1(zip_bytes, name, version)
            mod_h1 = compute_go_mod_h1(mod_bytes)
            sums_dict = {version: zip_h1, f"{version}.mod": mod_h1}
            sums_bytes = json.dumps(sums_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
            sums_digest = hashlib.sha256(sums_bytes).hexdigest()
            self.blobs[sums_digest] = sums_bytes

        return ResolvedPackage(
            ecosystem="go",
            name=name,
            version=version,
            upload_time=date,
            dependencies=tuple(deps),
            artifacts={mod_key: mod_sha, zip_key: zip_sha},
            metadata_digest=meta_digest,
            info_digest=info_digest,
            sums_digest=sums_digest,
        ), None
