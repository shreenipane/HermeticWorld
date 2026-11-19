"""Class-B substrate inventory and release metadata generation for D5b.

Enumerates installed distributions and packages in a sealed task rootfs:
- Debian/Ubuntu dpkg status (/var/lib/dpkg/status)
- Python installed distributions (.dist-info and .egg-info)
- Conda environment packages (conda-meta/*.json)

Attaches release metadata ONLY from local, pinned, digest-checked sources:
- Debian snapshot / apt index files (Packages checked against Release SHA256)
- PyPI metadata (hermetic_pkgrec manifest or simple index)
- Conda repodata (repodata.json)

Never fabricates digests or dates: unverified entries remain unknown.
Evaluates with D5b and produces canonical substrate entries and substrate_at_t.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime
import email.utils
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

from hermetic_d5b.check import (
    evaluate_inventory,
    load_json_bounded,
    normalize_pypi_name,
    parse_rfc3339_ns,
    safe_read_bytes,
)
from hermetic_d5b.model import (
    D5bError,
    InventoryPackage,
    MAX_INVENTORY_BYTES,
    MAX_METADATA_BYTES,
    MAX_PACKAGES,
    MAX_STRING_LEN,
    MODES,
)
import hermetic_safe_io

MAX_ROOTFS_FILES = 200_000
MAX_TRAVERSAL_DEPTH = 32
MAX_DEB822_BYTES = 64 * 1024 * 1024
MAX_METADATA_FILE_BYTES = 1 * 1024 * 1024
DIGEST_RE = re.compile(r"^(sha256|blake3):[0-9a-f]{64}$")
RFC3339_OR_YMD_RE = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}(?:[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})?)?)$"
)


@dataclass(frozen=True, order=True)
class SubstrateEntry:
    """Canonical substrate entry for WorldManifest (§4, §13.1)."""

    name: str
    version: str
    digest: str
    date: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name or len(self.name) > MAX_STRING_LEN:
            raise D5bError("invalid substrate entry name")
        if not isinstance(self.version, str) or not self.version or len(self.version) > MAX_STRING_LEN:
            raise D5bError("invalid substrate entry version")
        if not isinstance(self.digest, str) or not DIGEST_RE.fullmatch(self.digest):
            raise D5bError(f"invalid substrate entry digest format: {self.digest}")
        if not isinstance(self.date, str) or not RFC3339_OR_YMD_RE.fullmatch(self.date):
            raise D5bError(f"invalid substrate entry date format: {self.date}")

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "digest": self.digest,
            "date": self.date,
        }


def parse_deb822_stanzas(text: str) -> list[dict[str, str]]:
    """Parse Debian RFC 2822 / deb822 stanzas with continuation lines."""
    stanzas: list[dict[str, str]] = []
    current: dict[str, str] = {}
    current_key: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        if not line:
            if current:
                stanzas.append(current)
                current = {}
                current_key = None
            continue
        if line[0] in (" ", "\t"):
            # Continuation line
            if current_key is not None:
                current[current_key] = current[current_key] + "\n" + line.strip()
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            current[key] = val
            current_key = key
        else:
            current_key = None

    if current:
        stanzas.append(current)

    return stanzas


def scan_dpkg_status(rootfs: Path | str) -> list[InventoryPackage]:
    """Scan <rootfs>/var/lib/dpkg/status for installed Debian/Ubuntu packages."""
    rootfs_path = Path(rootfs)
    status_file = rootfs_path / "var/lib/dpkg/status"
    if not status_file.is_file():
        return []

    raw = safe_read_bytes(str(status_file), MAX_DEB822_BYTES)
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception as exc:
        raise D5bError("failed to decode dpkg status file") from exc

    stanzas = parse_deb822_stanzas(text)
    pkgs: list[InventoryPackage] = []

    for s in stanzas:
        pkg_name = s.get("Package")
        version = s.get("Version")
        status = s.get("Status", "")

        if not pkg_name or not version:
            continue

        # Package is installed if Status ends with "installed" (e.g. "install ok installed")
        status_tokens = status.strip().split()
        if not status_tokens or status_tokens[-1] != "installed":
            continue

        pkgs.append(
            InventoryPackage(
                ecosystem="dpkg",
                name=pkg_name,
                version=version,
                file=None,
            )
        )

    return pkgs


def _is_repo_path(rel_path: str) -> bool:
    """Return True if relative path is inside repository code or metadata."""
    norm = rel_path.replace("\\", "/").strip("/")
    parts = norm.split("/")
    return "testbed" in parts or ".git" in parts


def scan_python_packages(rootfs: Path | str) -> list[InventoryPackage]:
    """Scan rootfs for Python dist-info and egg-info metadata, skipping repository code."""
    rootfs_path = Path(rootfs).resolve()
    pkgs: list[InventoryPackage] = []
    visited_files = 0

    for dirpath, dirnames, filenames in os.walk(str(rootfs_path), followlinks=False):
        rel_dir = os.path.relpath(dirpath, str(rootfs_path))
        if _is_repo_path(rel_dir):
            dirnames.clear()
            continue

        depth = len(Path(rel_dir).parts) if rel_dir != "." else 0
        if depth > MAX_TRAVERSAL_DEPTH:
            dirnames.clear()
            continue

        # Filter dirnames in-place to avoid descending into symlinks or testbed/.git
        valid_dirnames = []
        for d in dirnames:
            child_rel = os.path.join(rel_dir, d) if rel_dir != "." else d
            if _is_repo_path(child_rel):
                continue
            full_child = os.path.join(dirpath, d)
            try:
                st = os.lstat(full_child)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            valid_dirnames.append(d)
        dirnames[:] = valid_dirnames

        # Inspect directories for .dist-info or .egg-info
        for d in list(dirnames):
            if d.endswith(".dist-info") or d.endswith(".egg-info"):
                dist_dir = Path(dirpath) / d
                meta_name = "METADATA" if d.endswith(".dist-info") else "PKG-INFO"
                meta_file = dist_dir / meta_name

                pkg_name: Optional[str] = None
                pkg_ver: Optional[str] = None

                if meta_file.is_file():
                    try:
                        raw = safe_read_bytes(str(meta_file), MAX_METADATA_FILE_BYTES)
                        text = raw.decode("utf-8", errors="replace")
                        for line in text.splitlines()[:50]:
                            if line.startswith("Name:"):
                                pkg_name = line.partition(":")[2].strip()
                            elif line.startswith("Version:"):
                                pkg_ver = line.partition(":")[2].strip()
                            if pkg_name and pkg_ver:
                                break
                    except Exception:
                        pass

                # Fallback to dirname parsing
                if not pkg_name or not pkg_ver:
                    base = d[:-10] if d.endswith(".dist-info") else d[:-9]
                    if "-" in base:
                        p, _, v = base.partition("-")
                        pkg_name = pkg_name or p
                        pkg_ver = pkg_ver or v

                if pkg_name and pkg_ver:
                    try:
                        norm = normalize_pypi_name(pkg_name)
                        pkgs.append(
                            InventoryPackage(
                                ecosystem="pypi",
                                name=norm,
                                version=pkg_ver,
                                file=None,
                            )
                        )
                    except D5bError:
                        pass

        # Also inspect egg-info files (not directories)
        for fn in filenames:
            visited_files += 1
            if visited_files > MAX_ROOTFS_FILES:
                raise D5bError("rootfs file count cap exceeded during package scan")
            if fn.endswith(".egg-info"):
                egg_file = Path(dirpath) / fn
                if egg_file.is_file() and not egg_file.is_symlink():
                    try:
                        raw = safe_read_bytes(str(egg_file), MAX_METADATA_FILE_BYTES)
                        text = raw.decode("utf-8", errors="replace")
                        pkg_name = None
                        pkg_ver = None
                        for line in text.splitlines()[:50]:
                            if line.startswith("Name:"):
                                pkg_name = line.partition(":")[2].strip()
                            elif line.startswith("Version:"):
                                pkg_ver = line.partition(":")[2].strip()
                            if pkg_name and pkg_ver:
                                break
                        if not pkg_name or not pkg_ver:
                            raise D5bError(f"malformed egg-info record in {fn}")
                        norm = normalize_pypi_name(pkg_name)
                        pkgs.append(
                            InventoryPackage(
                                ecosystem="pypi",
                                name=norm,
                                version=pkg_ver,
                                file=None,
                            )
                        )
                    except D5bError:
                        raise
                    except Exception as exc:
                        raise D5bError(f"failed to read or parse egg-info record {fn}: {exc}") from exc

    return pkgs


def scan_conda_packages(rootfs: Path | str) -> list[InventoryPackage]:
    """Scan rootfs for Conda environment packages in conda-meta/*.json."""
    rootfs_path = Path(rootfs).resolve()
    pkgs: list[InventoryPackage] = []

    for dirpath, dirnames, filenames in os.walk(str(rootfs_path), followlinks=False):
        rel_dir = os.path.relpath(dirpath, str(rootfs_path))
        if _is_repo_path(rel_dir):
            dirnames.clear()
            continue

        if os.path.basename(dirpath) == "conda-meta":
            for fn in filenames:
                if fn.endswith(".json"):
                    meta_path = Path(dirpath) / fn
                    if meta_path.is_file() and not meta_path.is_symlink():
                        try:
                            raw = safe_read_bytes(str(meta_path), MAX_METADATA_FILE_BYTES)
                            data = json.loads(raw.decode("utf-8"))
                            if not isinstance(data, dict):
                                raise D5bError(f"malformed conda-meta: {fn} root is not an object")
                            name = data.get("name")
                            version = data.get("version")
                            fn_val = data.get("fn")
                            if not name or not version:
                                raise D5bError(f"malformed conda-meta: missing name or version in {fn}")
                            pkgs.append(
                                InventoryPackage(
                                    ecosystem="conda",
                                    name=str(name),
                                    version=str(version),
                                    file=str(fn_val) if fn_val else None,
                                )
                            )
                        except D5bError:
                            raise
                        except Exception as exc:
                            raise D5bError(f"failed to read or parse conda-meta record {fn}: {exc}") from exc

    return pkgs


def scan_rootfs_packages(rootfs: Path | str, *, allow_empty: bool = False) -> list[InventoryPackage]:
    """Enumerate all installed packages from dpkg, Python, and conda in rootfs."""
    rootfs_path = Path(rootfs).resolve()
    if not rootfs_path.is_dir():
        raise D5bError(f"rootfs directory not found: {rootfs}")

    all_pkgs: list[InventoryPackage] = []
    all_pkgs.extend(scan_dpkg_status(rootfs_path))
    all_pkgs.extend(scan_python_packages(rootfs_path))
    all_pkgs.extend(scan_conda_packages(rootfs_path))

    # Deduplicate deterministically
    seen: Set[Tuple[str, str, str, Optional[str]]] = set()
    unique_pkgs: list[InventoryPackage] = []
    for p in sorted(all_pkgs):
        key = (p.ecosystem, p.name, p.version, p.file)
        if key not in seen:
            seen.add(key)
            unique_pkgs.append(p)

    if not unique_pkgs and not allow_empty:
        # An empty result usually means the scan missed the package databases.
        # Callers that know the rootfs has no package manager (static binaries
        # only) must say so explicitly with allow_empty=True.
        raise D5bError("empty_rootfs_inventory: no installed packages found in rootfs")

    if len(unique_pkgs) > MAX_PACKAGES:
        raise D5bError("rootfs package count exceeds MAX_PACKAGES")

    return unique_pkgs


def _parse_release_date_rfc3339(date_str: str) -> str:
    """Parse date string from Debian Release file or RFC 3339 into strict RFC 3339 UTC."""
    date_str = date_str.strip()
    try:
        # Check if already RFC 3339
        parse_rfc3339_ns(date_str)
        return date_str
    except D5bError:
        pass

    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        dt_utc = dt.astimezone(datetime.timezone.utc)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception as exc:
        raise D5bError(f"unparsable date string: {date_str}") from exc


def load_apt_release_metadata(
    packages_path: Path | str,
    release_path: Optional[Path | str] = None,
    snapshot_date: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[Tuple[str, str], SubstrateEntry]]:
    """Load Debian/Ubuntu apt release metadata, verifying Packages hash against Release."""
    pkg_raw = safe_read_bytes(str(packages_path), MAX_DEB822_BYTES)
    computed_sha256 = hashlib.sha256(pkg_raw).hexdigest()

    release_date_str: Optional[str] = None
    if snapshot_date is not None:
        release_date_str = _parse_release_date_rfc3339(snapshot_date)

    if release_path is None:
        raise D5bError("apt_release_required: Release file required to verify apt Packages index")

    rel_raw = safe_read_bytes(str(release_path), MAX_METADATA_FILE_BYTES)
    rel_text = rel_raw.decode("utf-8", errors="replace")
    rel_stanzas = parse_deb822_stanzas(rel_text)
    if not rel_stanzas:
        raise D5bError("malformed Release file in apt metadata")

    rel_stanza = rel_stanzas[0]
    date_header = rel_stanza.get("Date")
    if date_header:
        release_date_str = _parse_release_date_rfc3339(date_header)

    # Check SHA256 table in Release
    sha256_table = rel_stanza.get("SHA256", "")
    hashes_in_release: Set[str] = set()
    for line in sha256_table.splitlines():
        tokens = line.strip().split()
        if len(tokens) >= 3 and len(tokens[0]) == 64:
            hashes_in_release.add(tokens[0].lower())

    if not hashes_in_release or computed_sha256.lower() not in hashes_in_release:
        raise D5bError(
            f"apt_packages_hash_mismatch: Packages sha256 {computed_sha256} not in Release file"
        )

    try:
        pkg_text = pkg_raw.decode("utf-8", errors="replace")
    except Exception as exc:
        raise D5bError("failed to decode apt Packages index") from exc

    stanzas = parse_deb822_stanzas(pkg_text)
    d5b_apt_map: Dict[str, Dict[str, str]] = {}
    substrate_map: Dict[Tuple[str, str], SubstrateEntry] = {}

    for s in stanzas:
        name = s.get("Package")
        version = s.get("Version")
        sha256 = s.get("SHA256")
        if not name or not version:
            continue

        if release_date_str is not None:
            d5b_apt_map.setdefault(name, {})[version] = release_date_str

        if sha256 and release_date_str is not None:
            digest = f"sha256:{sha256.strip().lower()}"
            if DIGEST_RE.fullmatch(digest):
                entry = SubstrateEntry(
                    name=name,
                    version=version,
                    digest=digest,
                    date=release_date_str,
                )
                substrate_map[(name, version)] = entry
                substrate_map[("dpkg", name, version)] = entry
                substrate_map[("apt", name, version)] = entry

    meta_chunk = {"dpkg": d5b_apt_map, "apt": d5b_apt_map}
    return meta_chunk, substrate_map


def load_pypi_release_metadata(
    manifest_path: Path | str,
) -> Tuple[Dict[str, Any], Dict[Tuple[str, str], SubstrateEntry]]:
    """Load PyPI release metadata from hermetic_pkgrec manifest or simple index."""
    raw = safe_read_bytes(str(manifest_path), MAX_METADATA_BYTES)
    data = load_json_bounded(raw, MAX_METADATA_BYTES)

    files_list: list[dict[str, Any]] = []
    if isinstance(data, dict):
        if "files" in data and isinstance(data["files"], list):
            files_list = data["files"]
        elif "packages" in data and isinstance(data["packages"], list):
            files_list = data["packages"]
    elif isinstance(data, list):
        files_list = data

    d5b_pypi_map: Dict[str, Dict[str, Dict[str, str]]] = {}
    substrate_candidates: Dict[Tuple[str, str], Tuple[str, str, str]] = {}
    substrate_map: Dict[Any, SubstrateEntry] = {}

    for item in files_list:
        if not isinstance(item, dict):
            continue
        project = item.get("project") or item.get("name")
        filename = item.get("filename")
        sha256 = item.get("sha256")
        upload_time = item.get("upload-time") or item.get("upload_time")
        version = item.get("version")

        if not project or not upload_time:
            continue

        try:
            norm_name = normalize_pypi_name(str(project))
        except D5bError:
            continue

        # Extract version from filename if not explicitly provided
        if not version and filename:
            fn_str = str(filename)
            if fn_str.endswith(".whl"):
                tokens = fn_str.split("-")
                if len(tokens) >= 2:
                    version = tokens[1]
            elif fn_str.endswith(".tar.gz"):
                base = fn_str[:-7]
                if "-" in base:
                    version = base.rsplit("-", 1)[1]
            elif fn_str.endswith(".zip"):
                base = fn_str[:-4]
                if "-" in base:
                    version = base.rsplit("-", 1)[1]

        if not version:
            continue

        version = str(version)
        fn_key = str(filename) if filename else f"{norm_name}-{version}"

        d5b_pypi_map.setdefault(norm_name, {}).setdefault(version, {})[fn_key] = str(upload_time)

        if sha256:
            digest = f"sha256:{str(sha256).strip().lower()}"
            if DIGEST_RE.fullmatch(digest):
                cand = (str(upload_time), fn_key, digest)
                key = (norm_name, version)
                if key not in substrate_candidates or (cand[0], cand[1]) < (substrate_candidates[key][0], substrate_candidates[key][1]):
                    substrate_candidates[key] = cand

    for (norm_name, version), (u_time, fn_key, digest) in substrate_candidates.items():
        entry = SubstrateEntry(
            name=norm_name,
            version=version,
            digest=digest,
            date=u_time,
        )
        substrate_map[(norm_name, version)] = entry
        substrate_map[("pypi", norm_name, version)] = entry

    return {"pypi": d5b_pypi_map}, substrate_map


def load_conda_release_metadata(
    repodata_path: Path | str,
) -> Tuple[Dict[str, Any], Dict[Tuple[str, str], SubstrateEntry]]:
    """Load Conda release metadata from repodata.json."""
    raw = safe_read_bytes(str(repodata_path), MAX_METADATA_BYTES)
    data = load_json_bounded(raw, MAX_METADATA_BYTES)

    d5b_conda_map: Dict[str, Dict[str, Optional[int]]] = {}
    substrate_map: Dict[Tuple[str, str], SubstrateEntry] = {}

    for map_key in ("packages", "packages.conda"):
        pkg_map = data.get(map_key, {})
        if not isinstance(pkg_map, dict):
            continue
        for fn, record in pkg_map.items():
            if not isinstance(record, dict):
                continue
            name = record.get("name")
            version = record.get("version")
            timestamp = record.get("timestamp")
            sha256 = record.get("sha256")

            if not name or not version:
                continue

            name = str(name)
            version = str(version)

            if timestamp is not None and isinstance(timestamp, int) and not isinstance(timestamp, bool):
                if timestamp <= 253402300799:
                    timestamp = timestamp * 1000
                d5b_conda_map.setdefault(name, {})[version] = timestamp
                # Convert timestamp ms to RFC 3339
                dt = datetime.datetime.fromtimestamp(timestamp / 1000.0, tz=datetime.timezone.utc)
                date_rfc3339 = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

                if sha256:
                    digest = f"sha256:{str(sha256).strip().lower()}"
                    if DIGEST_RE.fullmatch(digest):
                        entry = SubstrateEntry(
                            name=name,
                            version=version,
                            digest=digest,
                            date=date_rfc3339,
                        )
                        substrate_map[(name, version)] = entry
                        substrate_map[("conda", name, version)] = entry

    return {"conda": d5b_conda_map}, substrate_map


def build_d5b_inventory(
    rootfs: Path | str,
    cutoff: str,
    *,
    mode: str = "repo_only",
    apt_index: Optional[Path | str] = None,
    apt_release: Optional[Path | str] = None,
    apt_snapshot_date: Optional[str] = None,
    pypi_manifest: Optional[Path | str] = None,
    conda_repodata: Optional[Path | str] = None,
    metadata_path: Optional[Path | str] = None,
    exemptions_path: Optional[Path | str] = None,
    metadata_data: Optional[Dict[str, Any]] = None,
    exemptions_data: Any = None,
    allow_empty: bool = False,
) -> Dict[str, Any]:
    """Produce canonical class-B inventory and release metadata evaluated by D5b.

    allow_empty: accept a rootfs with no package databases at all. The result then
    has no substrate entries and substrate_at_t "none" (nothing is claimed)."""
    if mode not in MODES:
        raise D5bError("invalid mode; expected 'strict' or 'repo_only'")
    parse_rfc3339_ns(cutoff)

    # 1. Enumerate installed packages from rootfs
    packages = scan_rootfs_packages(rootfs, allow_empty=allow_empty)

    # 2. Collect release metadata ONLY from local, pinned, digest-checked sources
    full_metadata: Dict[str, Any] = {
        "pypi": {},
        "conda": {},
        "npm": {},
        "crates": {},
        "dpkg": {},
        "apt": {},
    }
    substrate_map: Dict[Tuple[str, ...], SubstrateEntry] = {}

    if apt_index is not None:
        if apt_release is None:
            raise D5bError("apt_index requires apt_release for verification")
        apt_meta, apt_sub = load_apt_release_metadata(apt_index, apt_release, apt_snapshot_date)
        for eco in ("dpkg", "apt"):
            for pkg, ver_map in apt_meta.get(eco, {}).items():
                full_metadata[eco].setdefault(pkg, {}).update(ver_map)
        for k, sub in apt_sub.items():
            if len(k) == 3:
                substrate_map[k] = sub
            elif len(k) == 2:
                substrate_map[("dpkg", k[0], k[1])] = sub
                substrate_map[("apt", k[0], k[1])] = sub

    if pypi_manifest is not None:
        pypi_meta, pypi_sub = load_pypi_release_metadata(pypi_manifest)
        for pkg, ver_map in pypi_meta.get("pypi", {}).items():
            full_metadata["pypi"].setdefault(pkg, {}).update(ver_map)
        for k, sub in pypi_sub.items():
            if len(k) == 3:
                substrate_map[k] = sub
            elif len(k) == 2:
                substrate_map[("pypi", k[0], k[1])] = sub

    if conda_repodata is not None:
        conda_meta, conda_sub = load_conda_release_metadata(conda_repodata)
        for pkg, ver_map in conda_meta.get("conda", {}).items():
            full_metadata["conda"].setdefault(pkg, {}).update(ver_map)
        for k, sub in conda_sub.items():
            if len(k) == 3:
                substrate_map[k] = sub
            elif len(k) == 2:
                substrate_map[("conda", k[0], k[1])] = sub

    def _merge_unpinned_metadata(target: Dict[str, Any], source: Dict[str, Any]) -> None:
        for eco in ("pypi", "conda", "npm", "crates", "dpkg", "apt"):
            if eco in source and isinstance(source[eco], dict):
                for pkg, ver_map in source[eco].items():
                    if isinstance(ver_map, dict):
                        target_ver_map = target[eco].setdefault(pkg, {})
                        for ver, val in ver_map.items():
                            if ver not in target_ver_map:
                                target_ver_map[ver] = val

    if metadata_path is not None:
        raw_meta = safe_read_bytes(str(metadata_path), MAX_METADATA_BYTES)
        json_meta = load_json_bounded(raw_meta, MAX_METADATA_BYTES)
        if isinstance(json_meta, dict):
            _merge_unpinned_metadata(full_metadata, json_meta)

    if metadata_data is not None and isinstance(metadata_data, dict):
        _merge_unpinned_metadata(full_metadata, metadata_data)

    # 3. Assemble D5b inventory
    inventory_data = {
        "packages": [p.to_dict() for p in packages],
    }

    # 4. Load exemptions
    exemptions_input = exemptions_data
    if exemptions_path is not None:
        raw_ex = safe_read_bytes(str(exemptions_path), MAX_INVENTORY_BYTES)
        exemptions_input = load_json_bounded(raw_ex, MAX_INVENTORY_BYTES)

    # 5. Evaluate with D5b
    report = evaluate_inventory(inventory_data, full_metadata, cutoff, mode, exemptions_input)

    # 6. Assemble verified SubstrateEntry items (never fabricate digests or dates)
    substrate_entries: list[SubstrateEntry] = []
    seen_substrate: Set[Tuple[str, str, str]] = set()

    for p in packages:
        key = (p.ecosystem, p.name, p.version)
        if key in substrate_map and key not in seen_substrate:
            sub = substrate_map[key]
            substrate_entries.append(sub)
            seen_substrate.add(key)

    substrate_entries.sort()

    # 7. Compute substrate_at_t
    counts = report.get("counts", {})
    ok_count = counts.get("ok", 0)
    total_count = counts.get("total", 0)
    newer_count = counts.get("newer", 0)
    unknown_count = counts.get("unknown", 0)
    exempt_count = counts.get("exempt", 0)

    all_packages_verified = (
        total_count > 0 and len(substrate_entries) == len(packages)
    )

    if (
        total_count > 0
        and ok_count == total_count
        and newer_count == 0
        and unknown_count == 0
        and exempt_count == 0
        and all_packages_verified
    ):
        substrate_at_t = "full"
    elif ok_count > 0:
        substrate_at_t = "partial"
    else:
        substrate_at_t = "none"

    return {
        "schema": "hermetic-d5b-inventory/v1",
        "cutoff": cutoff,
        "mode": mode,
        "inventory": inventory_data,
        "d5b_report": report,
        "substrate": [s.to_dict() for s in substrate_entries],
        "substrate_at_t": substrate_at_t,
    }


def write_canonical_inventory(out_path: Path | str, payload: Dict[str, Any]) -> None:
    """Write canonical inventory JSON atomically with mode 0600."""
    canonical_bytes = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("utf-8")
    hermetic_safe_io.atomic_write(out_path, canonical_bytes)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="hermetic_d5b_inventory", add_help=False)
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--cutoff", required=True)
    parser.add_argument("--mode", default="repo_only")
    parser.add_argument("--apt-index", default=None)
    parser.add_argument("--apt-release", default=None)
    parser.add_argument("--apt-snapshot-date", default=None)
    parser.add_argument("--pypi-manifest", default=None)
    parser.add_argument("--conda-repodata", default=None)
    parser.add_argument("--metadata", default=None)
    parser.add_argument("--exemptions", default=None)
    parser.add_argument("--out", default=None)

    try:
        args = parser.parse_args(argv)
    except SystemExit:
        sys.stderr.write("error: invalid command-line arguments\n")
        return 1

    try:
        result = build_d5b_inventory(
            rootfs=args.rootfs,
            cutoff=args.cutoff,
            mode=args.mode,
            apt_index=args.apt_index,
            apt_release=args.apt_release,
            apt_snapshot_date=args.apt_snapshot_date,
            pypi_manifest=args.pypi_manifest,
            conda_repodata=args.conda_repodata,
            metadata_path=args.metadata,
            exemptions_path=args.exemptions,
        )
    except D5bError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    if args.out:
        try:
            write_canonical_inventory(args.out, result)
        except Exception as exc:
            sys.stderr.write(f"error writing output: {exc}\n")
            return 1
    else:
        output = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        sys.stdout.write(output + "\n")

    if result.get("d5b_report", {}).get("result") == "gate":
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
