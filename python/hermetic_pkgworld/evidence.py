"""Deterministic Merkle digest computation over Layer-1 package closures and Layer-2 baselines.

Implements requirements for WorldManifest PackagesRecord {closure_root, baseline_month, baseline_root}.
Every computation verifies underlying filesystem artifacts, enforces strict immutability and
safety bounds, and fails closed with precise typed errors on any tampering or missing inputs.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

import hermetic_safe_io
from hermetic_safe_io import open_parent, open_regular, validate_path
from hermetic_pkgbase.builder import is_store_frozen
from hermetic_pkgbase.errors import StoreIOError, UnsafePathError as PkgBaseUnsafePathError
from hermetic_pkgrec.filter import validate_filename, validate_sha256
from hermetic_pkgworld.constants import (
    FILE_CHUNK_BYTES,
    MAX_DIR_ENTRIES,
    MAX_FILE_BYTES,
    MAX_MANIFEST_BYTES,
    MAX_PLAN_BYTES,
    MAX_PROJECT_SUB_ENTRIES,
    MAX_TOTAL_FILES,
    PKG_EMPTY_TAG,
    PKG_LEAF_TAG,
    PKG_NODE_TAG,
)
from hermetic_pkgworld.errors import (
    BaselineError,
    ClosureError,
    CutoffMismatchError,
    IntegrityError,
    SafeIOError,
)

_MONTH_RE = re.compile(r"\A[0-9]{4}-(?:0[1-9]|1[0-2])\Z")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_json_bytes(payload: Any) -> bytes:
    """Format payload as canonical JSON (sorted keys, compact separators, UTF-8)."""
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def compute_leaf_hash(domain_tag: bytes, path: str | bytes, value: bytes) -> bytes:
    """Compute cryptographic leaf hash with domain separation and length prefixing.

    Leaf hash: SHA256(domain_tag || len(path) u32 LE || path || len(value) u32 LE || value).
    """
    path_bytes = path.encode("utf-8") if isinstance(path, str) else path
    hasher = hashlib.sha256()
    hasher.update(domain_tag)
    hasher.update(len(path_bytes).to_bytes(4, "little"))
    hasher.update(path_bytes)
    hasher.update(len(value).to_bytes(4, "little"))
    hasher.update(value)
    return hasher.digest()


def compute_merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """Compute binary Merkle tree root over leaf hashes.

    Internal node: SHA256(PKG_NODE_TAG || left || right).
    An odd node at a level is promoted unchanged.
    The empty tree is SHA256(PKG_EMPTY_TAG).
    """
    if not leaf_hashes:
        return hashlib.sha256(PKG_EMPTY_TAG).digest()

    current = list(leaf_hashes)
    while len(current) > 1:
        next_level: list[bytes] = []
        i = 0
        while i < len(current):
            if i + 1 < len(current):
                hasher = hashlib.sha256()
                hasher.update(PKG_NODE_TAG)
                hasher.update(current[i])
                hasher.update(current[i + 1])
                next_level.append(hasher.digest())
                i += 2
            else:
                next_level.append(current[i])
                i += 1
        current = next_level
    return current[0]


def _read_regular_file_bounded(path: Path, max_bytes: int) -> bytes:
    """Safely read a regular file without following symlinks and bounded by max_bytes."""
    try:
        fd = open_regular(path, max_bytes)
    except hermetic_safe_io.UnsafePathError as exc:
        raise SafeIOError(f"Refusing unsafe path or symlink at {path}: {exc}") from exc
    except FileNotFoundError as exc:
        raise SafeIOError(f"File not found: {path}") from exc
    except OSError as exc:
        raise SafeIOError(f"Error accessing file {path}: {exc}") from exc

    try:
        chunks: list[bytes] = []
        total = 0
        max_read_loops = max_bytes + 1
        for _ in range(max_read_loops):
            try:
                chunk = os.read(fd, FILE_CHUNK_BYTES)
            except OSError as exc:
                raise SafeIOError(f"Error reading file {path}: {exc}") from exc
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise IntegrityError(f"File {path} exceeds maximum byte limit of {max_bytes}")
            chunks.append(chunk)
        else:
            raise SafeIOError(f"File {path} exceeded read iteration cap ({max_read_loops})")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _verify_file_hash_on_disk(file_path: Path, expected_sha256: str) -> None:
    """Verify that a distribution file exists as a regular file and matches expected SHA-256."""
    try:
        st = os.lstat(file_path)
    except FileNotFoundError as exc:
        raise IntegrityError(f"Missing distribution file on disk: {file_path}") from exc
    except OSError as exc:
        raise SafeIOError(f"Failed inspecting file {file_path}: {exc}") from exc

    if stat.S_ISLNK(st.st_mode):
        raise SafeIOError(f"Distribution file must not be a symlink: {file_path}")
    if not stat.S_ISREG(st.st_mode):
        raise SafeIOError(f"Distribution file must be a regular file: {file_path}")
    if st.st_size > MAX_FILE_BYTES:
        raise IntegrityError(f"Distribution file {file_path} exceeds maximum size cap {MAX_FILE_BYTES}")

    try:
        fd = open_regular(file_path, MAX_FILE_BYTES)
    except Exception as exc:
        raise SafeIOError(f"Cannot safely open distribution file {file_path}: {exc}") from exc

    hasher = hashlib.sha256()
    total = 0
    max_read_loops = MAX_FILE_BYTES + 1
    try:
        for _ in range(max_read_loops):
            try:
                chunk = os.read(fd, FILE_CHUNK_BYTES)
            except OSError as exc:
                raise SafeIOError(f"Error reading file {file_path}: {exc}") from exc
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise IntegrityError(f"Distribution file {file_path} exceeded size cap during streaming")
            hasher.update(chunk)
        else:
            raise SafeIOError(f"Distribution file {file_path} exceeded read iteration cap ({max_read_loops})")
    finally:
        os.close(fd)

    actual_sha = hasher.hexdigest().lower()
    if actual_sha != expected_sha256.lower():
        raise IntegrityError(
            f"Digest mismatch for {file_path.name}: expected {expected_sha256}, got {actual_sha}"
        )


def _check_no_rogue_files(root: Path, expected_files: set[tuple[str, str]], expected_projects: set[str]) -> None:
    """Ensure directory tree contains only declared index pages and distribution files."""
    files_dir = root / "files"
    simple_dir = root / "simple"

    try:
        st_files = os.lstat(files_dir)
        has_files = True
    except FileNotFoundError:
        has_files = False
    except OSError as exc:
        raise SafeIOError(f"Error inspecting files directory: {exc}") from exc

    if has_files:
        if stat.S_ISLNK(st_files.st_mode) or not stat.S_ISDIR(st_files.st_mode):
            raise ClosureError(f"files path is not a genuine directory: {files_dir}")
        try:
            with os.scandir(files_dir) as sha_it:
                count = 0
                for sha_entry in sha_it:
                    count += 1
                    if count > MAX_DIR_ENTRIES:
                        raise ClosureError("files/ directory exceeds maximum entry limit")
                    try:
                        is_link = sha_entry.is_symlink()
                        is_dir = sha_entry.is_dir()
                    except OSError as exc:
                        raise SafeIOError(f"Failed inspecting entry {sha_entry.name} in files/: {exc}") from exc
                    if is_link or not is_dir:
                        raise ClosureError(f"Unexpected entry in files/: {sha_entry.name}")
                    sha_name = sha_entry.name
                    try:
                        scan_entry = os.scandir(sha_entry.path)
                    except OSError as exc:
                        raise SafeIOError(f"Failed scanning files/{sha_name}: {exc}") from exc
                    with scan_entry as file_it:
                        for f_entry in file_it:
                            try:
                                f_is_link = f_entry.is_symlink()
                                f_is_file = f_entry.is_file()
                            except OSError as exc:
                                raise SafeIOError(f"Failed inspecting entry {f_entry.name} in files/{sha_name}: {exc}") from exc
                            if f_is_link or not f_is_file:
                                raise ClosureError(f"Unexpected non-file in files/{sha_name}: {f_entry.name}")
                            if (sha_name, f_entry.name) not in expected_files:
                                raise ClosureError(f"Undeclared rogue file found in closure: {sha_name}/{f_entry.name}")
        except ClosureError:
            raise
        except OSError as exc:
            raise SafeIOError(f"Failed scanning files/ directory: {exc}") from exc

    try:
        st_simple = os.lstat(simple_dir)
        has_simple = True
    except FileNotFoundError:
        has_simple = False
    except OSError as exc:
        raise SafeIOError(f"Error inspecting simple directory: {exc}") from exc

    if has_simple:
        if stat.S_ISLNK(st_simple.st_mode) or not stat.S_ISDIR(st_simple.st_mode):
            raise ClosureError(f"simple path is not a genuine directory: {simple_dir}")
        try:
            with os.scandir(simple_dir) as proj_it:
                count = 0
                for proj_entry in proj_it:
                    count += 1
                    if count > MAX_DIR_ENTRIES:
                        raise ClosureError("simple/ directory exceeds maximum entry limit")
                    try:
                        is_link = proj_entry.is_symlink()
                        is_dir = proj_entry.is_dir()
                    except OSError as exc:
                        raise SafeIOError(f"Failed inspecting entry {proj_entry.name} in simple/: {exc}") from exc
                    if is_link or not is_dir:
                        raise ClosureError(f"Unexpected entry in simple/: {proj_entry.name}")
                    if proj_entry.name not in expected_projects:
                        raise ClosureError(f"Undeclared rogue project found in simple/: {proj_entry.name}")
                    try:
                        scan_proj = os.scandir(proj_entry.path)
                    except OSError as exc:
                        raise SafeIOError(f"Failed scanning simple/{proj_entry.name}: {exc}") from exc
                    with scan_proj as sub_it:
                        sub_names: list[str] = []
                        for sub_entry in sub_it:
                            sub_names.append(sub_entry.name)
                            if len(sub_names) >= MAX_PROJECT_SUB_ENTRIES:
                                break
                        if sub_names != ["index.json"]:
                            raise ClosureError(f"Unexpected files in project index directory: {proj_entry.name}")
        except ClosureError:
            raise
        except OSError as exc:
            raise SafeIOError(f"Failed scanning simple/ directory: {exc}") from exc


def compute_closure_root(
    closure_dir: str | Path,
    *,
    verify_files: bool = True,
) -> tuple[str, dict[str, Any]]:
    """Compute closure_root as a deterministic Merkle digest over a frozen Layer-1 closure.

    The closure directory must have been produced and signed off by hermetic_pkgrec freeze.
    A task with no third-party packages must contain a valid zero-file manifest signed off by pkgrec,
    and produces a deterministic non-empty Merkle root binding the manifest schema and cutoff.
    """
    try:
        validate_path(str(closure_dir))
    except (ValueError, hermetic_safe_io.UnsafePathError) as exc:
        raise SafeIOError(f"Invalid or unsafe closure directory path {closure_dir!r}: {exc}") from exc
    supplied_path = Path(closure_dir)
    if supplied_path.is_symlink():
        raise ClosureError(f"Package closure directory must not be a symlink: {supplied_path}")
    root_path = supplied_path.resolve()
    if not root_path.is_dir() or root_path.is_symlink():
        raise ClosureError(f"Package closure directory is not a physical directory: {root_path}")

    # Locate manifest.json or closure-manifest.json
    manifest_path = root_path / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        alt_manifest = root_path / "closure-manifest.json"
        if alt_manifest.is_file() and not alt_manifest.is_symlink():
            manifest_path = alt_manifest
        else:
            raise ClosureError(
                f"Missing package closure manifest (manifest.json) in {root_path}. "
                "Tasks with zero packages must have an explicit zero-file manifest signed off by pkgrec."
            )

    raw_manifest = _read_regular_file_bounded(manifest_path, MAX_MANIFEST_BYTES)
    try:
        manifest_data = json.loads(raw_manifest.decode("utf-8"))
    except Exception as exc:
        raise ClosureError(f"Corrupted closure manifest JSON: {exc}") from exc

    if not isinstance(manifest_data, dict):
        raise ClosureError("Closure manifest root must be a JSON object")

    schema = manifest_data.get("schema")
    if schema != "hermetic.pkgrec.manifest/1":
        raise ClosureError(f"Unsupported package closure manifest schema: {schema!r}")

    cutoff = manifest_data.get("cutoff")
    if not isinstance(cutoff, str) or not cutoff:
        raise ClosureError("Closure manifest missing valid cutoff timestamp")

    raw_files = manifest_data.get("files")
    if not isinstance(raw_files, list):
        raise ClosureError("Closure manifest 'files' field must be a list")
    if len(raw_files) > MAX_TOTAL_FILES:
        raise ClosureError(f"Closure total files {len(raw_files)} exceeds cap {MAX_TOTAL_FILES}")

    expected_files: set[tuple[str, str]] = set()
    expected_projects: set[str] = set()
    seen_identities: set[tuple[str, str, str]] = set()
    records: list[dict[str, str]] = []

    for item in raw_files:
        if not isinstance(item, dict):
            raise ClosureError("Malformed manifest file entry: expected object")
        proj = item.get("project")
        fname = item.get("filename")
        sha = item.get("sha256")
        utime = item.get("upload-time") or item.get("upload_time")
        ydec = item.get("yank_decision") or item.get("yank-decision") or "not_yanked"

        if not isinstance(proj, str) or not proj:
            raise ClosureError("Closure file record missing valid project")
        if "/" in proj or "\\" in proj or "\0" in proj:
            raise ClosureError(f"Unsafe project name in closure manifest: {proj!r}")
        if not isinstance(fname, str) or not fname:
            raise ClosureError("Closure file record missing valid filename")
        # Reject absolute, separator-containing, traversal, or NUL filenames (CWE-22)
        try:
            validate_filename(fname)
        except Exception as exc:
            raise ClosureError(f"Unsafe distribution filename in closure manifest: {fname!r}") from exc
        try:
            norm_sha = validate_sha256(sha)
        except Exception as exc:
            raise ClosureError(f"Closure file record has invalid sha256: {sha!r}") from exc
        if not isinstance(utime, str) or not utime:
            raise ClosureError("Closure file record missing upload-time")
        if not isinstance(ydec, str):
            raise ClosureError("Closure file record missing yank_decision")

        norm_proj = proj.lower().replace("_", "-").replace(".", "-")
        file_id = (norm_proj, fname, norm_sha)
        if file_id in seen_identities:
            raise ClosureError(f"Duplicate file record identity in closure manifest: {file_id}")
        seen_identities.add(file_id)

        records.append({
            "filename": fname,
            "project": norm_proj,
            "sha256": norm_sha,
            "upload-time": utime,
            "yank_decision": ydec,
        })
        expected_files.add((norm_sha, fname))
        expected_projects.add(norm_proj)

    if verify_files:
        # Verify on-disk distribution files and index pages
        files_dir = root_path / "files"
        simple_dir = root_path / "simple"

        for rec in records:
            art_path = files_dir / rec["sha256"] / rec["filename"]
            _verify_file_hash_on_disk(art_path, rec["sha256"])

            idx_path = simple_dir / rec["project"] / "index.json"
            if not idx_path.is_file() or idx_path.is_symlink():
                raise ClosureError(f"Missing PEP 691 index page for project {rec['project']} at {idx_path}")

        _check_no_rogue_files(root_path, expected_files, expected_projects)

    # Sort records deterministically by (project, filename, sha256)
    records.sort(key=lambda r: (r["project"], r["filename"], r["sha256"]))

    # Construct canonical leaves
    leaves: list[tuple[str, bytes]] = []

    # 1. Manifest metadata leaf explicitly binds cutoff and schema (vital for zero-file signoff)
    manifest_leaf_path = "/manifest"
    manifest_leaf_val = canonical_json_bytes({
        "cutoff": cutoff,
        "files_count": len(records),
        "schema": "hermetic.pkgrec.manifest/1",
    })
    leaves.append((manifest_leaf_path, manifest_leaf_val))

    # 2. Per-file canonical leaves
    for rec in records:
        leaf_path = f"/files/{rec['project']}/{rec['filename']}/{rec['sha256']}"
        leaf_val = canonical_json_bytes({
            "filename": rec["filename"],
            "project": rec["project"],
            "sha256": rec["sha256"],
            "upload-time": rec["upload-time"],
            "yank_decision": rec["yank_decision"],
        })
        leaves.append((leaf_path, leaf_val))

    # Sort leaves strictly by path in byte order
    leaves.sort(key=lambda l: l[0].encode("utf-8"))

    # Compute leaf hashes and Merkle root
    leaf_hashes = [compute_leaf_hash(PKG_LEAF_TAG, p, v) for p, v in leaves]
    root_bytes = compute_merkle_root(leaf_hashes)
    closure_root = f"sha256:{root_bytes.hex()}"

    summary = {
        "cutoff": cutoff,
        "files_count": len(records),
        "projects_count": len(expected_projects),
        "closure_root": closure_root,
    }
    return closure_root, summary


def compute_baseline_root(
    baseline_dir: str | Path,
    *,
    expected_month: str | None = None,
    verify_files: bool = True,
) -> tuple[str, str, dict[str, Any]]:
    """Compute baseline_root and baseline_month over a Layer-2 baseline plan/store.

    The baseline store directory must have been built and frozen by hermetic_pkgbase.
    Verifies that the store is frozen (.frozen marker), validates baseline-manifest.json,
    reads the canonical baseline plan, checks on-disk artifacts against declared checksums,
    and returns (baseline_root, baseline_month, summary).
    """
    try:
        validate_path(str(baseline_dir))
    except (ValueError, hermetic_safe_io.UnsafePathError) as exc:
        raise SafeIOError(f"Invalid or unsafe baseline directory path {baseline_dir!r}: {exc}") from exc
    supplied_path = Path(baseline_dir)
    if supplied_path.is_symlink():
        raise BaselineError(f"Baseline store directory must not be a symlink: {supplied_path}")
    root_path = supplied_path.resolve()
    if not root_path.is_dir() or root_path.is_symlink():
        raise BaselineError(f"Baseline store directory is not a physical directory: {root_path}")

    # Check store frozen marker
    try:
        store_frozen = is_store_frozen(root_path)
    except (PkgBaseUnsafePathError, StoreIOError) as exc:
        raise SafeIOError(f"Failed inspecting frozen marker at {root_path}: {exc}") from exc
    if not store_frozen:
        raise BaselineError(f"Baseline store at {root_path} is not frozen (missing or invalid .frozen marker)")

    # Read baseline-manifest.json
    manifest_path = root_path / "baseline-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise BaselineError(f"Missing baseline-manifest.json in baseline store at {root_path}")

    raw_manifest = _read_regular_file_bounded(manifest_path, MAX_MANIFEST_BYTES)
    try:
        manifest_data = json.loads(raw_manifest.decode("utf-8"))
    except Exception as exc:
        raise BaselineError(f"Corrupted baseline-manifest.json: {exc}") from exc

    if not isinstance(manifest_data, dict):
        raise BaselineError("baseline-manifest.json root must be a JSON object")

    cutoff_month = manifest_data.get("cutoff_month")
    if not isinstance(cutoff_month, str) or not _MONTH_RE.fullmatch(cutoff_month):
        raise BaselineError(f"Invalid or missing cutoff_month in baseline-manifest.json: {cutoff_month!r}")

    if expected_month is not None and cutoff_month != expected_month:
        raise CutoffMismatchError(
            f"Baseline cutoff_month {cutoff_month} does not match expected month {expected_month}"
        )

    cutoff_timestamp = manifest_data.get("cutoff_timestamp")
    if not isinstance(cutoff_timestamp, str) or not cutoff_timestamp:
        raise BaselineError("Missing cutoff_timestamp in baseline-manifest.json")

    total_files_declared = manifest_data.get("total_files")
    if (
        isinstance(total_files_declared, bool)
        or not isinstance(total_files_declared, int)
        or total_files_declared < 0
        or total_files_declared > MAX_TOTAL_FILES
    ):
        raise BaselineError(f"Invalid total_files in baseline-manifest.json: {total_files_declared!r}")

    # Locate baseline-plan.json or plan.json
    plan_path = root_path / "baseline-plan.json"
    if not plan_path.is_file() or plan_path.is_symlink():
        alt_plan = root_path / "plan.json"
        if alt_plan.is_file() and not alt_plan.is_symlink():
            plan_path = alt_plan
        else:
            raise BaselineError(f"Missing baseline-plan.json (or plan.json) in baseline store at {root_path}")

    raw_plan = _read_regular_file_bounded(plan_path, MAX_PLAN_BYTES)

    # Bind the plan to its recorded plan hash from .frozen marker (Finding 5)
    frozen_marker_path = root_path / ".frozen"
    raw_frozen = _read_regular_file_bounded(frozen_marker_path, MAX_MANIFEST_BYTES)
    try:
        frozen_data = json.loads(raw_frozen.decode("utf-8"))
    except Exception as exc:
        raise BaselineError(f"Corrupted .frozen marker JSON: {exc}") from exc
    if not isinstance(frozen_data, dict):
        raise BaselineError(".frozen marker must be a JSON object")
    recorded_plan_hash = frozen_data.get("plan_hash")
    if not isinstance(recorded_plan_hash, str) or not recorded_plan_hash:
        raise BaselineError("Missing plan_hash in .frozen marker")
    actual_plan_hash = hashlib.sha256(raw_plan).hexdigest()
    if actual_plan_hash != recorded_plan_hash:
        raise BaselineError(
            f"Baseline plan hash mismatch: .frozen records {recorded_plan_hash}, "
            f"but actual plan file hashes to {actual_plan_hash}"
        )

    try:
        plan_data = json.loads(raw_plan.decode("utf-8"))
    except Exception as exc:
        raise BaselineError(f"Corrupted baseline plan JSON: {exc}") from exc

    if not isinstance(plan_data, dict):
        raise BaselineError("Baseline plan root must be a JSON object")

    plan_month = plan_data.get("cutoff_month")
    if plan_month != cutoff_month:
        raise BaselineError(
            f"Baseline plan cutoff_month ({plan_month}) mismatch with baseline manifest ({cutoff_month})"
        )

    plan_timestamp = plan_data.get("cutoff_timestamp")
    if plan_timestamp != cutoff_timestamp:
        raise BaselineError(
            f"Baseline plan cutoff_timestamp ({plan_timestamp}) mismatch with baseline manifest ({cutoff_timestamp})"
        )

    raw_files = plan_data.get("files")
    if not isinstance(raw_files, list):
        raise BaselineError("Baseline plan 'files' field must be a list")
    if len(raw_files) > MAX_TOTAL_FILES:
        raise BaselineError(f"Baseline plan total files {len(raw_files)} exceeds cap {MAX_TOTAL_FILES}")
    if len(raw_files) != total_files_declared:
        raise BaselineError(
            f"Baseline plan file count ({len(raw_files)}) does not match baseline manifest ({total_files_declared})"
        )

    expected_files: set[tuple[str, str]] = set()
    expected_projects: set[str] = set()
    seen_identities: set[tuple[str, str, str]] = set()
    records: list[dict[str, str]] = []

    for item in raw_files:
        if not isinstance(item, dict):
            raise BaselineError("Malformed baseline plan file entry: expected object")
        proj = item.get("project")
        fname = item.get("filename")
        sha = item.get("sha256")
        utime = item.get("upload-time") or item.get("upload_time")
        yanked = item.get("yanked", False)
        if not isinstance(yanked, bool):
            raise BaselineError(f"Invalid yanked field in baseline plan: expected boolean, got {yanked!r}")
        yank_dec = "yanked" if yanked else "not_yanked"

        if not isinstance(proj, str) or not proj:
            raise BaselineError("Baseline plan file record missing valid project")
        if "/" in proj or "\\" in proj or "\0" in proj:
            raise BaselineError(f"Unsafe project name in baseline plan: {proj!r}")
        if not isinstance(fname, str) or not fname:
            raise BaselineError("Baseline plan file record missing valid filename")
        # Reject absolute, separator-containing, traversal, or NUL filenames (CWE-22)
        try:
            validate_filename(fname)
        except Exception as exc:
            raise BaselineError(f"Unsafe distribution filename in baseline plan: {fname!r}") from exc
        try:
            norm_sha = validate_sha256(sha)
        except Exception as exc:
            raise BaselineError(f"Baseline plan file record has invalid sha256: {sha!r}") from exc
        if not isinstance(utime, str) or not utime:
            raise BaselineError("Baseline plan file record missing upload-time")

        norm_proj = proj.lower().replace("_", "-").replace(".", "-")
        file_id = (norm_proj, fname, norm_sha)
        if file_id in seen_identities:
            raise BaselineError(f"Duplicate file record identity in baseline plan: {file_id}")
        seen_identities.add(file_id)

        records.append({
            "filename": fname,
            "project": norm_proj,
            "sha256": norm_sha,
            "upload-time": utime,
            "yank_decision": yank_dec,
        })
        expected_files.add((norm_sha, fname))
        expected_projects.add(norm_proj)

    if verify_files:
        files_dir = root_path / "files"
        simple_dir = root_path / "simple"

        for rec in records:
            art_path = files_dir / rec["sha256"] / rec["filename"]
            _verify_file_hash_on_disk(art_path, rec["sha256"])

            idx_path = simple_dir / rec["project"] / "index.json"
            if not idx_path.is_file() or idx_path.is_symlink():
                raise BaselineError(f"Missing index page for baseline project {rec['project']} at {idx_path}")

        _check_no_rogue_files(root_path, expected_files, expected_projects)

    # Sort records deterministically by (project, filename, sha256)
    records.sort(key=lambda r: (r["project"], r["filename"], r["sha256"]))

    # Construct canonical leaves (same way as Layer-1 closure)
    leaves: list[tuple[str, bytes]] = []

    # 1. Manifest metadata leaf
    manifest_leaf_path = "/manifest"
    manifest_leaf_val = canonical_json_bytes({
        "cutoff_month": cutoff_month,
        "cutoff_timestamp": cutoff_timestamp,
        "files_count": len(records),
        "schema": "hermetic.pkgbase.baseline/1",
    })
    leaves.append((manifest_leaf_path, manifest_leaf_val))

    # 2. Per-file canonical leaves
    for rec in records:
        leaf_path = f"/files/{rec['project']}/{rec['filename']}/{rec['sha256']}"
        leaf_val = canonical_json_bytes({
            "filename": rec["filename"],
            "project": rec["project"],
            "sha256": rec["sha256"],
            "upload-time": rec["upload-time"],
            "yank_decision": rec["yank_decision"],
        })
        leaves.append((leaf_path, leaf_val))

    leaves.sort(key=lambda l: l[0].encode("utf-8"))

    leaf_hashes = [compute_leaf_hash(PKG_LEAF_TAG, p, v) for p, v in leaves]
    root_bytes = compute_merkle_root(leaf_hashes)
    baseline_root = f"sha256:{root_bytes.hex()}"

    summary = {
        "cutoff_month": cutoff_month,
        "cutoff_timestamp": cutoff_timestamp,
        "files_count": len(records),
        "projects_count": len(expected_projects),
        "baseline_root": baseline_root,
    }
    return baseline_root, cutoff_month, summary


def compute_package_evidence(
    closure_dir: str | Path,
    baseline_dir: str | Path,
    *,
    expected_pkg_cutoff: str | None = None,
    verify_files: bool = True,
) -> dict[str, str]:
    """Compute the PackagesRecord {closure_root, baseline_month, baseline_root} needed by WorldManifest.

    Validates both the Layer-1 frozen closure and the Layer-2 baseline store.
    If expected_pkg_cutoff is provided, validates that baseline_month equals the YYYY-MM
    of expected_pkg_cutoff.
    Returns dictionary with keys 'closure_root', 'baseline_month', 'baseline_root'.
    """
    closure_root, closure_summary = compute_closure_root(closure_dir, verify_files=verify_files)

    expected_month = None
    if expected_pkg_cutoff:
        if len(expected_pkg_cutoff) < 7 or not _MONTH_RE.match(expected_pkg_cutoff[:7]):
            raise CutoffMismatchError(f"Invalid package cutoff timestamp: {expected_pkg_cutoff!r}")
        expected_month = expected_pkg_cutoff[:7]

        closure_cutoff = closure_summary.get("cutoff", "")
        granularity = min(len(closure_cutoff), len(expected_pkg_cutoff))
        if closure_cutoff[:granularity] != expected_pkg_cutoff[:granularity]:
            raise CutoffMismatchError(
                f"Closure cutoff {closure_cutoff} does not match expected package cutoff {expected_pkg_cutoff}"
            )

    baseline_root, baseline_month, _ = compute_baseline_root(
        baseline_dir, expected_month=expected_month, verify_files=verify_files
    )

    return {
        "baseline_month": baseline_month,
        "baseline_root": baseline_root,
        "closure_root": closure_root,
    }
