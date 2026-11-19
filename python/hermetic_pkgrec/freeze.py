"""Freezes recorded store and manifest into a static hermetic_pkgindex world root."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
from typing import Any

from hermetic_pkgrec.constants import (
    FILE_CHUNK_BYTES,
    MAX_DIR_ENTRIES,
    MAX_DIST_FILE_BYTES,
    MAX_TEMP_ATTEMPTS,
)
from hermetic_pkgrec.errors import (
    ExistingFrozenRootError,
    FreezeError,
    StoreError,
    SymlinkError,
)
from hermetic_pkgrec.filter import normalize_project_name, validate_filename, validate_sha256
from hermetic_pkgrec.manifest import Manifest
from hermetic_pkgrec.models import ManifestRecord
import hermetic_safe_io


def _ensure_dir_private(dir_path: Path) -> None:
    parts = dir_path.resolve().parts
    current = Path(parts[0])
    for part in parts[1:]:
        current = current / part
        try:
            st = os.lstat(current)
            if stat.S_ISLNK(st.st_mode):
                raise SymlinkError("Refusing symlink directory in frozen root.")
            if not stat.S_ISDIR(st.st_mode):
                raise FreezeError("Path component is not a directory.")
        except FileNotFoundError:
            current.mkdir(mode=0o700, exist_ok=True)
            os.chmod(current, 0o700)


def _hash_file(file_path: Path) -> str:
    fd = hermetic_safe_io.open_regular(file_path, MAX_DIST_FILE_BYTES)
    hasher = hashlib.sha256()
    try:
        max_loops = (MAX_DIST_FILE_BYTES // FILE_CHUNK_BYTES) + 2
        for _ in range(max_loops):
            chunk = os.read(fd, FILE_CHUNK_BYTES)
            if not chunk:
                break
            hasher.update(chunk)
        return hasher.hexdigest().lower()
    finally:
        os.close(fd)


def _render_frozen_project_json(proj: str, records: list[ManifestRecord]) -> bytes:
    """Build canonical PEP 691 JSON bytes for a project's index in the frozen root."""
    files_list: list[dict[str, Any]] = []
    for r in sorted(records, key=lambda x: x.filename):
        entry: dict[str, Any] = {
            "filename": r.filename,
            "hashes": {"sha256": r.sha256},
            "url": f"/files/{r.sha256}/{r.filename}",
        }
        if r.yank_decision == "yanked":
            entry["yanked"] = True
        elif r.yank_decision in ("not_yanked", "unyanked_after_cutoff", "unyanked_unknown_date"):
            entry["yanked"] = False
        files_list.append(entry)

    proj_payload = {
        "meta": {"api-version": "1.0"},
        "name": proj,
        "files": files_list,
    }
    return (json.dumps(proj_payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _check_idempotent_match(out_root: Path, manifest: Manifest) -> bool:
    """Check if out_root already matches the manifest completely and identically."""
    files_dir = out_root / "files"
    simple_dir = out_root / "simple"

    try:
        if not files_dir.is_dir() or not simple_dir.is_dir():
            return False

        # Validate each manifest record and group by normalized project.
        projects: dict[str, list[ManifestRecord]] = {}
        expected_sha_to_files: dict[str, set[str]] = {}
        for rec in manifest.files:
            val_sha = validate_sha256(rec.sha256)
            val_fn = validate_filename(rec.filename)
            norm_proj = normalize_project_name(rec.project)
            projects.setdefault(norm_proj, []).append(rec)
            expected_sha_to_files.setdefault(val_sha, set()).add(val_fn)

        # 1. Validate simple/ directory.
        expected_projects = set(projects.keys())
        with os.scandir(simple_dir) as it:
            actual_projects = set()
            count = 0
            for entry in it:
                count += 1
                if count > MAX_DIR_ENTRIES:
                    return False
                if entry.is_symlink() or not entry.is_dir():
                    return False
                actual_projects.add(entry.name)
        if actual_projects != expected_projects:
            return False

        for proj, records in projects.items():
            proj_dir = simple_dir / proj
            idx_path = proj_dir / "index.json"
            st = os.lstat(idx_path)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                return False
            expected_bytes = _render_frozen_project_json(proj, records)
            fd = hermetic_safe_io.open_regular(idx_path, MAX_DIST_FILE_BYTES)
            try:
                raw = os.read(fd, len(expected_bytes) + 1)
                if raw != expected_bytes:
                    return False
            finally:
                os.close(fd)

            # Ensure no extra files exist in the project directory.
            with os.scandir(proj_dir) as it:
                proj_files = [e.name for e in it]
                if proj_files != ["index.json"]:
                    return False

        # 2. Validate files/ directory.
        with os.scandir(files_dir) as it:
            actual_sha_dirs = set()
            count = 0
            for entry in it:
                count += 1
                if count > MAX_DIR_ENTRIES:
                    return False
                if entry.is_symlink() or not entry.is_dir():
                    return False
                actual_sha_dirs.add(entry.name)
        if actual_sha_dirs != set(expected_sha_to_files.keys()):
            return False

        for sha, expected_filenames in expected_sha_to_files.items():
            sha_dir = files_dir / sha
            with os.scandir(sha_dir) as it:
                actual_filenames = set()
                count = 0
                for entry in it:
                    count += 1
                    if count > MAX_DIR_ENTRIES:
                        return False
                    if entry.is_symlink() or not entry.is_file():
                        return False
                    actual_filenames.add(entry.name)
            if actual_filenames != expected_filenames:
                return False

            for fn in expected_filenames:
                target = sha_dir / fn
                st = os.lstat(target)
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                    return False
                actual_sha = _hash_file(target)
                if actual_sha != sha:
                    return False

        # 3. Validate manifest.json (must be present for a valid frozen root).
        manifest_file = out_root / "manifest.json"
        if not manifest_file.exists():
            return False
        st = os.lstat(manifest_file)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return False
        expected_manifest_bytes = manifest.to_canonical_json()
        fd = hermetic_safe_io.open_regular(manifest_file, MAX_DIST_FILE_BYTES)
        try:
            raw = os.read(fd, len(expected_manifest_bytes) + 1)
            if raw != expected_manifest_bytes:
                return False
        finally:
            os.close(fd)

        return True
    except Exception:
        return False


def freeze_world(
    store_dir: str | Path,
    manifest_path: str | Path,
    out_dir: str | Path,
    *,
    misses_path: str | Path | None = None,
) -> None:
    """Freeze a recorded store and manifest into a hermetic_pkgindex world root."""
    store_root = Path(store_dir).resolve()
    manifest_file = Path(manifest_path).resolve()
    out_root = Path(out_dir).resolve()

    if misses_path is not None:
        misses_file = Path(misses_path).resolve()
        if misses_file == out_root or misses_file.is_relative_to(out_root):
            raise FreezeError("Misses log file must not be placed inside the frozen root.")

    if not store_root.is_dir():
        raise StoreError(f"Store directory does not exist: {store_root.name}")

    manifest = Manifest.load(manifest_file)

    # Validate every record before touching filesystem (Finding 7).
    validated_files: list[tuple[str, str, str, str]] = []  # (norm_project, filename, sha256, yank_decision)
    for rec in manifest.files:
        val_sha = validate_sha256(rec.sha256)
        val_fn = validate_filename(rec.filename)
        norm_proj = normalize_project_name(rec.project)

        # Ensure destination path remains inside files/ directory.
        dst_candidate = (out_root / "files" / val_sha / val_fn).resolve()
        if not dst_candidate.is_relative_to((out_root / "files").resolve()):
            raise FreezeError(f"File destination escapes files root: {rec.filename}")

        validated_files.append((norm_proj, val_fn, val_sha, rec.yank_decision))

    if out_root.exists():
        # Inspect existing directory.
        if _check_idempotent_match(out_root, manifest):
            # Idempotent match: already cleanly frozen with identical contents.
            return
        raise ExistingFrozenRootError(
            f"Refusing to modify existing frozen root directory: {out_root.name}"
        )

    # Fresh freeze: stage in a sibling temporary directory (Finding 6).
    staging_dir: Path | None = None
    for _ in range(MAX_TEMP_ATTEMPTS):
        cand = out_root.with_name(f"{out_root.name}.tmp-{os.urandom(8).hex()}")
        if not cand.exists():
            staging_dir = cand
            break
    if staging_dir is None:
        raise FreezeError("Failed to allocate temporary staging directory.")

    _ensure_dir_private(staging_dir)
    try:
        staging_simple = staging_dir / "simple"
        staging_files = staging_dir / "files"
        _ensure_dir_private(staging_simple)
        _ensure_dir_private(staging_files)

        # 1. Copy distribution files into staging_files/<sha256>/<filename>.
        store_files = store_root / "files"
        for norm_proj, val_fn, val_sha, yank_dec in validated_files:
            src_file = store_files / val_sha / val_fn
            if not src_file.is_file():
                raise StoreError(f"File missing from store: {val_fn} ({val_sha})")

            src_sha = _hash_file(src_file)
            if src_sha != val_sha:
                raise StoreError(f"Store file corruption detected for {val_fn}")

            dst_sha_dir = staging_files / val_sha
            _ensure_dir_private(dst_sha_dir)
            dst_file = dst_sha_dir / val_fn

            src_fd = hermetic_safe_io.open_regular(src_file, MAX_DIST_FILE_BYTES)
            try:
                chunks: list[bytes] = []
                max_loops = (MAX_DIST_FILE_BYTES // FILE_CHUNK_BYTES) + 2
                for _ in range(max_loops):
                    chunk = os.read(src_fd, FILE_CHUNK_BYTES)
                    if not chunk:
                        break
                    chunks.append(chunk)
                payload = b"".join(chunks)
            finally:
                os.close(src_fd)

            hermetic_safe_io.atomic_write(dst_file, payload)

        # 2. Write project index pages into staging_simple/<project>/index.json.
        projects: dict[str, list[ManifestRecord]] = {}
        for rec in manifest.files:
            norm = normalize_project_name(rec.project)
            projects.setdefault(norm, []).append(rec)

        for proj, records in sorted(projects.items()):
            proj_dir = staging_simple / proj
            _ensure_dir_private(proj_dir)
            json_bytes = _render_frozen_project_json(proj, records)
            hermetic_safe_io.atomic_write(proj_dir / "index.json", json_bytes)

        # 3. Write canonical manifest into staging_dir/manifest.json.
        manifest_bytes = manifest.to_canonical_json()
        hermetic_safe_io.atomic_write(staging_dir / "manifest.json", manifest_bytes)

        # Atomically publish the staging tree as out_root.
        staging_dir.rename(out_root)
    except Exception:
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise
