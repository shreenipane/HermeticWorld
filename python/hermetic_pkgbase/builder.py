"""Content-addressed store builder and freezing enforcement for hermetic_pkgbase.

Builds a frozen package store compatible with python/hermetic_pkgindex store.py:
- STORE/simple/<normalized-project>/index.json (PEP 691 JSON)
- STORE/files/<sha256>/<filename>
- STORE/.frozen marker file

Verifies every SHA-256 digest before admission.
Once frozen, the baseline is immutable and all modification attempts are refused.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
from typing import Any, Callable, Protocol, Sequence

from hermetic_safe_io import (
    IO_CHUNK_BYTES,
    UnsafePathError as BaseUnsafePathError,
    atomic_write_at,
    open_parent,
    open_regular_at,
)
from .errors import (
    CapExceededError,
    HashMismatchError,
    PkgBaseError,
    StoreImmutableError,
    StoreIOError,
    TotalBytesCapExceededError,
    UnsafePathError,
)
from .planner import MAX_TOTAL_BYTES, Plan
from .resolver import ResolvedFile
from .safe_io import (
    DIR_MODE,
    FILE_MODE,
    _DIR_FLAGS,
    freeze_directory_tree,
    safe_ensure_dir,
    safe_open_dir,
    safe_read_bytes,
    safe_write_file,
    validate_path_components,
)
from .spec import MAX_FILE_BYTES, normalize_project_name, validate_distribution_filename


class Fetcher(Protocol):
    """Protocol for fetching artifact binary content by SHA-256 and filename."""

    def fetch(self, project: str, filename: str, sha256: str) -> bytes:
        ...


class OfflineFixtureFetcher:
    """In-memory offline fetcher for tests."""

    def __init__(self, file_map: dict[str, bytes] | dict[tuple[str, str], bytes]) -> None:
        self._by_sha: dict[str, bytes] = {}
        self._by_name: dict[str, bytes] = {}

        for key, content in file_map.items():
            if isinstance(key, str):
                self._by_sha[key.lower()] = content
                self._by_name[key] = content
            elif isinstance(key, tuple) and len(key) == 2:
                self._by_sha[key[0].lower()] = content
                self._by_name[key[1]] = content

    def fetch(self, project: str, filename: str, sha256: str) -> bytes:
        norm_sha = sha256.lower()
        if norm_sha in self._by_sha:
            return self._by_sha[norm_sha]
        if filename in self._by_name:
            return self._by_name[filename]
        raise StoreIOError(f"Missing artifact content in offline fixture fetcher: {filename}")


def _invoke_fetcher(
    fetcher: Fetcher | Callable[..., bytes],
    project: str,
    filename: str,
    sha256: str,
) -> bytes:
    if hasattr(fetcher, "fetch") and callable(fetcher.fetch):
        return fetcher.fetch(project, filename, sha256)
    if callable(fetcher):
        return fetcher(project, filename, sha256)
    raise StoreIOError("Supplied fetcher is not callable or lacks a fetch() method.")


def is_store_frozen(store_dir: str | Path) -> bool:
    """Check if a baseline store directory is marked frozen."""
    raw, _ = validate_path_components(store_dir)
    frozen_marker = Path(raw) / ".frozen"
    dir_fd = -1
    try:
        try:
            dir_fd, leaf = open_parent(frozen_marker)
        except (BaseUnsafePathError, ValueError) as exc:
            raise UnsafePathError(f"Unsafe path to frozen marker: {exc}") from exc
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise StoreIOError(f"Error inspecting store directory: {exc}") from exc

        try:
            st = os.stat(leaf, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                raise UnsafePathError("Frozen marker cannot be a symlink.")
            return stat.S_ISREG(st.st_mode)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise StoreIOError(f"Error inspecting frozen marker: {exc}") from exc
    finally:
        if dir_fd >= 0:
            os.close(dir_fd)


class BaselineBuilder:
    """Constructs and freezes a Layer 2 package baseline store."""

    def __init__(
        self,
        store_dir: str | Path,
        *,
        max_file_bytes: int = MAX_FILE_BYTES,
        max_total_bytes: int = MAX_TOTAL_BYTES,
    ) -> None:
        raw, _ = validate_path_components(store_dir)
        self.root: Path = Path(raw)
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes

    def build(
        self,
        plan: Plan,
        fetcher: Fetcher | Callable[..., bytes],
    ) -> Path:
        """Fill content-addressed store from plan and freeze it.

        Refuses if store is already frozen.
        Verifies each sha256.
        """
        # 1. Immutability check
        if is_store_frozen(self.root):
            raise StoreImmutableError(
                f"Store at {self.root} is already frozen and cannot be modified."
            )

        safe_ensure_dir(self.root, mode=DIR_MODE)

        # Plan binding check to prevent cross-plan contamination on incomplete builds
        plan_hash = hashlib.sha256(plan.to_canonical_json().encode("utf-8")).hexdigest()
        build_plan_marker = self.root / ".build_plan"
        if build_plan_marker.exists():
            try:
                existing_plan_hash = safe_read_bytes(build_plan_marker, 128).decode("utf-8").strip()
            except Exception as exc:
                raise StoreIOError(f"Failed reading plan recovery record: {exc}") from exc
            if existing_plan_hash != plan_hash:
                raise StoreIOError(
                    f"Store at {self.root} contains incomplete build for another plan; refusing to overwrite."
                )
        else:
            simple_dir = self.root / "simple"
            if simple_dir.is_dir():
                raise StoreIOError(
                    f"Store at {self.root} contains existing index contents without a plan recovery record; refusing to overwrite."
                )

        root_setup_fd = safe_open_dir(self.root, mode=DIR_MODE)
        try:
            atomic_write_at(root_setup_fd, ".build_plan", (plan_hash + "\n").encode("utf-8"))
        except BaseUnsafePathError as exc:
            raise UnsafePathError(f"Unsafe destination for .build_plan: {exc}") from exc
        except OSError as exc:
            raise StoreIOError(f"Failed writing .build_plan recovery record: {exc}") from exc
        finally:
            os.close(root_setup_fd)

        # 2. Group files by project
        files_by_project: dict[str, list[ResolvedFile]] = {}
        for f in plan.files:
            files_by_project.setdefault(f.project, []).append(f)

        # 3. Fetch, verify, and write all distribution files
        files_dir = self.root / "files"
        safe_ensure_dir(files_dir, mode=DIR_MODE)
        files_fd = safe_open_dir(files_dir, mode=DIR_MODE)

        try:
            running_total_bytes = 0
            for f in plan.files:
                # Re-validate distribution filename strictly
                try:
                    validate_distribution_filename(f.filename)
                except ValueError as exc:
                    raise UnsafePathError(f"Invalid distribution filename {f.filename!r}: {exc}") from exc

                # Open the store's files/<sha256> directory relative to its parent descriptor with O_NOFOLLOW
                try:
                    os.mkdir(f.sha256, DIR_MODE, dir_fd=files_fd)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise StoreIOError(f"Failed creating directory component {f.sha256}: {exc}") from exc

                try:
                    sha_dir_fd = os.open(f.sha256, _DIR_FLAGS, dir_fd=files_fd)
                except OSError as exc:
                    raise UnsafePathError(
                        f"Refusing unsafe or symlink directory component {f.sha256}: {exc}"
                    ) from exc

                try:
                    st_sha = os.fstat(sha_dir_fd)
                    if not stat.S_ISDIR(st_sha.st_mode):
                        raise UnsafePathError(f"Path component {f.sha256} is not a directory")

                    # Read existing artifact with open_regular_at bounded by per-file cap
                    art_fd = -1
                    try:
                        art_fd = open_regular_at(sha_dir_fd, f.filename, self.max_file_bytes)
                    except FileNotFoundError:
                        art_fd = -1
                    except BaseUnsafePathError as exc:
                        if "exceeds byte cap" in str(exc):
                            raise CapExceededError(
                                f"Existing file size exceeds per-file cap {self.max_file_bytes} for {f.filename}"
                            ) from exc
                        raise UnsafePathError(f"Unsafe existing artifact {f.filename}: {exc}") from exc
                    except OSError as exc:
                        raise StoreIOError(f"Error opening existing artifact {f.filename}: {exc}") from exc

                    if art_fd >= 0:
                        try:
                            st_art = os.fstat(art_fd)
                            if st_art.st_size != f.size_bytes:
                                raise StoreIOError(
                                    f"Existing file size {st_art.st_size} does not match declared size_bytes {f.size_bytes} for {f.filename}"
                                )
                            if st_art.st_size > self.max_file_bytes:
                                raise CapExceededError(
                                    f"Existing file size {st_art.st_size} exceeds per-file cap {self.max_file_bytes} for {f.filename}"
                                )
                            if running_total_bytes + st_art.st_size > self.max_total_bytes:
                                raise TotalBytesCapExceededError(
                                    f"Total artifact storage cap of {self.max_total_bytes} bytes exceeded."
                                )

                            hasher = hashlib.sha256()
                            total_read = 0
                            max_chunks = (self.max_file_bytes // IO_CHUNK_BYTES) + 2
                            for _ in range(max_chunks):
                                chunk = os.read(art_fd, IO_CHUNK_BYTES)
                                if not chunk:
                                    break
                                total_read += len(chunk)
                                if total_read > self.max_file_bytes:
                                    raise CapExceededError(
                                        f"Existing file size exceeds per-file cap {self.max_file_bytes} for {f.filename}"
                                    )
                                hasher.update(chunk)
                            else:
                                raise StoreIOError(f"Read loop bounded iteration limit exceeded for {f.filename}")

                            if total_read != st_art.st_size:
                                raise StoreIOError(
                                    f"Existing file read size {total_read} did not match fstat size {st_art.st_size} for {f.filename}"
                                )

                            if not hmac.compare_digest(hasher.hexdigest().lower(), f.sha256.lower()):
                                raise HashMismatchError(
                                    f"Existing file SHA-256 mismatch for {f.filename}: "
                                    f"expected {f.sha256}, got {hasher.hexdigest()}"
                                )

                            running_total_bytes += total_read
                        finally:
                            os.close(art_fd)
                    else:
                        try:
                            data = _invoke_fetcher(fetcher, f.project, f.filename, f.sha256)
                        except PkgBaseError:
                            raise
                        except (TimeoutError, OSError) as exc:
                            raise StoreIOError(
                                f"Failed to fetch artifact {f.filename}: {exc}"
                            ) from exc
                        if not isinstance(data, (bytes, bytearray, memoryview)):
                            raise StoreIOError(f"Fetcher returned non-bytes for {f.filename}")
                        content = bytes(data)

                        # Check declared size_bytes
                        if len(content) != f.size_bytes:
                            raise StoreIOError(
                                f"Fetched content length {len(content)} does not match declared size_bytes {f.size_bytes} for {f.filename}"
                            )

                        # Check per-file cap
                        if len(content) > self.max_file_bytes:
                            raise CapExceededError(
                                f"Fetched content length {len(content)} exceeds per-file cap {self.max_file_bytes} for {f.filename}"
                            )

                        # Running total check
                        if running_total_bytes + len(content) > self.max_total_bytes:
                            raise TotalBytesCapExceededError(
                                f"Total artifact storage cap of {self.max_total_bytes} bytes exceeded."
                            )
                        running_total_bytes += len(content)

                        # Verify SHA-256
                        actual_sha = hashlib.sha256(content).hexdigest().lower()
                        expected_sha = f.sha256.lower()
                        if not hmac.compare_digest(actual_sha, expected_sha):
                            raise HashMismatchError(
                                f"SHA-256 digest mismatch for artifact {f.filename}: "
                                f"expected {expected_sha}, got {actual_sha}"
                            )

                        # Write artifact safely through pinned directory descriptor (atomic_write_at)
                        try:
                            atomic_write_at(sha_dir_fd, f.filename, content)
                        except BaseUnsafePathError as exc:
                            raise UnsafePathError(f"Unsafe destination for {f.filename}: {exc}") from exc
                        except OSError as exc:
                            raise StoreIOError(f"Failed writing artifact {f.filename}: {exc}") from exc
                finally:
                    os.close(sha_dir_fd)
        finally:
            os.close(files_fd)

        # 4. Generate PEP 691 index.json for each project in STORE/simple/<project>/index.json
        simple_root = self.root / "simple"
        safe_ensure_dir(simple_root, mode=DIR_MODE)
        simple_fd = safe_open_dir(simple_root, mode=DIR_MODE)
        try:
            for project in plan.resolved_projects:
                project_files = files_by_project.get(project, [])
                norm_project = normalize_project_name(project)

                try:
                    os.mkdir(norm_project, DIR_MODE, dir_fd=simple_fd)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise StoreIOError(f"Failed creating project directory {norm_project}: {exc}") from exc

                try:
                    proj_dir_fd = os.open(norm_project, _DIR_FLAGS, dir_fd=simple_fd)
                except OSError as exc:
                    raise UnsafePathError(
                        f"Refusing unsafe or symlink project directory {norm_project}: {exc}"
                    ) from exc

                try:
                    st_proj = os.fstat(proj_dir_fd)
                    if not stat.S_ISDIR(st_proj.st_mode):
                        raise UnsafePathError(f"Project path {norm_project} is not a directory")

                    files_meta: list[dict[str, Any]] = []
                    for pf in project_files:
                        entry: dict[str, Any] = {
                            "filename": pf.filename,
                            "hashes": {"sha256": pf.sha256},
                            "url": f"/files/{pf.sha256}/{pf.filename}",
                        }
                        if pf.requires_python is not None:
                            entry["requires-python"] = pf.requires_python
                        if pf.yanked:
                            entry["yanked"] = pf.yanked
                        files_meta.append(entry)

                    # Sort files entries deterministically by filename
                    files_meta.sort(key=lambda item: item["filename"])

                    pep691_payload = {
                        "meta": {"api-version": "1.0"},
                        "name": norm_project,
                        "files": files_meta,
                    }
                    index_bytes = (
                        json.dumps(pep691_payload, indent=2, sort_keys=False, ensure_ascii=False)
                        + "\n"
                    ).encode("utf-8")
                    try:
                        atomic_write_at(proj_dir_fd, "index.json", index_bytes)
                    except BaseUnsafePathError as exc:
                        raise UnsafePathError(f"Unsafe destination for {norm_project}/index.json: {exc}") from exc
                    except OSError as exc:
                        raise StoreIOError(f"Failed writing {norm_project}/index.json: {exc}") from exc
                finally:
                    os.close(proj_dir_fd)
        finally:
            os.close(simple_fd)

        root_fd = safe_open_dir(self.root, mode=DIR_MODE)
        try:
            # 5. Write baseline manifest
            manifest_payload = {
                "schema_version": 1,
                "cutoff_month": plan.spec.cutoff_month,
                "cutoff_timestamp": plan.spec.cutoff_timestamp,
                "total_files": len(plan.files),
                "total_bytes": plan.storage.total_bytes,
                "resolved_projects": list(plan.resolved_projects),
                "unresolved_packages": [u.project for u in plan.unresolved],
                "frozen": True,
            }
            manifest_bytes = (
                json.dumps(manifest_payload, indent=2, sort_keys=True, ensure_ascii=False)
                + "\n"
            ).encode("utf-8")
            try:
                atomic_write_at(root_fd, "baseline-manifest.json", manifest_bytes)
            except BaseUnsafePathError as exc:
                raise UnsafePathError(f"Unsafe destination for baseline-manifest.json: {exc}") from exc
            except OSError as exc:
                raise StoreIOError(f"Failed writing baseline-manifest.json: {exc}") from exc

            # 5b. Write baseline-plan.json
            plan_bytes = plan.to_canonical_json().encode("utf-8")
            try:
                atomic_write_at(root_fd, "baseline-plan.json", plan_bytes)
            except BaseUnsafePathError as exc:
                raise UnsafePathError(f"Unsafe destination for baseline-plan.json: {exc}") from exc
            except OSError as exc:
                raise StoreIOError(f"Failed writing baseline-plan.json: {exc}") from exc

            # 6. Write .frozen marker
            frozen_info = (
                json.dumps(
                    {
                        "cutoff_month": plan.spec.cutoff_month,
                        "plan_hash": plan_hash,
                        "frozen": True,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            try:
                atomic_write_at(root_fd, ".frozen", frozen_info)
            except BaseUnsafePathError as exc:
                raise UnsafePathError(f"Unsafe destination for .frozen: {exc}") from exc
            except OSError as exc:
                raise StoreIOError(f"Failed writing .frozen: {exc}") from exc

            # Remove in-progress recovery record now that .frozen is staged
            try:
                os.unlink(".build_plan", dir_fd=root_fd)
            except OSError:
                pass

            # 7. Freeze permissions (0400 for files, 0500 for directories)
            # If freeze fails, clean up .frozen so an incomplete freeze does not commit
            try:
                freeze_directory_tree(self.root)
            except BaseException:
                try:
                    os.unlink(".frozen", dir_fd=root_fd)
                except OSError:
                    pass
                raise
        finally:
            os.close(root_fd)

        return self.root
