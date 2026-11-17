"""Deterministic D7 build recipe generation and emission for Hermetic World.

During a seal, for every artifact in the world that was built from source
in the task environment (wheels/sdists built locally, compiled extension
modules, generated files listed by the build), the sealer writes one strict
`hermetic.d7.recipe/1` entry::

    {"schema": "hermetic.d7.recipe/1",
     "entries": [{"id": "pkg-wheel",
                  "artifact": "dist/pkg-1.0-py3-none-any.whl",
                  "source": "src/pkg",
                  "builder": "python-wheel",
                  "args": ["--no-isolation"]}],
     "unattributed": ["opt/env/orphan.so"]}

Invariants:
- Relative paths only; no host paths, host times, hostnames or usernames.
- Deterministic order (entries sorted by id, unattributed sorted alphabetically).
- All reads and loops bounded by named constants.
- No-follow descriptor pinning; symlinks and non-regular files are refused.
- Artifacts whose provenance cannot be established are listed in "unattributed",
  never guessed.
- Output file created with mode 0600.
"""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import hermetic_safe_io
from hermetic_d7.deep_audit import (
    MAX_ARG_BYTES,
    MAX_ARGS,
    MAX_RECIPE_BYTES,
    MAX_RECIPE_ENTRIES,
    RECIPE_SCHEMA,
    RecipeEntry,
    _BUILDER_RE,
    _ID_RE,
    _open_no_follow,
    _read_no_follow,
    _strict_pairs,
    parse_recipe,
)
from hermetic_d7.normalise import (
    HermeticD7Error,
    InvalidArtifactError,
    ResourceLimitError,
    SecurityViolationError,
    validate_member_path,
)

MAX_UNATTRIBUTED_ENTRIES: int = 4096
MAX_BUILD_MANIFEST_BYTES: int = 4 * 1024 * 1024  # 4 MiB
MAX_SCAN_FILES: int = 500_000
MAX_SCAN_DEPTH: int = 32
MAX_PATH_BYTES: int = 4096
READ_CHUNK_SIZE: int = 65_536

COMPILED_EXTENSION_SUFFIXES: tuple[str, ...] = (".so", ".dylib", ".pyd")
LOCAL_DIST_SUFFIXES: tuple[str, ...] = (".whl", ".tar.gz", ".zip", ".tar.bz2", ".tar.xz", ".tgz")


class RecipeError(HermeticD7Error):
    """Base typed error for recipe building or emission failure."""


class RecipeFormatError(RecipeError, InvalidArtifactError):
    """Recipe data or build specification is malformed."""


class RecipeSecurityError(RecipeError, SecurityViolationError):
    """Symlink, directory traversal, or special file detected in recipe inputs."""


class RecipeResourceLimitError(RecipeError, ResourceLimitError):
    """Entry count, file count, or depth cap exceeded."""


def _has_compiled_extension(name: str) -> bool:
    lower = name.lower()
    return any(lower.endswith(sfx) for sfx in COMPILED_EXTENSION_SUFFIXES)


def _has_local_dist_suffix(name: str) -> bool:
    lower = name.lower()
    return any(lower.endswith(sfx) for sfx in LOCAL_DIST_SUFFIXES)


def scan_built_artifacts(
    root_fd: int,
    *,
    build_directories: Sequence[str] | None = None,
) -> list[str]:
    """Scan candidate locations for locally built artifacts.

    Collects compiled extension modules (.so, .dylib, .pyd) and locally
    built distribution packages (.whl, or archives under dist/ or build/).
    Excludes installed artifacts whose wheel came from the package store
    by parsing installed-distribution RECORD files (.dist-info/RECORD).
    If build_directories is provided, limits traversal to those directories;
    otherwise scans the root tree (documented limitation: directory scope
    must be constrained or installed RECORD files present to avoid scanning
    the entire system rootfs).
    Every read and directory traversal is bounded by named constant caps.
    Symlinks on built artifact candidates are refused.
    """
    found: list[str] = []
    visited_files = 0
    installed_wheel_files: set[str] = set()

    def walk(current_fd: int, rel_prefix: str, depth: int) -> None:
        nonlocal visited_files
        if depth > MAX_SCAN_DEPTH:
            raise RecipeResourceLimitError(f"directory nesting exceeds cap of {MAX_SCAN_DEPTH}")
        names: list[str] = []
        with os.scandir(current_fd) as scanner:
            for count, entry in zip(range(MAX_SCAN_FILES + 1), scanner):
                if count >= MAX_SCAN_FILES:
                    raise RecipeResourceLimitError(f"directory entry cap of {MAX_SCAN_FILES} exceeded")
                names.append(entry.name)
        for name in sorted(names):
            if name in (".git", ".hg", ".svn"):
                continue
            child_rel = f"{rel_prefix}/{name}" if rel_prefix else name
            try:
                st = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            except OSError:
                raise RecipeSecurityError(f"cannot inspect {child_rel!r}") from None
            if stat.S_ISLNK(st.st_mode):
                if _has_compiled_extension(name) or name.lower().endswith(".whl"):
                    raise RecipeSecurityError(f"built artifact candidate {child_rel!r} is a symlink")
                continue
            if stat.S_ISDIR(st.st_mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=current_fd,
                )
                try:
                    if name.endswith((".dist-info", ".egg-info")):
                        # Parse installed distribution metadata to tie files to installed packages
                        for rec_name in ("RECORD", "installed-files.txt"):
                            try:
                                rec_st = os.stat(rec_name, dir_fd=child_fd, follow_symlinks=False)
                                if stat.S_ISREG(rec_st.st_mode) and rec_st.st_size <= MAX_BUILD_MANIFEST_BYTES:
                                    rec_fd = os.open(rec_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=child_fd)
                                    try:
                                        rec_bytes = os.read(rec_fd, MAX_BUILD_MANIFEST_BYTES + 1)
                                        if len(rec_bytes) <= MAX_BUILD_MANIFEST_BYTES:
                                            for line in rec_bytes.decode("utf-8", "replace").splitlines():
                                                if not line.strip():
                                                    continue
                                                member = line.split(",", 1)[0].strip().strip('"')
                                                if not member or member.startswith("/"):
                                                    continue
                                                prefix = f"{child_rel}" if rec_name == "installed-files.txt" else (f"{rel_prefix}" if rel_prefix else "")
                                                full_member = os.path.normpath(
                                                    f"{prefix}/{member}" if prefix else member
                                                )
                                                if not full_member.startswith("..") and not full_member.startswith("/"):
                                                    installed_wheel_files.add(full_member)
                                    finally:
                                        os.close(rec_fd)
                            except OSError:
                                pass
                        continue
                    walk(child_fd, child_rel, depth + 1)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(st.st_mode):
                visited_files += 1
                if visited_files > MAX_SCAN_FILES:
                    raise RecipeResourceLimitError(f"file count cap of {MAX_SCAN_FILES} exceeded")
                is_ext = _has_compiled_extension(name)
                is_whl = name.lower().endswith(".whl")
                is_dist = (
                    any(part in ("dist", "build", "target") for part in child_rel.split("/"))
                    and _has_local_dist_suffix(name)
                )
                if is_ext or is_whl or is_dist:
                    found.append(child_rel)
            else:
                raise RecipeSecurityError(f"special file {child_rel!r} refused")

    if build_directories is not None:
        for bdir in build_directories:
            try:
                bdir_rel = validate_member_path(bdir, is_dir=False)
            except HermeticD7Error as exc:
                raise RecipeSecurityError(f"build directory {bdir!r} is unsafe") from exc
            try:
                bdir_fd = _open_no_follow(root_fd, bdir_rel, directory=True)
            except FileNotFoundError:
                continue
            except SecurityViolationError as exc:
                raise RecipeSecurityError(f"build directory {bdir_rel!r} is unsafe") from exc
            except OSError:
                continue
            try:
                walk(bdir_fd, bdir_rel, 0)
            finally:
                os.close(bdir_fd)
    else:
        walk(root_fd, "", 0)

    return sorted(p for p in found if p not in installed_wheel_files)


def _safe_inspect_source_exists(root_fd: int, rel_source: str) -> bool:
    """Inspect source path components without following symlinks.

    Returns True if the source directory exists safely and is not a link.
    Returns False if the source directory is absent.
    Raises RecipeSecurityError if any component is a symlink or special file.
    """
    parts = rel_source.split("/")
    current = os.dup(root_fd)
    try:
        for idx, part in enumerate(parts):
            try:
                st = os.stat(part, dir_fd=current, follow_symlinks=False)
            except FileNotFoundError:
                return False
            except OSError as exc:
                raise RecipeSecurityError(f"cannot inspect source component {part!r}") from exc
            if stat.S_ISLNK(st.st_mode):
                raise RecipeSecurityError(f"source component {part!r} is a symlink")
            if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                raise RecipeSecurityError(f"source component {part!r} is a special file")
            if not stat.S_ISDIR(st.st_mode):
                return False
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=current,
            )
            os.close(current)
            current = next_fd
        return True
    finally:
        os.close(current)


def build_recipe(
    world_root: Path | str | None = None,
    *,
    build_manifest: Sequence[dict[str, Any]] | Path | str | None = None,
    entries: Sequence[RecipeEntry | dict[str, Any]] | None = None,
    unattributed: Sequence[str] | None = None,
) -> bytes:
    """Build canonical recipe mapping bytes for the given world root.

    For every artifact built from source in the task environment:
    - If provenance (id, artifact, source, builder, args) is verified and
      both artifact and source exist safely in the world: records a strict
      RecipeEntry in entries.
    - If provenance cannot be established (missing/unverifiable source,
      missing builder, or unlisted artifact found in the tree): records
      the artifact relative path in unattributed, never guessing.
    Hostile or symlinked inputs are refused with typed errors.
    """
    raw_manifest_entries: list[dict[str, Any]] = []
    raw_manifest_unattributed: list[str] = []
    raw_generated_files: list[str] = []
    raw_build_directories: list[str] = []

    root_fd: int | None = None
    if world_root is not None:
        root_path = Path(world_root)
        try:
            root_fd = os.open(root_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            raise RecipeSecurityError("world root is not a valid directory (links refused)") from exc

    try:
        # 1. Load build manifest from outside the world tree (in-world auto-discovery is forbidden)
        if isinstance(build_manifest, (str, Path)):
            manifest_path = Path(build_manifest)
            if manifest_path.is_symlink():
                raise RecipeSecurityError(f"build manifest {manifest_path!r} is a symlink")
            try:
                m_fd = hermetic_safe_io.open_regular(manifest_path, MAX_BUILD_MANIFEST_BYTES)
            except (hermetic_safe_io.UnsafePathError, ValueError) as exc:
                raise RecipeSecurityError(f"build manifest {manifest_path!r} is unsafe") from exc
            except FileNotFoundError as exc:
                raise RecipeFormatError(f"build manifest {manifest_path!r} not found") from exc
            except OSError as exc:
                raise RecipeFormatError(f"cannot open build manifest {manifest_path!r}") from exc
            try:
                data = os.read(m_fd, MAX_BUILD_MANIFEST_BYTES + 1)
                if len(data) > MAX_BUILD_MANIFEST_BYTES:
                    raise RecipeResourceLimitError("build manifest exceeds byte cap")
            finally:
                os.close(m_fd)
            try:
                parsed_manifest = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs)
            except (UnicodeDecodeError, ValueError, RecursionError) as exc:
                raise RecipeFormatError("build manifest is not valid UTF-8 JSON") from exc
            if isinstance(parsed_manifest, dict):
                raw_manifest_entries.extend(parsed_manifest.get("entries", []))
                raw_manifest_unattributed.extend(parsed_manifest.get("unattributed", []))
                raw_generated_files.extend(parsed_manifest.get("generated_files", []))
                raw_build_directories.extend(parsed_manifest.get("build_directories", []))
            elif isinstance(parsed_manifest, list):
                raw_manifest_entries.extend(parsed_manifest)
            else:
                raise RecipeFormatError("build manifest must be a JSON object or array")
        elif isinstance(build_manifest, dict):
            raw_manifest_entries.extend(build_manifest.get("entries", []))
            raw_manifest_unattributed.extend(build_manifest.get("unattributed", []))
            raw_generated_files.extend(build_manifest.get("generated_files", []))
            raw_build_directories.extend(build_manifest.get("build_directories", []))
        elif isinstance(build_manifest, Sequence):
            raw_manifest_entries.extend(build_manifest)
        elif build_manifest is not None:
            raise RecipeFormatError("build manifest must be a path, dict, or sequence")

        if entries is not None:
            for item in entries:
                if isinstance(item, RecipeEntry):
                    raw_manifest_entries.append(
                        {
                            "id": item.id,
                            "artifact": item.artifact,
                            "source": item.source,
                            "builder": item.builder,
                            "args": list(item.args),
                        }
                    )
                elif isinstance(item, dict):
                    raw_manifest_entries.append(item)
                else:
                    raise RecipeFormatError("entries must be RecipeEntry instances or dicts")

        if unattributed is not None:
            raw_manifest_unattributed.extend(unattributed)

        attributed_entries: dict[str, RecipeEntry] = {}
        unattributed_set: set[str] = set()

        # 2. Process candidate entries from build records
        if len(raw_manifest_entries) > MAX_RECIPE_ENTRIES:
            raise RecipeResourceLimitError(f"recipe entry count exceeds {MAX_RECIPE_ENTRIES}")

        for idx, raw in enumerate(raw_manifest_entries):
            if not isinstance(raw, dict):
                raise RecipeFormatError(f"recipe entry {idx} must be a dict")
            artifact_val = raw.get("artifact")
            if not isinstance(artifact_val, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in artifact_val):
                raise RecipeFormatError(f"recipe entry {idx} has invalid artifact path")
            try:
                art_rel = validate_member_path(artifact_val, is_dir=False)
            except HermeticD7Error as exc:
                raise RecipeSecurityError(f"entry artifact {artifact_val!r} is unsafe") from exc

            # Verify artifact exists and is not a link
            if root_fd is not None:
                try:
                    fd = _open_no_follow(root_fd, art_rel, directory=False)
                    os.close(fd)
                except FileNotFoundError as exc:
                    raise RecipeFormatError(f"artifact {art_rel!r} does not exist in world") from exc
                except SecurityViolationError as exc:
                    raise RecipeSecurityError(f"artifact {art_rel!r} is a symlink or special file") from exc
                except OSError as exc:
                    raise RecipeFormatError(f"artifact {art_rel!r} does not exist in world") from exc

            ident = raw.get("id")
            builder = raw.get("builder")
            args = raw.get("args")
            source_val = raw.get("source")

            if not isinstance(ident, str) or not _ID_RE.fullmatch(ident):
                raise RecipeFormatError(f"recipe entry {idx} has an invalid id")
            if not isinstance(builder, str) or not _BUILDER_RE.fullmatch(builder):
                raise RecipeFormatError(f"recipe entry {ident!r} has an invalid builder")
            if (
                not isinstance(args, list)
                or len(args) > MAX_ARGS
                or not all(
                    isinstance(a, str)
                    and "\x00" not in a
                    and len(a.encode("utf-8", "surrogatepass")) <= MAX_ARG_BYTES
                    and not any(0xD800 <= ord(c) <= 0xDFFF for c in a)
                    for a in args
                )
            ):
                raise RecipeFormatError(f"recipe entry {ident!r} has invalid args")

            if not isinstance(source_val, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in source_val):
                raise RecipeFormatError(f"recipe entry {ident!r} source must be a valid string")
            try:
                src_rel = validate_member_path(source_val, is_dir=False)
            except HermeticD7Error as exc:
                raise RecipeSecurityError(f"entry source {source_val!r} is unsafe") from exc

            # Check if source exists in the world root
            if root_fd is not None and not _safe_inspect_source_exists(root_fd, src_rel):
                # Source does not exist: provenance cannot be established, never guess
                unattributed_set.add(art_rel)
                continue

            if art_rel in attributed_entries:
                raise RecipeFormatError(f"duplicate recipe artifact {art_rel!r}")
            if any(e.id == ident for e in attributed_entries.values()):
                raise RecipeFormatError(f"duplicate recipe id {ident!r}")
            attributed_entries[art_rel] = RecipeEntry(ident, art_rel, src_rel, builder, tuple(args))

        # 3. Scan world root for built artifacts
        if root_fd is not None:
            scanned = scan_built_artifacts(
                root_fd,
                build_directories=raw_build_directories if raw_build_directories else None,
            )
            # Also include generated files listed by the build
            for gen in raw_generated_files:
                if not isinstance(gen, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in gen):
                    raise RecipeFormatError("generated file entry must be a valid string")
                try:
                    gen_rel = validate_member_path(gen, is_dir=False)
                except HermeticD7Error as exc:
                    raise RecipeSecurityError(f"generated file {gen!r} is unsafe") from exc
                try:
                    fd = _open_no_follow(root_fd, gen_rel, directory=False)
                    os.close(fd)
                    if gen_rel not in scanned:
                        scanned.append(gen_rel)
                except FileNotFoundError:
                    continue
                except SecurityViolationError as exc:
                    raise RecipeSecurityError(f"generated file {gen_rel!r} is a symlink") from exc
                except OSError:
                    continue

            for artifact_path in scanned:
                if artifact_path not in attributed_entries:
                    # Provenance not established: never guess, list in unattributed
                    unattributed_set.add(artifact_path)

        # 4. Process explicit unattributed paths
        for idx, item in enumerate(raw_manifest_unattributed):
            if not isinstance(item, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                raise RecipeFormatError(f"unattributed item {idx} must be a valid string")
            try:
                rel = validate_member_path(item, is_dir=False)
            except HermeticD7Error as exc:
                raise RecipeSecurityError(f"unattributed item {item!r} is unsafe") from exc
            if root_fd is not None:
                try:
                    fd = _open_no_follow(root_fd, rel, directory=False)
                    os.close(fd)
                except FileNotFoundError as exc:
                    raise RecipeFormatError(f"unattributed artifact {rel!r} does not exist in world") from exc
                except SecurityViolationError as exc:
                    raise RecipeSecurityError(f"unattributed artifact {rel!r} is a symlink") from exc
                except OSError as exc:
                    raise RecipeFormatError(f"unattributed artifact {rel!r} does not exist in world") from exc
            unattributed_set.add(rel)

        # Remove any attributed artifact from unattributed
        for art in attributed_entries:
            unattributed_set.discard(art)

        if len(attributed_entries) > MAX_RECIPE_ENTRIES:
            raise RecipeResourceLimitError(f"recipe entry count {len(attributed_entries)} exceeds {MAX_RECIPE_ENTRIES}")
        if len(unattributed_set) > MAX_UNATTRIBUTED_ENTRIES:
            raise RecipeResourceLimitError(f"unattributed count {len(unattributed_set)} exceeds {MAX_UNATTRIBUTED_ENTRIES}")

        sorted_entries = sorted(attributed_entries.values(), key=lambda e: (e.id, e.artifact))
        sorted_unattributed = sorted(unattributed_set)

        doc = {
            "entries": [
                {
                    "args": list(e.args),
                    "artifact": e.artifact,
                    "builder": e.builder,
                    "id": e.id,
                    "source": e.source,
                }
                for e in sorted_entries
            ],
            "schema": RECIPE_SCHEMA,
            "unattributed": sorted_unattributed,
        }

        data = (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(data) > MAX_RECIPE_BYTES:
            raise RecipeResourceLimitError("recipe exceeds byte cap")
        parse_recipe(data)
        return data
    finally:
        if root_fd is not None:
            os.close(root_fd)


def emit_recipe(
    world_root: Path | str,
    output_path: Path | str | None = None,
    *,
    build_manifest: Sequence[dict[str, Any]] | Path | str | None = None,
    entries: Sequence[RecipeEntry | dict[str, Any]] | None = None,
    unattributed: Sequence[str] | None = None,
) -> bytes:
    """Build and write d7-recipe.json with permissions 0600, refusing symlinks.

    Returns the canonical recipe bytes written.
    """
    data = build_recipe(
        world_root,
        build_manifest=build_manifest,
        entries=entries,
        unattributed=unattributed,
    )
    target = Path(output_path) if output_path is not None else Path(world_root) / "d7-recipe.json"
    try:
        hermetic_safe_io.atomic_write(target, data)
    except (hermetic_safe_io.UnsafePathError, ValueError) as exc:
        raise RecipeSecurityError(f"cannot open output file {target!r} safely") from exc
    except OSError as exc:
        raise RecipeError(f"failed to write {target!r}") from exc
    return data
