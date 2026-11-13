
"""Deterministic directory hashing and manifest generation for Hermetic World E7."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import hermetic_safe_io

# Named constant caps bounding every read and loop.
READ_CHUNK_BYTES: int = 65_536
MAX_FILE_BYTES: int = 256 * 1024 * 1024
MAX_FILE_READ_CHUNKS: int = (MAX_FILE_BYTES // READ_CHUNK_BYTES) + 2
MAX_TREE_ENTRIES: int = 100_000
MAX_DIR_CHILDREN: int = 50_000
MAX_TREE_DEPTH: int = 64
MAX_PATH_BYTES: int = 4_096


class HermeticError(Exception):
    """Base typed error for all Hermetic World E7 failures."""


class WorldPathError(HermeticError):
    """Raised when a world root or entry path does not exist or cannot be accessed."""

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"Invalid world path '{path}': {reason}")


class UnsupportedEntryError(HermeticError):
    """Raised when encountering symlinks, hard links, devices, FIFOs, or sockets."""

    def __init__(self, path: str, entry_kind: str) -> None:
        self.path = path
        self.entry_kind = entry_kind
        super().__init__(f"Refused unsupported {entry_kind} at '{path}'")


class CapExceededError(HermeticError):
    """Raised when a safety bound on file size, entry count, or depth is exceeded."""

    def __init__(self, cap_name: str, limit: int, path: str | None = None) -> None:
        self.cap_name = cap_name
        self.limit = limit
        self.path = path
        loc = f" at '{path}'" if path else ""
        super().__init__(f"Safety cap {cap_name} ({limit}) exceeded{loc}")


def _classify_unsupported_mode(mode: int) -> str | None:
    """Return a descriptive kind if mode is not a regular file or directory."""
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "FIFO"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode):
        return "block device"
    if stat.S_ISCHR(mode):
        return "character device"
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        return "special file"
    return None


def _lstat_checked(full_path: Path, display_path: str) -> os.stat_result:
    """Perform lstat without following symlinks and translate OS errors."""
    try:
        return os.lstat(full_path)
    except OSError as exc:
        raise WorldPathError(display_path, exc.strerror or str(exc)) from exc


def open_regular_no_follow(full_path: Path, rel_path: str) -> int:
    """Open a regular file with every path component opened no-follow and non-blocking.

    A component replaced by a symlink, or the file replaced by a FIFO, after the
    caller's lstat is refused instead of being followed or blocking.
    """
    try:
        return hermetic_safe_io.open_regular(full_path, sys.maxsize)
    except hermetic_safe_io.UnsafePathError as exc:
        raise UnsupportedEntryError(rel_path, "symlink or non-regular file") from exc
    except ValueError as exc:
        raise WorldPathError(rel_path, "invalid path") from exc
    except OSError as exc:
        raise WorldPathError(rel_path, exc.strerror or type(exc).__name__) from exc


def _hash_regular_file(full_path: Path, rel_path: str) -> tuple[str, int]:
    """Compute SHA-256 and byte size of a regular file without following symlinks."""
    fd = open_regular_no_follow(full_path, rel_path)

    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise WorldPathError(rel_path, exc.strerror or str(exc)) from exc

        bad_kind = _classify_unsupported_mode(st.st_mode)
        if bad_kind is not None:
            raise UnsupportedEntryError(rel_path, bad_kind)
        if not stat.S_ISREG(st.st_mode):
            raise UnsupportedEntryError(rel_path, "non-regular file")
        if st.st_nlink > 1:
            raise UnsupportedEntryError(rel_path, "hard link")
        if st.st_size > MAX_FILE_BYTES:
            raise CapExceededError("MAX_FILE_BYTES", MAX_FILE_BYTES, rel_path)

        hasher = hashlib.sha256()
        total_bytes = 0
        for _ in range(MAX_FILE_READ_CHUNKS):
            try:
                chunk = os.read(fd, READ_CHUNK_BYTES)
            except OSError as exc:
                raise WorldPathError(rel_path, exc.strerror or str(exc)) from exc
            if not chunk:
                if total_bytes != st.st_size:
                    raise WorldPathError(rel_path, "file changed size while being hashed")
                return hasher.hexdigest(), total_bytes
            total_bytes += len(chunk)
            if total_bytes > MAX_FILE_BYTES:
                raise CapExceededError("MAX_FILE_BYTES", MAX_FILE_BYTES, rel_path)
            hasher.update(chunk)

        raise CapExceededError("MAX_FILE_READ_CHUNKS", MAX_FILE_READ_CHUNKS, rel_path)
    finally:
        os.close(fd)


def canonical_manifest_bytes(manifest_body: dict[str, Any]) -> bytes:
    """Serialize manifest body as canonical JSON (sorted keys, no spaces) in UTF-8."""
    return json.dumps(
        manifest_body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def build_manifest(root_dir: str | Path) -> dict[str, Any]:
    """Seal a world directory into a deterministic manifest with canonical SHA-256 root."""
    root_path = Path(root_dir)
    root_display = str(root_dir)
    root_stat = _lstat_checked(root_path, root_display)

    bad_root = _classify_unsupported_mode(root_stat.st_mode)
    if bad_root is not None:
        raise UnsupportedEntryError(root_display, bad_root)
    if not stat.S_ISDIR(root_stat.st_mode):
        raise WorldPathError(root_display, "root path is not a directory")

    entries: list[dict[str, Any]] = []
    seen_inodes: set[tuple[int, int]] = {(root_stat.st_dev, root_stat.st_ino)}
    stack: list[tuple[Path, str, int]] = [(root_path, "", 0)]

    for _ in range(MAX_TREE_ENTRIES + 1):
        if not stack:
            break
        current_dir, rel_prefix, depth = stack.pop()
        if depth > MAX_TREE_DEPTH:
            raise CapExceededError("MAX_TREE_DEPTH", MAX_TREE_DEPTH, rel_prefix or root_display)

        try:
            with os.scandir(current_dir) as it:
                raw_names: list[str] = []
                for idx, dir_entry in enumerate(it):
                    if idx >= MAX_DIR_CHILDREN:
                        raise CapExceededError(
                            "MAX_DIR_CHILDREN",
                            MAX_DIR_CHILDREN,
                            rel_prefix or root_display,
                        )
                    raw_names.append(dir_entry.name)
        except HermeticError:
            raise
        except OSError as exc:
            raise WorldPathError(rel_prefix or root_display, exc.strerror or str(exc)) from exc

        raw_names.sort(key=lambda name: name.encode("utf-8", errors="surrogateescape"))

        child_dirs: list[tuple[Path, str, int]] = []
        for name in raw_names:
            if len(entries) >= MAX_TREE_ENTRIES:
                raise CapExceededError("MAX_TREE_ENTRIES", MAX_TREE_ENTRIES, rel_prefix or root_display)

            rel_path = f"{rel_prefix}/{name}" if rel_prefix else name
            try:
                rel_bytes = rel_path.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise WorldPathError(rel_path, "path is not valid UTF-8") from exc

            if len(rel_bytes) > MAX_PATH_BYTES:
                raise CapExceededError("MAX_PATH_BYTES", MAX_PATH_BYTES, rel_path)

            full_path = current_dir / name
            st = _lstat_checked(full_path, rel_path)
            bad_kind = _classify_unsupported_mode(st.st_mode)
            if bad_kind is not None:
                raise UnsupportedEntryError(rel_path, bad_kind)

            inode_key = (st.st_dev, st.st_ino)
            if stat.S_ISDIR(st.st_mode):
                if inode_key in seen_inodes:
                    raise UnsupportedEntryError(rel_path, "hard-linked directory")
                seen_inodes.add(inode_key)
                entries.append({"path": rel_path, "type": "dir"})
                child_dirs.append((full_path, rel_path, depth + 1))
            elif stat.S_ISREG(st.st_mode):
                if st.st_nlink > 1 or inode_key in seen_inodes:
                    raise UnsupportedEntryError(rel_path, "hard link")
                seen_inodes.add(inode_key)
                digest, size = _hash_regular_file(full_path, rel_path)
                entries.append(
                    {
                        "executable": bool(st.st_mode & 0o111),
                        "path": rel_path,
                        "sha256": digest,
                        "size": size,
                        "type": "file",
                    }
                )
            else:
                raise UnsupportedEntryError(rel_path, "special file")

        for item in reversed(child_dirs):
            stack.append(item)
    else:
        raise CapExceededError("MAX_TREE_ENTRIES", MAX_TREE_ENTRIES, root_display)

    entries.sort(key=lambda item: item["path"].encode("utf-8"))
    manifest_body: dict[str, Any] = {"entries": entries}
    root_hash = hashlib.sha256(canonical_manifest_bytes(manifest_body)).hexdigest()
    return {
        "entries": entries,
        "root": root_hash,
    }


