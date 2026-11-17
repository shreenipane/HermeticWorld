"""Descriptor-anchored regular-file I/O and symlink refusal for hermetic_pkgbase.

Files are opened without following symlinks and created with private permissions
(0600 for files, 0700 for directories; 0400/0500 when frozen).
All directory opens are anchored to parent descriptors with O_NOFOLLOW.
All reads and loops are bounded by named constants.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat

from hermetic_safe_io import (
    IO_CHUNK_BYTES,
    MAX_PATH_BYTES,
    MAX_PATH_COMPONENTS,
    UnsafePathError as BaseUnsafePathError,
    atomic_write_at,
    open_parent,
    open_regular_at,
    scandir,
    validate_path,
)
from .errors import StoreIOError, UnsafePathError

MAX_TEMP_ATTEMPTS: int = 256
MAX_DIR_ENTRIES: int = 100_000
MAX_WALK_DEPTH: int = 64

DIR_MODE: int = 0o700
FILE_MODE: int = 0o600
FROZEN_DIR_MODE: int = 0o500
FROZEN_FILE_MODE: int = 0o400

_DIR_FLAGS: int = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def validate_path_components(path: str | os.PathLike[str]) -> tuple[str, list[str]]:
    """Validate path syntax, length, and reject null bytes or parent traversal."""
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw:
        raise UnsafePathError("Invalid empty path.")
    if len(raw) > MAX_PATH_BYTES or "\x00" in raw:
        raise UnsafePathError("Path exceeds byte limit or contains null byte.")
    try:
        encoded = os.fsencode(raw)
        if len(encoded) > MAX_PATH_BYTES:
            raise UnsafePathError("Path encoded length exceeds byte limit.")
    except UnicodeError as exc:
        raise UnsafePathError("Path cannot be encoded.") from exc

    parts = [part for part in raw.split("/") if part not in ("", ".")]
    if len(parts) > MAX_PATH_COMPONENTS:
        raise UnsafePathError("Path exceeds maximum component count.")
    if ".." in parts:
        raise UnsafePathError("Path traversal ('..') is refused.")
    return raw, parts


def safe_read_bytes(path: str | os.PathLike[str], max_bytes: int) -> bytes:
    """Read a regular file safely without following any symlinks, bounded by max_bytes."""
    validate_path_components(path)
    directory = -1
    try:
        try:
            directory, leaf = open_parent(path)
        except (BaseUnsafePathError, ValueError) as exc:
            raise UnsafePathError(f"Unsafe path: {path}") from exc
        except FileNotFoundError as exc:
            raise StoreIOError(f"File not found: {path}") from exc
        except OSError as exc:
            raise StoreIOError(f"Error opening parent: {exc}") from exc

        try:
            fd = open_regular_at(directory, leaf, max_bytes)
        except BaseUnsafePathError as exc:
            raise UnsafePathError(f"Unsafe file: {exc}") from exc
        except FileNotFoundError as exc:
            raise StoreIOError(f"File not found: {path}") from exc
        except OSError as exc:
            raise StoreIOError(f"Failed to open regular file: {exc}") from exc

        try:
            chunks: list[bytes] = []
            total = 0
            max_chunks = (max_bytes // IO_CHUNK_BYTES) + 2
            for _ in range(max_chunks):
                chunk = os.read(fd, IO_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise StoreIOError(f"File exceeded cap {max_bytes} during read")
                chunks.append(chunk)
            else:
                raise StoreIOError("Read loop bounded iteration limit exceeded")
            return b"".join(chunks)
        except OSError as exc:
            raise StoreIOError(f"Failed reading file: {exc}") from exc
        finally:
            os.close(fd)
    finally:
        if directory >= 0:
            os.close(directory)


def safe_open_dir(path: str | os.PathLike[str], mode: int = DIR_MODE) -> int:
    """Ensure directory exists without traversing or creating through symlinks and return open fd.

    Every directory component is opened relative to its parent with O_NOFOLLOW.
    Caller is responsible for closing the returned file descriptor.
    """
    raw, parts = validate_path_components(path)
    is_abs = raw.startswith("/")

    try:
        current_fd = os.open("/" if is_abs else ".", _DIR_FLAGS)
    except OSError as exc:
        raise StoreIOError(f"Failed to open root directory: {exc}") from exc

    try:
        for part in parts:
            try:
                os.mkdir(part, mode, dir_fd=current_fd)
            except FileExistsError:
                pass
            except OSError as exc:
                raise StoreIOError(f"Failed creating directory component {part}: {exc}") from exc

            try:
                next_fd = os.open(part, _DIR_FLAGS, dir_fd=current_fd)
            except OSError as exc:
                raise UnsafePathError(f"Refusing unsafe or symlink directory component {part}: {exc}") from exc

            st = os.fstat(next_fd)
            if not stat.S_ISDIR(st.st_mode):
                os.close(next_fd)
                raise UnsafePathError(f"Path component {part} is not a directory")

            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def safe_ensure_dir(path: str | os.PathLike[str], mode: int = DIR_MODE) -> Path:
    """Ensure directory exists without traversing or creating through symlinks.

    Every directory component is opened relative to its parent with O_NOFOLLOW.
    """
    raw, _ = validate_path_components(path)
    fd = safe_open_dir(raw, mode=mode)
    os.close(fd)
    return Path(raw)


def safe_write_file(path: str | os.PathLike[str], data: bytes, mode: int = FILE_MODE) -> None:
    """Safely and atomically write data to a file with private permissions (0600).

    Uses descriptor-anchored open_parent and atomic_write_at.
    """
    raw, parts = validate_path_components(path)
    if not parts:
        raise UnsafePathError("Invalid path for file write.")

    target = Path(raw)
    parent_dir = target.parent
    safe_ensure_dir(parent_dir, mode=DIR_MODE)

    directory = -1
    try:
        try:
            directory, leaf = open_parent(raw)
        except (BaseUnsafePathError, ValueError) as exc:
            raise UnsafePathError(f"Unsafe path for write: {exc}") from exc
        except OSError as exc:
            raise StoreIOError(f"Failed to open parent directory: {exc}") from exc

        try:
            atomic_write_at(directory, leaf, data)
            if mode != 0o600:
                try:
                    os.chmod(leaf, mode, dir_fd=directory, follow_symlinks=False)
                except OSError as exc:
                    raise StoreIOError(f"Failed setting mode {oct(mode)}: {exc}") from exc
        except BaseUnsafePathError as exc:
            raise UnsafePathError(f"Unsafe destination: {exc}") from exc
        except OSError as exc:
            raise StoreIOError(f"Failed atomic write: {exc}") from exc
    finally:
        if directory >= 0:
            os.close(directory)


def _freeze_dir_fd(dir_fd: int, depth: int) -> None:
    if depth > MAX_WALK_DEPTH:
        raise StoreIOError("Depth cap exceeded during tree freeze.")

    subdirs: list[str] = []
    with os.scandir(dir_fd) as entries:
        entry_count = 0
        for entry in entries:
            entry_count += 1
            if entry_count > MAX_DIR_ENTRIES:
                raise StoreIOError("Directory entry cap exceeded during tree freeze.")
            if entry.is_symlink():
                raise UnsafePathError(f"Refusing symlink encountered during freeze: {entry.name}")
            if entry.is_file(follow_symlinks=False):
                try:
                    os.chmod(entry.name, FROZEN_FILE_MODE, dir_fd=dir_fd, follow_symlinks=False)
                except OSError as exc:
                    raise StoreIOError(f"Failed setting file mode for {entry.name}: {exc}") from exc
            elif entry.is_dir(follow_symlinks=False):
                subdirs.append(entry.name)
            else:
                raise UnsafePathError(f"Refusing non-regular file encountered during freeze: {entry.name}")

    for subdir in subdirs:
        child_fd = -1
        try:
            child_fd = os.open(subdir, _DIR_FLAGS, dir_fd=dir_fd)
        except OSError as exc:
            raise UnsafePathError(f"Failed opening directory {subdir}: {exc}") from exc
        try:
            _freeze_dir_fd(child_fd, depth + 1)
        finally:
            os.close(child_fd)

    try:
        os.fchmod(dir_fd, FROZEN_DIR_MODE)
    except OSError as exc:
        raise StoreIOError(f"Failed setting directory mode: {exc}") from exc


def freeze_directory_tree(root: str | os.PathLike[str]) -> None:
    """Recursively set files to 0400 (read-only) and directories to 0500 (read+exec).

    All directories are opened relative to parents with O_NOFOLLOW.
    Symlinks are strictly refused.
    """
    raw, _ = validate_path_components(root)
    root_fd = safe_open_dir(raw)
    try:
        _freeze_dir_fd(root_fd, depth=0)
    finally:
        os.close(root_fd)
