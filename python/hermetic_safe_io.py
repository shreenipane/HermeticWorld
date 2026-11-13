"""Linux descriptor-anchored regular-file I/O shared by grading tools."""

from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass

MAX_PATH_BYTES = 4096
MAX_PATH_COMPONENTS = 256
MAX_TEMP_ATTEMPTS = 256
IO_CHUNK_BYTES = 65536


class UnsafePathError(OSError):
    """A path names an unsupported object or changed during inspection."""


def validate_path(path: str | os.PathLike[str]) -> tuple[str, list[str]]:
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or len(raw) > MAX_PATH_BYTES or "\0" in raw:
        raise ValueError("Invalid path")
    try:
        size = len(os.fsencode(raw))
    except UnicodeError as exc:
        raise ValueError("Invalid path") from exc
    parts = [part for part in raw.split("/") if part not in ("", ".")]
    if size > MAX_PATH_BYTES or len(parts) > MAX_PATH_COMPONENTS or ".." in parts:
        raise ValueError("Invalid path")
    if not parts or raw.endswith("/") or raw.split("/")[-1] == ".":
        raise ValueError("Invalid file path")
    return raw, parts


def _same_object(before: os.stat_result, after: os.stat_result) -> bool:
    return (before.st_dev, before.st_ino, before.st_mode) == (
        after.st_dev, after.st_ino, after.st_mode
    )


def open_parent(path: str | os.PathLike[str]) -> tuple[int, str]:
    raw, parts = validate_path(path)
    if not all(hasattr(os, name) for name in ("O_PATH", "O_NOFOLLOW", "O_DIRECTORY")):
        raise UnsafePathError("Safe path handles unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/" if raw.startswith("/") else ".", flags)
    try:
        for part in parts[:-1]:
            before = os.stat(part, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise UnsafePathError("Unsafe directory component")
            child = os.open(part, flags, dir_fd=directory)
            try:
                if not _same_object(before, os.fstat(child)):
                    raise UnsafePathError("Directory changed during inspection")
            except BaseException:
                os.close(child)
                raise
            os.close(directory)
            directory = child
        return directory, parts[-1]
    except BaseException:
        os.close(directory)
        raise


def open_regular(path: str | os.PathLike[str], max_bytes: int) -> int:
    directory, leaf = open_parent(path)
    pinned = None
    readable = None
    try:
        before = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise UnsafePathError("Input is not a regular file")
        pinned = os.open(leaf, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        inspected = os.fstat(pinned)
        if not stat.S_ISREG(inspected.st_mode) or not _same_object(before, inspected):
            raise UnsafePathError("Input changed during inspection")
        if inspected.st_size > max_bytes:
            raise UnsafePathError("Input exceeds byte cap")
        # This kernel-owned magic link references the pinned inode, never the supplied path.
        readable = os.open(f"/proc/self/fd/{pinned}", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        if not _same_object(inspected, os.fstat(readable)):
            raise UnsafePathError("Input handle changed")
        result = readable
        readable = None
        return result
    finally:
        if readable is not None:
            os.close(readable)
        if pinned is not None:
            os.close(pinned)
        os.close(directory)


@contextmanager
def scandir(path: str | os.PathLike[str]):
    """List a pinned directory; never follow a supplied symlink component."""
    directory, _ = open_parent(os.path.join(os.fspath(path), ".directory-probe"))
    try:
        with os.scandir(directory) as entries:
            yield (_DirectoryEntry(entry.name, entry.stat(follow_symlinks=False)) for entry in entries)
    finally:
        os.close(directory)


@dataclass(frozen=True)
class _DirectoryEntry:
    """Metadata captured while its parent descriptor is still alive."""

    name: str
    metadata: os.stat_result

    @property
    def path(self) -> str:
        return self.name

    def stat(self, *, follow_symlinks: bool = False) -> os.stat_result:
        if follow_symlinks:
            raise UnsafePathError("Symlink following is unavailable")
        return self.metadata

    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.metadata.st_mode)


def atomic_write(path: str | os.PathLike[str], data: bytes) -> None:
    directory, leaf = open_parent(path)
    temporary = None
    descriptor = None
    try:
        try:
            existing = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise UnsafePathError("Destination is not a regular file")
        for attempt in range(MAX_TEMP_ATTEMPTS):
            candidate = f".tmp.hermetic.{attempt}"
            if candidate == leaf:
                continue
            try:
                descriptor = os.open(
                    candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=directory,
                )
            except FileExistsError:
                continue
            temporary = candidate
            break
        if descriptor is None:
            raise UnsafePathError("Temporary file attempts exhausted")
        view = memoryview(data)
        offset = 0
        # Each successful iteration advances at least one byte, even on a short write.
        for _ in range(len(data) + 1):
            if offset == len(data):
                break
            count = os.write(descriptor, view[offset:offset + IO_CHUNK_BYTES])
            if count <= 0:
                raise OSError("Write made no progress")
            offset += count
        os.fsync(descriptor)
        os.replace(temporary, leaf, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None
        os.fsync(directory)
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            try:
                if temporary is not None:
                    os.unlink(temporary, dir_fd=directory)
            finally:
                os.close(directory)
