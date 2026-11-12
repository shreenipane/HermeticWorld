"""Hermetic file I/O helpers: no symlinks, regular files only, bounded reads, atomic writes."""

from __future__ import annotations

import errno
import os
import stat

from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.limits import (
    MAX_ATOMIC_TEMP_ATTEMPTS,
    MAX_READ_CHUNK_BYTES,
    MAX_SOURCE_BYTES,
)


def _validate_path_str(path: str | os.PathLike[str]) -> str:
    try:
        path_str = os.fspath(path)
    except TypeError as exc:
        raise FlowError("Invalid path type", code="INVALID_PATH") from exc
    if not isinstance(path_str, str) or not path_str or "\x00" in path_str:
        raise FlowError("Invalid file path", code="INVALID_PATH")
    return path_str


def read_regular_file_bounded(
    path: str | os.PathLike[str],
    max_bytes: int = MAX_SOURCE_BYTES,
) -> bytes:
    """Read a regular file without following symlinks, refusing FIFOs/devices, bounded by max_bytes."""
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise FlowError("Invalid byte limit", code="INVALID_LIMIT")
    if max_bytes > MAX_SOURCE_BYTES:
        raise FlowError("Requested byte limit exceeds maximum cap", code="INVALID_LIMIT")

    path_str = _validate_path_str(path)

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    try:
        fd = os.open(path_str, flags)
    except OSError as exc:
        raise FlowError("Unable to open regular input file", code="OPEN_ERROR") from exc

    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise FlowError("Unable to stat opened file descriptor", code="STAT_ERROR") from exc

        if not stat.S_ISREG(st.st_mode):
            raise FlowError("Input path is not a regular file", code="NOT_REGULAR_FILE")

        if st.st_size > max_bytes:
            raise FlowError(
                f"Input file exceeds maximum size of {max_bytes} bytes",
                code="SOURCE_TOO_LARGE",
            )

        chunks: list[bytes] = []
        total = 0
        max_iterations = (max_bytes // MAX_READ_CHUNK_BYTES) + 4

        for _ in range(max_iterations):
            remaining = (max_bytes + 1) - total
            if remaining <= 0:
                break
            to_read = min(MAX_READ_CHUNK_BYTES, remaining)
            try:
                chunk = os.read(fd, to_read)
            except OSError as exc:
                raise FlowError("Failed while reading input file", code="READ_ERROR") from exc
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise FlowError(
                    f"Input file exceeds maximum size of {max_bytes} bytes",
                    code="SOURCE_TOO_LARGE",
                )
            chunks.append(chunk)
        else:
            raise FlowError("Bounded read loop limit exceeded", code="READ_LIMIT_EXCEEDED")

        return b"".join(chunks)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def atomic_write_bytes(
    path: str | os.PathLike[str],
    data: bytes,
    max_bytes: int = MAX_SOURCE_BYTES,
) -> None:
    """Write bytes atomically via a same-directory temp file, fsync, and rename without following symlinks."""
    if not isinstance(data, bytes):
        raise FlowError("Data to write must be bytes", code="INVALID_TYPE")
    if len(data) > max_bytes:
        raise FlowError(
            f"Output data exceeds maximum size of {max_bytes} bytes",
            code="OUTPUT_TOO_LARGE",
        )

    path_str = _validate_path_str(path)
    parent_dir = os.path.dirname(path_str) or "."
    base_name = os.path.basename(path_str)
    if not base_name or base_name in {".", ".."}:
        raise FlowError("Target path must refer to a file name", code="INVALID_PATH")

    # Refuse symlink or non-regular existing destination without following links.
    try:
        existing_st = os.lstat(path_str)
    except FileNotFoundError:
        existing_st = None
    except OSError as exc:
        raise FlowError("Unable to inspect destination path", code="STAT_ERROR") from exc

    if existing_st is not None:
        if stat.S_ISLNK(existing_st.st_mode) or not stat.S_ISREG(existing_st.st_mode):
            raise FlowError(
                "Refusing to overwrite symlink or non-regular destination",
                code="UNSAFE_DESTINATION",
            )

    dir_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        dir_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        dir_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        dir_flags |= os.O_CLOEXEC

    try:
        dir_fd = os.open(parent_dir, dir_flags)
    except OSError as exc:
        raise FlowError("Unable to open destination directory", code="OPEN_DIR_ERROR") from exc

    try:
        tmp_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            tmp_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            tmp_flags |= os.O_CLOEXEC

        tmp_path: str | None = None
        tmp_fd: int | None = None

        for attempt in range(MAX_ATOMIC_TEMP_ATTEMPTS):
            candidate = os.path.join(parent_dir, f".{base_name}.tmp.{attempt:04d}")
            try:
                tmp_fd = os.open(candidate, tmp_flags, 0o600)
                tmp_path = candidate
                break
            except FileExistsError:
                continue
            except OSError as exc:
                if exc.errno == errno.EEXIST:
                    continue
                raise FlowError("Unable to create temporary file", code="TEMP_OPEN_ERROR") from exc

        if tmp_fd is None or tmp_path is None:
            raise FlowError("Exhausted temporary file creation attempts", code="TEMP_EXHAUSTED")

        try:
            view = memoryview(data)
            written = 0
            max_write_iters = (len(data) // MAX_READ_CHUNK_BYTES) + 4
            for _ in range(max_write_iters):
                if written >= len(data):
                    break
                end = min(written + MAX_READ_CHUNK_BYTES, len(data))
                try:
                    n = os.write(tmp_fd, view[written:end])
                except OSError as exc:
                    raise FlowError("Failed while writing temporary file", code="WRITE_ERROR") from exc
                if n <= 0:
                    raise FlowError("Zero-byte write on temporary file", code="WRITE_ERROR")
                written += n
            else:
                raise FlowError("Bounded write loop limit exceeded", code="WRITE_LIMIT_EXCEEDED")

            try:
                os.fsync(tmp_fd)
            except OSError as exc:
                raise FlowError("Failed to fsync temporary file", code="FSYNC_ERROR") from exc

            os.close(tmp_fd)
            tmp_fd = None

            try:
                os.replace(tmp_path, path_str)
                tmp_path = None
            except OSError as exc:
                raise FlowError("Failed to atomically rename temporary file", code="RENAME_ERROR") from exc

            try:
                os.fsync(dir_fd)
            except OSError:
                # Some filesystems do not support fsync on directory descriptors.
                pass
        finally:
            if tmp_fd is not None:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass
