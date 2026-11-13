"""Bounded descriptor-anchored file I/O for assertion analysis."""

from __future__ import annotations

import os

from hermetic_safe_io import UnsafePathError, atomic_write, open_regular, validate_path
from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.limits import MAX_READ_CHUNK_BYTES, MAX_SOURCE_BYTES


def _validate_path_str(path: str | os.PathLike[str]) -> str:
    try:
        raw, _ = validate_path(path)
        return raw
    except (TypeError, ValueError) as exc:
        raise FlowError("Invalid file path", code="INVALID_PATH") from exc


def _validate_limit(max_bytes: int) -> None:
    if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_SOURCE_BYTES:
        raise FlowError("Invalid byte limit", code="INVALID_LIMIT")


def read_regular_file_bounded(
    path: str | os.PathLike[str], max_bytes: int = MAX_SOURCE_BYTES,
) -> bytes:
    """Read only a pinned regular inode, with every path component inspected first."""
    _validate_limit(max_bytes)
    raw = _validate_path_str(path)
    try:
        fd = open_regular(raw, max_bytes)
        try:
            chunks: list[bytes] = []
            total = 0
            for _ in range(max_bytes + 2):
                chunk = os.read(fd, min(MAX_READ_CHUNK_BYTES, max_bytes + 1 - total))
                if not chunk:
                    return b"".join(chunks)
                total += len(chunk)
                if total > max_bytes:
                    raise FlowError("Input exceeds byte cap", code="SOURCE_TOO_LARGE")
                chunks.append(chunk)
            raise FlowError("Read iteration cap exceeded", code="READ_LIMIT_EXCEEDED")
        finally:
            os.close(fd)
    except OSError as exc:
        raise FlowError("Unable to read regular input file", code="OPEN_ERROR") from exc


def atomic_write_bytes(
    path: str | os.PathLike[str], data: bytes, max_bytes: int = MAX_SOURCE_BYTES,
) -> None:
    """Publish a private file using an inspected, pinned parent directory."""
    _validate_limit(max_bytes)
    if not isinstance(data, bytes):
        raise FlowError("Data must be bytes", code="INVALID_TYPE")
    if len(data) > max_bytes:
        raise FlowError("Output exceeds byte cap", code="OUTPUT_TOO_LARGE")
    raw = _validate_path_str(path)
    try:
        atomic_write(raw, data)
    except UnsafePathError as exc:
        raise FlowError("Unsafe destination", code="UNSAFE_DESTINATION") from exc
    except OSError as exc:
        raise FlowError("Unable to publish regular output file", code="WRITE_ERROR") from exc
