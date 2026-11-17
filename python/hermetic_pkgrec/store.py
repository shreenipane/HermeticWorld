"""Content-addressed filesystem store compatible with hermetic_pkgindex."""

from __future__ import annotations

from collections.abc import Iterator
import hashlib
import hmac
import os
from pathlib import Path
import stat
import sys

from hermetic_pkgrec.constants import (
    FILE_CHUNK_BYTES,
    MAX_DIST_FILE_BYTES,
    MAX_TEMP_ATTEMPTS,
)
from hermetic_pkgrec.errors import (
    HashMismatchError,
    OversizeFileError,
    PathTraversalError,
    StoreError,
    SymlinkError,
)
from hermetic_pkgrec.filter import validate_filename, validate_sha256
import hermetic_safe_io


def _ensure_dir_nofollow(dir_path: Path) -> None:
    """Recursively create directories with mode 0700 refusing symlinks."""
    parts = dir_path.resolve().parts
    current = Path(parts[0])
    for part in parts[1:]:
        current = current / part
        try:
            st = os.lstat(current)
            if stat.S_ISLNK(st.st_mode):
                raise SymlinkError(f"Refusing symlink directory: {current.name}")
            if not stat.S_ISDIR(st.st_mode):
                raise StoreError(f"Path component is not a directory: {current.name}")
        except FileNotFoundError:
            current.mkdir(mode=0o700, exist_ok=True)
            # Ensure permissions are private.
            os.chmod(current, 0o700)


class RecordingStore:
    """Content-addressed distribution store compatible with hermetic_pkgindex layout."""

    def __init__(
        self,
        store_dir: str | Path,
        *,
        max_dist_bytes: int = MAX_DIST_FILE_BYTES,
    ) -> None:
        self.root = Path(store_dir).resolve()
        self.max_dist_bytes = max_dist_bytes
        self.files_root = self.root / "files"
        _ensure_dir_nofollow(self.files_root)

    def file_path(self, sha256: str, filename: str) -> Path:
        valid_sha = validate_sha256(sha256)
        valid_name = validate_filename(filename)
        return self.files_root / valid_sha / valid_name

    def has_file(self, sha256: str, filename: str) -> bool:
        """Check if file exists as a verified regular file inside the store."""
        target = self.file_path(sha256, filename)
        try:
            st = os.lstat(target)
            if stat.S_ISLNK(st.st_mode):
                raise SymlinkError("Refusing symlink file in store.")
            return stat.S_ISREG(st.st_mode) and st.st_size <= self.max_dist_bytes
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise StoreError(f"Failed to inspect store file: {exc}") from exc

    def open_file_for_reading(self, sha256: str, filename: str) -> int:
        """Open an inspected regular file descriptor without following symlinks."""
        target = self.file_path(sha256, filename)
        try:
            return hermetic_safe_io.open_regular(target, self.max_dist_bytes)
        except hermetic_safe_io.UnsafePathError as exc:
            raise SymlinkError("Refusing symlink or unsafe path in store.") from exc
        except (ValueError, OSError) as exc:
            raise StoreError(f"Failed opening store file: {exc}") from exc

    def iter_file(self, sha256: str, filename: str) -> Iterator[bytes]:
        """Stream chunks from an existing regular file in the store."""
        fd = self.open_file_for_reading(sha256, filename)
        try:
            max_loops = (self.max_dist_bytes // FILE_CHUNK_BYTES) + 2
            for _ in range(max_loops):
                chunk = os.read(fd, FILE_CHUNK_BYTES)
                if not chunk:
                    break
                yield chunk
        finally:
            os.close(fd)

    def save_file_stream(
        self,
        sha256: str,
        filename: str,
        stream: Iterator[bytes],
    ) -> Path:
        """Stream bytes into a verified content-addressed store location atomically."""
        valid_sha = validate_sha256(sha256)
        valid_name = validate_filename(filename)

        sha_dir = self.files_root / valid_sha
        _ensure_dir_nofollow(sha_dir)
        final_path = sha_dir / valid_name

        # If already exists and valid, skip re-download.
        if self.has_file(valid_sha, valid_name):
            return final_path

        # Open directory descriptor to ensure no-follow atomic replacement.
        dir_fd = os.open(
            sha_dir,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            tmp_name: str | None = None
            tmp_fd: int | None = None
            for attempt in range(MAX_TEMP_ATTEMPTS):
                cand = f".tmp.rec.{valid_sha[:8]}.{attempt}"
                try:
                    tmp_fd = os.open(
                        cand,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600,
                        dir_fd=dir_fd,
                    )
                    tmp_name = cand
                    break
                except FileExistsError:
                    continue
                except OSError as exc:
                    raise StoreError(f"Failed creating temp file: {exc}") from exc

            if tmp_fd is None or tmp_name is None:
                raise StoreError("Exhausted temporary file creation attempts in store.")

            hasher = hashlib.sha256()
            total_bytes = 0

            try:
                for chunk in stream:
                    total_bytes += len(chunk)
                    if total_bytes > self.max_dist_bytes:
                        raise OversizeFileError(
                            f"File {valid_name} exceeded max byte cap ({self.max_dist_bytes})."
                        )
                    hasher.update(chunk)

                    view = memoryview(chunk)
                    offset = 0
                    max_loops = (len(chunk) // FILE_CHUNK_BYTES) + 2
                    for _ in range(max_loops):
                        if offset >= len(chunk):
                            break
                        written = os.write(tmp_fd, view[offset : offset + FILE_CHUNK_BYTES])
                        if written <= 0:
                            raise StoreError("Zero bytes written to temporary file.")
                        offset += written

                os.fsync(tmp_fd)
                os.close(tmp_fd)
                tmp_fd = None

                actual_sha = hasher.hexdigest().lower()
                if not hmac.compare_digest(actual_sha, valid_sha):
                    # Hash mismatch! Remove temporary file and refuse.
                    try:
                        os.unlink(tmp_name, dir_fd=dir_fd)
                        tmp_name = None
                    except OSError:
                        pass
                    raise HashMismatchError(
                        f"Hash mismatch for {valid_name}: expected {valid_sha}, computed {actual_sha}."
                    )

                # Atomically replace destination.
                os.replace(tmp_name, valid_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                tmp_name = None
                os.fsync(dir_fd)
                return final_path

            finally:
                if tmp_fd is not None:
                    try:
                        os.close(tmp_fd)
                    except OSError:
                        pass
                if tmp_name is not None:
                    try:
                        os.unlink(tmp_name, dir_fd=dir_fd)
                    except OSError:
                        pass
        finally:
            os.close(dir_fd)
