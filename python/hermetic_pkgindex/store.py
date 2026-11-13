
"""Filesystem-backed frozen package store and atomic miss log."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
import hashlib
import hmac
import html
import json
import logging
import os
from pathlib import Path
import re
import stat
import sys
import threading
from typing import Any

import hermetic_safe_io

logger = logging.getLogger("hermetic_pkgindex.store")

# Named caps bounding all filesystem reads, directory scans, and log sizes.
MAX_PROJECT_NAME_BYTES: int = 256
MAX_FILENAME_BYTES: int = 255
MAX_JSON_FILE_BYTES: int = 10 * 1024 * 1024  # 10 MiB
MAX_DIST_FILE_BYTES: int = 512 * 1024 * 1024  # 512 MiB
FILE_CHUNK_BYTES: int = 65536  # 64 KiB
MAX_DIR_ENTRIES: int = 100_000
MAX_MISS_LOG_BYTES: int = 10 * 1024 * 1024  # 10 MiB
SHA256_HEX_LEN: int = 64

_PEP503_NORMALIZE_RE = re.compile(r"[-_.]+")
_PEP508_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class PkgIndexError(Exception):
    """Base typed exception for all hermetic_pkgindex errors."""


class InvalidNameError(PkgIndexError):
    """Raised when a project name, hash, or filename violates format rules."""


class PathTraversalError(PkgIndexError):
    """Raised when a path attempts traversal or escapes the store root."""


class SymlinkError(PkgIndexError):
    """Raised when a symbolic link is encountered inside a managed path."""


class NotFoundMissError(PkgIndexError):
    """Raised when a requested project or file does not exist in the store."""


class IntegrityError(PkgIndexError):
    """Raised when stored metadata or file content fails integrity verification."""


class StoreLimitError(PkgIndexError):
    """Raised when a stored object exceeds a configured size or entry cap."""


class MissLogError(PkgIndexError):
    """Raised when the miss log cannot be safely read or updated."""


@dataclass(frozen=True, slots=True)
class ProjectPage:
    """Rendered PEP 691 JSON and PEP 503 HTML representations for a project."""

    name: str
    json_bytes: bytes
    html_bytes: bytes


@dataclass(frozen=True, slots=True)
class VerifiedFile:
    """Metadata for a regular distribution file whose SHA-256 has been verified."""

    path: Path
    sha256: str
    filename: str
    size: int
    content_type: str
    # Identity of the inode whose digest was verified; streaming refuses any other.
    identity: tuple[int, int, int, int] = (0, 0, 0, 0)


def normalize_project_name(name: str) -> str:
    """Validate and normalize a project name according to PEP 503."""
    if not isinstance(name, str) or not name:
        raise InvalidNameError("Project name must be a non-empty string.")
    encoded = name.encode("utf-8")
    if len(encoded) > MAX_PROJECT_NAME_BYTES:
        raise InvalidNameError("Project name exceeds maximum byte length.")
    if not _PEP508_NAME_RE.match(name):
        raise InvalidNameError(f"Invalid project name: {name!r}")
    return _PEP503_NORMALIZE_RE.sub("-", name).lower()


def validate_sha256(sha256: str) -> str:
    """Validate a lowercase 64-character hexadecimal SHA-256 digest."""
    if not isinstance(sha256, str) or not _SHA256_HEX_RE.match(sha256):
        raise InvalidNameError(f"Invalid SHA-256 digest: {sha256!r}")
    return sha256


def validate_filename(filename: str) -> str:
    """Validate a single distribution filename segment."""
    if not isinstance(filename, str) or not filename:
        raise InvalidNameError("Filename must be a non-empty string.")
    if len(filename.encode("utf-8")) > MAX_FILENAME_BYTES:
        raise InvalidNameError("Filename exceeds maximum byte length.")
    if filename in (".", "..") or "/" in filename or "\\" in filename or "\x00" in filename:
        raise InvalidNameError(f"Unsafe filename: {filename!r}")
    return filename


def _content_type_for_filename(filename: str) -> str:
    """Deterministically determine Content-Type without reading host MIME tables."""
    lower = filename.lower()
    if lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        return "application/gzip"
    if lower.endswith(".zip"):
        return "application/zip"
    return "application/octet-stream"


def render_root_json(projects: list[str]) -> bytes:
    """Render PEP 691 JSON for the /simple/ project list."""
    payload = {
        "meta": {"api-version": "1.0"},
        "projects": [{"name": name} for name in projects],
    }
    return (json.dumps(payload, indent=2, sort_keys=False) + "\n").encode("utf-8")


def render_root_html(projects: list[str]) -> bytes:
    """Render PEP 503 HTML for the /simple/ project list."""
    lines = [
        "<!DOCTYPE html>",
        "<html>",
        "  <head>",
        '    <meta name="pypi:repository-version" content="1.0">',
        "    <title>Simple Index</title>",
        "  </head>",
        "  <body>",
    ]
    for name in projects:
        escaped = html.escape(name, quote=True)
        lines.append(f'    <a href="/simple/{escaped}/">{escaped}</a>')
    lines.extend(["  </body>", "</html>", ""])
    return "\n".join(lines).encode("utf-8")


def render_project_html(project_name: str, payload: dict[str, Any]) -> bytes:
    """Render PEP 503 HTML from a parsed PEP 691 project index.json dict."""
    files = payload.get("files", [])
    if not isinstance(files, list):
        raise IntegrityError(f"Invalid 'files' list in index.json for {project_name!r}")

    escaped_title = html.escape(project_name, quote=True)
    lines = [
        "<!DOCTYPE html>",
        "<html>",
        "  <head>",
        '    <meta name="pypi:repository-version" content="1.0">',
        f"    <title>Links for {escaped_title}</title>",
        "  </head>",
        "  <body>",
        f"    <h1>Links for {escaped_title}</h1>",
    ]

    for entry in files:
        if not isinstance(entry, dict):
            raise IntegrityError(f"Invalid file entry in index.json for {project_name!r}")
        filename = entry.get("filename")
        if not isinstance(filename, str) or not filename:
            raise IntegrityError(f"Missing filename in index.json for {project_name!r}")

        hashes = entry.get("hashes")
        sha256: str | None = None
        if isinstance(hashes, dict) and isinstance(hashes.get("sha256"), str):
            sha256 = hashes["sha256"]

        raw_url = entry.get("url")
        if isinstance(raw_url, str) and raw_url:
            href = raw_url
        elif sha256:
            href = f"/files/{sha256}/{filename}"
        else:
            raise IntegrityError(f"Missing url and sha256 for {filename!r} in {project_name!r}")

        if sha256 and "#" not in href:
            href = f"{href}#sha256={sha256}"

        attrs = [f'href="{html.escape(href, quote=True)}"']

        requires_python = entry.get("requires-python")
        if isinstance(requires_python, str) and requires_python:
            attrs.append(f'data-requires-python="{html.escape(requires_python, quote=True)}"')

        yanked = entry.get("yanked")
        if isinstance(yanked, str) and yanked:
            attrs.append(f'data-yanked="{html.escape(yanked, quote=True)}"')
        elif yanked is True:
            attrs.append('data-yanked=""')

        escaped_filename = html.escape(filename, quote=False)
        lines.append(f"    <a {' '.join(attrs)}>{escaped_filename}</a>")

    lines.extend(["  </body>", "</html>", ""])
    return "\n".join(lines).encode("utf-8")


def _file_identity(st: os.stat_result) -> tuple[int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def _open_regular_file_nofollow(
    root: Path,
    rel_parts: tuple[str, ...],
    max_bytes: int,
) -> tuple[int, int, Path]:
    """Open a regular file inside `root` without following any symlink or blocking on a FIFO.

    Every component is opened relative to its parent descriptor with no-follow
    semantics (hermetic_safe_io), so a component swapped for a symlink between
    inspection and open is refused instead of followed.
    """
    for part in rel_parts:
        if part in ("", ".", "..") or "/" in part or "\\" in part or "\x00" in part:
            raise PathTraversalError(f"Unsafe path component: {part!r}")
    current = root.joinpath(*rel_parts)
    try:
        fd = hermetic_safe_io.open_regular(current, sys.maxsize)
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise NotFoundMissError(f"Missing path component: {current}") from exc
    except hermetic_safe_io.UnsafePathError as exc:
        raise SymlinkError(f"Refusing symlink or non-regular object in store: {current}") from exc
    except ValueError as exc:
        raise PathTraversalError(f"Unsafe store path: {current}") from exc
    except OSError as exc:
        raise IntegrityError(f"OS error accessing {current}: {exc}") from exc

    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise SymlinkError(f"Opened descriptor is not a regular file: {current}")
        if fst.st_size > max_bytes:
            raise StoreLimitError(
                f"File {current} size {fst.st_size} exceeds cap {max_bytes}"
            )
        return fd, fst.st_size, current
    except BaseException:
        os.close(fd)
        raise


class FrozenStore:
    """Read-only interface to a frozen Hermetic World PyPI store."""

    def __init__(
        self,
        store_dir: Path | str,
        *,
        max_json_bytes: int = MAX_JSON_FILE_BYTES,
        max_dist_bytes: int = MAX_DIST_FILE_BYTES,
        max_dir_entries: int = MAX_DIR_ENTRIES,
    ) -> None:
        raw_path = Path(store_dir)
        try:
            resolved = raw_path.resolve(strict=True)
        except OSError as exc:
            raise IntegrityError(f"Store directory does not exist: {store_dir}") from exc
        if not resolved.is_dir():
            raise IntegrityError(f"Store path is not a directory: {resolved}")

        self.root: Path = resolved
        self.max_json_bytes = max_json_bytes
        self.max_dist_bytes = max_dist_bytes
        self.max_dir_entries = max_dir_entries

    def list_projects(self) -> list[str]:
        """Return deterministically sorted normalized project names in STORE/simple/."""
        simple_dir = self.root / "simple"
        try:
            st = os.lstat(simple_dir)
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise IntegrityError(f"Error inspecting {simple_dir}: {exc}") from exc

        if stat.S_ISLNK(st.st_mode):
            raise SymlinkError(f"Refusing symlink directory: {simple_dir}")
        if not stat.S_ISDIR(st.st_mode):
            raise IntegrityError(f"Expected directory at {simple_dir}")

        projects: set[str] = set()
        count = 0
        try:
            with os.scandir(simple_dir) as it:
                for entry in it:
                    count += 1
                    if count > self.max_dir_entries:
                        raise StoreLimitError(
                            f"Directory {simple_dir} exceeds cap {self.max_dir_entries}"
                        )
                    if entry.is_symlink():
                        logger.warning("Ignoring symlink in simple index: %s", entry.path)
                        continue
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    try:
                        norm = normalize_project_name(entry.name)
                    except InvalidNameError:
                        continue
                    if norm != entry.name:
                        # Only normalised directories are reachable by get_project_page;
                        # listing any other name would advertise an unservable project.
                        continue
                    index_path = Path(entry.path) / "index.json"
                    try:
                        idx_st = os.lstat(index_path)
                    except OSError:
                        continue
                    if stat.S_ISLNK(idx_st.st_mode) or not stat.S_ISREG(idx_st.st_mode):
                        continue
                    projects.add(norm)
        except OSError as exc:
            raise IntegrityError(f"Failed scanning {simple_dir}: {exc}") from exc

        return sorted(projects)

    def get_project_page(self, raw_project: str) -> ProjectPage:
        """Load STORE/simple/<normalised project>/index.json and render HTML."""
        norm_name = normalize_project_name(raw_project)
        fd, _, index_path = _open_regular_file_nofollow(
            self.root,
            ("simple", norm_name, "index.json"),
            self.max_json_bytes,
        )
        chunks: list[bytes] = []
        total = 0
        try:
            while True:
                chunk = os.read(fd, FILE_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.max_json_bytes:
                    raise StoreLimitError(f"JSON page {index_path} exceeds cap")
                chunks.append(chunk)
        except OSError as exc:
            raise IntegrityError(f"Failed reading {index_path}: {exc}") from exc
        finally:
            os.close(fd)

        raw_bytes = b"".join(chunks)
        try:
            payload = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.error("Corrupted JSON in %s: %s", index_path, exc)
            raise IntegrityError(f"Corrupted JSON in {index_path}") from exc

        if not isinstance(payload, dict):
            logger.error("Non-object JSON in %s", index_path)
            raise IntegrityError(f"Non-object JSON in {index_path}")

        html_bytes = render_project_html(norm_name, payload)
        return ProjectPage(name=norm_name, json_bytes=raw_bytes, html_bytes=html_bytes)

    def verify_and_prepare_file(self, sha256: str, filename: str) -> VerifiedFile:
        """Verify regular file existence, size cap, and SHA-256 digest."""
        valid_sha = validate_sha256(sha256)
        valid_name = validate_filename(filename)

        fd, expected_size, file_path = _open_regular_file_nofollow(
            self.root,
            ("files", valid_sha, valid_name),
            self.max_dist_bytes,
        )
        hasher = hashlib.sha256()
        total = 0
        try:
            identity = _file_identity(os.fstat(fd))
            while True:
                chunk = os.read(fd, FILE_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.max_dist_bytes:
                    raise StoreLimitError(f"File {file_path} exceeds cap {self.max_dist_bytes}")
                hasher.update(chunk)
        except OSError as exc:
            logger.error("OS read error while hashing %s: %s", file_path, exc)
            raise IntegrityError(f"Failed reading {file_path}") from exc
        finally:
            os.close(fd)

        if total != expected_size:
            raise IntegrityError(f"File {file_path} changed size while being hashed")

        actual_sha = hasher.hexdigest()
        if not hmac.compare_digest(actual_sha, valid_sha):
            logger.error(
                "SHA-256 mismatch for %s: expected %s, got %s",
                file_path,
                valid_sha,
                actual_sha,
            )
            raise IntegrityError(
                f"SHA-256 mismatch for {valid_name}: expected {valid_sha}, got {actual_sha}"
            )

        return VerifiedFile(
            path=file_path,
            sha256=valid_sha,
            filename=valid_name,
            size=total,
            content_type=_content_type_for_filename(valid_name),
            identity=identity,
        )

    def iter_file_range(self, verified: VerifiedFile, start: int, end: int) -> Iterator[bytes]:
        """Stream inclusive byte range [start, end] from a verified regular file."""
        if start < 0 or end < start or end >= verified.size:
            raise ValueError(f"Invalid byte range {start}-{end} for size {verified.size}")

        fd, _, _ = _open_regular_file_nofollow(
            self.root,
            ("files", verified.sha256, verified.filename),
            self.max_dist_bytes,
        )
        remaining = end - start + 1
        try:
            current_identity = _file_identity(os.fstat(fd))
            if current_identity != verified.identity or current_identity[2] != verified.size:
                raise IntegrityError(
                    f"File {verified.path} changed after its digest was verified"
                )
            os.lseek(fd, start, os.SEEK_SET)
            while remaining > 0:
                to_read = min(FILE_CHUNK_BYTES, remaining)
                chunk = os.read(fd, to_read)
                if not chunk:
                    raise IntegrityError(f"Unexpected EOF while streaming {verified.path}")
                remaining -= len(chunk)
                yield chunk
        finally:
            os.close(fd)


class MissLog:
    """Atomic, size-capped, sequence-numbered JSON-lines log for 404 misses."""

    def __init__(
        self,
        path: Path | str,
        *,
        max_bytes: int = MAX_MISS_LOG_BYTES,
    ) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._seq: int | None = None

    def record_project_miss(self, project: str, request_path: str) -> int:
        """Record a 404 miss for a project lookup and return its sequence number."""
        return self._append(
            {
                "kind": "project",
                "path": request_path,
                "project": project,
            }
        )

    def record_file_miss(self, sha256: str, filename: str, request_path: str) -> int:
        """Record a 404 miss for a distribution file lookup and return its sequence number."""
        return self._append(
            {
                "filename": filename,
                "kind": "file",
                "path": request_path,
                "sha256": sha256,
            }
        )

    def _read_existing_lines(self) -> tuple[list[bytes], int]:
        """Read existing valid JSON lines up to max_bytes and find highest sequence number."""
        try:
            st = os.lstat(self.path)
        except FileNotFoundError:
            return [], 0
        except OSError as exc:
            raise MissLogError(f"Cannot stat miss log {self.path}: {exc}") from exc

        if stat.S_ISLNK(st.st_mode):
            raise SymlinkError(f"Refusing symlink miss log: {self.path}")
        if not stat.S_ISREG(st.st_mode):
            raise MissLogError(f"Miss log path is not a regular file: {self.path}")

        try:
            # Descriptor-anchored, no-follow, non-blocking open of a regular file.
            fd = hermetic_safe_io.open_regular(self.path, sys.maxsize)
        except FileNotFoundError:
            return [], 0
        except hermetic_safe_io.UnsafePathError as exc:
            raise SymlinkError(f"Refusing unsafe miss log: {self.path}") from exc
        except (OSError, ValueError) as exc:
            raise MissLogError(f"Cannot open miss log {self.path}: {exc}") from exc

        chunks: list[bytes] = []
        total = 0
        try:
            while total < self.max_bytes:
                to_read = min(FILE_CHUNK_BYTES, self.max_bytes - total)
                chunk = os.read(fd, to_read)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        except OSError as exc:
            raise MissLogError(f"Cannot read miss log {self.path}: {exc}") from exc
        finally:
            os.close(fd)

        raw = b"".join(chunks)
        lines: list[bytes] = []
        max_seq = 0
        for raw_line in raw.splitlines(keepends=True):
            if not raw_line.endswith(b"\n"):
                continue
            try:
                parsed = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(parsed, dict):
                lines.append(raw_line)
                seq_val = parsed.get("seq")
                if isinstance(seq_val, int) and seq_val > max_seq:
                    max_seq = seq_val
        return lines, max_seq

    def _append(self, entry: dict[str, Any]) -> int:
        """Atomically append one JSON line while keeping total file size <= max_bytes."""
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise MissLogError(f"Cannot create parent directory for {self.path}: {exc}") from exc

            existing_lines, disk_max_seq = self._read_existing_lines()
            if self._seq is None:
                self._seq = disk_max_seq
            self._seq += 1
            seq = self._seq

            record = dict(entry)
            record["seq"] = seq
            new_line = (
                json.dumps(record, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
                + "\n"
            ).encode("utf-8")

            if len(new_line) > self.max_bytes:
                raise MissLogError(
                    f"Single miss log entry ({len(new_line)} bytes) exceeds cap {self.max_bytes}"
                )

            kept_lines = list(existing_lines)
            current_size = sum(len(line) for line in kept_lines)
            while kept_lines and current_size + len(new_line) > self.max_bytes:
                dropped = kept_lines.pop(0)
                current_size -= len(dropped)

            payload = b"".join(kept_lines) + new_line
            try:
                hermetic_safe_io.atomic_write(self.path, payload)
            except hermetic_safe_io.UnsafePathError as exc:
                raise SymlinkError(f"Refusing unsafe miss log: {self.path}") from exc
            except (OSError, ValueError) as exc:
                raise MissLogError(f"Atomic write to miss log {self.path} failed: {exc}") from exc

            return seq


