
"""Safe artifact ingestion and deterministic normalisation for Detector D7.

Design invariants:
- Standard library only; never imports, executes, or evaluates artifact code.
- Never follows symlinks; refuses symlinks, hardlinks, FIFOs, sockets, and devices.
- Every read and loop is bounded by explicit named constant caps.
- Line endings (CRLF vs LF) are intentionally NOT normalised.
"""

from __future__ import annotations

import csv
import hashlib
import io
import gzip
import os
import stat
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, fields
from pathlib import Path, PurePosixPath
from typing import BinaryIO

import hermetic_safe_io

# Named constant caps bounding every read and loop.
PYC_HEADER_SIZE: int = 16
MAX_ARCHIVE_MEMBERS: int = 10_000
MAX_MEMBER_BYTES: int = 64 * 1024 * 1024  # 64 MiB per member
MAX_TOTAL_DECOMPRESSED_BYTES: int = 256 * 1024 * 1024  # 256 MiB total per artifact
MAX_NESTING_DEPTH: int = 32
MAX_TEXT_DIFF_BYTES: int = 1 * 1024 * 1024  # 1 MiB per text member for diffing
MAX_DIFF_LINES: int = 200
READ_CHUNK_SIZE: int = 65_536  # 64 KiB read chunk
MAX_READ_CHUNKS: int = (MAX_MEMBER_BYTES // READ_CHUNK_SIZE) + 2
MAX_RECORD_LINES: int = 50_000
MAX_METADATA_LINES: int = 50_000
MAX_DIFF_INPUT_LINES: int = 50_000
# Cap on a single tar extended header (pax or GNU long name/link). tarfile reads
# these fully into memory before any member cap applies.
MAX_TAR_EXTENDED_HEADER_BYTES: int = 1024 * 1024
MAX_ARTIFACT_BYTES: int = 256 * 1024 * 1024

COMPILED_EXTENSION_SUFFIXES: tuple[str, ...] = (".so", ".dylib", ".pyd")


class HermeticD7Error(Exception):
    """Base typed error for all Detector D7 failures."""


class InvalidArtifactError(HermeticD7Error):
    """Raised when an artifact path, format, or member payload is invalid or corrupt."""


class SecurityViolationError(HermeticD7Error):
    """Raised when an artifact contains path traversal, symlinks, or non-regular files."""


class ResourceLimitError(HermeticD7Error):
    """Raised when an artifact exceeds member count, nesting depth, or decompressed byte caps."""


class CliUsageError(HermeticD7Error):
    """Raised when CLI arguments are invalid."""


@dataclass(frozen=True)
class ResourceLimits:
    """Bounded resource limits applied during artifact inspection and comparison."""

    max_archive_members: int = MAX_ARCHIVE_MEMBERS
    max_member_bytes: int = MAX_MEMBER_BYTES
    max_total_decompressed_bytes: int = MAX_TOTAL_DECOMPRESSED_BYTES
    max_nesting_depth: int = MAX_NESTING_DEPTH
    max_text_diff_bytes: int = MAX_TEXT_DIFF_BYTES
    max_diff_lines: int = MAX_DIFF_LINES
    read_chunk_size: int = READ_CHUNK_SIZE
    max_record_lines: int = MAX_RECORD_LINES
    max_metadata_lines: int = MAX_METADATA_LINES
    max_diff_input_lines: int = MAX_DIFF_INPUT_LINES

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value < 0 or (field.name == "read_chunk_size" and value == 0):
                raise ResourceLimitError(f"Invalid resource cap: {field.name}")


@dataclass(frozen=True)
class NormalisedMember:
    """Normalised representation of a single regular file inside an artifact."""

    path: str
    data: bytes
    sha256: str
    executable: bool
    is_pyc: bool


def normalise_executable(mode: int) -> bool:
    """Reduce file permission bits to whether any executable bit is set."""
    return bool(mode & 0o111)


def normalise_pyc(raw_bytes: bytes, member_path: str) -> bytes:
    """Strip the 16-byte PEP 552 header from a .pyc file before comparison."""
    if len(raw_bytes) < PYC_HEADER_SIZE:
        raise InvalidArtifactError(
            f".pyc member {member_path!r} is truncated ({len(raw_bytes)} bytes < {PYC_HEADER_SIZE})"
        )
    return raw_bytes[PYC_HEADER_SIZE:]


def _is_wheel_record(member_path: str) -> bool:
    """Return True if member_path refers to a wheel .dist-info/RECORD file."""
    posix = PurePosixPath(member_path)
    if posix.name != "RECORD":
        return False
    parts = posix.parts
    if len(parts) == 1:
        return True
    return len(parts) == 2 and parts[0].endswith(".dist-info")


def _is_metadata_file(member_path: str) -> bool:
    """Return True if member_path refers to PKG-INFO or METADATA."""
    name = PurePosixPath(member_path).name
    return name in {"PKG-INFO", "METADATA"}


def normalise_record(
    raw_bytes: bytes,
    member_path: str,
    max_lines: int = MAX_RECORD_LINES,
) -> bytes:
    """Normalise a wheel RECORD file by dropping its self-line and sorting lines.

    Line endings are preserved rather than normalised.
    """
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidArtifactError(f"RECORD member {member_path!r} is not valid UTF-8") from exc

    lines = text.splitlines(keepends=True)
    if len(lines) > max_lines:
        raise ResourceLimitError(
            f"RECORD member {member_path!r} exceeds line cap ({len(lines)} > {max_lines})"
        )

    default_eol = "\r\n" if "\r\n" in text else "\n"
    kept: list[str] = []
    for idx, line in enumerate(lines):
        if idx >= max_lines:
            raise ResourceLimitError(f"RECORD member {member_path!r} exceeded line iteration cap")
        stripped = line.rstrip("\r\n")
        if stripped:
            try:
                row = next(csv.reader([stripped]))
                first_col = row[0] if row else ""
            except csv.Error:
                first_col = stripped.split(",", 1)[0]
        else:
            first_col = ""

        if first_col == member_path:
            continue

        if len(lines) > 1 and not line.endswith(("\n", "\r")):
            line = line + default_eol
        kept.append(line)

    kept.sort()
    return "".join(kept).encode("utf-8")


def normalise_metadata(
    raw_bytes: bytes,
    member_path: str = "METADATA",
    max_lines: int = MAX_METADATA_LINES,
) -> bytes:
    """Normalise PKG-INFO/METADATA by dropping trailing blank lines.

    Line endings are preserved rather than normalised.
    """
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidArtifactError(f"Metadata member {member_path!r} is not valid UTF-8") from exc

    lines = text.splitlines(keepends=True)
    if len(lines) > max_lines:
        raise ResourceLimitError(
            f"Metadata member {member_path!r} exceeds line cap ({len(lines)} > {max_lines})"
        )

    for _ in range(len(lines)):
        if lines and lines[-1].strip() == "":
            lines.pop()
        else:
            break

    return "".join(lines).encode("utf-8")


def normalise_member_bytes(
    member_path: str,
    raw_bytes: bytes,
    limits: ResourceLimits | None = None,
) -> tuple[bytes, bool]:
    """Normalise known nondeterminism in member bytes.

    Returns (normalised_bytes, is_pyc). Line endings are NOT normalised.
    """
    active_limits = limits or ResourceLimits()
    if member_path.endswith(".pyc"):
        return normalise_pyc(raw_bytes, member_path), True
    if _is_wheel_record(member_path):
        return (
            normalise_record(raw_bytes, member_path, max_lines=active_limits.max_record_lines),
            False,
        )
    if _is_metadata_file(member_path):
        return (
            normalise_metadata(raw_bytes, member_path, max_lines=active_limits.max_metadata_lines),
            False,
        )
    return raw_bytes, False


def validate_member_path(
    raw_path: str,
    *,
    is_dir: bool,
    max_depth: int = MAX_NESTING_DEPTH,
) -> str:
    """Validate and canonicalise an archive or directory member path.

    Refuses empty paths, NUL bytes, backslashes, absolute paths, drive prefixes,
    '..' traversal segments, and nesting beyond max_depth.
    """
    if not raw_path:
        raise InvalidArtifactError("Empty member path in artifact")
    if "\x00" in raw_path:
        raise SecurityViolationError(f"NUL byte in member path {raw_path!r}")
    if "\\" in raw_path:
        raise SecurityViolationError(f"Backslash path separator refused in {raw_path!r}")
    if raw_path.startswith("/"):
        raise SecurityViolationError(f"Absolute member path refused: {raw_path!r}")
    if len(raw_path) >= 2 and raw_path[1] == ":" and raw_path[0].isalpha():
        raise SecurityViolationError(f"Drive-prefixed member path refused: {raw_path!r}")

    cleaned = raw_path
    if cleaned in {".", "./"}:
        if is_dir:
            return ""
        raise InvalidArtifactError(f"Invalid regular file path {raw_path!r}")

    if cleaned.startswith("./"):
        cleaned = cleaned[2:]

    if cleaned.endswith("/"):
        if not is_dir:
            raise InvalidArtifactError(f"Regular file path cannot end with '/': {raw_path!r}")
        cleaned = cleaned.rstrip("/")
        if not cleaned:
            raise SecurityViolationError(f"Root-only path refused: {raw_path!r}")

    parts = cleaned.split("/")
    if len(parts) > max_depth:
        raise ResourceLimitError(
            f"Member path {raw_path!r} exceeds max nesting depth ({len(parts)} > {max_depth})"
        )

    for part in parts:
        if part in {"", ".", ".."}:
            raise SecurityViolationError(f"Unsafe path segment in member path: {raw_path!r}")

    return "/".join(parts)


def _read_bounded_stream(
    stream: BinaryIO,
    member_path: str,
    limits: ResourceLimits,
    total_bytes_so_far: int,
) -> tuple[bytes, int]:
    """Read a binary stream in bounded chunks up to per-member and total caps."""
    chunk_size = max(1, limits.read_chunk_size)
    max_chunks = max(MAX_READ_CHUNKS, (limits.max_member_bytes // chunk_size) + 2)
    chunks: list[bytes] = []
    member_bytes = 0
    total_bytes = total_bytes_so_far

    for _ in range(max_chunks):
        try:
            chunk = stream.read(chunk_size)
        except (OSError, EOFError, zlib.error, tarfile.TarError, zipfile.BadZipFile) as exc:
            raise InvalidArtifactError(
                f"Corrupt or unreadable member stream {member_path!r}: {exc}"
            ) from exc

        if not chunk:
            break

        member_bytes += len(chunk)
        if member_bytes > limits.max_member_bytes:
            raise ResourceLimitError(
                f"Member {member_path!r} exceeds per-member byte cap ({limits.max_member_bytes})"
            )

        total_bytes += len(chunk)
        if total_bytes > limits.max_total_decompressed_bytes:
            raise ResourceLimitError(
                f"Artifact exceeds total decompressed byte cap ({limits.max_total_decompressed_bytes})"
            )

        chunks.append(chunk)
    else:
        raise ResourceLimitError(
            f"Member {member_path!r} exceeded maximum read chunk iterations ({max_chunks})"
        )

    return b"".join(chunks), total_bytes


def _build_member(
    norm_path: str,
    raw_bytes: bytes,
    executable: bool,
    limits: ResourceLimits,
) -> NormalisedMember:
    """Normalise raw bytes and compute the SHA-256 digest of the normalised content."""
    norm_bytes, is_pyc = normalise_member_bytes(norm_path, raw_bytes, limits=limits)
    digest = hashlib.sha256(norm_bytes).hexdigest()
    return NormalisedMember(
        path=norm_path,
        data=norm_bytes,
        sha256=digest,
        executable=executable,
        is_pyc=is_pyc,
    )


def _read_directory(root_path: Path, limits: ResourceLimits) -> dict[str, NormalisedMember]:
    """Load regular files from a directory tree without following symlinks."""
    members: dict[str, NormalisedMember] = {}
    stack: list[tuple[Path, str, int]] = [(root_path, "", 0)]
    entries_seen = 0
    total_bytes = 0

    for _ in range(limits.max_archive_members + 1):
        if not stack:
            break
        current_dir, prefix, depth = stack.pop()

        raw_entries: list[os.DirEntry[str]] = []
        try:
            with hermetic_safe_io.scandir(current_dir) as it:
                # Bounded: a directory with more entries than the member cap is refused
                # before its listing is held in memory.
                for scanned in it:
                    if entries_seen + len(raw_entries) >= limits.max_archive_members:
                        raise ResourceLimitError(
                            f"Directory exceeds max member count ({limits.max_archive_members})"
                        )
                    raw_entries.append(scanned)
        except OSError as exc:
            raise InvalidArtifactError(
                f"Failed to scan directory {prefix or '.'!r}: {type(exc).__name__}"
            ) from exc

        raw_entries.sort(key=lambda e: e.name)

        for entry in raw_entries:
            entries_seen += 1
            if entries_seen > limits.max_archive_members:
                raise ResourceLimitError(
                    f"Directory exceeds max member count ({limits.max_archive_members})"
                )

            try:
                if entry.is_symlink():
                    raise SecurityViolationError(
                        f"Symlink refused in directory artifact: {entry.path}"
                    )
                est = entry.stat(follow_symlinks=False)
            except SecurityViolationError:
                raise
            except OSError as exc:
                raise InvalidArtifactError(f"Failed to stat {entry.path}: {exc}") from exc

            if stat.S_ISLNK(est.st_mode):
                raise SecurityViolationError(f"Symlink refused in directory artifact: {entry.path}")

            rel_path = f"{prefix}/{entry.name}" if prefix else entry.name

            if stat.S_ISDIR(est.st_mode):
                next_depth = depth + 1
                if next_depth > limits.max_nesting_depth:
                    raise ResourceLimitError(
                        f"Directory nesting depth exceeds cap ({next_depth} > {limits.max_nesting_depth})"
                    )
                validate_member_path(rel_path, is_dir=True, max_depth=limits.max_nesting_depth)
                stack.append((current_dir / entry.name, rel_path, next_depth))
            elif stat.S_ISREG(est.st_mode):
                norm_path = validate_member_path(
                    rel_path, is_dir=False, max_depth=limits.max_nesting_depth
                )
                if est.st_nlink > 1:
                    raise SecurityViolationError(
                        f"Hardlinked file refused in directory artifact: {norm_path!r}"
                    )
                if norm_path in members:
                    raise SecurityViolationError(f"Duplicate directory member: {norm_path!r}")
                if est.st_size > limits.max_member_bytes:
                    raise ResourceLimitError(
                        f"File {norm_path!r} exceeds per-member byte cap ({limits.max_member_bytes})"
                    )
                try:
                    # Descriptor-anchored, no-follow, non-blocking: a member swapped for a
                    # symlink or FIFO after the stat above is refused, never followed.
                    fd = hermetic_safe_io.open_regular(current_dir / entry.name, limits.max_member_bytes)
                except (OSError, ValueError) as exc:
                    raise SecurityViolationError(
                        f"Failed to open {norm_path!r} safely: {type(exc).__name__}"
                    ) from exc
                with os.fdopen(fd, "rb") as fobj:
                    opened = os.fstat(fobj.fileno())
                    if opened.st_nlink > 1:
                        raise SecurityViolationError("Hardlinked file refused")
                    raw_bytes, total_bytes = _read_bounded_stream(
                        fobj, norm_path, limits, total_bytes
                    )
                members[norm_path] = _build_member(
                    norm_path,
                    raw_bytes,
                    normalise_executable(opened.st_mode),
                    limits,
                )
            else:
                raise SecurityViolationError(
                    f"Non-regular filesystem entry refused: {entry.path} (mode={oct(est.st_mode)})"
                )
    else:
        raise ResourceLimitError(
            f"Directory traversal exceeded maximum directory count ({limits.max_archive_members})"
        )

    return members


def _read_zip(archive_path: Path, limits: ResourceLimits) -> dict[str, NormalisedMember]:
    """Load regular files from a .zip or .whl archive with strict member and size checks."""
    members: dict[str, NormalisedMember] = {}
    total_bytes = 0

    try:
        zf_ctx = zipfile.ZipFile(_archive_stream(archive_path), mode="r")
    except (zipfile.BadZipFile, OSError, EOFError, zlib.error) as exc:
        raise InvalidArtifactError(f"Invalid ZIP/wheel archive {archive_path}: {exc}") from exc

    with zf_ctx as zf:
        infolist = zf.infolist()
        if len(infolist) > limits.max_archive_members:
            raise ResourceLimitError(
                f"Archive exceeds max member count ({len(infolist)} > {limits.max_archive_members})"
            )

        for idx, info in enumerate(infolist, start=1):
            if idx > limits.max_archive_members:
                raise ResourceLimitError(
                    f"Archive exceeds max member count ({limits.max_archive_members})"
                )

            posix_mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(posix_mode)

            if file_type == stat.S_IFLNK:
                raise SecurityViolationError(f"Symlink refused in ZIP archive: {info.filename!r}")
            if file_type != 0 and file_type not in (stat.S_IFREG, stat.S_IFDIR):
                raise SecurityViolationError(
                    f"Non-regular file refused in ZIP archive: {info.filename!r} (mode={oct(posix_mode)})"
                )

            is_dir = info.is_dir() or file_type == stat.S_IFDIR
            norm_path = validate_member_path(
                info.filename, is_dir=is_dir, max_depth=limits.max_nesting_depth
            )

            if is_dir:
                if info.file_size > 0:
                    raise InvalidArtifactError(
                        f"Directory entry {info.filename!r} has non-zero payload ({info.file_size})"
                    )
                continue

            if norm_path in members:
                raise SecurityViolationError(f"Duplicate archive member refused: {norm_path!r}")

            if info.file_size < 0 or info.file_size > limits.max_member_bytes:
                raise ResourceLimitError(
                    f"Member {norm_path!r} declared size exceeds cap ({info.file_size} > {limits.max_member_bytes})"
                )

            try:
                stream_ctx = zf.open(info, mode="r")
            except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, zlib.error) as exc:
                raise InvalidArtifactError(
                    f"Failed to open ZIP member {norm_path!r}: {exc}"
                ) from exc

            with stream_ctx as fobj:
                raw_bytes, total_bytes = _read_bounded_stream(
                    fobj, norm_path, limits, total_bytes
                )

            members[norm_path] = _build_member(
                norm_path,
                raw_bytes,
                normalise_executable(posix_mode),
                limits,
            )

    return members


_TAR_EXTENDED_TYPES = frozenset(
    {
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.SOLARIS_XHDTYPE,
    }
)


class _CappedTarInfo(tarfile.TarInfo):
    """TarInfo that refuses oversized extended headers before tarfile buffers them."""

    def _proc_member(self, tarfile_obj: tarfile.TarFile) -> tarfile.TarInfo:  # type: ignore[override]
        if self.type in _TAR_EXTENDED_TYPES and self.size > MAX_TAR_EXTENDED_HEADER_BYTES:
            raise tarfile.HeaderError(
                f"Extended tar header exceeds cap ({self.size} > {MAX_TAR_EXTENDED_HEADER_BYTES})"
            )
        return super()._proc_member(tarfile_obj)


def _read_tar(
    archive_path: Path,
    tar_mode: str,
    limits: ResourceLimits,
) -> dict[str, NormalisedMember]:
    """Load regular files from a .tar or .tar.gz archive with strict member and size checks."""
    members: dict[str, NormalisedMember] = {}
    total_bytes = 0

    try:
        stream = _archive_stream(archive_path)
        if tar_mode == "r:gz":
            with gzip.GzipFile(fileobj=stream) as compressed:
                unpacked = compressed.read(MAX_ARTIFACT_BYTES + 1)
            if len(unpacked) > MAX_ARTIFACT_BYTES:
                raise ResourceLimitError("TAR stream byte cap exceeded")
            stream = io.BytesIO(unpacked)
        tf_ctx = tarfile.open(fileobj=stream, mode="r:", tarinfo=_CappedTarInfo)
    except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
        raise InvalidArtifactError(f"Invalid TAR archive {archive_path}: {exc}") from exc

    with tf_ctx as tf:
        try:
            for idx, member in enumerate(tf, start=1):
                if idx > limits.max_archive_members:
                    raise ResourceLimitError(
                        f"TAR archive exceeds max member count ({limits.max_archive_members})"
                    )

                if member.issym() or member.islnk():
                    raise SecurityViolationError(
                        f"Link member refused in TAR archive: {member.name!r} -> {member.linkname!r}"
                    )

                if member.isdir():
                    validate_member_path(
                        member.name, is_dir=True, max_depth=limits.max_nesting_depth
                    )
                    continue

                if not member.isreg():
                    raise SecurityViolationError(
                        f"Non-regular member refused in TAR archive: {member.name!r} (type={member.type!r})"
                    )

                norm_path = validate_member_path(
                    member.name, is_dir=False, max_depth=limits.max_nesting_depth
                )

                if norm_path in members:
                    raise SecurityViolationError(f"Duplicate archive member refused: {norm_path!r}")

                if member.size < 0 or member.size > limits.max_member_bytes:
                    raise ResourceLimitError(
                        f"Member {norm_path!r} declared size exceeds cap ({member.size} > {limits.max_member_bytes})"
                    )

                extracted = tf.extractfile(member)
                if extracted is None:
                    raise InvalidArtifactError(f"Could not extract TAR member {norm_path!r}")

                with extracted:
                    raw_bytes, total_bytes = _read_bounded_stream(
                        extracted, norm_path, limits, total_bytes
                    )

                members[norm_path] = _build_member(
                    norm_path,
                    raw_bytes,
                    normalise_executable(member.mode),
                    limits,
                )
        except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:
            raise InvalidArtifactError(f"Corrupt TAR stream in {archive_path}: {exc}") from exc

    return members


def _archive_stream(path: Path) -> io.BytesIO:
    """Pin and bound the archive before any parser can reopen the supplied path."""
    try:
        fd = hermetic_safe_io.open_regular(path, MAX_ARTIFACT_BYTES)
        with os.fdopen(fd, "rb") as stream:
            if os.fstat(stream.fileno()).st_nlink > 1:
                raise SecurityViolationError("Hardlinked archive refused")
            data = stream.read(MAX_ARTIFACT_BYTES + 1)
        if len(data) > MAX_ARTIFACT_BYTES:
            raise ResourceLimitError("Archive input byte cap exceeded")
        return io.BytesIO(data)
    except (OSError, ValueError) as exc:
        raise SecurityViolationError(f"Unsafe archive input: {type(exc).__name__}") from exc


def _read_regular_file(
    file_path: Path,
    limits: ResourceLimits,
) -> dict[str, NormalisedMember]:
    """Load a single regular file artifact (such as a compiled extension module or generated file)."""
    norm_name = validate_member_path(file_path.name, is_dir=False, max_depth=limits.max_nesting_depth)
    try:
        fd = hermetic_safe_io.open_regular(file_path, limits.max_member_bytes)
    except (OSError, ValueError) as exc:
        raise SecurityViolationError(
            f"Failed to open {norm_name!r} safely: {type(exc).__name__}"
        ) from exc
    with os.fdopen(fd, "rb") as fobj:
        opened = os.fstat(fobj.fileno())
        if opened.st_nlink > 1:
            raise SecurityViolationError("Hardlinked file refused")
        raw_bytes, _ = _read_bounded_stream(
            fobj, norm_name, limits, 0
        )
    return {
        norm_name: _build_member(
            norm_name,
            raw_bytes,
            normalise_executable(opened.st_mode),
            limits,
        )
    }


def load_artifact(
    artifact_path: str | Path,
    limits: ResourceLimits | None = None,
    *,
    generated_files: Sequence[str | Path] | set[str] | None = None,
) -> dict[str, NormalisedMember]:
    """Load and normalise an artifact (directory tree, .whl/.zip, .tar/.tar.gz, compiled extension, or generated file)."""
    active_limits = limits or ResourceLimits()
    path = Path(artifact_path)

    try:
        st = os.lstat(path)
    except FileNotFoundError as exc:
        raise InvalidArtifactError(f"Artifact path does not exist: {path}") from exc
    except OSError as exc:
        raise InvalidArtifactError(f"Cannot stat artifact path {path}: {exc}") from exc

    if stat.S_ISLNK(st.st_mode):
        raise SecurityViolationError(f"Top-level artifact path cannot be a symlink: {path}")

    if stat.S_ISDIR(st.st_mode):
        return _read_directory(path, active_limits)

    if not stat.S_ISREG(st.st_mode):
        raise SecurityViolationError(
            f"Top-level artifact must be a regular file or directory: {path} (mode={oct(st.st_mode)})"
        )

    lower_name = path.name.lower()
    if lower_name.endswith((".whl", ".zip")):
        return _read_zip(path, active_limits)
    if lower_name.endswith((".tar.gz", ".tgz")):
        return _read_tar(path, "r:gz", active_limits)
    if lower_name.endswith(".tar"):
        return _read_tar(path, "r:", active_limits)

    is_compiled = any(lower_name.endswith(sfx) for sfx in COMPILED_EXTENSION_SUFFIXES)
    is_generated = False
    if generated_files is not None:
        raw_str = str(artifact_path)
        gen_strs = {str(g) for g in generated_files} | {Path(g).name for g in generated_files}
        is_generated = raw_str in gen_strs or path.name in gen_strs or str(path) in gen_strs

    if is_compiled or is_generated:
        return _read_regular_file(path, active_limits)

    raise InvalidArtifactError(
        f"Unsupported artifact format for {path.name!r}; expected directory, .whl, .zip, .tar, .tar.gz, compiled extension, or listed generated file"
    )


