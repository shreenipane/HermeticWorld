"""Go h1 and sumdb provenance verification and generation for Hermetic World.

Implements the official Go module checksum specification (RFC/go.dev/ref/mod#checksums
and golang.org/x/mod/sumdb/dirhash). Computes and verifies exact h1: hashes for .mod
and module zip archives, formats sumdb lookup records, and formats go.sum entries.
All operations are offline, bounded, and refuse malformed or hostile inputs.
"""

from __future__ import annotations

import base64
import hashlib
import io
import posixpath
import re
import zipfile

from .cut import CutError

MAX_ZIP_BYTES: int = 64 * 1024 * 1024
MAX_ZIP_FILES: int = 10_000
MAX_PATH_BYTES: int = 1024
MAX_FILE_BYTES: int = 32 * 1024 * 1024
MAX_UNCOMPRESSED_ZIP_BYTES: int = 500 * 1024 * 1024
MAX_MODULE_PATH_BYTES: int = 256
MAX_VERSION_BYTES: int = 128

_H1_RE = re.compile(r"^h1:[A-Za-z0-9+/]{43}=$")
_MODULE_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]*(?:/[A-Za-z0-9][A-Za-z0-9._~-]*)+$")


class ProvenanceError(CutError):
    """Sanitized failure for Go h1 or sumdb provenance verification."""


def compute_go_mod_h1(mod_bytes: bytes) -> str:
    """Compute the Go h1 checksum for a go.mod file.

    Follows the Go dirhash.Hash1 specification for a single file "go.mod":
    Computes hex SHA-256 of the go.mod bytes, formats the summary line:
      f"{hex_sha256}  go.mod\n"
    and hashes that line with SHA-256, encoded as "h1:" + base64.
    """
    if not isinstance(mod_bytes, bytes):
        raise ProvenanceError("go.mod content must be bytes")
    if len(mod_bytes) > MAX_FILE_BYTES:
        raise ProvenanceError("go.mod exceeds maximum byte limit")
    file_hex = hashlib.sha256(mod_bytes).hexdigest()
    summary_line = f"{file_hex}  go.mod\n".encode("utf-8")
    digest = hashlib.sha256(summary_line).digest()
    return "h1:" + base64.b64encode(digest).decode("ascii")


def compute_go_zip_h1(zip_bytes: bytes, module_path: str, version: str) -> str:
    """Compute the Go h1 directory hash for a module zip archive.

    Follows the dirhash.HashZip and dirhash.Hash1 specifications from Go:
    Each file in the zip must start with '{module_path}@{version}/'.
    Directory entries are skipped.
    For each file:
      file_hash = hex(sha256(file_content))
      line = f"{file_hash}  {full_entry_name}\n"
    Lines are sorted lexicographically by full entry name (ASCII byte order).
    The final hash is h1: + base64(sha256(concatenated_lines)).
    """
    if not isinstance(zip_bytes, bytes):
        raise ProvenanceError("Module zip content must be bytes")
    if len(zip_bytes) > MAX_ZIP_BYTES:
        raise ProvenanceError("Module zip exceeds maximum byte limit")
    if not isinstance(module_path, str) or not _MODULE_PATH_RE.fullmatch(module_path):
        raise ProvenanceError("Invalid module path")
    if not isinstance(version, str) or len(version) > MAX_VERSION_BYTES or not version.startswith("v"):
        raise ProvenanceError("Invalid version for Go module")

    prefix = f"{module_path}@{version}/"

    try:
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes), mode="r")
    except zipfile.BadZipFile as exc:
        raise ProvenanceError("Malformed module zip archive") from exc

    namelist = archive.namelist()
    if len(namelist) > MAX_ZIP_FILES:
        raise ProvenanceError("Module zip contains too many entries")

    declared_total = sum(item.file_size for item in archive.infolist() if not item.filename.endswith("/"))
    if declared_total > MAX_UNCOMPRESSED_ZIP_BYTES:
        raise ProvenanceError("Total declared uncompressed size exceeds cap")

    files_map: dict[str, str] = {}
    seen_paths: set[str] = set()
    total_uncompressed_read = 0

    for item in archive.infolist():
        filename = item.filename
        if len(filename.encode("utf-8")) > MAX_PATH_BYTES:
            raise ProvenanceError("File path in module zip exceeds byte cap")
        if "\x00" in filename or "\\" in filename:
            raise ProvenanceError("Invalid path characters in module zip")

        # Skip directory entries
        if filename.endswith("/") or (hasattr(item, "is_dir") and item.is_dir()):
            continue

        if not filename.startswith(prefix):
            raise ProvenanceError(f"File in module zip does not begin with prefix {prefix}")

        rel_path = filename[len(prefix):]
        # Validate relative path (no leading slash, no '..', normalized)
        norm_rel = posixpath.normpath(rel_path)
        if norm_rel.startswith("../") or norm_rel == ".." or norm_rel.startswith("/"):
            raise ProvenanceError("Directory traversal path in module zip")
        if norm_rel in seen_paths:
            raise ProvenanceError("Duplicate file entry in module zip")
        seen_paths.add(norm_rel)

        if item.file_size > MAX_FILE_BYTES:
            raise ProvenanceError("Uncompressed file size exceeds cap")

        try:
            content = archive.read(item)
        except (zipfile.BadZipFile, OSError) as exc:
            raise ProvenanceError("Error decompressing zip entry") from exc

        if len(content) > MAX_FILE_BYTES:
            raise ProvenanceError("Decompressed content exceeds cap")

        total_uncompressed_read += len(content)
        if total_uncompressed_read > MAX_UNCOMPRESSED_ZIP_BYTES:
            raise ProvenanceError("Total uncompressed content exceeds cap")

        file_hex = hashlib.sha256(content).hexdigest()
        files_map[filename] = file_hex

    if not files_map:
        raise ProvenanceError("Module zip contains no regular files")

    # Sort files lexicographically by full entry path (ASCII byte order) per Go dirhash.HashZip
    lines: list[bytes] = []
    for full_name in sorted(files_map.keys()):
        if "\n" in full_name:
            raise ProvenanceError("Filename contains newline character")
        line = f"{files_map[full_name]}  {full_name}\n".encode("utf-8")
        lines.append(line)

    h = hashlib.sha256(b"".join(lines)).digest()
    return "h1:" + base64.b64encode(h).decode("ascii")


def verify_go_provenance(
    module_path: str,
    version: str,
    mod_bytes: bytes,
    zip_bytes: bytes,
    *,
    expected_mod_h1: str | None = None,
    expected_zip_h1: str | None = None,
) -> tuple[str, str]:
    """Verify and compute the Go h1 checksums for both .mod and .zip files.

    If expected checksums are provided, verifies that they match exactly.
    Returns (zip_h1, mod_h1).
    """
    mod_h1 = compute_go_mod_h1(mod_bytes)
    zip_h1 = compute_go_zip_h1(zip_bytes, module_path, version)

    if expected_mod_h1 is not None:
        if not isinstance(expected_mod_h1, str) or not _H1_RE.fullmatch(expected_mod_h1):
            raise ProvenanceError("Invalid expected mod h1 checksum format")
        if expected_mod_h1 != mod_h1:
            raise ProvenanceError("go.mod h1 checksum mismatch")

    if expected_zip_h1 is not None:
        if not isinstance(expected_zip_h1, str) or not _H1_RE.fullmatch(expected_zip_h1):
            raise ProvenanceError("Invalid expected zip h1 checksum format")
        if expected_zip_h1 != zip_h1:
            raise ProvenanceError("Module zip h1 checksum mismatch")

    return zip_h1, mod_h1


def format_sumdb_lookup(
    module_path: str,
    version: str,
    zip_h1: str,
    mod_h1: str,
    record_id: int = 1,
) -> bytes:
    """Format a sum.golang.org /lookup response for a module version."""
    if not _H1_RE.fullmatch(zip_h1) or not _H1_RE.fullmatch(mod_h1):
        raise ProvenanceError("Invalid h1 format for sumdb record")
    if record_id <= 0:
        raise ProvenanceError("Record ID must be positive")
    body = (
        f"{record_id}\n"
        f"{module_path} {version} {zip_h1}\n"
        f"{module_path} {version}/go.mod {mod_h1}\n"
    )
    return body.encode("utf-8")


def format_go_sum(
    module_path: str,
    version: str,
    zip_h1: str,
    mod_h1: str,
) -> bytes:
    """Format canonical go.sum lines for a module version."""
    if not _H1_RE.fullmatch(zip_h1) or not _H1_RE.fullmatch(mod_h1):
        raise ProvenanceError("Invalid h1 format for go.sum entry")
    body = (
        f"{module_path} {version} {zip_h1}\n"
        f"{module_path} {version}/go.mod {mod_h1}\n"
    )
    return body.encode("utf-8")
