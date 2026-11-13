
"""World manifest comparison, file classification, and diff localisation for E7."""

from __future__ import annotations

import difflib
import itertools
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hermetic_e7.tree import (
    CapExceededError,
    READ_CHUNK_BYTES,
    UnsupportedEntryError,
    WorldPathError,
    build_manifest,
    open_regular_no_follow,
)

# Named constant caps bounding every read and loop.
EXT4_BLOCK_SIZE: int = 4_096
MAX_IMAGE_BLOCKS: int = 1_048_576
MAX_JSON_BYTES: int = 16 * 1024 * 1024
MAX_JSON_READ_CHUNKS: int = (MAX_JSON_BYTES // READ_CHUNK_BYTES) + 2
MAX_JSON_NODES: int = 200_000
MAX_JSON_DEPTH: int = 64
MAX_REPORTED_JSON_PATHS: int = 50
MAX_TEXT_BYTES: int = 16 * 1024 * 1024
MAX_TEXT_READ_CHUNKS: int = (MAX_TEXT_BYTES // READ_CHUNK_BYTES) + 2
MAX_TEXT_LINES: int = 200_000
MAX_DIFF_LINES: int = 40
MAX_DIFF_ENTRIES: int = 10_000
MAX_REPORTED_ITEMS: int = 200
MAX_CAUSE_KEYS: int = 50

SUSPECTED_CAUSE_KEYWORDS: tuple[str, ...] = (
    "mtime",
    "time",
    "date",
    "created",
    "modified",
    "timestamp",
    "uuid",
    "hostname",
    "user",
)

_TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".txt",
        ".md",
        ".markdown",
        ".rst",
        ".csv",
        ".tsv",
        ".log",
        ".cfg",
        ".conf",
        ".ini",
        ".toml",
        ".yaml",
        ".yml",
        ".xml",
        ".html",
        ".htm",
        ".css",
        ".js",
        ".ts",
        ".py",
        ".sh",
        ".bash",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".rs",
        ".go",
        ".java",
        ".rb",
        ".sql",
        ".env",
        ".properties",
        ".gitignore",
        ".gitattributes",
    }
)

_TEXT_FILENAMES: frozenset[str] = frozenset(
    {
        "readme",
        "license",
        "makefile",
        "dockerfile",
    }
)

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PATH_SEGMENT_RE = re.compile(r'\.([A-Za-z_][A-Za-z0-9_]*)|\["([^"\\]*(?:\\.[^"\\]*)*)"\]')


@dataclass(frozen=True)
class SuspectedCause:
    """Hint linking differing JSON key names to common non-determinism keywords."""

    key_name: str
    keyword: str


@dataclass(frozen=True)
class JsonLocalisation:
    """Localised differences within a differing JSON file."""

    differing_paths: list[str]
    truncated: bool = False
    suspected_causes: list[SuspectedCause] = field(default_factory=list)
    parse_error: str | None = None


@dataclass(frozen=True)
class TextLocalisation:
    """Localised differences within a differing text file."""

    first_diff_line: int | None
    diff_lines: list[str]
    truncated: bool = False


@dataclass(frozen=True)
class ImageLocalisation:
    """4 KiB block-level difference summary for an ext4 image (*.img)."""

    first_diff_block: int | None
    last_diff_block: int | None
    diff_block_count: int
    total_blocks_compared: int


@dataclass(frozen=True)
class SideOnlyEntry:
    """An entry present in only one of the two world trees."""

    path: str
    entry_type: str
    classification: str | None = None


@dataclass(frozen=True)
class SizeHashDiff:
    """A regular file present in both worlds whose size or SHA-256 differs."""

    path: str
    classification: str
    size_a: int
    size_b: int
    sha256_a: str
    sha256_b: str
    json_loc: JsonLocalisation | None = None
    text_loc: TextLocalisation | None = None
    image_loc: ImageLocalisation | None = None


@dataclass(frozen=True)
class ModeDiff:
    """An entry present in both worlds whose executable bit or entry type differs."""

    path: str
    classification: str | None
    detail: str


@dataclass(frozen=True)
class ComparisonReport:
    """Complete structured comparison result for two worlds."""

    reproducible: bool
    status: str
    root_a: str
    root_b: str
    only_in_a: list[SideOnlyEntry] = field(default_factory=list)
    only_in_b: list[SideOnlyEntry] = field(default_factory=list)
    size_hash_diffs: list[SizeHashDiff] = field(default_factory=list)
    mode_diffs: list[ModeDiff] = field(default_factory=list)


def classify_file(rel_path: str) -> str:
    """Classify a file by name: ext4 image, tar, JSON, text, or other."""
    name = Path(rel_path).name
    lower = name.lower()
    if lower.endswith(".img"):
        return "ext4 image"
    if lower.endswith(".tar.gz") or lower.endswith(".tar"):
        return "tar"
    if lower.endswith(".json"):
        return "JSON"
    if lower in _TEXT_FILENAMES or Path(lower).suffix in _TEXT_EXTENSIONS:
        return "text"
    return "other"


def _open_regular_file(full_path: Path, rel_path: str) -> int:
    """Open a regular file without following symlinks and verify its file status."""
    fd = open_regular_no_follow(full_path, rel_path)

    try:
        st = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise WorldPathError(rel_path, exc.strerror or str(exc)) from exc

    if stat.S_ISLNK(st.st_mode):
        os.close(fd)
        raise UnsupportedEntryError(rel_path, "symlink")
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise UnsupportedEntryError(rel_path, "non-regular file")
    if st.st_nlink > 1:
        os.close(fd)
        raise UnsupportedEntryError(rel_path, "hard link")
    return fd


def _read_bounded_bytes(
    full_path: Path,
    rel_path: str,
    max_bytes: int,
    max_chunks: int,
    cap_name: str,
) -> bytes:
    """Read a regular file into memory up to a strict byte and chunk cap."""
    fd = _open_regular_file(full_path, rel_path)
    try:
        buf = bytearray()
        for _ in range(max_chunks):
            try:
                chunk = os.read(fd, READ_CHUNK_BYTES)
            except OSError as exc:
                raise WorldPathError(rel_path, exc.strerror or str(exc)) from exc
            if not chunk:
                return bytes(buf)
            if len(buf) + len(chunk) > max_bytes:
                raise CapExceededError(cap_name, max_bytes, rel_path)
            buf.extend(chunk)
        raise CapExceededError(cap_name, max_bytes, rel_path)
    finally:
        os.close(fd)


def _format_json_child(prefix: str, key: str) -> str:
    """Append an object key to a JSONPath prefix deterministically."""
    if _IDENT_RE.match(key):
        return f"{prefix}.{key}"
    return f"{prefix}[{json.dumps(key)}]"


def _json_values_equal(a: Any, b: Any) -> bool:
    """Compare JSON scalars strictly so bool True/False never equals int 1/0."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return a == b


def _extract_suspected_causes(differing_paths: list[str]) -> list[SuspectedCause]:
    """Identify common non-determinism key names present in differing JSON paths."""
    seen: set[tuple[str, str]] = set()
    causes: list[SuspectedCause] = []

    for json_path in differing_paths[:MAX_REPORTED_JSON_PATHS]:
        for match in _PATH_SEGMENT_RE.finditer(json_path):
            raw_key = match.group(1) if match.group(1) is not None else match.group(2)
            if raw_key is None:
                continue
            key_lower = raw_key.lower()
            for kw in SUSPECTED_CAUSE_KEYWORDS:
                if kw in key_lower:
                    pair = (raw_key, kw)
                    if pair not in seen:
                        seen.add(pair)
                        causes.append(SuspectedCause(key_name=raw_key, keyword=kw))
                        if len(causes) >= MAX_CAUSE_KEYS:
                            return sorted(causes, key=lambda c: (c.key_name, c.keyword))

    return sorted(causes, key=lambda c: (c.key_name, c.keyword))


def _localize_json(path_a: Path, path_b: Path, rel_path: str) -> JsonLocalisation:
    """Find differing JSON paths up to MAX_REPORTED_JSON_PATHS and detect suspected causes."""
    raw_a = _read_bounded_bytes(path_a, rel_path, MAX_JSON_BYTES, MAX_JSON_READ_CHUNKS, "MAX_JSON_BYTES")
    raw_b = _read_bounded_bytes(path_b, rel_path, MAX_JSON_BYTES, MAX_JSON_READ_CHUNKS, "MAX_JSON_BYTES")

    try:
        doc_a = json.loads(raw_a.decode("utf-8"))
        doc_b = json.loads(raw_b.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        # ValueError covers JSONDecodeError and over-long integer literals;
        # RecursionError covers nesting deeper than the parser's stack.
        return JsonLocalisation(
            differing_paths=[],
            truncated=False,
            suspected_causes=[],
            parse_error=str(exc),
        )

    differing_paths: list[str] = []
    truncated = False
    stack: list[tuple[str, Any, Any, int]] = [("$", doc_a, doc_b, 0)]

    for _ in range(MAX_JSON_NODES):
        if not stack:
            break
        if len(differing_paths) >= MAX_REPORTED_JSON_PATHS:
            truncated = True
            break

        cur_path, val_a, val_b, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            differing_paths.append(cur_path)
            continue

        if isinstance(val_a, dict) and isinstance(val_b, dict):
            all_keys = sorted(set(val_a.keys()) | set(val_b.keys()))
            pending: list[tuple[str, Any, Any, int]] = []
            for key in all_keys:
                child_path = _format_json_child(cur_path, str(key))
                if key not in val_a or key not in val_b:
                    if len(differing_paths) >= MAX_REPORTED_JSON_PATHS:
                        truncated = True
                        break
                    differing_paths.append(child_path)
                else:
                    pending.append((child_path, val_a[key], val_b[key], depth + 1))
            for item in reversed(pending):
                stack.append(item)
        elif isinstance(val_a, list) and isinstance(val_b, list):
            min_len = min(len(val_a), len(val_b))
            max_len = max(len(val_a), len(val_b))
            for extra_idx in range(min_len, max_len):
                if len(differing_paths) >= MAX_REPORTED_JSON_PATHS:
                    truncated = True
                    break
                differing_paths.append(f"{cur_path}[{extra_idx}]")
            for idx in range(min_len - 1, -1, -1):
                stack.append((f"{cur_path}[{idx}]", val_a[idx], val_b[idx], depth + 1))
        else:
            if not _json_values_equal(val_a, val_b):
                differing_paths.append(cur_path)
    else:
        if stack:
            truncated = True

    causes = _extract_suspected_causes(differing_paths)
    return JsonLocalisation(
        differing_paths=differing_paths,
        truncated=truncated,
        suspected_causes=causes,
    )


def _localize_text(path_a: Path, path_b: Path, rel_path: str) -> TextLocalisation:
    """Find the first differing line number (1-based) and a bounded unified diff."""
    raw_a = _read_bounded_bytes(path_a, rel_path, MAX_TEXT_BYTES, MAX_TEXT_READ_CHUNKS, "MAX_TEXT_BYTES")
    raw_b = _read_bounded_bytes(path_b, rel_path, MAX_TEXT_BYTES, MAX_TEXT_READ_CHUNKS, "MAX_TEXT_BYTES")

    lines_a = raw_a.decode("utf-8", errors="replace").splitlines()
    lines_b = raw_b.decode("utf-8", errors="replace").splitlines()

    if len(lines_a) > MAX_TEXT_LINES or len(lines_b) > MAX_TEXT_LINES:
        raise CapExceededError("MAX_TEXT_LINES", MAX_TEXT_LINES, rel_path)

    min_len = min(len(lines_a), len(lines_b))
    first_diff_line: int | None = None
    for idx in range(min_len):
        if lines_a[idx] != lines_b[idx]:
            first_diff_line = idx + 1
            break

    if first_diff_line is None and len(lines_a) != len(lines_b):
        first_diff_line = min_len + 1

    raw_diff = difflib.unified_diff(
        lines_a,
        lines_b,
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
        lineterm="",
        n=2,
    )
    bounded = list(itertools.islice(raw_diff, MAX_DIFF_LINES + 1))
    truncated = len(bounded) > MAX_DIFF_LINES
    return TextLocalisation(
        first_diff_line=first_diff_line,
        diff_lines=bounded[:MAX_DIFF_LINES],
        truncated=truncated,
    )


def _read_block(fd: int, rel_path: str, block_size: int) -> bytes:
    """Read up to block_size bytes from fd in a bounded loop."""
    buf = bytearray()
    for _ in range(block_size):
        remaining = block_size - len(buf)
        if remaining <= 0:
            break
        try:
            chunk = os.read(fd, remaining)
        except OSError as exc:
            raise WorldPathError(rel_path, exc.strerror or str(exc)) from exc
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _localize_image(path_a: Path, path_b: Path, rel_path: str) -> ImageLocalisation:
    """Compare two image files in 4 KiB blocks without ext4 filesystem parsing."""
    fd_a = _open_regular_file(path_a, rel_path)
    try:
        fd_b = _open_regular_file(path_b, rel_path)
        try:
            first_diff: int | None = None
            last_diff: int | None = None
            diff_count = 0
            total_blocks = 0

            for block_idx in range(MAX_IMAGE_BLOCKS + 1):
                block_a = _read_block(fd_a, rel_path, EXT4_BLOCK_SIZE)
                block_b = _read_block(fd_b, rel_path, EXT4_BLOCK_SIZE)
                if not block_a and not block_b:
                    break
                if block_idx >= MAX_IMAGE_BLOCKS:
                    raise CapExceededError("MAX_IMAGE_BLOCKS", MAX_IMAGE_BLOCKS, rel_path)
                total_blocks += 1
                if block_a != block_b:
                    if first_diff is None:
                        first_diff = block_idx
                    last_diff = block_idx
                    diff_count += 1

            return ImageLocalisation(
                first_diff_block=first_diff,
                last_diff_block=last_diff,
                diff_block_count=diff_count,
                total_blocks_compared=total_blocks,
            )
        finally:
            os.close(fd_b)
    finally:
        os.close(fd_a)


def compare_worlds(dir_a: str | Path, dir_b: str | Path) -> ComparisonReport:
    """Compare two sealed world directories and localise any differences."""
    manifest_a = build_manifest(dir_a)
    manifest_b = build_manifest(dir_b)
    root_a: str = manifest_a["root"]
    root_b: str = manifest_b["root"]

    if root_a == root_b:
        return ComparisonReport(
            reproducible=True,
            status="reproducible",
            root_a=root_a,
            root_b=root_b,
        )

    map_a: dict[str, dict[str, Any]] = {e["path"]: e for e in manifest_a["entries"]}
    map_b: dict[str, dict[str, Any]] = {e["path"]: e for e in manifest_b["entries"]}
    all_paths = sorted(set(map_a.keys()) | set(map_b.keys()), key=lambda p: p.encode("utf-8"))

    only_in_a: list[SideOnlyEntry] = []
    only_in_b: list[SideOnlyEntry] = []
    size_hash_diffs: list[SizeHashDiff] = []
    mode_diffs: list[ModeDiff] = []

    root_path_a = Path(dir_a)
    root_path_b = Path(dir_b)
    diff_counter = 0

    for rel_path in all_paths:
        in_a = rel_path in map_a
        in_b = rel_path in map_b

        if in_a and not in_b:
            diff_counter += 1
            if diff_counter > MAX_DIFF_ENTRIES:
                raise CapExceededError("MAX_DIFF_ENTRIES", MAX_DIFF_ENTRIES, rel_path)
            entry_a = map_a[rel_path]
            kind = classify_file(rel_path) if entry_a["type"] == "file" else None
            only_in_a.append(SideOnlyEntry(path=rel_path, entry_type=entry_a["type"], classification=kind))
            continue

        if in_b and not in_a:
            diff_counter += 1
            if diff_counter > MAX_DIFF_ENTRIES:
                raise CapExceededError("MAX_DIFF_ENTRIES", MAX_DIFF_ENTRIES, rel_path)
            entry_b = map_b[rel_path]
            kind = classify_file(rel_path) if entry_b["type"] == "file" else None
            only_in_b.append(SideOnlyEntry(path=rel_path, entry_type=entry_b["type"], classification=kind))
            continue

        entry_a = map_a[rel_path]
        entry_b = map_b[rel_path]

        if entry_a["type"] != entry_b["type"]:
            diff_counter += 1
            if diff_counter > MAX_DIFF_ENTRIES:
                raise CapExceededError("MAX_DIFF_ENTRIES", MAX_DIFF_ENTRIES, rel_path)
            mode_diffs.append(
                ModeDiff(
                    path=rel_path,
                    classification=None,
                    detail=f"type {entry_a['type']} -> {entry_b['type']}",
                )
            )
            continue

        if entry_a["type"] == "file":
            kind = classify_file(rel_path)
            mode_changed = entry_a["executable"] != entry_b["executable"]
            content_changed = (
                entry_a["size"] != entry_b["size"] or entry_a["sha256"] != entry_b["sha256"]
            )

            if mode_changed or content_changed:
                diff_counter += 1
                if diff_counter > MAX_DIFF_ENTRIES:
                    raise CapExceededError("MAX_DIFF_ENTRIES", MAX_DIFF_ENTRIES, rel_path)

            if mode_changed:
                mode_a = "executable" if entry_a["executable"] else "non-executable"
                mode_b = "executable" if entry_b["executable"] else "non-executable"
                mode_diffs.append(
                    ModeDiff(
                        path=rel_path,
                        classification=kind,
                        detail=f"{mode_a} -> {mode_b}",
                    )
                )

            if content_changed:
                full_a = root_path_a / rel_path
                full_b = root_path_b / rel_path
                json_loc: JsonLocalisation | None = None
                text_loc: TextLocalisation | None = None
                image_loc: ImageLocalisation | None = None

                if kind == "JSON":
                    json_loc = _localize_json(full_a, full_b, rel_path)
                elif kind == "text":
                    text_loc = _localize_text(full_a, full_b, rel_path)
                elif kind == "ext4 image":
                    image_loc = _localize_image(full_a, full_b, rel_path)

                size_hash_diffs.append(
                    SizeHashDiff(
                        path=rel_path,
                        classification=kind,
                        size_a=entry_a["size"],
                        size_b=entry_b["size"],
                        sha256_a=entry_a["sha256"],
                        sha256_b=entry_b["sha256"],
                        json_loc=json_loc,
                        text_loc=text_loc,
                        image_loc=image_loc,
                    )
                )

    return ComparisonReport(
        reproducible=False,
        status="differs",
        root_a=root_a,
        root_b=root_b,
        only_in_a=only_in_a,
        only_in_b=only_in_b,
        size_hash_diffs=size_hash_diffs,
        mode_diffs=mode_diffs,
    )


def format_report(report: ComparisonReport) -> str:
    """Format a ComparisonReport into a deterministic, human-readable report."""
    if report.reproducible:
        return f"reproducible\nroot: {report.root_a}"

    lines: list[str] = [
        "differs",
        f"root_a: {report.root_a}",
        f"root_b: {report.root_b}",
    ]

    lines.append("only-in-A:")
    if not report.only_in_a:
        lines.append("  (none)")
    else:
        for item in itertools.islice(report.only_in_a, MAX_REPORTED_ITEMS):
            if item.classification:
                lines.append(f"  - {item.path} ({item.entry_type}, {item.classification})")
            else:
                lines.append(f"  - {item.path} ({item.entry_type})")

    lines.append("only-in-B:")
    if not report.only_in_b:
        lines.append("  (none)")
    else:
        for item in itertools.islice(report.only_in_b, MAX_REPORTED_ITEMS):
            if item.classification:
                lines.append(f"  - {item.path} ({item.entry_type}, {item.classification})")
            else:
                lines.append(f"  - {item.path} ({item.entry_type})")

    lines.append("size/hash differences:")
    if not report.size_hash_diffs:
        lines.append("  (none)")
    else:
        for diff in itertools.islice(report.size_hash_diffs, MAX_REPORTED_ITEMS):
            lines.append(
                f"  - {diff.path} [{diff.classification}]: "
                f"size {diff.size_a} -> {diff.size_b}, "
                f"sha256 {diff.sha256_a} -> {diff.sha256_b}"
            )
            if diff.json_loc is not None:
                if diff.json_loc.parse_error:
                    lines.append(f"    JSON parse error: {diff.json_loc.parse_error}")
                else:
                    paths_str = ", ".join(diff.json_loc.differing_paths) or "(none)"
                    suffix = " (truncated)" if diff.json_loc.truncated else ""
                    lines.append(f"    JSON differing paths: {paths_str}{suffix}")
                    if diff.json_loc.suspected_causes:
                        formatted_causes = [
                            c.key_name
                            if c.key_name.lower() == c.keyword
                            else f"{c.key_name} ({c.keyword})"
                            for c in diff.json_loc.suspected_causes
                        ]
                        lines.append(f"    suspected cause: {', '.join(formatted_causes)}")
            elif diff.text_loc is not None:
                lines.append(f"    first differing line: {diff.text_loc.first_diff_line}")
                for dline in diff.text_loc.diff_lines:
                    lines.append(f"    | {dline}")
                if diff.text_loc.truncated:
                    lines.append("    | ... (diff truncated)")
            elif diff.image_loc is not None:
                lines.append(
                    f"    4 KiB blocks: first differing block: {diff.image_loc.first_diff_block}, "
                    f"last differing block: {diff.image_loc.last_diff_block}, "
                    f"differing block count: {diff.image_loc.diff_block_count}"
                )

    lines.append("mode differences:")
    if not report.mode_diffs:
        lines.append("  (none)")
    else:
        for mdiff in itertools.islice(report.mode_diffs, MAX_REPORTED_ITEMS):
            cls_tag = f" [{mdiff.classification}]" if mdiff.classification else ""
            lines.append(f"  - {mdiff.path}{cls_tag}: {mdiff.detail}")

    return "\n".join(lines)


