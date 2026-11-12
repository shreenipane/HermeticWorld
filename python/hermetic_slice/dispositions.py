"""Dispositions engine and CLI for tasks that fail the sealcheck gate (§5.5, TRD.md).

A task that fails the leak gate must never be dropped silently, because that changes
the score's denominator (§5.5). Each failing task gets a disposition:
  - 'clean': task passed the gate (no gate findings)
  - 'repaired': sealer removed the leak without changing the task, and re-scan is clean
  - 'excluded': the leak *is* the task (issue text is the fix), or a non-D0 detector has no
    automatic removal, or re-scan remained dirty after redaction.

# Offsets and Hash Convention
Byte offsets into the UTF-8 encoding of the statement, and lowercase hexadecimal SHA-256
for the span hash, in BOTH Python and Rust (§5.5, TRD.md).
Span objects record `start` (byte offset), `end` (byte offset), `sha256` (hex digest),
and `hash` (`sha256:<hex>`). The leaked text itself is NEVER recorded or logged.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import copy
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import selectors
import stat
import time
import uuid
import subprocess
import sys
import tempfile
from typing import Any, Callable


# Exclusion threshold: if redacting the leak would remove strictly more than 50%
# (fraction > MAX_REDACTION_FRACTION) of the problem statement UTF-8 bytes, or leave
# strictly fewer than 20 non-whitespace characters (remaining < MIN_REMAINING_CHARS),
# the leak *is* the task ("the issue text is the fix", §5.5).
# Exactly 50% (fraction <= 0.50) and exactly 20 characters (remaining >= 20) are eligible for repair.
MAX_REDACTION_FRACTION: float = 0.50
MIN_REMAINING_CHARS: int = 20

# Limits apply before allocation, traversal, parsing, and subprocess collection.
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_STATEMENT_BYTES = 1024 * 1024
MAX_PATCH_BYTES = 4 * 1024 * 1024
MAX_TASKS = 128
MAX_FINDINGS = 4096
MAX_SPANS = 4096
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100000
MAX_PATH_COMPONENTS = 128
MAX_PROCESS_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_PROCESS_READ_BYTES = 64 * 1024
PROCESS_TIMEOUT_SECONDS = 30.0
MAX_SCAN_ROOTS = 32
MAX_TOTAL_TASK_BYTES = 32 * 1024 * 1024
MAX_TASK_ID_BYTES = 128
MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_FINDING_PATH_BYTES = 4096
MAX_CHANNEL_BYTES = 64
DETECTORS = frozenset([f"D{i}" for i in range(13)] + ["D3b", "D5a", "T2"])

# Strict pattern for task_id: SWE-bench instance IDs (e.g. django__django-11099, sympy__sympy-20590).
# Alphanumeric, underscores, hyphens, periods. No '/', no '..', no leading '.'.
TASK_ID_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$")


class DispositionsError(Exception):
    """Base error for dispositions processing."""


class MalformedGateOutputError(DispositionsError):
    """Raised when gate output is corrupted, invalid JSON, or missing required fields."""


class MissingDispositionError(DispositionsError):
    """Raised when any task in the input set lacks a valid disposition or is missing from input."""


@dataclass(frozen=True)
class RedactedSpan:
    """Record of a single redacted span in the problem statement.

    Records UTF-8 byte offsets and SHA-256 cryptographic digest, NEVER the leaked text itself (§5.5).
    """

    start: int
    end: int
    sha256: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "end": self.end,
            "sha256": self.sha256,
            "hash": self.hash,
        }


@dataclass
class TaskDispositionResult:
    """Disposition result for a single task."""

    task_id: str
    disposition: str  # 'clean', 'repaired', 'excluded'
    detectors: list[str] = field(default_factory=list)
    reason: str = ""
    world_version: str | None = None
    redacted_spans: list[RedactedSpan] = field(default_factory=list)
    redacted_statement: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "disposition": self.disposition,
            "detectors": sorted(list(self.detectors)),
            "reason": self.reason,
            "world_version": self.world_version,
        }


def validate_task_id(task_id: Any) -> str:
    """Validate task_id against strict containment regex (no path traversal, no symlink tricks)."""
    if not isinstance(task_id, str):
        raise MalformedGateOutputError("task_id must be a string")
    if len(task_id) > MAX_TASK_ID_BYTES or not TASK_ID_REGEX.fullmatch(task_id) or ".." in task_id or "/" in task_id or task_id.startswith("."):
        raise MalformedGateOutputError("Invalid task_id format")
    return task_id


class SafeDirectory:
    """Retain no-follow directory descriptors for all filesystem operations."""

    def __init__(self, path: Path):
        self.fd = -1
        absolute = Path(os.path.abspath(path))
        if len(absolute.parts) > MAX_PATH_COMPONENTS:
            raise DispositionsError("Path component cap exceeded")
        self.fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in absolute.parts[1:]:
                next_fd = self._open_directory(part)
                os.close(self.fd)
                self.fd = next_fd
        except BaseException:
            self.close()
            raise

    def _open_directory(self, name: str) -> int:
        try:
            before = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise DispositionsError("Symlink rejected or non-directory component")
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                os.close(fd)
                raise DispositionsError("Directory changed during traversal")
            return fd
        except OSError:
            raise DispositionsError("Directory access rejected") from None

    def child(self, name: str) -> SafeDirectory:
        child = object.__new__(SafeDirectory)
        child.fd = self._open_directory(name)
        return child

    def close(self) -> None:
        if getattr(self, "fd", -1) >= 0:
            os.close(self.fd)
            self.fd = -1

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> SafeDirectory:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def names(self, cap: int = MAX_TASKS) -> list[str]:
        names = []
        try:
            with os.scandir(self.fd) as items:
                for item in items:
                    if len(names) >= cap:
                        if cap == MAX_SNAPSHOT_ENTRIES:
                            raise DispositionsError("Snapshot entry count cap exceeded")
                        raise DispositionsError("Directory entry cap exceeded")
                    names.append(item.name)
        except OSError as e:
            raise DispositionsError("Directory enumeration failed") from e
        return sorted(names)

    def check_file(self, name: str) -> os.stat_result | None:
        try:
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode):
            raise DispositionsError("Symlink rejected or non-regular file")
        return info

    def read(self, name: str, cap: int, *, optional: bool = False) -> str | None:
        before = self.check_file(name)
        if before is None:
            if optional:
                return None
            raise DispositionsError("Required file unavailable")
        if before.st_size > cap:
            raise DispositionsError("File byte cap exceeded")
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
            with os.fdopen(fd, "rb") as stream:
                after = os.fstat(stream.fileno())
                if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise DispositionsError("File changed during open")
                raw = stream.read(cap + 1)
            if len(raw) > cap:
                raise DispositionsError("File byte cap exceeded")
            return raw.decode("utf-8")
        except (OSError, UnicodeError):
            raise DispositionsError("File access rejected") from None

    def write(self, name: str, content: str) -> None:
        self.check_file(name)
        temp_name = ".disposition-" + uuid.uuid4().hex
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            self.check_file(name)
            os.replace(temp_name, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            try:
                os.unlink(temp_name, dir_fd=self.fd)
            except FileNotFoundError:
                pass


def bounded_structure(data: Any) -> None:
    pending = [(data, 0)]
    count = 0
    string_bytes = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise MalformedGateOutputError("JSON structure cap exceeded")
        if isinstance(value, (dict, list, tuple)):
            if len(value) > MAX_JSON_NODES:
                raise MalformedGateOutputError("JSON item cap exceeded")
            children = list(value.items()) if isinstance(value, dict) else value
            pending.extend((item, depth + 1) for item in children)
        elif isinstance(value, str):
            string_bytes += len(value.encode("utf-8"))
            if string_bytes > MAX_REPORT_BYTES:
                raise MalformedGateOutputError("JSON string cap exceeded")
        elif value is not None and type(value) not in (bool, int, float):
            raise MalformedGateOutputError("Invalid JSON value")


def parse_json(content: str) -> Any:
    if len(content.encode("utf-8")) > MAX_REPORT_BYTES:
        raise MalformedGateOutputError("JSON byte cap exceeded")
    # Bound nesting before the recursive decoder runs; braces in strings are ignored.
    depth = 0
    quoted = escaped = False
    for char in content:
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted:
            if char in "[{":
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    raise MalformedGateOutputError("JSON nesting cap exceeded")
            elif char in "]}":
                depth -= 1
    try:
        result = json.loads(content)
        bounded_structure(result)
        return result
    except (ValueError, RecursionError, UnicodeError):
        raise MalformedGateOutputError("Invalid JSON") from None


def bounded_process(command: list[str], timeout: float = PROCESS_TIMEOUT_SECONDS) -> tuple[int, str]:
    """Bound both pipes while the child runs, and terminate on deadline or overflow."""
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={"PATH": "/usr/bin:/bin", "LANG": "C"}) as proc:
        try:
            output = bytearray()
            total = 0
            deadline = time.monotonic() + min(timeout, PROCESS_TIMEOUT_SECONDS)
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ, True)
                selector.register(proc.stderr, selectors.EVENT_READ, False)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise DispositionsError("Process time cap exceeded")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fileobj.fileno(), MAX_PROCESS_READ_BYTES)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > MAX_PROCESS_OUTPUT_BYTES:
                            raise DispositionsError("Process output cap exceeded")
                        if key.data:
                            output.extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DispositionsError("Process time cap exceeded")
            code = proc.wait(timeout=remaining)
            return code, output.decode("utf-8")
        except BaseException as error:
            proc.kill()
            proc.wait()
            if isinstance(error, (subprocess.TimeoutExpired, UnicodeError)):
                raise DispositionsError("Process verification failed") from None
            raise


def find_binary(bin_name: str, custom_path: str | Path | None = None, env_var: str | None = None) -> str:
    """Locate executable binary securely."""
    if custom_path:
        cp = Path(custom_path)
        if cp.is_file() and os.access(cp, os.X_OK):
            return str(cp.resolve())
    if env_var:
        env_val = os.environ.get(env_var)
        if env_val:
            ep = Path(env_val)
            if ep.is_file() and os.access(ep, os.X_OK):
                return str(ep.resolve())

    which = shutil.which(bin_name)
    if which:
        return which

    candidates = [
        Path(f"target/debug/{bin_name}"),
        Path(f"target/release/{bin_name}"),
        Path(f"/home/flingboot/hermetic/cargo-target/t1.14/debug/{bin_name}"),
    ]
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return str(c.resolve())

    raise FileNotFoundError(f"Could not locate {bin_name} binary")


def validate_and_merge_spans(statement_bytes_len: int, spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Validate, sort, and merge overlapping, nested, or adjacent UTF-8 byte spans.

    Offsets must be within [0, statement_bytes_len].
    """
    if len(spans) > MAX_SPANS:
        raise DispositionsError("Span count cap exceeded")
    for span in spans:
        if not isinstance(span, (list, tuple)) or len(span) != 2 or any(type(v) is not int for v in span):
            raise DispositionsError("Invalid span")
        s_start, s_end = span
        if not (0 <= s_start <= s_end <= statement_bytes_len):
            raise DispositionsError("Invalid span offset range")

    if not spans:
        return []

    # Sort by start offset ascending, then end offset ascending
    sorted_spans = sorted(spans, key=lambda s: (s[0], s[1]))
    merged: list[tuple[int, int]] = [sorted_spans[0]]

    for s_start, s_end in sorted_spans[1:]:
        last_start, last_end = merged[-1]
        if s_start <= last_end:
            # Overlapping, nested, or adjacent: merge
            merged[-1] = (last_start, max(last_end, s_end))
        else:
            merged.append((s_start, s_end))

    return merged


def char_to_byte_span(text: str, char_start: int, char_end: int) -> tuple[int, int]:
    """Map character offsets in text to UTF-8 byte offsets."""
    prefix_bytes = text[:char_start].encode("utf-8")
    span_bytes = text[char_start:char_end].encode("utf-8")
    byte_start = len(prefix_bytes)
    byte_end = byte_start + len(span_bytes)
    return byte_start, byte_end


def find_spans_in_text(text: str, evidence_strings: list[str]) -> list[tuple[int, int]]:
    """Locate evidence string spans in problem statement text and return merged UTF-8 byte spans.

    Matches case-insensitively and whitespace-normalized by mapping back to original statement offsets.
    Splits joined windows on ' / '.
    When evidence is a 200-char truncation of a longer statement line, extends the span to the end of that statement line.
    Does not skip short lines inside multi-line evidence when they are part of the evidence.
    """
    statement_bytes = text.encode("utf-8")
    if len(statement_bytes) > MAX_STATEMENT_BYTES or len(evidence_strings) > MAX_FINDINGS:
        raise DispositionsError("Statement or evidence cap exceeded")
    if any(not isinstance(evidence, str) for evidence in evidence_strings) or sum(len(evidence.encode("utf-8")) for evidence in evidence_strings) > MAX_EVIDENCE_BYTES:
        raise DispositionsError("Invalid evidence or byte cap exceeded")
    raw_byte_spans: list[tuple[int, int]] = []

    # Flatten evidence: split on " / " if joined windows are present
    flattened_evidence: list[str] = []
    for ev in evidence_strings:
        if not ev:
            continue
        if " / " in ev:
            for part in ev.split(" / "):
                part_clean = part.strip()
                if part_clean:
                    if len(flattened_evidence) >= MAX_FINDINGS:
                        raise DispositionsError("Evidence count cap exceeded")
                    flattened_evidence.append(part_clean)
        else:
            flattened_evidence.append(ev)

    if len(flattened_evidence) > MAX_FINDINGS:
        raise DispositionsError("Evidence count cap exceeded")
    for ev in flattened_evidence:
        ev_clean = ev.strip()
        if not ev_clean:
            continue

        # Case-insensitive, whitespace-normalized matching
        words = [w for w in re.split(r"\s+", ev_clean) if w]
        if not words:
            continue

        pattern_str = r"\s+".join(re.escape(w) for w in words)
        try:
            pattern = re.compile(pattern_str, re.IGNORECASE)
        except re.error:
            pattern = re.compile(re.escape(ev_clean), re.IGNORECASE)

        for match in pattern.finditer(text):
            char_s, char_e = match.start(), match.end()

            # If evidence appears to be a 200-char truncation of a longer statement line,
            # extend char_e to the end of that statement line.
            if len(ev_clean) >= 200:
                line_end = text.find("\n", char_e)
                if line_end == -1:
                    line_end = len(text)
                char_e = line_end

            b_start, b_end = char_to_byte_span(text, char_s, char_e)
            if len(raw_byte_spans) >= MAX_SPANS:
                raise DispositionsError("Span count cap exceeded")
            raw_byte_spans.append((b_start, b_end))

    return validate_and_merge_spans(len(statement_bytes), raw_byte_spans)


def redact_problem_statement(
    statement: str,
    byte_spans: list[tuple[int, int]],
    placeholder: str = "[REDACTED]",
) -> tuple[str, list[RedactedSpan]]:
    """Redact UTF-8 byte spans from statement. Returns redacted string and RedactedSpan metadata."""
    statement_bytes = statement.encode("utf-8")
    if len(statement_bytes) > MAX_STATEMENT_BYTES:
        raise DispositionsError("Statement byte cap exceeded")
    merged_spans = validate_and_merge_spans(len(statement_bytes), byte_spans)

    for start, end in merged_spans:
        try:
            statement_bytes[:start].decode("utf-8")
            statement_bytes[:end].decode("utf-8")
        except UnicodeError:
            raise DispositionsError("Span is not on a UTF-8 character boundary") from None
    redacted_records: list[RedactedSpan] = []
    for b_start, b_end in merged_spans:
        span_bytes = statement_bytes[b_start:b_end]
        h = hashlib.sha256(span_bytes).hexdigest()
        redacted_records.append(
            RedactedSpan(
                start=b_start,
                end=b_end,
                sha256=h,
                hash=f"sha256:{h}",
            )
        )

    # Apply redactions in reverse byte order
    placeholder_bytes = placeholder.encode("utf-8")
    if len(placeholder_bytes) > MAX_STATEMENT_BYTES:
        raise DispositionsError("Placeholder byte cap exceeded")
    res_bytes = bytearray(statement_bytes)
    for b_start, b_end in reversed(merged_spans):
        res_bytes[b_start:b_end] = placeholder_bytes

    if len(res_bytes) > MAX_STATEMENT_BYTES:
        raise DispositionsError("Redacted statement byte cap exceeded")
    return res_bytes.decode("utf-8"), redacted_records


def validate_scan_config(config: Any) -> dict[str, Any]:
    if not isinstance(config, dict) or set(config) - {
        "base_tree", "roots", "signatures", "oci_inspect", "oci_history", "target_package", "baseline_budget",
        "_staged_contents", "_tree_stats", "_file_stats"
    }:
        raise DispositionsError("Complete scan configuration required")
    if not isinstance(config.get("base_tree"), str) or not isinstance(config.get("roots"), list) or not 1 <= len(config["roots"]) <= MAX_SCAN_ROOTS:
        raise DispositionsError("Base tree and scan roots required")
    paths = [config["base_tree"]]
    for root in config["roots"]:
        if not isinstance(root, dict) or set(root) != {"path", "visibility"} or not isinstance(root["path"], str) or root["visibility"] not in ("agent_visible", "image_only"):
            raise DispositionsError("Invalid scan root configuration")
        paths.append(root["path"])
    existing_tree_stats = config.get("_tree_stats")
    tree_stats = dict(existing_tree_stats) if isinstance(existing_tree_stats, dict) else {}
    for path in paths:
        with SafeDirectory(Path(path)) as directory:
            st = os.fstat(directory.fd)
            if path in tree_stats and (st.st_dev, st.st_ino) != tuple(tree_stats[path]):
                raise DispositionsError("Scan tree modified or replaced between validation and execution")
            if path not in tree_stats:
                tree_stats[path] = (st.st_dev, st.st_ino)
    config["_tree_stats"] = tree_stats
    staged_contents = {}
    file_stats = {}
    for key in ("signatures", "oci_inspect", "oci_history"):
        if key in config:
            if not isinstance(config[key], str):
                raise DispositionsError("Invalid scan configuration file")
            file_path = Path(config[key])
            with SafeDirectory(file_path.parent) as directory:
                info = directory.check_file(file_path.name)
                if info is None:
                    raise DispositionsError("Required scan configuration file unavailable")
                file_stats[key] = (info.st_dev, info.st_ino)
                staged_contents[key] = directory.read(file_path.name, MAX_REPORT_BYTES)
    config["_staged_contents"] = staged_contents
    config["_file_stats"] = file_stats
    if "target_package" in config and (not isinstance(config["target_package"], list) or len(config["target_package"]) > MAX_TASKS or any(not isinstance(v, str) or len(v) > MAX_TASK_ID_BYTES for v in config["target_package"])):
        raise DispositionsError("Invalid target package configuration")
    if "baseline_budget" in config and (type(config["baseline_budget"]) is not int or not 0 <= config["baseline_budget"] <= MAX_REPORT_BYTES):
        raise DispositionsError("Invalid baseline budget")
    return config


MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_ENTRIES = 100000
MAX_SYMLINK_HOPS = 32


def open_safe_descendant(
    root_dir: SafeDirectory,
    rel_path: tuple[str, ...],
    expected_identities: tuple[tuple[int, int], ...] | None = None,
) -> SafeDirectory:
    """Open a descendant directory safely from root_dir, retaining only 1 open descriptor
    and verifying expected directory identities including all ancestors."""
    if not rel_path:
        new_fd = os.dup(root_dir.fd)
        obj = object.__new__(SafeDirectory)
        obj.fd = new_fd
        return obj
    if expected_identities is not None and len(expected_identities) != len(rel_path):
        raise DispositionsError("Identity chain length mismatch")
    cur_fd = os.dup(root_dir.fd)
    try:
        for idx, part in enumerate(rel_path):
            before = os.stat(part, dir_fd=cur_fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise DispositionsError("Symlink rejected or non-directory component")
            if expected_identities is not None:
                expected_id = expected_identities[idx]
                if (before.st_dev, before.st_ino) != expected_id:
                    raise DispositionsError("Directory substituted or changed during traversal")
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur_fd)
            try:
                after = os.fstat(next_fd)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise DispositionsError("Directory changed during traversal")
                if expected_identities is not None:
                    expected_id = expected_identities[idx]
                    if (after.st_dev, after.st_ino) != expected_id:
                        raise DispositionsError("Directory substituted or changed during traversal")
            except BaseException:
                os.close(next_fd)
                raise
            os.close(cur_fd)
            cur_fd = next_fd
        obj = object.__new__(SafeDirectory)
        obj.fd = cur_fd
        return obj
    except BaseException:
        if cur_fd >= 0:
            os.close(cur_fd)
        raise


def verify_symlink_confined(root_fd: int, rel_path: tuple[str, ...], target: str) -> None:
    """Verify that a symlink target does not escape root_fd using descriptor traversal."""
    if not target:
        raise DispositionsError("Empty symlink target rejected")
    cur_parts = list(rel_path)
    cur_target = target
    hops = 0

    while True:
        if cur_target.startswith("/") or os.path.isabs(cur_target):
            raise DispositionsError("Escaping symlink rejected")

        raw_parts = [p for p in cur_target.split("/") if p and p != "."]
        resolved_parts = list(cur_parts)
        expanded_symlink = False

        for i, comp in enumerate(raw_parts):
            if comp == "..":
                if not resolved_parts:
                    raise DispositionsError("Escaping symlink rejected")
                resolved_parts.pop()
                continue

            cur_fd = os.dup(root_fd)
            try:
                for part in resolved_parts:
                    st = os.stat(part, dir_fd=cur_fd, follow_symlinks=False)
                    if not stat.S_ISDIR(st.st_mode):
                        raise DispositionsError("Symlink path traverses non-directory")
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur_fd)
                    os.close(cur_fd)
                    cur_fd = next_fd

                try:
                    info = os.stat(comp, dir_fd=cur_fd, follow_symlinks=False)
                except FileNotFoundError:
                    if i == len(raw_parts) - 1:
                        resolved_parts.append(comp)
                        break
                    raise DispositionsError("Symlink path traverses non-existent directory")

                if stat.S_ISLNK(info.st_mode):
                    hops += 1
                    if hops > MAX_SYMLINK_HOPS:
                        raise DispositionsError("Symlink hop cap exceeded")
                    try:
                        link_val = os.readlink(comp, dir_fd=cur_fd)
                    except OSError as e:
                        raise DispositionsError("Failed to readlink in traversal") from e
                    if link_val.startswith("/") or os.path.isabs(link_val):
                        raise DispositionsError("Escaping symlink rejected")
                    remaining = raw_parts[i + 1:]
                    if remaining:
                        cur_target = link_val + "/" + "/".join(remaining)
                    else:
                        cur_target = link_val
                    cur_parts = list(resolved_parts)
                    expanded_symlink = True
                    break
                elif stat.S_ISDIR(info.st_mode):
                    resolved_parts.append(comp)
                elif stat.S_ISREG(info.st_mode):
                    if i == len(raw_parts) - 1:
                        resolved_parts.append(comp)
                        break
                    raise DispositionsError("Symlink path traverses regular file as directory")
                else:
                    raise DispositionsError("Unsupported file system entry type in snapshot")
            finally:
                if cur_fd >= 0:
                    os.close(cur_fd)

        if not expanded_symlink:
            break


def validate_snapshot_symlinks(snap_path: Path) -> None:
    """Validate every link against the completed private snapshot using bounded confined traversal."""
    with SafeDirectory(snap_path) as root_dir:
        stack: list[tuple[tuple[str, ...], tuple[tuple[int, int], ...]]] = [((), ())]
        total_entries = 0
        while stack:
            rel_path, id_chain = stack.pop()
            if len(rel_path) > MAX_PATH_COMPONENTS:
                raise DispositionsError("Path component cap exceeded")
            with open_safe_descendant(root_dir, rel_path, id_chain) as curr_dir:
                names = curr_dir.names(cap=MAX_SNAPSHOT_ENTRIES)
                for name in names:
                    total_entries += 1
                    if total_entries > MAX_SNAPSHOT_ENTRIES:
                        raise DispositionsError("Snapshot entry count cap exceeded")
                    try:
                        info = os.stat(name, dir_fd=curr_dir.fd, follow_symlinks=False)
                    except OSError as e:
                        raise DispositionsError("Failed to stat directory entry during snapshot validation") from e
                    if stat.S_ISLNK(info.st_mode):
                        try:
                            target = os.readlink(name, dir_fd=curr_dir.fd)
                        except OSError as e:
                            raise DispositionsError("Failed to readlink during snapshot validation") from e
                        verify_symlink_confined(root_dir.fd, rel_path, target)
                    elif stat.S_ISDIR(info.st_mode):
                        child_chain = id_chain + ((info.st_dev, info.st_ino),)
                        stack.append((rel_path + (name,), child_chain))


def snapshot_tree_safely(src_path: Path, dst_path: Path, max_bytes: int = MAX_SNAPSHOT_BYTES) -> None:
    """Snapshot a directory tree into dst_path using safe descriptor traversal without check-then-use."""
    dst_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    total_bytes = 0
    total_entries = 0
    dir_times: list[tuple[Path, int, int]] = []
    with SafeDirectory(src_path) as root_dir:
        root_stat = os.fstat(root_dir.fd)
        dir_times.append((dst_path, root_stat.st_atime_ns, root_stat.st_mtime_ns))
        stack: list[tuple[tuple[str, ...], tuple[tuple[int, int], ...]]] = [((), ())]
        while stack:
            rel_path, id_chain = stack.pop()
            if len(rel_path) > MAX_PATH_COMPONENTS:
                raise DispositionsError("Path component cap exceeded")
            curr_dst = dst_path
            for part in rel_path:
                curr_dst = curr_dst / part
            curr_dst.mkdir(mode=0o700, exist_ok=True)
            with open_safe_descendant(root_dir, rel_path, id_chain) as curr_dir:
                names = curr_dir.names(cap=MAX_SNAPSHOT_ENTRIES)
                for name in names:
                    total_entries += 1
                    if total_entries > MAX_SNAPSHOT_ENTRIES:
                        raise DispositionsError("Snapshot entry count cap exceeded")
                    try:
                        info = os.stat(name, dir_fd=curr_dir.fd, follow_symlinks=False)
                    except OSError as e:
                        raise DispositionsError("Failed to stat directory entry during snapshot") from e
                    if stat.S_ISLNK(info.st_mode):
                        try:
                            target = os.readlink(name, dir_fd=curr_dir.fd)
                        except OSError as e:
                            raise DispositionsError("Failed to readlink during snapshot traversal") from e
                        verify_symlink_confined(root_dir.fd, rel_path, target)
                        link_dst = curr_dst / name
                        try:
                            os.symlink(target, link_dst)
                        except OSError as e:
                            raise DispositionsError("Failed to create symlink in snapshot") from e
                        try:
                            os.utime(link_dst, ns=(info.st_atime_ns, info.st_mtime_ns), follow_symlinks=False)
                        except (OSError, NotImplementedError) as e:
                            raise DispositionsError("Failed to preserve symlink timestamp in snapshot") from e
                    elif stat.S_ISDIR(info.st_mode):
                        child_dst = curr_dst / name
                        dir_times.append((child_dst, info.st_atime_ns, info.st_mtime_ns))
                        child_chain = id_chain + ((info.st_dev, info.st_ino),)
                        stack.append((rel_path + (name,), child_chain))
                    elif stat.S_ISREG(info.st_mode):
                        if total_bytes + info.st_size > max_bytes:
                            raise DispositionsError("Snapshot byte cap exceeded")
                        fd = -1
                        out_fd = -1
                        try:
                            try:
                                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=curr_dir.fd)
                            except OSError as e:
                                raise DispositionsError("Failed to open file for snapshot") from e
                            after = os.fstat(fd)
                            if not stat.S_ISREG(after.st_mode) or (info.st_dev, info.st_ino) != (after.st_dev, after.st_ino):
                                raise DispositionsError("File changed during snapshot traversal")
                            try:
                                with os.fdopen(fd, "rb") as stream:
                                    fd = -1
                                    content = stream.read(max_bytes - total_bytes + 1)
                            except OSError as e:
                                raise DispositionsError("Failed to read file for snapshot") from e
                            if len(content) > max_bytes - total_bytes:
                                raise DispositionsError("Snapshot byte cap exceeded")
                            total_bytes += len(content)
                            out_file = curr_dst / name
                            try:
                                out_fd = os.open(str(out_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                                with os.fdopen(out_fd, "wb") as out_stream:
                                    out_fd = -1
                                    out_stream.write(content)
                            except OSError as e:
                                raise DispositionsError("Failed to write snapshot file") from e
                            try:
                                os.utime(out_file, ns=(info.st_atime_ns, info.st_mtime_ns))
                            except OSError as e:
                                raise DispositionsError("Failed to preserve file timestamp in snapshot") from e
                        finally:
                            if fd >= 0:
                                os.close(fd)
                            if out_fd >= 0:
                                os.close(out_fd)
                    else:
                        raise DispositionsError("Unsupported file system entry type in snapshot")
    for d_path, atime_ns, mtime_ns in reversed(dir_times):
        try:
            os.utime(d_path, ns=(atime_ns, mtime_ns))
        except OSError as e:
            raise DispositionsError("Failed to preserve directory timestamp in snapshot") from e
    validate_snapshot_symlinks(dst_path)


def run_real_sealcheck(
    task_dir: Path,
    sealcheck_bin: str | Path,
    base_tree: Path | None = None,
    root: Path | None = None,
    timeout: float = PROCESS_TIMEOUT_SECONDS,
    *,
    scan_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Re-scan only with explicitly supplied real trees and scan options."""
    config = validate_scan_config(scan_config if scan_config is not None else {
        "base_tree": str(base_tree) if base_tree is not None else None,
        "roots": [{"path": str(root), "visibility": "agent_visible"}] if root is not None else [],
    })
    tree_stats = config.get("_tree_stats", {})
    all_trees = [config["base_tree"]] + [entry["path"] for entry in config["roots"]]
    for path in all_trees:
        with SafeDirectory(Path(path)) as directory:
            st = os.fstat(directory.fd)
            if path in tree_stats and (st.st_dev, st.st_ino) != tuple(tree_stats[path]):
                raise DispositionsError("Scan tree modified or replaced between validation and execution")
    # Verify and stage configuration files and immutable snapshots in a private bounded directory
    with tempfile.TemporaryDirectory(prefix="disposition_config_") as staging_dir:
        staged_dir = Path(staging_dir)
        staged_task = staged_dir / Path(task_dir).name
        snapshot_tree_safely(Path(task_dir), staged_task)
        staged_base = staged_dir / "base_tree"
        snapshot_tree_safely(Path(config["base_tree"]), staged_base)
        staged_roots = []
        for idx, entry in enumerate(config["roots"]):
            staged_root = staged_dir / f"root_{idx}"
            snapshot_tree_safely(Path(entry["path"]), staged_root)
            staged_roots.append((staged_root, entry["visibility"]))

        cmd = [str(sealcheck_bin), "scan", "--task", str(staged_task),
               "--base-tree", str(staged_base), "--format", "json"]
        for staged_root, vis in staged_roots:
            cmd.extend(["--root", str(staged_root), "--root-visibility", vis])
        staged_contents = config.get("_staged_contents", {})
        file_stats = config.get("_file_stats", {})
        for key in ("signatures", "oci_inspect", "oci_history"):
            if key in config:
                file_path = Path(config[key])
                with SafeDirectory(file_path.parent) as directory:
                    info = directory.check_file(file_path.name)
                    if info is None or (key in file_stats and (info.st_dev, info.st_ino) != tuple(file_stats[key])):
                        raise DispositionsError("Configuration file modified or replaced between validation and execution")
                staged_file = staged_dir / f"{key}.json"
                staged_file.write_text(staged_contents.get(key, ""), encoding="utf-8")
                cmd.extend(["--" + key.replace("_", "-"), str(staged_file)])
        if "baseline_budget" in config:
            cmd.extend(["--baseline-budget", str(config["baseline_budget"])])
        for package in config.get("target_package", []):
            cmd.extend(["--target-package", package])
        code, stdout = bounded_process(cmd, timeout)
    if code not in (0, 2):
        raise DispositionsError("Sealcheck process failed")
    report = parse_json(stdout)
    validate_report(report)
    if report["gate"] != (code == 2):
        raise MalformedGateOutputError("Sealcheck exit status contradicts report")
    return report


def compute_real_world_version(manifest_data: dict[str, Any], manifest_bin: str | Path | None = None) -> str:
    """Hash a complete supported manifest; keep its root in dispositions.json."""
    bounded_structure(manifest_data)
    content = json.dumps(manifest_data, sort_keys=True)
    if len(content.encode("utf-8")) > MAX_REPORT_BYTES:
        raise DispositionsError("Manifest byte cap exceeded")
    bin_path = manifest_bin or find_binary("hermetic-manifest", env_var="HERMETIC_MANIFEST_BIN")
    with tempfile.TemporaryDirectory(prefix="disposition_manifest_") as temp:
        path = Path(temp) / "manifest.json"
        atomic_write_file(path, content)
        code, output = bounded_process([str(bin_path), "root", "--manifest", str(path)])
    if code != 0 or re.fullmatch(r"blake3:[0-9a-f]{64}\n?", output) is None:
        raise DispositionsError("Manifest verification failed")
    return output.strip()


def validate_findings(findings: Any) -> list[dict[str, Any]]:
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise MalformedGateOutputError("Invalid findings list or count cap exceeded")
    for finding in findings:
        if not isinstance(finding, dict):
            raise MalformedGateOutputError("Finding entry is not an object")
        if "detector" not in finding:
            raise MalformedGateOutputError("Finding missing 'detector' field")
        if not isinstance(finding["detector"], str) or finding["detector"] not in DETECTORS:
            raise MalformedGateOutputError("Invalid detector identifier")
        if not {"severity", "visibility", "channel", "path", "confidence", "evidence"} <= finding.keys():
            raise MalformedGateOutputError("Finding missing required fields")
        if not isinstance(finding["channel"], str) or len(finding["channel"]) > MAX_CHANNEL_BYTES or re.fullmatch(r"[a-zA-Z0-9_]+", finding["channel"]) is None:
            raise MalformedGateOutputError("Invalid finding channel")
        if not isinstance(finding["path"], str) or len(finding["path"].encode("utf-8")) > MAX_FINDING_PATH_BYTES:
            raise MalformedGateOutputError("Invalid finding path")
        confidence = finding["confidence"]
        if type(confidence) not in (int, float) or not 0 <= confidence <= 1 or not math.isfinite(confidence):
            raise MalformedGateOutputError("Invalid finding confidence")
        if "hunk" in finding and finding["hunk"] is not None and (type(finding["hunk"]) is not int or not 0 <= finding["hunk"] <= MAX_FINDINGS):
            raise MalformedGateOutputError("Invalid finding hunk")
        if finding.get("severity") not in ("gate", "review", "info") or finding.get("visibility") not in ("agent_visible", "image_only"):
            raise MalformedGateOutputError("Invalid finding severity or visibility")
        evidence = finding.get("evidence", [])
        if not isinstance(evidence, list) or len(evidence) > MAX_FINDINGS or any(not isinstance(item, str) for item in evidence):
            raise MalformedGateOutputError("Invalid evidence list")
        if sum(len(item.encode("utf-8")) for item in evidence) > MAX_EVIDENCE_BYTES:
            raise MalformedGateOutputError("Evidence byte cap exceeded")
    return [f for f in findings if f["severity"] == "gate" and f.get("visibility", "agent_visible") == "agent_visible"]


INCOMPLETE_COVERAGE_CHANNELS = frozenset({
    "scan_error",
    "container_error",
    "container_skipped",
    "container_depth",
    "container_bomb",
    "binary_skipped",
    "large_archive_skipped",
    "index_skipped",
    "baseline_incomplete",
    "task_file_skipped",
    "skipped_symlink",
    "d8_error",
})


def has_incomplete_coverage(report: dict[str, Any]) -> list[str]:
    incomplete = list(report.get("not_covered", []))
    for f in report.get("findings", []):
        if not isinstance(f, dict):
            continue
        channel = f.get("channel", "")
        evidence = f.get("evidence", [])
        evidence_str = " ".join(evidence) if isinstance(evidence, list) else str(evidence)
        severity = f.get("severity", "")
        is_inc = (
            channel in INCOMPLETE_COVERAGE_CHANNELS
            or "skipped binary file" in evidence_str
            or "contains NUL byte" in evidence_str
            or "skipped file exceeding max size" in evidence_str
            or "file over 64 MiB skipped" in evidence_str
            or "read error" in evidence_str
            or "walk error" in evidence_str
            or "metadata error" in evidence_str
            or "broken symlink" in evidence_str
            or "skipped oversized" in evidence_str
            or "baseline incomplete" in evidence_str
            or "skipped task files" in evidence_str
            or "decompression error" in evidence_str
            or "error reading zip" in evidence_str
            or "error reading tar" in evidence_str
            or (severity in ("info", "review") and any(w in evidence_str.lower() for w in ("skip", "skipped", "bomb", "incomplete", "unreadable", "decompression error")))
        )
        if is_inc:
            det = f.get("detector")
            if det and det not in incomplete:
                incomplete.append(det)
            elif not det and "incomplete_coverage" not in incomplete:
                incomplete.append("incomplete_coverage")
    return incomplete


def append_manifest_disposition(manifest: dict[str, Any], entry: dict[str, Any]) -> None:
    dispositions = manifest.setdefault("dispositions", [])
    if entry not in dispositions:
        dispositions.append(entry)


def validate_report(report: Any) -> None:
    bounded_structure(report)
    if not isinstance(report, dict) or "findings" not in report:
        raise MalformedGateOutputError("Report missing findings")
    gate_findings = validate_findings(report["findings"])
    incomplete = has_incomplete_coverage(report)
    if "not_covered" not in report:
        fingerprint_fields = {"lines", "windows", "removed_markers", "diff_shapes", "subtracted", "winnow", "winnow_subtracted", "binary_items", "binary_subtracted"}
        fingerprints = report.get("fingerprints")
        if report.get("schema") != "hermetic-sealcheck/v0" or report.get("mode") is not None or not isinstance(fingerprints, dict) or set(fingerprints) != fingerprint_fields or any(type(value) is not int or value < 0 for value in fingerprints.values()):
            raise MalformedGateOutputError("Report requires complete scan coverage")
        validate_task_id(report.get("instance_id"))
        report["not_covered"] = incomplete
    else:
        for item in incomplete:
            if item not in report["not_covered"]:
                report["not_covered"].append(item)
    if type(report.get("gate")) is not bool or not isinstance(report.get("not_covered"), list):
        raise MalformedGateOutputError("Report requires gate and not_covered fields")
    if report["not_covered"]:
        raise MalformedGateOutputError("Report contains not_covered detectors")
    if report.get("schema", "hermetic-sealcheck/v0") != "hermetic-sealcheck/v0" or report.get("mode") is not None:
        raise MalformedGateOutputError("Unsupported scan report schema or mode")
    if report["gate"] != bool(gate_findings):
        raise MalformedGateOutputError("Report gate contradicts findings")


def decide_task_disposition(
    task_id: str,
    findings: list[dict[str, Any]],
    *,
    gate_flag: bool | None = None,
    not_covered: list[str] | None = None,
    problem_statement: str | None = None,
    explicit_spans: list[tuple[int, int]] | None = None,
    issue_text_is_the_fix: bool = False,
    rescan_fn: Callable[[str, str], dict[str, Any] | list[dict[str, Any]]] | None = None,
    manifest: dict[str, Any] | None = None,
    world_version: str | None = None,
    manifest_bin: str | Path | None = None,
) -> TaskDispositionResult:
    """Decide disposition for a single task according to §5.5 rules."""
    validate_task_id(task_id)

    bounded_structure(findings)
    gate_findings = validate_findings(findings)
    if not_covered:
        raise MalformedGateOutputError("Report contains not_covered detectors")
    if gate_flag is not None and (type(gate_flag) is not bool or gate_flag != bool(gate_findings)):
        raise MalformedGateOutputError("gate is true but findings contains no gate findings or gate contradicts findings")
    if problem_statement is not None and (not isinstance(problem_statement, str) or len(problem_statement.encode("utf-8")) > MAX_STATEMENT_BYTES):
        raise MalformedGateOutputError("Invalid problem_statement or byte cap exceeded")

    # Clean case
    if not gate_findings:
        if manifest is not None:
            append_manifest_disposition(manifest, {"kind": "clean", "detector": "none", "detail": "gate passed"})
        return TaskDispositionResult(
            task_id=task_id,
            disposition="clean",
            detectors=[],
            reason="gate passed",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
        )

    # Fired gate detectors
    fired_detectors = sorted(list({str(f["detector"]) for f in gate_findings}))

    # 1. Non-D0 detectors: no automatic removal exists in sealer -> excluded
    non_d0 = [d for d in fired_detectors if d != "D0"]
    if non_d0:
        if manifest is not None:
            for d in fired_detectors:
                append_manifest_disposition(manifest, {
                    "kind": "excluded",
                    "detector": d,
                    "detail": f"no automatic removal for detector: {d}",
                })
        return TaskDispositionResult(
            task_id=task_id,
            disposition="excluded",
            detectors=fired_detectors,
            reason=f"unsupported detector with no automatic removal: {', '.join(non_d0)}",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
        )

    # 2. Only D0 fired: check if leak *is* the task or can be repaired
    if issue_text_is_the_fix:
        if manifest is not None:
            append_manifest_disposition(manifest, {
                "kind": "excluded",
                "detector": "D0",
                "detail": "the leak is the task: issue text is the fix",
            })
        return TaskDispositionResult(
            task_id=task_id,
            disposition="excluded",
            detectors=["D0"],
            reason="the leak is the task: issue text is the fix",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
        )

    if problem_statement is None:
        if manifest is not None:
            append_manifest_disposition(manifest, {
                "kind": "excluded",
                "detector": "D0",
                "detail": "problem statement unavailable for leak repair",
            })
        return TaskDispositionResult(
            task_id=task_id,
            disposition="excluded",
            detectors=["D0"],
            reason="problem statement unavailable for leak repair",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
        )

    statement_bytes = problem_statement.encode("utf-8")
    stmt_len = len(statement_bytes)

    # Identify spans to redact (UTF-8 byte offsets)
    if explicit_spans is not None:
        merged_spans = validate_and_merge_spans(stmt_len, explicit_spans)
    else:
        evidence_list: list[str] = []
        for f in gate_findings:
            if f.get("detector") == "D0":
                ev = f.get("evidence", [])
                if isinstance(ev, list):
                    evidence_list.extend(str(item) for item in ev)
                elif isinstance(ev, str):
                    evidence_list.append(ev)
        merged_spans = find_spans_in_text(problem_statement, evidence_list)

    if not merged_spans:
        if manifest is not None:
            append_manifest_disposition(manifest, {
                "kind": "excluded",
                "detector": "D0",
                "detail": "leaking span cannot be located without destroying problem statement",
            })
        return TaskDispositionResult(
            task_id=task_id,
            disposition="excluded",
            detectors=["D0"],
            reason="the leak is the task: leaking span cannot be removed without destroying problem statement",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
        )

    # Defect 13: Redaction fraction using merged spans
    total_span_bytes = sum(s_end - s_start for s_start, s_end in merged_spans)
    fraction = total_span_bytes / stmt_len if stmt_len > 0 else 1.0

    # Simulate redaction to count remaining non-whitespace characters
    redacted_text, redacted_spans = redact_problem_statement(problem_statement, merged_spans)
    non_ws_remaining = len(re.sub(r"\s+", "", redacted_text.replace("[REDACTED]", "")))

    # Boundary check: fraction > 0.50 or non_ws_remaining < 20 excludes
    if fraction > MAX_REDACTION_FRACTION or non_ws_remaining < MIN_REMAINING_CHARS:
        if manifest is not None:
            append_manifest_disposition(manifest, {
                "kind": "excluded",
                "detector": "D0",
                "detail": "the leak is the task: issue text is the fix",
            })
        return TaskDispositionResult(
            task_id=task_id,
            disposition="excluded",
            detectors=["D0"],
            reason=(
                f"the leak is the task: issue text is the fix (redaction removes {fraction:.1%} "
                f"> {MAX_REDACTION_FRACTION:.1%} or leaves {non_ws_remaining} < {MIN_REMAINING_CHARS} chars)"
            ),
            world_version=world_version or (manifest.get("world_root") if manifest else None),
            redacted_spans=[],
        )

    # 3. Redaction holds only if re-scan is clean
    if rescan_fn is None:
        raise DispositionsError(f"Task '{task_id}': re-scan mechanism not configured for verification")

    rescan_output = rescan_fn(task_id, redacted_text)
    validate_report(rescan_output)
    rescan_gate_findings = validate_findings(rescan_output["findings"])

    if rescan_gate_findings:
        # Defect 11: When re-scan is still dirty, keep original D0 together with re-scan's detectors
        rescan_detectors = sorted(list({"D0"} | {str(f.get("detector", "")) for f in rescan_gate_findings if f.get("detector")}))
        if manifest is not None:
            for d in rescan_detectors:
                append_manifest_disposition(manifest, {
                    "kind": "excluded",
                    "detector": d,
                    "detail": f"re-scan still dirty after redaction: {d}",
                })
        return TaskDispositionResult(
            task_id=task_id,
            disposition="excluded",
            detectors=rescan_detectors,
            reason=f"re-scan still dirty after redaction: {', '.join(rescan_detectors)} fired",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
            redacted_spans=[],
        )

    if manifest is None:
        raise DispositionsError("Complete manifest required for repair")
    spans_payload = [span.to_dict() for span in redacted_spans]
    append_manifest_disposition(manifest, {
        "kind": "repaired", "detector": "D0",
        "detail": json.dumps({"problem_statement_redacted": spans_payload,
                              "statement_sha256": hashlib.sha256(redacted_text.encode("utf-8")).hexdigest()}, sort_keys=True),
    })
    new_version = compute_real_world_version(manifest, manifest_bin=manifest_bin)

    return TaskDispositionResult(
        task_id=task_id,
        disposition="repaired",
        detectors=["D0"],
        reason="D0 leak repaired: problem statement redacted and re-scan clean",
        world_version=new_version,
        redacted_spans=redacted_spans,
        redacted_statement=redacted_text,
    )


def validate_gate_input_strictly(data: Any) -> list[dict[str, Any]]:
    """Validate every report and inline input before accessing task files."""
    bounded_structure(data)
    if isinstance(data, dict):
        if "tasks" in data:
            data = data["tasks"]
        elif "task_id" in data or "instance_id" in data:
            data = [data]
        else:
            mapped = []
            for key, value in data.items():
                validate_task_id(key)
                if not isinstance(value, dict):
                    raise MalformedGateOutputError("Invalid task report")
                item = dict(value)
                item.setdefault("task_id", key)
                if item["task_id"] != key:
                    raise MalformedGateOutputError("Task identity mismatch")
                mapped.append(item)
            data = mapped
    if not isinstance(data, list) or not 1 <= len(data) <= MAX_TASKS:
        raise MalformedGateOutputError("Invalid task report list or count cap exceeded")
    seen = set()
    for item in data:
        if not isinstance(item, dict):
            raise MalformedGateOutputError("Invalid task report")
        tid = validate_task_id(item.get("task_id", item.get("instance_id")))
        if tid in seen:
            raise MalformedGateOutputError("Duplicate task_id")
        seen.add(tid)
        if "instance_id" in item and item["instance_id"] != tid:
            raise MalformedGateOutputError("Task identity mismatch")
        validate_report(item)
        for key, cap in (("problem_statement", MAX_STATEMENT_BYTES), ("gold_patch", MAX_PATCH_BYTES), ("test_patch", MAX_PATCH_BYTES)):
            if key in item and (not isinstance(item[key], str) or len(item[key].encode("utf-8")) > cap):
                raise MalformedGateOutputError("Invalid task text or byte cap exceeded")
        if "explicit_spans" in item:
            if "problem_statement" in item:
                redact_problem_statement(item["problem_statement"], item["explicit_spans"])
            elif not isinstance(item["explicit_spans"], list) or len(item["explicit_spans"]) > MAX_SPANS:
                raise MalformedGateOutputError("Invalid explicit_spans")
        if "issue_text_is_the_fix" in item and type(item["issue_text_is_the_fix"]) is not bool:
            raise MalformedGateOutputError("Invalid issue_text_is_the_fix")
        for key in ("manifest", "task_json"):
            if key in item and not isinstance(item[key], dict):
                raise MalformedGateOutputError("Invalid task metadata")
    return data


def load_gate_output(gate_source: str | Path) -> list[dict[str, Any]]:
    path = Path(gate_source)
    try:
        with SafeDirectory(path.parent) as parent:
            try:
                info = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
            except OSError:
                raise DispositionsError("Gate input file unavailable") from None
            if stat.S_ISREG(info.st_mode):
                return validate_gate_input_strictly(parse_json(parent.read(path.name, MAX_REPORT_BYTES)))
            if not stat.S_ISDIR(info.st_mode):
                raise DispositionsError("Symlink rejected or unsupported gate path")
            with parent.child(path.name) as directory:
                reports = []
                total = 0
                for name in directory.names():
                    if name.endswith(".json"):
                        text = directory.read(name, MAX_REPORT_BYTES)
                        total += len(text.encode("utf-8"))
                        if total > MAX_REPORT_BYTES:
                            raise DispositionsError("Report directory byte cap exceeded")
                        reports.extend(validate_gate_input_strictly(parse_json(text)))
                        if len(reports) > MAX_TASKS:
                            raise DispositionsError("Task count cap exceeded")
                return validate_gate_input_strictly(reports)
    except (DispositionsError, MalformedGateOutputError):
        raise
    except OSError:
        raise DispositionsError("Gate input path unavailable") from None


def atomic_write_file(target_path: Path, content: str) -> None:
    with SafeDirectory(Path(target_path).parent) as directory:
        directory.write(Path(target_path).name, content)


def validate_task_inputs(tid: str, task: Any, gold: Any, test: Any) -> None:
    if not isinstance(task, dict) or task.get("instance_id") != tid:
        raise DispositionsError("Complete task metadata required")
    for key in ("repo", "base_commit"):
        if not isinstance(task.get(key), str) or not task[key]:
            raise DispositionsError("Complete task metadata required")
    cutoffs = task.get("cutoffs")
    if not isinstance(cutoffs, dict) or any(not isinstance(cutoffs.get(k), str) for k in ("t_world", "t_clock")):
        raise DispositionsError("Complete task cutoffs required")
    for patch in (gold, test):
        if not isinstance(patch, str) or len(patch.encode("utf-8")) > MAX_PATCH_BYTES:
            raise DispositionsError("Complete task patches required")


def staged_rescan(tid: str, statement: str, task: dict[str, Any], gold: str, test: str,
                  config: dict[str, Any], binary: str) -> dict[str, Any]:
    validate_task_inputs(tid, task, gold, test)
    with tempfile.TemporaryDirectory(prefix="disposition_scan_") as temporary:
        staging = Path(temporary) / tid
        staging.mkdir(mode=0o700)
        (staging / "agent").mkdir(mode=0o700)
        (staging / "staging").mkdir(mode=0o700)
        for name, content in (("task.json", json.dumps(task)), ("staging/gold.patch", gold),
                              ("staging/test.patch", test), ("agent/problem_statement.md", statement)):
            atomic_write_file(staging / name, content)
        return run_real_sealcheck(staging, binary, scan_config=config)


def verify_repair_metadata(metadata: Any, statement: str, manifest: Any) -> list[RedactedSpan]:
    if not isinstance(metadata, dict) or not isinstance(metadata.get("spans"), list) or not 1 <= len(metadata["spans"]) <= MAX_SPANS:
        raise DispositionsError("Invalid persisted repair metadata")
    digest = hashlib.sha256(statement.encode("utf-8")).hexdigest()
    if metadata.get("statement_sha256") != digest or not isinstance(manifest, dict):
        raise DispositionsError("Persisted repair content mismatch")
    spans = []
    last_end = 0
    shift = 0
    statement_bytes = statement.encode("utf-8")
    for item in metadata["spans"]:
        if not isinstance(item, dict) or set(item) != {"start", "end", "sha256", "hash"}:
            raise DispositionsError("Invalid persisted repair span")
        start, end = item["start"], item["end"]
        if type(start) is not int or type(end) is not int or not last_end <= start < end <= MAX_STATEMENT_BYTES or re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])) is None or item["hash"] != "sha256:" + item["sha256"]:
            raise DispositionsError("Invalid persisted repair span")
        position = start + shift
        if position < 0 or statement_bytes[position:position + len(b"[REDACTED]")] != b"[REDACTED]":
            raise DispositionsError("Persisted repair marker mismatch")
        shift += len(b"[REDACTED]") - (end - start)
        last_end = end
        spans.append(RedactedSpan(**item))
    if not last_end <= len(statement_bytes) - shift <= MAX_STATEMENT_BYTES:
        raise DispositionsError("Persisted repair length mismatch")
    detail = {"problem_statement_redacted": metadata["spans"], "statement_sha256": digest}
    expected = {"kind": "repaired", "detector": "D0", "detail": json.dumps(detail, sort_keys=True)}
    if expected not in manifest.get("dispositions", []):
        raise DispositionsError("Persisted repair manifest mismatch")
    return spans


def is_exclusion_only(report: dict[str, Any], stmt: str | None = None, is_persisted_repair: bool = False) -> bool:
    """Determine if a report is guaranteed to be excluded without re-scan."""
    if report.get("issue_text_is_the_fix"):
        return True
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        return False
    gate_findings = [
        f for f in findings
        if isinstance(f, dict) and f.get("severity") == "gate" and f.get("visibility", "agent_visible") == "agent_visible"
    ]
    if not gate_findings:
        return False
    if any(f.get("detector") != "D0" for f in gate_findings):
        return True
    if is_persisted_repair:
        return False
    problem_text = stmt if stmt is not None else report.get("problem_statement")
    if problem_text is None:
        return True
    stmt_bytes = problem_text.encode("utf-8")
    stmt_len = len(stmt_bytes)
    if "explicit_spans" in report:
        try:
            spans = validate_and_merge_spans(stmt_len, report["explicit_spans"])
        except DispositionsError:
            return True
    else:
        evidence_list: list[str] = []
        for f in gate_findings:
            if f.get("detector") == "D0":
                ev = f.get("evidence", [])
                if isinstance(ev, list):
                    evidence_list.extend(str(item) for item in ev)
                elif isinstance(ev, str):
                    evidence_list.append(ev)
        try:
            spans = find_spans_in_text(problem_text, evidence_list)
        except DispositionsError:
            return True
    if not spans:
        return True
    total_span_bytes = sum(s_end - s_start for s_start, s_end in spans)
    fraction = total_span_bytes / stmt_len if stmt_len > 0 else 1.0
    try:
        redacted_text, _ = redact_problem_statement(problem_text, spans)
    except DispositionsError:
        return True
    non_ws_remaining = len(re.sub(r"\s+", "", redacted_text.replace("[REDACTED]", "")))
    if fraction > MAX_REDACTION_FRACTION or non_ws_remaining < MIN_REMAINING_CHARS:
        return True
    return False


def process_dispositions(
    gate_source: str | Path | list[dict[str, Any]] | dict[str, Any],
    out_path: str | Path | None = None,
    tasks_dir: str | Path | None = None,
    rescan_fn: Callable[[str, str], dict[str, Any]] | None = None,
    sealcheck_bin: str | Path | None = None,
    manifest_bin: str | Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    reports = load_gate_output(gate_source) if isinstance(gate_source, (str, Path)) else validate_gate_input_strictly(gate_source)
    reports = copy.deepcopy(reports)
    with ExitStack() as stack:
        tasks = stack.enter_context(SafeDirectory(Path(tasks_dir))) if tasks_dir else None
        if tasks:
            expected = set()
            for name in tasks.names():
                info = os.stat(name, dir_fd=tasks.fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    raise DispositionsError("Symlink rejected in task directory")
                if stat.S_ISDIR(info.st_mode) and not name.startswith("."):
                    validate_task_id(name)
                    expected.add(name)
            if expected - {r.get("task_id", r.get("instance_id")) for r in reports}:
                raise MissingDispositionError("Missing gate report for task")
        output = stack.enter_context(SafeDirectory(Path(out_path).parent)) if out_path else None
        if output:
            output.check_file(Path(out_path).name)
            if tasks:
                out_resolved = Path(out_path).resolve()
                for name in tasks.names():
                    task_base = (Path(tasks_dir) / name).resolve()
                    forbidden_artifacts = [
                        task_base / "manifest.json",
                        task_base / "problem_statement_redacted.json",
                        task_base / "task.json",
                        task_base / "agent" / "problem_statement.md",
                        task_base / "staging" / "gold.patch",
                        task_base / "staging" / "test.patch",
                    ]
                    for artifact in forbidden_artifacts:
                        if out_resolved == artifact:
                            raise DispositionsError(f"Report destination overlaps task artifact: {artifact.name}")
                        try:
                            if out_resolved.exists() and artifact.exists():
                                if (out_resolved.stat().st_dev, out_resolved.stat().st_ino) == (artifact.stat().st_dev, artifact.stat().st_ino):
                                    raise DispositionsError(f"Report destination overlaps task artifact: {artifact.name}")
                        except OSError:
                            pass
                    if out_resolved == task_base or task_base in out_resolved.parents:
                        raise DispositionsError("Report destination inside task directory")
        prepared = []
        total_task_bytes = 0
        # Retain task and agent descriptors, and validate every destination even with inline text.
        for report in reports:
            tid = report.get("task_id", report.get("instance_id"))
            task_dir = stack.enter_context(tasks.child(tid)) if tasks else None
            task_dir_stat = os.fstat(task_dir.fd) if task_dir else None
            agent = stack.enter_context(task_dir.child("agent")) if task_dir else None
            stmt = report.get("problem_statement")
            manifest = report.get("manifest")
            task = report.get("task_json")
            gold, test = report.get("gold_patch"), report.get("test_patch")
            metadata = None
            needs_rescan = rescan_fn is None and not is_exclusion_only(report, stmt, is_persisted_repair=(metadata is not None)) and (report["gate"] or metadata is not None)
            if task_dir:
                for name in ("manifest.json", "problem_statement_redacted.json"):
                    task_dir.check_file(name)
                raw_metadata = task_dir.read("problem_statement_redacted.json", MAX_REPORT_BYTES, optional=True)
                metadata = parse_json(raw_metadata) if raw_metadata is not None else None
                disk_statement = agent.read("problem_statement.md", MAX_STATEMENT_BYTES)
                if stmt is not None and metadata is None and stmt != disk_statement:
                    raise DispositionsError("Conflicting inline problem_statement and on-disk statement")
                stmt = disk_statement if stmt is None else stmt
                disk_manifest = task_dir.read("manifest.json", MAX_REPORT_BYTES, optional=True)
                if disk_manifest is not None:
                    parsed_disk_manifest = parse_json(disk_manifest)
                    if manifest is not None and manifest != parsed_disk_manifest:
                        raise DispositionsError("Conflicting inline manifest and on-disk manifest")
                    manifest = parsed_disk_manifest if manifest is None else manifest
                raw_task = task_dir.read("task.json", MAX_REPORT_BYTES, optional=True)
                if raw_task is not None:
                    parsed_disk_task = parse_json(raw_task)
                    if task is not None and task != parsed_disk_task:
                        raise DispositionsError("Conflicting inline task_json and on-disk task metadata")
                    task = parsed_disk_task if task is None else task
                # Re-compute needs_rescan now that metadata may be loaded from disk
                needs_rescan = rescan_fn is None and not is_exclusion_only(report, stmt, is_persisted_repair=(metadata is not None)) and (report["gate"] or metadata is not None)
                if needs_rescan:
                    with task_dir.child("staging") as stage:
                        disk_gold = stage.read("gold.patch", MAX_PATCH_BYTES)
                        disk_test = stage.read("test.patch", MAX_PATCH_BYTES)
                    if gold is not None and gold != disk_gold:
                        raise DispositionsError("Conflicting inline gold_patch and on-disk patch")
                    if test is not None and test != disk_test:
                        raise DispositionsError("Conflicting inline test_patch and on-disk patch")
                    gold = disk_gold if gold is None else gold
                    test = disk_test if test is None else test
            if stmt is not None and len(stmt.encode("utf-8")) > MAX_STATEMENT_BYTES:
                raise DispositionsError("Statement byte cap exceeded")
            if "explicit_spans" in report and stmt is not None and metadata is None:
                redact_problem_statement(stmt, report["explicit_spans"])
            if manifest is not None:
                if not isinstance(manifest, dict) or manifest.get("task_id") != tid:
                    raise DispositionsError("Manifest task identity mismatch")
                compute_real_world_version(manifest, manifest_bin)
            config = None
            if needs_rescan:
                config = validate_scan_config(report.get("scan_config"))
                validate_task_inputs(tid, task, gold, test)
            if metadata is not None:
                spans = verify_repair_metadata(metadata, disk_statement, manifest)
                source_spans = [(span.start, span.end) for span in spans]
                if stmt != disk_statement:
                    recovered, records = redact_problem_statement(stmt, source_spans)
                    if recovered != disk_statement or records != spans:
                        raise DispositionsError("Persisted repair statement mismatch")
                stmt = disk_statement
                if "explicit_spans" in report:
                    original_length = len(stmt.encode("utf-8")) + sum(span.end - span.start - len(b"[REDACTED]") for span in spans)
                    if validate_and_merge_spans(original_length, report["explicit_spans"]) != source_spans:
                        raise DispositionsError("Persisted repair spans mismatch")
            else:
                spans = []
            retained = json.dumps([stmt, manifest, task, gold, test])
            total_task_bytes += len(retained.encode("utf-8"))
            if total_task_bytes > MAX_TOTAL_TASK_BYTES:
                raise DispositionsError("Total task input byte cap exceeded")
            prepared.append((report, task_dir, agent, stmt, manifest, task, gold, test, config, spans, task_dir_stat))

        results = []
        updates = []
        for report, task_dir, agent, stmt, manifest, task, gold, test, config, spans, task_dir_stat in prepared:
            tid = report.get("task_id", report.get("instance_id"))
            scan = rescan_fn
            if scan is None and config is not None:
                binary = find_binary("hermetic-sealcheck", custom_path=sealcheck_bin, env_var="SEALCHECK_BIN")
                def scan(task_id: str, text: str) -> dict[str, Any]:
                    return staged_rescan(task_id, text, task, gold, test, config, binary)
            if is_exclusion_only(report, stmt, is_persisted_repair=(len(spans) > 0)):
                result = decide_task_disposition(
                    tid, report["findings"], gate_flag=report["gate"],
                    not_covered=report["not_covered"], problem_statement=stmt,
                    explicit_spans=report.get("explicit_spans"),
                    issue_text_is_the_fix=report.get("issue_text_is_the_fix", False),
                    rescan_fn=None, manifest=manifest, manifest_bin=manifest_bin,
                )
            elif spans:
                if scan is None:
                    raise DispositionsError("Re-scan mechanism not configured for verification")
                current_report = scan(tid, stmt)
                validate_report(current_report)
                if current_report["gate"] or any(f["detector"] != "D0" for f in validate_findings(report["findings"])):
                    result = TaskDispositionResult(tid, "excluded", sorted({"D0"} | {f["detector"] for f in validate_findings(current_report["findings"])} | {f["detector"] for f in validate_findings(report["findings"])}), "re-scan still dirty after redaction")
                    for detector in result.detectors:
                        append_manifest_disposition(manifest, {"kind": "excluded", "detector": detector, "detail": result.reason})
                else:
                    result = TaskDispositionResult(tid, "repaired", ["D0"], "D0 leak repaired: problem statement redacted and re-scan clean", redacted_spans=spans, redacted_statement=stmt)
            else:
                result = decide_task_disposition(tid, report["findings"], gate_flag=report["gate"],
                    not_covered=report["not_covered"], problem_statement=stmt,
                    explicit_spans=report.get("explicit_spans"), issue_text_is_the_fix=report.get("issue_text_is_the_fix", False),
                    rescan_fn=scan, manifest=manifest, manifest_bin=manifest_bin)
            if manifest is not None:
                result.world_version = compute_real_world_version(manifest, manifest_bin)
            results.append(result)
            updates.append((task_dir, agent, result, manifest, task_dir_stat))
        manifest_by_id = {u[2].task_id: u[3] for u in updates}
        results.sort(key=lambda result: result.task_id)
        entries = []
        for result in results:
            entry = result.to_dict()
            if result.disposition == "repaired":
                entry["redacted_statement"] = result.redacted_statement
                entry["problem_statement_redacted"] = {
                    "spans": [span.to_dict() for span in result.redacted_spans],
                    "statement_sha256": hashlib.sha256(result.redacted_statement.encode("utf-8")).hexdigest() if result.redacted_statement else "",
                }
                m = manifest_by_id.get(result.task_id)
                if m is not None:
                    entry["manifest"] = m
            entries.append(entry)
        counts = {kind: sum(result.disposition == kind for result in results) for kind in ("clean", "repaired", "excluded")}
        detectors = sorted({detector for result in results for detector in result.detectors})
        summary = {"total_tasks": len(results), "dispositions": counts,
                   "detectors": {detector: sum(detector in result.detectors for result in results) for detector in detectors}}
        # All validation and staged scans completed before the first atomic replacement.
        for task_dir, agent, result, manifest, task_dir_stat in updates:
            if task_dir:
                tid = result.task_id
                if tasks:
                    try:
                        current_pub_stat = os.stat(tid, dir_fd=tasks.fd, follow_symlinks=False)
                    except OSError:
                        raise DispositionsError("Published task directory missing or unavailable")
                    if not stat.S_ISDIR(current_pub_stat.st_mode) or (current_pub_stat.st_dev, current_pub_stat.st_ino) != (task_dir_stat.st_dev, task_dir_stat.st_ino):
                        raise DispositionsError("Task directory modified or replaced between validation and publication")
                if result.disposition == "repaired":
                    agent.write("problem_statement.md", result.redacted_statement)
                    task_dir.write("problem_statement_redacted.json", json.dumps({
                        "spans": [span.to_dict() for span in result.redacted_spans],
                        "statement_sha256": hashlib.sha256(result.redacted_statement.encode("utf-8")).hexdigest(),
                    }, sort_keys=True, indent=2) + "\n")
                    agent_stat = os.fstat(agent.fd)
                    try:
                        pub_stat = os.stat("agent", dir_fd=task_dir.fd, follow_symlinks=False)
                    except OSError:
                        pub_stat = None
                    if pub_stat is None or not stat.S_ISDIR(pub_stat.st_mode) or (pub_stat.st_dev, pub_stat.st_ino) != (agent_stat.st_dev, agent_stat.st_ino):
                        if pub_stat is not None and stat.S_ISLNK(pub_stat.st_mode):
                            os.unlink("agent", dir_fd=task_dir.fd)
                            os.mkdir("agent", mode=0o755, dir_fd=task_dir.fd)
                        with task_dir.child("agent") as pub_agent:
                            pub_agent.write("problem_statement.md", result.redacted_statement)
                    verify_dir = tasks.child(tid) if tasks else task_dir
                    try:
                        with verify_dir.child("agent") as verify_agent:
                            published_text = verify_agent.read("problem_statement.md", MAX_STATEMENT_BYTES)
                            if published_text != result.redacted_statement:
                                raise DispositionsError("Published task path repair verification failed")
                    finally:
                        if verify_dir is not task_dir:
                            verify_dir.close()
                if manifest is not None:
                    task_dir.write("manifest.json", json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        if output:
            output.write(Path(out_path).name, json.dumps(entries, indent=2) + "\n")
        return entries, summary


def format_summary(summary: dict[str, Any]) -> str:
    """Format short summary text for CLI output."""
    lines = [
        "Dispositions summary:",
        f"  clean:    {summary['dispositions'].get('clean', 0)}",
        f"  repaired: {summary['dispositions'].get('repaired', 0)}",
        f"  excluded: {summary['dispositions'].get('excluded', 0)}",
        f"Total tasks: {summary.get('total_tasks', 0)}",
    ]
    det = summary.get("detectors", {})
    if det:
        lines.append("Fired detectors:")
        for k, v in det.items():
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)


def dispositions_cli(argv: list[str] | None = None) -> int:
    """CLI entry point for dispositions command."""
    parser = argparse.ArgumentParser(
        prog="hermetic_slice dispositions",
        description="Emit dispositions.json and summary for tasks that fail the gate (§5.5)",
    )
    parser.add_argument(
        "--gate-output",
        "-i",
        type=Path,
        required=True,
        help="Path to gate output JSON file or directory containing gate reports",
    )
    parser.add_argument(
        "--out",
        "-o",
        type=Path,
        default=Path("dispositions.json"),
        help="Path to output dispositions.json (default: dispositions.json)",
    )
    parser.add_argument(
        "--tasks-dir",
        type=Path,
        default=None,
        help="Optional directory containing task folders for reading/updating manifests and problem statements",
    )
    parser.add_argument(
        "--sealcheck",
        type=Path,
        default=None,
        help="Optional path to hermetic-sealcheck binary",
    )

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1

    try:
        entries, summary = process_dispositions(
            gate_source=args.gate_output,
            out_path=args.out,
            tasks_dir=args.tasks_dir,
            sealcheck_bin=args.sealcheck,
        )
    except (MalformedGateOutputError, MissingDispositionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print("Fatal error processing dispositions: verification failed", file=sys.stderr)
        return 2

    print(format_summary(summary))
    return 0


if __name__ == "__main__":
    sys.exit(dispositions_cli())
