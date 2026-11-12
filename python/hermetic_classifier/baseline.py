"""Baseline retrieval classifier: derived vs retrieved (TR-CLS-1, TR-CLS-2).

Classifies an agent's patch against a gold patch to determine whether the solution
was derived (worked out independently) or retrieved (copied from the known fix).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Literal, NamedTuple

# -----------------------------------------------------------------------------
# Bounds, caps and thresholds
# -----------------------------------------------------------------------------

MAX_PATCH_BYTES: int = 10_000_000  # 10 MB input patch cap
MAX_LINE_LENGTH: int = 10_000      # 10 KB maximum line length
MAX_FILES: int = 1_000             # Maximum files per diff
MAX_HUNKS: int = 10_000            # Maximum hunks across patch (rejects runaway hunks)
MAX_EVIDENCE_COUNT: int = 1_000    # Maximum evidence items retained

DEFAULT_MIN_LINE_LENGTH: int = 10           # Minimum characters for qualifying line
DEFAULT_MIN_QUALIFYING_LINES: int = 5       # Minimum qualifying lines in gold patch
DEFAULT_OVERLAP_THRESHOLD_PER_MILLE: int = 800  # 800‰ (80.0%) overlap threshold

RUN_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HUNK_HEADER_RE = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$")


# -----------------------------------------------------------------------------
# Fixed Confidence Table
# -----------------------------------------------------------------------------
# Fixed mapping from classification conditions to confidence in per-mille (0..1000).
#
# Condition                                                    | Confidence (‰)
# -------------------------------------------------------------|---------------
# Exact match (identical normalized changes per file)          | 1000
# Retrieved via 1000‰ overlap (non-exact match)                | 950
# Retrieved via 900..999‰ overlap                              | 900
# Retrieved via 800..899‰ overlap                              | 850
# Derived with 0‰ overlap                                      | 950
# Derived with 1..200‰ overlap                                 | 900
# Derived with 201..500‰ overlap                               | 800
# Derived with 501..799‰ overlap                               | 700
# Derived due to tiny gold patch (< min_qualifying_lines)      | 600

def compute_confidence(
    exact_match: bool,
    is_retrieved: bool,
    overlap_per_mille: int,
    qualifying_count: int,
    min_qualifying_lines: int,
) -> int:
    """Look up deterministic confidence integer per-mille from the fixed table."""
    if exact_match:
        return 1000

    if is_retrieved:
        if overlap_per_mille >= 1000:
            return 950
        elif overlap_per_mille >= 900:
            return 900
        else:
            return 850
    else:
        # Derived
        if qualifying_count < min_qualifying_lines and overlap_per_mille >= 800:
            # Overlap is high but gold patch is too small to reliably prove retrieval
            return 600
        elif overlap_per_mille == 0:
            return 950
        elif overlap_per_mille <= 200:
            return 900
        elif overlap_per_mille <= 500:
            return 800
        else:
            return 700


# -----------------------------------------------------------------------------
# Typed Exceptions
# -----------------------------------------------------------------------------

class ClassifierError(Exception):
    """Base exception for hermetic_classifier."""


class MalformedDiffError(ClassifierError):
    """Raised when unified diff input is malformed, binary, or exceeds bounded limits."""


class ValidationError(ClassifierError):
    """Raised when input parameters (e.g. run digest or labels) fail validation."""


# -----------------------------------------------------------------------------
# Data Structures
# -----------------------------------------------------------------------------

class EvidenceSpan(NamedTuple):
    """Evidence span linking matching lines across agent and gold patches."""
    file: str
    agent_line: int
    gold_line: int


@dataclass(frozen=True)
class Result:
    """Outcome of classifying agent patch against gold patch."""
    exact_match: bool
    added_line_overlap: int  # Integer per-mille [0, 1000]
    label: str               # "derived" or "retrieved"
    confidence: int          # Integer per-mille [0, 1000]
    evidence: list[EvidenceSpan]

    def to_dict(self) -> dict[str, Any]:
        """Convert Result to a plain dictionary."""
        return {
            "exact_match": self.exact_match,
            "added_line_overlap": self.added_line_overlap,
            "label": self.label,
            "confidence": self.confidence,
            "evidence": [
                {
                    "file": span.file,
                    "agent_line": span.agent_line,
                    "gold_line": span.gold_line,
                }
                for span in self.evidence
            ],
        }


@dataclass
class NormalizedFilePatch:
    """Normalized additions and deletions for a single file in a diff."""
    path: str
    added_lines: list[str]
    removed_lines: list[str]
    added_line_entries: list[tuple[int, str]]  # (target_line_number, normalized_line)


# -----------------------------------------------------------------------------
# Normalisation & Parsing
# -----------------------------------------------------------------------------

def normalize_line(line: str) -> str | None:
    """Normalise a single line from a unified diff.

    1. Drop blank lines.
    2. Drop pure comment lines for Python (`#`).
    3. Strip trailing whitespace.
    4. Collapse runs of spaces and tabs.
    5. Keep everything else exactly.

    Returns the normalised line string, or None if the line is dropped.
    """
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith("#"):
        return None

    # Strip trailing whitespace
    res = line.rstrip(" \t\r\n")
    # Collapse runs of spaces and tabs
    res = re.sub(r"[ \t]+", " ", res)
    return res


def _clean_path(raw_path: str) -> str:
    """Sanitize and normalize a diff file path."""
    clean = raw_path.strip().strip('"')
    if clean.startswith("a/") or clean.startswith("b/"):
        clean = clean[2:]
    return clean.replace("\\", "/").strip()


def parse_patch(diff_text: str) -> dict[str, NormalizedFilePatch]:
    """Parse unified diff into per-file lists of added and removed lines.

    Enforces bounds on input size, line length, hunk count, and file count.
    Rejects NUL bytes, binary diffs, and malformed structures.
    """
    if "\x00" in diff_text:
        raise MalformedDiffError("Diff contains NUL byte")

    diff_bytes = diff_text.encode("utf-8")
    if len(diff_bytes) > MAX_PATCH_BYTES:
        raise MalformedDiffError(
            f"Patch size {len(diff_bytes)} exceeds limit of {MAX_PATCH_BYTES} bytes"
        )

    # Check for binary diff indicators
    if "GIT binary patch" in diff_text or re.search(r"(?m)^Binary files\s+", diff_text):
        raise MalformedDiffError("Binary diffs are not supported")

    lines = diff_text.splitlines()
    for line in lines:
        if len(line) > MAX_LINE_LENGTH:
            raise MalformedDiffError(
                f"Line length {len(line)} exceeds limit of {MAX_LINE_LENGTH} chars"
            )

    # Empty patch produces empty dictionary
    if not diff_text.strip():
        return {}

    # Identify file chunks
    has_git_diff = bool(re.search(r"(?m)^diff --git\s+", diff_text))
    has_std_diff = bool(re.search(r"(?m)^---\s+", diff_text) and re.search(r"(?m)^\+\+\+\s+", diff_text))

    if not has_git_diff and not has_std_diff:
        raise MalformedDiffError("No diff headers found in patch")

    file_chunks: list[list[str]] = []
    if has_git_diff:
        starts = [i for i, line in enumerate(lines) if line.startswith("diff --git ")]
        for idx, start_idx in enumerate(starts):
            end_idx = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
            file_chunks.append(lines[start_idx:end_idx])
    else:
        # Standard diff: split on '--- ' headers that are followed by '+++ '
        starts = []
        for i, line in enumerate(lines):
            if line.startswith("--- ") and (i + 1 < len(lines) and lines[i + 1].startswith("+++ ")):
                starts.append(i)
        if not starts:
            raise MalformedDiffError("No valid diff headers found in standard diff")
        for idx, start_idx in enumerate(starts):
            end_idx = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
            file_chunks.append(lines[start_idx:end_idx])

    if len(file_chunks) > MAX_FILES:
        raise MalformedDiffError(
            f"File count {len(file_chunks)} exceeds limit of {MAX_FILES}"
        )

    parsed_files: dict[str, NormalizedFilePatch] = {}
    total_hunk_count = 0

    for chunk in file_chunks:
        if not chunk:
            continue

        # Extract file path from headers
        path: str | None = None
        hunk_start_indices: list[int] = []

        # Check for rename/copy headers
        rename_to = None
        minus_path = None
        plus_path = None

        for idx, line in enumerate(chunk):
            if line.startswith("@@"):
                hunk_start_indices.append(idx)
            elif line.startswith("rename to "):
                rename_to = line[len("rename to "):].strip()
            elif line.startswith("+++ "):
                target = line[4:].strip()
                if not target.startswith("/dev/null"):
                    plus_path = target
            elif line.startswith("--- "):
                target = line[4:].strip()
                if not target.startswith("/dev/null"):
                    minus_path = target

        if rename_to:
            path = _clean_path(rename_to)
        elif plus_path:
            path = _clean_path(plus_path)
        elif minus_path:
            path = _clean_path(minus_path)
        elif chunk[0].startswith("diff --git "):
            parts = chunk[0].split()
            if len(parts) >= 4 and parts[3].startswith("b/"):
                path = _clean_path(parts[3])
            elif len(parts) >= 3 and parts[2].startswith("a/"):
                path = _clean_path(parts[2])

        if not path:
            raise MalformedDiffError("Could not determine file path from diff chunk")

        total_hunk_count += len(hunk_start_indices)
        if total_hunk_count > MAX_HUNKS:
            raise MalformedDiffError(
                f"Hunk count exceeds limit of {MAX_HUNKS}"
            )

        added_lines: list[str] = []
        removed_lines: list[str] = []
        added_entries: list[tuple[int, str]] = []

        # Parse hunks
        for h_i, h_start in enumerate(hunk_start_indices):
            h_end = hunk_start_indices[h_i + 1] if h_i + 1 < len(hunk_start_indices) else len(chunk)
            header_line = chunk[h_start]
            m = HUNK_HEADER_RE.match(header_line)
            if not m:
                raise MalformedDiffError(f"Malformed hunk header: {header_line[:60]}")

            old_start = int(m.group(1))
            new_start = int(m.group(3))
            curr_old = old_start
            curr_new = new_start

            for line in chunk[h_start + 1:h_end]:
                if line.startswith("+"):
                    raw = line[1:]
                    norm = normalize_line(raw)
                    if norm is not None:
                        added_lines.append(norm)
                        added_entries.append((curr_new, norm))
                    curr_new += 1
                elif line.startswith("-"):
                    raw = line[1:]
                    norm = normalize_line(raw)
                    if norm is not None:
                        removed_lines.append(norm)
                    curr_old += 1
                elif line.startswith(" ") or line == "":
                    curr_old += 1
                    curr_new += 1
                elif line.startswith("\\"):
                    # e.g. "\ No newline at end of file"
                    continue
                else:
                    raise MalformedDiffError(
                        f"Malformed line in hunk body: {line[:50]}"
                    )

        if path in parsed_files:
            # Merge if the same file appeared in multiple sections
            existing = parsed_files[path]
            existing.added_lines.extend(added_lines)
            existing.removed_lines.extend(removed_lines)
            existing.added_line_entries.extend(added_entries)
        else:
            parsed_files[path] = NormalizedFilePatch(
                path=path,
                added_lines=added_lines,
                removed_lines=removed_lines,
                added_line_entries=added_entries,
            )

    return parsed_files


# -----------------------------------------------------------------------------
# Classifier
# -----------------------------------------------------------------------------

def classify(
    agent_patch: str,
    gold_patch: str,
    *,
    min_line_length: int = DEFAULT_MIN_LINE_LENGTH,
    min_qualifying_lines: int = DEFAULT_MIN_QUALIFYING_LINES,
    overlap_threshold_per_mille: int = DEFAULT_OVERLAP_THRESHOLD_PER_MILLE,
) -> Result:
    """Classify agent patch against gold patch.

    Returns Result containing:
    - exact_match: bool
    - added_line_overlap: integer per-mille
    - label: 'derived' or 'retrieved'
    - confidence: integer per-mille
    - evidence: sorted list of EvidenceSpan
    """
    agent_parsed = parse_patch(agent_patch)
    gold_parsed = parse_patch(gold_patch)

    # Filter to active files with non-empty normalized changes
    agent_active = {p: f for p, f in agent_parsed.items() if f.added_lines or f.removed_lines}
    gold_active = {p: f for p, f in gold_parsed.items() if f.added_lines or f.removed_lines}

    # 1. Exact match determination
    # Normalised added and removed lines identical per file, ignoring hunk positions and file order
    if not gold_active and not agent_active:
        exact_match = True
    elif set(gold_active.keys()) != set(agent_active.keys()):
        exact_match = False
    else:
        exact_match = True
        for path, g_file in gold_active.items():
            a_file = agent_active[path]
            if g_file.added_lines != a_file.added_lines or g_file.removed_lines != a_file.removed_lines:
                exact_match = False
                break

    # 2. Added line overlap and evidence determination
    total_qualifying = 0
    matched_qualifying = 0
    evidence: list[EvidenceSpan] = []

    for path, g_file in gold_parsed.items():
        a_file = agent_parsed.get(path)
        a_entries = a_file.added_line_entries if a_file is not None else []
        used_agent_indices: set[int] = set()

        for g_line_num, g_norm in g_file.added_line_entries:
            if len(g_norm) < min_line_length:
                continue
            total_qualifying += 1

            # Check if this qualifying line occurs in agent's added lines for this file
            match_idx = None
            for idx, (a_line_num, a_norm) in enumerate(a_entries):
                if idx not in used_agent_indices and a_norm == g_norm:
                    match_idx = idx
                    break

            if match_idx is not None:
                used_agent_indices.add(match_idx)
                matched_qualifying += 1
                evidence.append(
                    EvidenceSpan(
                        file=path,
                        agent_line=a_entries[match_idx][0],
                        gold_line=g_line_num,
                    )
                )

    # Sort evidence deterministically by (file, agent_line, gold_line)
    evidence.sort(key=lambda e: (e.file, e.agent_line, e.gold_line))
    if len(evidence) > MAX_EVIDENCE_COUNT:
        evidence = evidence[:MAX_EVIDENCE_COUNT]

    # Added line overlap in integer per-mille
    if total_qualifying > 0:
        added_line_overlap = (matched_qualifying * 1000) // total_qualifying
    else:
        added_line_overlap = 0

    # 3. Label determination
    # retrieved when exact match, or when overlap is at or above named threshold
    # and the gold patch has at least a named minimum number of qualifying lines; else derived
    is_retrieved = exact_match or (
        added_line_overlap >= overlap_threshold_per_mille
        and total_qualifying >= min_qualifying_lines
    )
    label = "retrieved" if is_retrieved else "derived"

    # 4. Confidence lookup
    confidence = compute_confidence(
        exact_match=exact_match,
        is_retrieved=is_retrieved,
        overlap_per_mille=added_line_overlap,
        qualifying_count=total_qualifying,
        min_qualifying_lines=min_qualifying_lines,
    )

    return Result(
        exact_match=exact_match,
        added_line_overlap=added_line_overlap,
        label=label,
        confidence=confidence,
        evidence=evidence,
    )


# -----------------------------------------------------------------------------
# Status Rule (TR-CLS-2)
# -----------------------------------------------------------------------------

def run_status_hint(
    label: str,
    world_sealed: bool,
    gate_says_leak: bool,
) -> Literal["review"] | None:
    """Status hint for run resolution according to TR-CLS-2.

    A retrieved label in a sealed world gives 'review';
    a disagreement between the gate and the classifier gives 'review';
    otherwise None.
    """
    if label not in ("derived", "retrieved"):
        raise ValueError(f"Invalid label: {label!r}; expected 'derived' or 'retrieved'")

    classifier_says_leak = (label == "retrieved")

    if classifier_says_leak and world_sealed:
        return "review"

    if classifier_says_leak != gate_says_leak:
        return "review"

    return None


# -----------------------------------------------------------------------------
# Validation & Audit Record Payload
# -----------------------------------------------------------------------------

def validate_run_digest(digest: str) -> None:
    """Validate that run digest is 'sha256:' followed by 64 lowercase hex characters."""
    if not isinstance(digest, str) or not RUN_DIGEST_RE.match(digest):
        raise ValidationError(
            f"Invalid run_digest: {digest!r}. Must start with 'sha256:' followed by 64 lowercase hex digits."
        )


def build_audit_predicate(
    run_digest: str,
    label: str | Result,
    confidence: int | None = None,
    evidence: list[Any] | None = None,
) -> dict[str, Any]:
    """Build the hermetic-transcript-audit/v1 predicate dictionary.

    Validates inputs and returns a plain dict with keys:
    - run_digest
    - label
    - confidence (integer per-mille)
    - evidence_spans (sorted list of dicts)
    """
    if isinstance(label, Result):
        res = label
        label_val = res.label
        conf_val = res.confidence
        ev_val = res.evidence
    else:
        label_val = label
        if confidence is None:
            raise ValidationError("confidence must be provided when label is a string")
        conf_val = confidence
        ev_val = evidence if evidence is not None else []

    validate_run_digest(run_digest)

    if label_val not in ("derived", "retrieved"):
        raise ValidationError(f"Invalid label: {label_val!r}")

    if isinstance(conf_val, bool) or not isinstance(conf_val, int) or not (0 <= conf_val <= 1000):
        raise ValidationError(f"Invalid confidence: {conf_val!r}. Must be an integer in 0..1000.")

    formatted_spans: list[dict[str, Any]] = []
    for item in ev_val:
        if isinstance(item, (tuple, list)):
            if len(item) < 3:
                raise ValidationError(f"Evidence tuple must have 3 elements: {item!r}")
            f, a, g = item[0], item[1], item[2]
        elif isinstance(item, dict):
            f = item.get("file")
            a = item.get("agent_line")
            g = item.get("gold_line")
        else:
            f = getattr(item, "file", None)
            a = getattr(item, "agent_line", None)
            g = getattr(item, "gold_line", None)

        if f is None or a is None or g is None:
            raise ValidationError(f"Malformed evidence item: {item!r}")

        f_str = str(f)
        try:
            a_int = int(a)
            g_int = int(g)
        except (ValueError, TypeError) as e:
            raise ValidationError(f"Evidence line numbers must be integers: {e}") from e

        if a_int < 1 or g_int < 1:
            raise ValidationError(f"Evidence line numbers must be >= 1: agent={a_int}, gold={g_int}")

        formatted_spans.append({
            "agent_line": a_int,
            "file": f_str,
            "gold_line": g_int,
        })

    # Sort deterministically by (file, agent_line, gold_line)
    formatted_spans.sort(key=lambda x: (x["file"], x["agent_line"], x["gold_line"]))
    if len(formatted_spans) > MAX_EVIDENCE_COUNT:
        formatted_spans = formatted_spans[:MAX_EVIDENCE_COUNT]

    return {
        "confidence": conf_val,
        "evidence_spans": formatted_spans,
        "label": label_val,
        "run_digest": run_digest,
    }


def audit_predicate_to_json(predicate: dict[str, Any], *, indent: int | None = 2) -> str:
    """Serialize predicate dictionary to deterministic JSON with sorted keys and no floats."""
    if indent is None:
        return json.dumps(predicate, sort_keys=True, separators=(",", ":"))
    return json.dumps(predicate, sort_keys=True, indent=indent)


# Alias
audit_record_payload = build_audit_predicate


# -----------------------------------------------------------------------------
# Safe File I/O
# -----------------------------------------------------------------------------

def safe_read_file(path_str: str | Path, *, max_bytes: int = MAX_PATCH_BYTES) -> str:
    """Safely open and read a regular file without following symlinks.

    Verifies:
    - Path exists and is not a symlink (via lstat).
    - Opens with O_NOFOLLOW | O_NONBLOCK to prevent symlink traversal and FIFO hangs.
    - fstat confirms opened descriptor is regular and matches lstat dev/inode.
    - File size and read stream bounded by max_bytes cap.
    - Decodes valid UTF-8 and rejects NUL bytes.
    """
    path = Path(path_str)

    # 1. lstat verification
    try:
        lst = os.lstat(path)
    except OSError as e:
        raise ClassifierError(f"Cannot stat file {path}: {e}") from e

    if stat.S_ISLNK(lst.st_mode):
        raise ClassifierError(f"Symlinks are rejected: {path}")
    if not stat.S_ISREG(lst.st_mode):
        raise ClassifierError(f"Not a regular file: {path}")
    if lst.st_size > max_bytes:
        raise ClassifierError(
            f"File size {lst.st_size} exceeds cap of {max_bytes} bytes: {path}"
        )

    # 2. Open with O_NOFOLLOW and O_NONBLOCK
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise ClassifierError(f"Cannot open file {path}: {e}") from e

    try:
        # 3. fstat verification against TOCTOU race
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise ClassifierError(f"Opened file is not regular: {path}")
        if (lst.st_dev, lst.st_ino) != (fst.st_dev, fst.st_ino):
            raise ClassifierError(f"File swapped during open: {path}")
        if fst.st_size > max_bytes:
            raise ClassifierError(
                f"File size {fst.st_size} exceeds cap of {max_bytes} bytes: {path}"
            )

        # 4. Bounded read
        content_bytes = bytearray()
        while len(content_bytes) <= max_bytes:
            chunk = os.read(fd, min(65536, max_bytes - len(content_bytes) + 1))
            if not chunk:
                break
            content_bytes.extend(chunk)
            if len(content_bytes) > max_bytes:
                raise ClassifierError(
                    f"File read exceeded cap of {max_bytes} bytes: {path}"
                )

        # 5. Decode UTF-8
        try:
            content_str = content_bytes.decode("utf-8")
        except UnicodeDecodeError as e:
            raise MalformedDiffError(f"File contains invalid UTF-8: {path}") from e

        if "\x00" in content_str:
            raise MalformedDiffError(f"File contains NUL byte: {path}")

        return content_str
    finally:
        os.close(fd)
