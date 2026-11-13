"""Baseline retrieval classifier: derived vs retrieved (TR-CLS-1, TR-CLS-2).

Classifies an agent's patch against a gold patch to determine whether the solution
was derived (worked out independently) or retrieved (copied from the known fix).
"""

from __future__ import annotations

from collections import deque
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

RUN_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")  # used with fullmatch()
MAX_HUNK_NUMBER_DIGITS: int = 9  # Bounds hunk header numbers (int() of huge digit runs raises)
HUNK_HEADER_RE = re.compile(
    r"^@@[ \t]+-(\d{1,9})(?:,(\d{1,9}))?[ \t]+\+(\d{1,9})(?:,(\d{1,9}))?[ \t]+@@(.*)$"
)


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
# Derived due to tiny gold patch (< min_qualifying_lines,      | 600
#   overlap at or above the threshold)                         |

def compute_confidence(
    exact_match: bool,
    is_retrieved: bool,
    overlap_per_mille: int,
    qualifying_count: int,
    min_qualifying_lines: int,
    overlap_threshold_per_mille: int = DEFAULT_OVERLAP_THRESHOLD_PER_MILLE,
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
        if (qualifying_count < min_qualifying_lines
                and overlap_per_mille >= overlap_threshold_per_mille):
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


class ValidationError(ClassifierError, ValueError):
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

PYTHON_SUFFIXES: tuple[str, ...] = (".py", ".pyi")


def is_python_path(path: str) -> bool:
    """True when ``path`` names a Python source file (comment dropping applies)."""
    return path.endswith(PYTHON_SUFFIXES)


def normalize_line(line: str, *, python: bool = True) -> str | None:
    """Normalise a single line from a unified diff.

    1. Drop blank lines.
    2. Drop pure comment lines (``#``), only when ``python`` is true; for other
       languages a leading ``#`` is code (``#include``, ``#define``) and is kept.
    3. Strip trailing whitespace.
    4. Collapse runs of spaces and tabs.
    5. Keep everything else exactly.

    Returns the normalised line string, or None if the line is dropped.
    """
    stripped = line.strip(" \t\r\n\f\v")
    if not stripped:
        return None
    if python and stripped.startswith("#"):
        return None

    # Strip trailing whitespace
    res = line.rstrip(" \t\r\n\f\v")
    # Collapse runs of spaces and tabs
    res = _WS_RUN_RE.sub(" ", res)
    return res


_WS_RUN_RE = re.compile(r"[ \t]+")

# Git's C-style quoting of path names (core.quotePath).
_C_ESCAPES: dict[str, int] = {
    "a": 0x07, "b": 0x08, "t": 0x09, "n": 0x0A, "v": 0x0B, "f": 0x0C, "r": 0x0D,
    '"': 0x22, "\\": 0x5C,
}
_OCTAL_DIGITS = "01234567"


def _unquote_git_path(quoted: str) -> str:
    """Decode a Git C-quoted path (including the surrounding quotes)."""
    if len(quoted) < 2 or quoted[0] != '"' or quoted[-1] != '"':
        raise MalformedDiffError("Malformed quoted path")
    body = quoted[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\":
            nxt = body[i + 1] if i + 1 < len(body) else ""
            if nxt in _C_ESCAPES:
                out.append(_C_ESCAPES[nxt])
                i += 2
            elif nxt and nxt in "0123":
                digits = body[i + 1:i + 4]
                if len(digits) != 3 or any(d not in _OCTAL_DIGITS for d in digits):
                    raise MalformedDiffError("Malformed octal escape in quoted path")
                out.append(int(digits, 8))
                i += 4
            else:
                raise MalformedDiffError("Malformed escape in quoted path")
        elif c == '"':
            raise MalformedDiffError("Unescaped quote in quoted path")
        else:
            out.extend(c.encode("utf-8", "surrogatepass"))
            i += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError as e:
        raise MalformedDiffError("Quoted path is not valid UTF-8") from e


def _split_quoted_prefix(text: str) -> str:
    """Return the leading Git-quoted token of ``text`` (quotes included)."""
    i = 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            return text[:i + 1]
        i += 1
    raise MalformedDiffError("Unterminated quoted path")


def _header_path(rest: str) -> str:
    """Path named by a ``---``/``+++`` header, without any trailing timestamp."""
    if rest.startswith('"'):
        return _unquote_git_path(_split_quoted_prefix(rest))
    # GNU diff separates the file name from its modification time with a TAB; Git
    # appends a TAB after names that contain spaces.
    return rest.split("\t", 1)[0].strip(" ")


def _ext_header_path(rest: str) -> str:
    """Path named by an extended header (``rename to``); no ``a/``/``b/`` prefix."""
    rest = rest.strip(" ")
    if rest.startswith('"'):
        return _unquote_git_path(rest)
    return rest


def _strip_diff_prefix(path: str) -> str:
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def _check_repo_path(path: str) -> str:
    """Validate a repository-relative path; fail closed on anything else."""
    path = path.replace("\\", "/")
    if not path or path.startswith("/"):
        raise MalformedDiffError("Diff file path must be a non-empty relative path")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise MalformedDiffError("Diff file path has an empty, '.' or '..' component")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        raise MalformedDiffError("Diff file path contains control characters")
    return path


def _clean_path(raw_path: str) -> str:
    """Sanitize and normalize a ``---``/``+++``/``diff --git`` path (prefix removed)."""
    return _check_repo_path(_strip_diff_prefix(raw_path))


class _FileState:
    """Mutable parser state for one file section of a diff."""

    __slots__ = ("git_path", "minus", "plus", "rename_to", "seen_pair", "hunks", "path",
                 "python", "added", "removed", "entries")

    def __init__(self, git_path: str | None) -> None:
        self.git_path = git_path
        self.minus: str | None = None
        self.plus: str | None = None
        self.rename_to: str | None = None
        self.seen_pair = False
        self.hunks = 0
        self.path: str | None = None
        self.python = False
        self.added: list[str] = []
        self.removed: list[str] = []
        self.entries: list[tuple[int, str]] = []

    def resolve_path(self) -> str:
        if self.path is None:
            if self.plus is not None and self.plus != DEV_NULL:
                self.path = _clean_path(self.plus)
            elif self.rename_to is not None:
                self.path = _check_repo_path(self.rename_to)
            elif self.minus is not None and self.minus != DEV_NULL:
                self.path = _clean_path(self.minus)
            elif self.git_path is not None:
                self.path = _clean_path(self.git_path)
            else:
                raise MalformedDiffError("Could not determine file path from diff chunk")
            self.python = is_python_path(self.path)
        return self.path


DEV_NULL = "/dev/null"


def _git_header_fallback(line: str) -> str | None:
    """Best-effort path from ``diff --git a/X b/X`` (used only without other headers)."""
    parts = line.split()
    if len(parts) >= 4 and parts[3].startswith("b/"):
        return parts[3]
    if len(parts) >= 3 and parts[2].startswith("a/"):
        return parts[2]
    return None


def parse_patch(diff_text: str) -> dict[str, NormalizedFilePatch]:
    """Parse unified diff into per-file lists of added and removed lines.

    Enforces bounds on input size, line length, hunk count, and file count.
    Rejects NUL bytes, binary diffs, truncated or overlong hunks (declared line
    counts must match the body), and malformed structures. File headers and binary
    markers are recognised only outside hunk bodies.
    """
    if not isinstance(diff_text, str):
        raise MalformedDiffError("Diff must be text")
    if len(diff_text) > MAX_PATCH_BYTES:
        raise MalformedDiffError(
            f"Patch size {len(diff_text)} exceeds limit of {MAX_PATCH_BYTES} bytes"
        )
    try:
        diff_size = len(diff_text.encode("utf-8"))
    except UnicodeEncodeError as e:
        raise MalformedDiffError("Diff is not encodable as UTF-8") from e
    if diff_size > MAX_PATCH_BYTES:
        raise MalformedDiffError(
            f"Patch size {diff_size} exceeds limit of {MAX_PATCH_BYTES} bytes"
        )
    if "\x00" in diff_text:
        raise MalformedDiffError("Diff contains NUL byte")

    # Empty patch produces empty dictionary
    if not diff_text.strip():
        return {}

    # Split only at LF record boundaries: U+2028, U+2029 and form feeds are payload.
    lines = diff_text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()

    parsed_files: dict[str, NormalizedFilePatch] = {}
    file_count = 0
    total_hunk_count = 0
    current: _FileState | None = None
    old_rem = 0
    new_rem = 0
    curr_old = 0
    curr_new = 0

    def flush(state: _FileState | None) -> None:
        if state is None:
            return
        path = state.resolve_path()
        existing = parsed_files.get(path)
        if existing is not None:
            # Merge if the same file appeared in multiple sections
            existing.added_lines.extend(state.added)
            existing.removed_lines.extend(state.removed)
            existing.added_line_entries.extend(state.entries)
        else:
            parsed_files[path] = NormalizedFilePatch(
                path=path,
                added_lines=state.added,
                removed_lines=state.removed,
                added_line_entries=state.entries,
            )

    def new_file(git_path: str | None) -> _FileState:
        nonlocal file_count
        file_count += 1
        if file_count > MAX_FILES:
            raise MalformedDiffError(f"File count exceeds limit of {MAX_FILES}")
        return _FileState(git_path)

    i = 0
    n_lines = len(lines)
    while i < n_lines:
        line = lines[i]
        if line.endswith("\r"):
            line = line[:-1]
        lineno = i + 1
        i += 1
        if len(line) > MAX_LINE_LENGTH:
            raise MalformedDiffError(
                f"Line length {len(line)} exceeds limit of {MAX_LINE_LENGTH} chars"
            )

        if old_rem > 0 or new_rem > 0:
            # Inside a hunk body: every line is content, never a header.
            if current is None:  # unreachable: counts are only set with a file
                raise MalformedDiffError("Hunk without a file header")
            if line.startswith("+"):
                if new_rem <= 0:
                    raise MalformedDiffError(f"Hunk body longer than declared at line {lineno}")
                norm = normalize_line(line[1:], python=current.python)
                if norm is not None:
                    current.added.append(norm)
                    current.entries.append((curr_new, norm))
                curr_new += 1
                new_rem -= 1
            elif line.startswith("-"):
                if old_rem <= 0:
                    raise MalformedDiffError(f"Hunk body longer than declared at line {lineno}")
                norm = normalize_line(line[1:], python=current.python)
                if norm is not None:
                    current.removed.append(norm)
                curr_old += 1
                old_rem -= 1
            elif line.startswith(" ") or line == "":
                if old_rem <= 0 or new_rem <= 0:
                    raise MalformedDiffError(f"Hunk body longer than declared at line {lineno}")
                curr_old += 1
                curr_new += 1
                old_rem -= 1
                new_rem -= 1
            elif line.startswith("\\"):
                # e.g. "\ No newline at end of file"
                continue
            else:
                raise MalformedDiffError(f"Malformed or truncated hunk body at line {lineno}")
            continue

        # Outside any hunk body.
        if line.startswith("diff --git "):
            flush(current)
            current = new_file(_git_header_fallback(line))
        elif line.startswith("--- ") and i < n_lines and lines[i].startswith("+++ "):
            if current is None or current.seen_pair or current.hunks > 0:
                flush(current)
                current = new_file(None)
            plus_line = lines[i]
            if plus_line.endswith("\r"):
                plus_line = plus_line[:-1]
            if len(plus_line) > MAX_LINE_LENGTH:
                raise MalformedDiffError(
                    f"Line length {len(plus_line)} exceeds limit of {MAX_LINE_LENGTH} chars"
                )
            i += 1
            current.minus = _header_path(line[4:])
            current.plus = _header_path(plus_line[4:])
            current.seen_pair = True
        elif line.startswith("@@"):
            if current is None:
                raise MalformedDiffError(f"Hunk without a file header at line {lineno}")
            m = HUNK_HEADER_RE.match(line)
            if not m:
                raise MalformedDiffError(f"Malformed hunk header at line {lineno}")
            total_hunk_count += 1
            if total_hunk_count > MAX_HUNKS:
                raise MalformedDiffError(f"Hunk count exceeds limit of {MAX_HUNKS}")
            current.resolve_path()
            current.hunks += 1
            old_start = int(m.group(1))
            old_rem = int(m.group(2)) if m.group(2) is not None else 1
            new_start = int(m.group(3))
            new_rem = int(m.group(4)) if m.group(4) is not None else 1
            if old_rem == 0 and new_rem == 0:
                raise MalformedDiffError(f"Empty hunk at line {lineno}")
            if (old_rem > 0 and old_start == 0) or (new_rem > 0 and new_start == 0):
                raise MalformedDiffError(f"Invalid hunk start at line {lineno}")
            curr_old = old_start
            curr_new = new_start
        elif line.startswith("rename to "):
            if current is not None:
                current.rename_to = _ext_header_path(line[len("rename to "):])
        elif line == "GIT binary patch" or line.startswith("Binary files "):
            raise MalformedDiffError("Binary diffs are not supported")
        elif current is not None and line[:1] in ("+", "-", " ") and line != "-- ":
            # Content-like line outside any hunk: a hunk body longer than its
            # declared counts, or a stray header. ("-- " is the mail signature.)
            raise MalformedDiffError(f"Diff line outside any hunk at line {lineno}")
        # Anything else outside a hunk (extended headers such as "index", mode lines,
        # mail preamble) carries no added or removed content and is ignored.

    if old_rem > 0 or new_rem > 0:
        raise MalformedDiffError("Truncated hunk at end of diff")
    if current is None:
        raise MalformedDiffError("No diff headers found in patch")
    flush(current)
    return parsed_files


# -----------------------------------------------------------------------------
# Classifier
# -----------------------------------------------------------------------------

def _check_param(name: str, value: Any, low: int, high: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not (low <= value <= high):
        raise ValidationError(f"{name} must be an integer in {low}..{high}")


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
    _check_param("min_line_length", min_line_length, 0, MAX_LINE_LENGTH)
    _check_param("min_qualifying_lines", min_qualifying_lines, 0, MAX_PATCH_BYTES)
    _check_param("overlap_threshold_per_mille", overlap_threshold_per_mille, 0, 1000)

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
        # Index the agent's added lines: normalised text -> queue of line numbers in
        # patch order. Each gold line consumes the first unused agent occurrence, so
        # matching stays one-to-one and runs in linear time.
        available: dict[str, deque[int]] = {}
        if a_file is not None:
            for a_line_num, a_norm in a_file.added_line_entries:
                available.setdefault(a_norm, deque()).append(a_line_num)

        for g_line_num, g_norm in g_file.added_line_entries:
            if len(g_norm) < min_line_length:
                continue
            total_qualifying += 1

            queue = available.get(g_norm)
            if queue:
                matched_qualifying += 1
                evidence.append(
                    EvidenceSpan(
                        file=path,
                        agent_line=queue.popleft(),
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
        overlap_threshold_per_mille=overlap_threshold_per_mille,
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
        raise ValidationError("Invalid label; expected 'derived' or 'retrieved'")
    if not isinstance(world_sealed, bool) or not isinstance(gate_says_leak, bool):
        raise ValidationError("world_sealed and gate_says_leak must be booleans")

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
    if not isinstance(digest, str) or not RUN_DIGEST_RE.fullmatch(digest):
        raise ValidationError(
            "Invalid run_digest: must be 'sha256:' followed by 64 lowercase hex digits."
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
        raise ValidationError("Invalid label; expected 'derived' or 'retrieved'")

    if isinstance(conf_val, bool) or not isinstance(conf_val, int) or not (0 <= conf_val <= 1000):
        raise ValidationError(f"Invalid confidence: {conf_val!r}. Must be an integer in 0..1000.")

    if not isinstance(ev_val, (list, tuple)):
        raise ValidationError("Evidence must be a list")
    formatted_spans: list[dict[str, Any]] = []
    for count, item in enumerate(ev_val):
        if count >= MAX_EVIDENCE_COUNT:
            raise ValidationError(f"Evidence exceeds limit of {MAX_EVIDENCE_COUNT} spans")
        if isinstance(item, (tuple, list)):
            if len(item) < 3:
                raise ValidationError("Evidence tuple must have 3 elements")
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
            raise ValidationError("Malformed evidence item")

        if not isinstance(f, str) or not f:
            raise ValidationError("Evidence file must be a non-empty string")
        if isinstance(a, bool) or isinstance(g, bool) or not isinstance(a, int) or not isinstance(g, int):
            raise ValidationError("Evidence line numbers must be integers")
        f_str = f
        a_int = a
        g_int = g

        if a_int < 1 or g_int < 1:
            raise ValidationError(f"Evidence line numbers must be >= 1: agent={a_int}, gold={g_int}")

        formatted_spans.append({
            "agent_line": a_int,
            "file": f_str,
            "gold_line": g_int,
        })

    # Sort deterministically by (file, agent_line, gold_line)
    formatted_spans.sort(key=lambda x: (x["file"], x["agent_line"], x["gold_line"]))

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

MAX_PATH_COMPONENTS: int = 256  # Maximum directory depth walked by safe_read_file
READ_CHUNK_BYTES: int = 65_536   # Read size per os.read call

_DIR_OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                   | getattr(os, "O_CLOEXEC", 0))
_FILE_OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOCTTY", 0))


def _open_parent_dir(parts: tuple[str, ...]) -> int:
    """Open the directory chain ``parts`` from ``/`` without following any symlink."""
    fd = os.open("/", _DIR_OPEN_FLAGS)
    try:
        for part in parts:
            try:
                info = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except OSError as e:
                raise ClassifierError(f"Cannot stat path component: {e.strerror}") from e
            if stat.S_ISLNK(info.st_mode):
                raise ClassifierError("Symlinks are rejected in path components")
            if not stat.S_ISDIR(info.st_mode):
                raise ClassifierError("Path component is not a directory")
            try:
                next_fd = os.open(part, _DIR_OPEN_FLAGS, dir_fd=fd)
            except OSError as e:
                raise ClassifierError(f"Cannot open path component: {e.strerror}") from e
            try:
                opened = os.fstat(next_fd)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    raise ClassifierError("Path component swapped during open")
            except BaseException:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def safe_read_file(path_str: str | Path, *, max_bytes: int = MAX_PATCH_BYTES) -> str:
    """Safely open and read a regular file without following symlinks.

    Verifies:
    - Every directory component is opened relative to its parent with
      O_NOFOLLOW | O_DIRECTORY, so no symlink anywhere in the path is followed.
    - The final component is not a symlink (lstat), is a regular file (FIFOs,
      sockets and devices are refused) and is opened with O_NOFOLLOW | O_NONBLOCK.
    - fstat confirms the opened descriptor is regular and matches lstat dev/inode.
    - File size and read stream bounded by max_bytes cap.
    - Decodes valid UTF-8 and rejects NUL bytes.
    """
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not (0 <= max_bytes <= MAX_PATCH_BYTES):
        raise ValidationError(f"max_bytes must be an integer in 0..{MAX_PATCH_BYTES}")
    try:
        path = Path(path_str).absolute()
    except (OSError, TypeError, ValueError) as e:
        raise ClassifierError("Invalid file path") from e
    parts = path.parts[1:]
    if not parts:
        raise ClassifierError(f"Not a regular file: {path}")
    if len(parts) > MAX_PATH_COMPONENTS:
        raise ClassifierError(f"Path has more than {MAX_PATH_COMPONENTS} components")
    name = parts[-1]

    try:
        parent_fd = _open_parent_dir(parts[:-1])
    except OSError as e:
        raise ClassifierError(f"Cannot open parent directory of {path}: {e.strerror}") from e
    try:
        # 1. lstat verification
        try:
            lst = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as e:
            raise ClassifierError(f"Cannot stat file {path}: {e.strerror}") from e

        if stat.S_ISLNK(lst.st_mode):
            raise ClassifierError(f"Symlinks are rejected: {path}")
        if not stat.S_ISREG(lst.st_mode):
            raise ClassifierError(f"Not a regular file: {path}")
        if lst.st_size > max_bytes:
            raise ClassifierError(
                f"File size {lst.st_size} exceeds cap of {max_bytes} bytes: {path}"
            )

        # 2. Open with O_NOFOLLOW and O_NONBLOCK
        try:
            fd = os.open(name, _FILE_OPEN_FLAGS, dir_fd=parent_fd)
        except OSError as e:
            raise ClassifierError(f"Cannot open file {path}: {e.strerror}") from e
    finally:
        os.close(parent_fd)

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
            chunk = os.read(fd, min(READ_CHUNK_BYTES, max_bytes - len(content_bytes) + 1))
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
    except OSError as e:
        raise ClassifierError(f"Cannot read file {path}: {e.strerror}") from e
    finally:
        os.close(fd)
