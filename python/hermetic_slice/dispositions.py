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
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
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
    if not TASK_ID_REGEX.match(task_id) or ".." in task_id or "/" in task_id or task_id.startswith("."):
        raise MalformedGateOutputError(f"Invalid task_id format: '{task_id}'")
    return task_id


def assert_not_symlink(path: Path) -> None:
    """Refuse symlinks using lstat on the target path."""
    if path.is_symlink() or os.path.islink(path):
        raise DispositionsError(f"Symlink rejected at '{path.name}'")


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
    for s_start, s_end in spans:
        if not (0 <= s_start <= s_end <= statement_bytes_len):
            raise DispositionsError(
                f"Span offset out of range: {s_start}..{s_end} for statement of length {statement_bytes_len}"
            )

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
                    flattened_evidence.append(part_clean)
        else:
            flattened_evidence.append(ev)

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
            raw_byte_spans.append((b_start, b_end))

    return validate_and_merge_spans(len(statement_bytes), raw_byte_spans)


def redact_problem_statement(
    statement: str,
    byte_spans: list[tuple[int, int]],
    placeholder: str = "[REDACTED]",
) -> tuple[str, list[RedactedSpan]]:
    """Redact UTF-8 byte spans from statement. Returns redacted string and RedactedSpan metadata."""
    statement_bytes = statement.encode("utf-8")
    merged_spans = validate_and_merge_spans(len(statement_bytes), byte_spans)

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
    res_bytes = bytearray(statement_bytes)
    for b_start, b_end in reversed(merged_spans):
        res_bytes[b_start:b_end] = placeholder_bytes

    return res_bytes.decode("utf-8", errors="replace"), redacted_records


def run_real_sealcheck(
    task_dir: Path,
    sealcheck_bin: str | Path,
    base_tree: Path | None = None,
    root: Path | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Execute real hermetic-sealcheck scan on a task directory."""
    cmd = [str(sealcheck_bin), "scan", "--task", str(task_dir)]

    # Provide base-tree and root arguments
    temp_dir = None
    try:
        bt_path = base_tree
        r_path = root
        if bt_path is None or not bt_path.exists():
            temp_dir = tempfile.mkdtemp(prefix="rescan_dummy_")
            bt_path = Path(temp_dir) / "base"
            bt_path.mkdir(parents=True, exist_ok=True)
        if r_path is None or not r_path.exists():
            if temp_dir is None:
                temp_dir = tempfile.mkdtemp(prefix="rescan_dummy_")
            r_path = Path(temp_dir) / "root"
            r_path.mkdir(parents=True, exist_ok=True)

        cmd.extend([
            "--base-tree", str(bt_path),
            "--root", str(r_path),
            "--root-visibility", "agent_visible",
            "--format", "json",
        ])

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            shell=False,
        )

        if proc.returncode not in (0, 2):
            raise DispositionsError(
                f"sealcheck process failed with exit code {proc.returncode}"
            )

        try:
            return json.loads(proc.stdout)
        except Exception as exc:
            raise MalformedGateOutputError(f"sealcheck stdout is not valid JSON: {exc}") from exc
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


def compute_real_world_version(
    manifest_data: dict[str, Any],
    manifest_bin: str | Path | None = None,
) -> str:
    """Compute real world root version using hermetic-manifest CLI root subcommand."""
    bin_path = manifest_bin or find_binary("hermetic-manifest", env_var="HERMETIC_MANIFEST_BIN")

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as tf:
        json.dump(manifest_data, tf)
        tmp_manifest_path = tf.name

    try:
        proc = subprocess.run(
            [str(bin_path), "root", "--manifest", tmp_manifest_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        version_str = proc.stdout.strip()
        if not version_str.startswith("blake3:") or len(version_str) != 71:
            raise DispositionsError(f"Invalid world root output from hermetic-manifest: length {len(version_str)}")
        return version_str
    finally:
        if os.path.exists(tmp_manifest_path):
            os.remove(tmp_manifest_path)


def synthesize_minimal_manifest(
    task_id: str,
    dispositions: list[dict[str, Any]],
    redacted_spans: list[RedactedSpan],
) -> dict[str, Any]:
    """Synthesize minimal valid WorldManifest to compute cryptographic world root (§13.1)."""
    detail_data = {"problem_statement_redacted": [s.to_dict() for s in redacted_spans]}
    disp_entries = []
    for d in dispositions:
        entry = dict(d)
        if entry.get("kind") == "repaired" and "problem_statement_redacted" not in entry.get("detail", ""):
            entry["detail"] = json.dumps(detail_data)
        disp_entries.append(entry)

    return {
        "spec_version": "hermetic-world/v1",
        "task_id": task_id,
        "task_class": "dated",
        "seal_level": "strict",
        "cutoffs": {
            "t_world": "2024-01-01T00:00:00Z",
            "t_clock": "2024-01-01T00:00:00Z",
            "base_commit": "0123456789abcdef0123456789abcdef01234567",
            "pkg_cutoff": "2024-01-01T00:00:00Z",
        },
        "repo_tree_digest": "blake3:0000000000000000000000000000000000000000000000000000000000000001",
        "rootfs_digest": "blake3:0000000000000000000000000000000000000000000000000000000000000002",
        "packages": {
            "closure_root": "blake3:0000000000000000000000000000000000000000000000000000000000000003",
            "baseline_month": "2024-01",
            "baseline_root": "blake3:0000000000000000000000000000000000000000000000000000000000000004",
        },
        "substrate_at_t": "full",
        "world_ca_cert_sha256": "blake3:0000000000000000000000000000000000000000000000000000000000000007",
        "run_spec": {
            "env": {},
            "workdir": "/testbed",
            "user": "root",
            "entrypoint": ["/bin/bash"],
            "resources": {
                "vcpus": 4,
                "memory_mib": 8192,
                "disk_mib": 20480,
                "wall_time_s": 1800,
            },
        },
        "sealcheck_report_digest": "blake3:0000000000000000000000000000000000000000000000000000000000000008",
        "dispositions": disp_entries,
    }


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

    # Defect 7: Check query-mode not_covered entries -> not clean (error)
    if not_covered:
        raise MalformedGateOutputError(
            f"Task '{task_id}': sealcheck report contains not_covered detectors: {not_covered}"
        )

    # Validate findings structure and check detector presence
    gate_findings: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            raise MalformedGateOutputError(f"Task '{task_id}': finding entry is not an object")
        severity = f.get("severity")
        visibility = f.get("visibility", "agent_visible")
        if severity == "gate" and visibility != "image_only":
            detector = f.get("detector")
            if not detector or not isinstance(detector, str) or not detector.strip():
                raise MalformedGateOutputError(f"Task '{task_id}': gate finding missing 'detector' field")
            gate_findings.append(f)

    # Defect 7: {"gate": true, "findings": []} is contradictory and must be an error
    if gate_flag is True and not gate_findings:
        raise MalformedGateOutputError(f"Task '{task_id}': gate is true but findings contains no gate findings")

    # Clean case
    if not gate_findings:
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
                manifest.setdefault("dispositions", []).append({
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
            manifest.setdefault("dispositions", []).append({
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
            manifest.setdefault("dispositions", []).append({
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
            manifest.setdefault("dispositions", []).append({
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
            manifest.setdefault("dispositions", []).append({
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
    if isinstance(rescan_output, dict):
        rescan_findings = rescan_output.get("findings", [])
    elif isinstance(rescan_output, list):
        rescan_findings = rescan_output
    else:
        raise MalformedGateOutputError(f"Task '{task_id}': invalid re-scan output type {type(rescan_output).__name__}")

    rescan_gate_findings = [
        f for f in rescan_findings
        if isinstance(f, dict) and f.get("severity") == "gate" and f.get("visibility", "agent_visible") != "image_only"
    ]

    if rescan_gate_findings:
        # Defect 11: When re-scan is still dirty, keep original D0 together with re-scan's detectors
        rescan_detectors = sorted(list({"D0"} | {str(f.get("detector", "")) for f in rescan_gate_findings if f.get("detector")}))
        if manifest is not None:
            for d in rescan_detectors:
                manifest.setdefault("dispositions", []).append({
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

    # 4. Re-scan is clean -> repaired!
    # Defect 11: Record redacted spans' offsets and hashes in the manifest
    spans_payload = [s.to_dict() for s in redacted_spans]
    if manifest is not None:
        manifest.setdefault("dispositions", []).append({
            "kind": "repaired",
            "detector": "D0",
            "detail": json.dumps({"problem_statement_redacted": spans_payload}),
        })
        # Record into manifest problem_statement_redacted field if manifest allows or in root
        manifest["problem_statement_redacted"] = spans_payload

    # Defect 10: Compute new world version with real function
    target_manifest = manifest if manifest is not None else synthesize_minimal_manifest(task_id, [{"kind": "repaired", "detector": "D0"}], redacted_spans)
    new_version = compute_real_world_version(target_manifest, manifest_bin=manifest_bin)
    if manifest is not None:
        manifest["world_root"] = new_version

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
    """Strictly validate gate input before touching any file.

    Defect 6: Never embed whole items, reports, or evidence in errors.
    """
    if isinstance(data, list):
        reports: list[dict[str, Any]] = []
        for idx, item in enumerate(data):
            if not isinstance(item, dict):
                raise MalformedGateOutputError(f"Entry at index {idx} is not an object (type: {type(item).__name__})")
            tid = item.get("task_id") or item.get("instance_id")
            if not tid or not isinstance(tid, str):
                raise MalformedGateOutputError(f"Entry at index {idx} missing valid task_id")
            validate_task_id(tid)

            findings = item.get("findings")
            if findings is None:
                raise MalformedGateOutputError(f"Task '{tid}' missing 'findings' field")
            if not isinstance(findings, list):
                raise MalformedGateOutputError(f"Task '{tid}' has non-list findings (type: {type(findings).__name__})")

            reports.append(item)
        return reports

    if isinstance(data, dict):
        if "schema" in data and ("instance_id" in data or "task_id" in data):
            tid = data.get("task_id") or data.get("instance_id")
            validate_task_id(tid)
            if not isinstance(data.get("findings"), list):
                raise MalformedGateOutputError(f"Task '{tid}' has non-list findings")
            return [data]

        if "tasks" in data and isinstance(data["tasks"], list):
            return validate_gate_input_strictly(data["tasks"])

        reports = []
        for key, val in data.items():
            validate_task_id(key)
            if not isinstance(val, dict):
                raise MalformedGateOutputError(f"Report for task '{key}' is not an object (type: {type(val).__name__})")
            item = dict(val)
            item.setdefault("task_id", key)
            if not isinstance(item.get("findings"), list):
                raise MalformedGateOutputError(f"Task '{key}' has non-list findings")
            reports.append(item)
        return reports

    raise MalformedGateOutputError(f"Gate output must be a list or dict, got {type(data).__name__}")


def load_gate_output(gate_source: str | Path) -> list[dict[str, Any]]:
    """Load gate output from file or directory, validating strictly."""
    path = Path(gate_source)
    if not path.exists():
        raise MalformedGateOutputError("Gate output path does not exist")

    if path.is_file():
        assert_not_symlink(path)
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as exc:
            raise MalformedGateOutputError(f"Failed to read gate output file: {exc}") from exc

        try:
            data = json.loads(content)
        except Exception as exc:
            raise MalformedGateOutputError("Gate output file contains invalid JSON") from exc

        return validate_gate_input_strictly(data)

    if path.is_dir():
        assert_not_symlink(path)
        reports: list[dict[str, Any]] = []
        json_files = sorted(path.glob("*.json"))
        if not json_files:
            raise MalformedGateOutputError("No JSON gate reports found in directory")
        for jf in json_files:
            assert_not_symlink(jf)
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
            except Exception as exc:
                raise MalformedGateOutputError("Invalid JSON in gate report file") from exc
            reports.extend(validate_gate_input_strictly(data))
        return reports

    raise MalformedGateOutputError("Unsupported gate path type")


def atomic_write_file(target_path: Path, content: str) -> None:
    """Write file atomically using a temporary file in the same directory and fsync.

    Replaces destination without following existing symlinks.
    """
    target_path = Path(target_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path_str = tempfile.mkstemp(dir=target_path.parent, prefix=".tmp_atomic_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path_str, target_path)
    except Exception:
        if os.path.exists(tmp_path_str):
            os.remove(tmp_path_str)
        raise


def process_dispositions(
    gate_source: str | Path | list[dict[str, Any]] | dict[str, Any],
    out_path: str | Path | None = None,
    tasks_dir: str | Path | None = None,
    rescan_fn: Callable[[str, str], dict[str, Any] | list[dict[str, Any]]] | None = None,
    sealcheck_bin: str | Path | None = None,
    manifest_bin: str | Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Process gate outputs for all tasks, decide dispositions, and emit dispositions.json atomically.

    Defect 8: Guard denominator (duplicate task_ids fail, every task under tasks_dir must have report).
    Defect 9: Validate entire input before touching any file; write dispositions.json first; make rerun idempotent.
    Defect 12: Refuse symlinks, validate task_id strictly.
    """
    # 1. Parse and validate all reports upfront
    if isinstance(gate_source, (str, Path)):
        reports = load_gate_output(gate_source)
    else:
        reports = validate_gate_input_strictly(gate_source)

    if not reports:
        raise MalformedGateOutputError("Gate output contains no tasks")

    # Defect 8: Duplicate task_id check
    seen_task_ids: set[str] = set()
    for r in reports:
        tid = r.get("task_id") or r.get("instance_id")
        validate_task_id(tid)
        if tid in seen_task_ids:
            raise MalformedGateOutputError(f"Duplicate task_id found in gate reports: '{tid}'")
        seen_task_ids.add(tid)

    # Defect 8: If tasks_dir is provided, verify EVERY task directory has a gate report
    tasks_base = Path(tasks_dir) if tasks_dir else None
    if tasks_base:
        assert_not_symlink(tasks_base)
        expected_tasks = set()
        for item in sorted(tasks_base.iterdir()):
            if item.is_dir() and not item.is_symlink() and not item.name.startswith("."):
                expected_tasks.add(item.name)

        missing_tasks = expected_tasks - seen_task_ids
        if missing_tasks:
            raise MissingDispositionError(
                f"Missing gate report for task(s) under tasks-dir: {sorted(missing_tasks)}"
            )

    # 2. Compute decisions in memory (no disk mutations yet!)
    computed_results: list[TaskDispositionResult] = []
    task_disk_updates: list[dict[str, Any]] = []

    for report in reports:
        task_id = report.get("task_id") or report.get("instance_id")
        findings = report.get("findings", [])
        gate_flag = report.get("gate")
        not_covered = report.get("not_covered", [])

        stmt_text = report.get("problem_statement")
        manifest_data = report.get("manifest")
        task_json_data = report.get("task_json")
        w_version = report.get("world_version")

        task_dir_path = (tasks_base / task_id) if tasks_base else None

        # Defect 9: Idempotent rerun check
        # If problem_statement_redacted.json already exists and problem statement is clean, stay repaired!
        is_already_repaired = False
        existing_redacted_spans: list[RedactedSpan] = []
        if task_dir_path and task_dir_path.exists():
            assert_not_symlink(task_dir_path)
            redacted_info_file = task_dir_path / "problem_statement_redacted.json"
            if redacted_info_file.is_file():
                assert_not_symlink(redacted_info_file)
                try:
                    red_info = json.loads(redacted_info_file.read_text(encoding="utf-8"))
                    if red_info.get("spans"):
                        existing_redacted_spans = [
                            RedactedSpan(s["start"], s["end"], s["sha256"], s["hash"])
                            for s in red_info["spans"]
                        ]
                        is_already_repaired = True
                except Exception:
                    pass

            stmt_file = task_dir_path / "agent" / "problem_statement.md"
            if stmt_text is None and stmt_file.is_file():
                assert_not_symlink(stmt_file)
                stmt_text = stmt_file.read_text(encoding="utf-8")

            manifest_file = task_dir_path / "manifest.json"
            if manifest_data is None and manifest_file.is_file():
                assert_not_symlink(manifest_file)
                try:
                    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
                except Exception:
                    manifest_data = None

            task_file = task_dir_path / "task.json"
            if task_json_data is None and task_file.is_file():
                assert_not_symlink(task_file)
                try:
                    task_json_data = json.loads(task_file.read_text(encoding="utf-8"))
                except Exception:
                    task_json_data = None

        if w_version is None and manifest_data:
            w_version = manifest_data.get("world_root")

        # Setup re-scan callback: use real sealcheck if rescan_fn is None
        effective_rescan = rescan_fn
        if effective_rescan is None:
            # Wire in real sealcheck binary re-scan
            s_bin = find_binary("hermetic-sealcheck", custom_path=sealcheck_bin, env_var="SEALCHECK_BIN")
            def real_rescan_runner(tid: str, r_stmt: str) -> dict[str, Any]:
                # Redacted statement scanned using real sealcheck binary
                if task_dir_path and task_dir_path.exists():
                    stmt_target = task_dir_path / "agent" / "problem_statement.md"
                    backup_content = stmt_target.read_text(encoding="utf-8") if stmt_target.exists() else ""
                    try:
                        stmt_target.write_text(r_stmt, encoding="utf-8")
                        return run_real_sealcheck(task_dir_path, s_bin)
                    finally:
                        if backup_content:
                            stmt_target.write_text(backup_content, encoding="utf-8")
                else:
                    # Synthetic temporary task dir
                    with tempfile.TemporaryDirectory(prefix="rescan_task_") as tmp_td_str:
                        tmp_td = Path(tmp_td_str)
                        (tmp_td / "agent").mkdir(parents=True, exist_ok=True)
                        (tmp_td / "agent" / "problem_statement.md").write_text(r_stmt, encoding="utf-8")
                        (tmp_td / "task.json").write_text(json.dumps({
                            "instance_id": tid,
                            "gold_patch": "",
                            "test_patch": "",
                        }), encoding="utf-8")
                        return run_real_sealcheck(tmp_td, s_bin)
            effective_rescan = real_rescan_runner

        if is_already_repaired and (not findings or not any(f.get("severity") == "gate" for f in findings)):
            # Idempotent rerun: already repaired and current state is clean
            w_root = w_version or (manifest_data.get("world_root") if manifest_data else None)
            disp_res = TaskDispositionResult(
                task_id=task_id,
                disposition="repaired",
                detectors=["D0"],
                reason="D0 leak repaired: problem statement redacted and re-scan clean",
                world_version=w_root,
                redacted_spans=existing_redacted_spans,
                redacted_statement=stmt_text,
            )
        else:
            disp_res = decide_task_disposition(
                task_id=task_id,
                findings=findings,
                gate_flag=gate_flag,
                not_covered=not_covered,
                problem_statement=stmt_text,
                explicit_spans=report.get("explicit_spans"),
                issue_text_is_the_fix=report.get("issue_text_is_the_fix", False),
                rescan_fn=effective_rescan,
                manifest=manifest_data,
                world_version=w_version,
                manifest_bin=manifest_bin,
            )

        computed_results.append(disp_res)
        if task_dir_path and task_dir_path.exists():
            task_disk_updates.append({
                "task_dir": task_dir_path,
                "disposition_result": disp_res,
                "manifest_data": manifest_data,
            })

    # Defect 8: Verify no task lacks a disposition
    if len(computed_results) != len(seen_task_ids):
        raise MissingDispositionError("One or more tasks lack a disposition")

    # Output for N tasks always has N entries; sorted and stable
    computed_results.sort(key=lambda r: r.task_id)
    entries = [r.to_dict() for r in computed_results]

    summary_counts: dict[str, int] = {"clean": 0, "repaired": 0, "excluded": 0}
    detector_counts: dict[str, int] = {}
    for r in computed_results:
        summary_counts[r.disposition] = summary_counts.get(r.disposition, 0) + 1
        for d in r.detectors:
            detector_counts[d] = detector_counts.get(d, 0) + 1

    summary = {
        "total_tasks": len(computed_results),
        "dispositions": summary_counts,
        "detectors": dict(sorted(detector_counts.items())),
    }

    # Defect 9: Write dispositions.json FIRST
    if out_path:
        atomic_write_file(Path(out_path), json.dumps(entries, indent=2) + "\n")

    # Defect 9: ONLY THEN apply task-directory rewrites
    for update in task_disk_updates:
        t_dir: Path = update["task_dir"]
        res: TaskDispositionResult = update["disposition_result"]
        m_data: dict[str, Any] | None = update["manifest_data"]

        if res.disposition == "repaired":
            if res.redacted_statement is not None:
                stmt_file = t_dir / "agent" / "problem_statement.md"
                assert_not_symlink(stmt_file) if stmt_file.exists() else None
                atomic_write_file(stmt_file, res.redacted_statement)

            if res.redacted_spans:
                redacted_json_file = t_dir / "problem_statement_redacted.json"
                assert_not_symlink(redacted_json_file) if redacted_json_file.exists() else None
                spans_dict = [s.to_dict() for s in res.redacted_spans]
                atomic_write_file(redacted_json_file, json.dumps({"spans": spans_dict}, indent=2) + "\n")

        if m_data:
            manifest_file = t_dir / "manifest.json"
            assert_not_symlink(manifest_file) if manifest_file.exists() else None
            atomic_write_file(manifest_file, json.dumps(m_data, indent=2) + "\n")

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
        print(f"Fatal error processing dispositions: {exc}", file=sys.stderr)
        return 2

    print(format_summary(summary))
    return 0


if __name__ == "__main__":
    sys.exit(dispositions_cli())
