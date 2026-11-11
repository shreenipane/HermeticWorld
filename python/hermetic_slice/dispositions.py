"""Dispositions engine and CLI for tasks that fail the sealcheck gate (§5.5, TRD.md).

A task that fails the leak gate must never be dropped silently, because that changes
the score's denominator (§5.5). Each failing task gets a disposition:
  - 'clean': task passed the gate (no gate findings)
  - 'repaired': sealer removed the leak without changing the task, and re-scan is clean
  - 'excluded': the leak *is* the task (issue text is the fix), or a non-D0 detector has no
    automatic removal, or re-scan remained dirty after redaction.
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


# Exclusion threshold: if redacting the leak would remove more than 50% of the
# original problem statement (by characters), or leave fewer than 20 non-whitespace
# characters, the leak *is* the task ("the issue text is the fix", §5.5).
MAX_REDACTION_FRACTION: float = 0.50
MIN_REMAINING_CHARS: int = 20


class DispositionsError(Exception):
    """Base error for dispositions processing."""


class MalformedGateOutputError(DispositionsError):
    """Raised when gate output is corrupted, invalid JSON, or missing required fields."""


class MissingDispositionError(DispositionsError):
    """Raised when any task in the input set lacks a valid disposition."""


@dataclass(frozen=True)
class RedactedSpan:
    """Record of a single redacted span in the problem statement.

    Records offsets and cryptographic digest, NEVER the leaked text itself (§5.5).
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


def find_spans_in_text(text: str, evidence_strings: list[str]) -> list[tuple[int, int]]:
    """Locate evidence string spans in problem statement text and merge overlapping intervals."""
    raw_spans: list[tuple[int, int]] = []

    for ev in evidence_strings:
        if not ev:
            continue
        # 1. Exact match
        start = 0
        while True:
            idx = text.find(ev, start)
            if idx == -1:
                break
            raw_spans.append((idx, idx + len(ev)))
            start = idx + 1

        # 2. Stripped match if not found
        ev_stripped = ev.strip()
        if ev_stripped and ev_stripped != ev:
            start = 0
            while True:
                idx = text.find(ev_stripped, start)
                if idx == -1:
                    break
                raw_spans.append((idx, idx + len(ev_stripped)))
                start = idx + 1

        # 3. Line by line match if multiline
        if "\n" in ev:
            for line in ev.splitlines():
                line_stripped = line.strip()
                if len(line_stripped) >= 10:
                    start = 0
                    while True:
                        idx = text.find(line_stripped, start)
                        if idx == -1:
                            break
                        raw_spans.append((idx, idx + len(line_stripped)))
                        start = idx + 1

    if not raw_spans:
        return []

    # Sort and merge overlapping or adjacent spans
    raw_spans.sort(key=lambda s: (s[0], s[1]))
    merged: list[tuple[int, int]] = [raw_spans[0]]
    for s_start, s_end in raw_spans[1:]:
        last_start, last_end = merged[-1]
        if s_start <= last_end:
            merged[-1] = (last_start, max(last_end, s_end))
        else:
            merged.append((s_start, s_end))

    return merged


def redact_problem_statement(
    statement: str,
    spans: list[tuple[int, int]],
    placeholder: str = "[REDACTED]",
) -> tuple[str, list[RedactedSpan]]:
    """Redact spans from statement. Returns redacted string and RedactedSpan metadata."""
    redacted_records: list[RedactedSpan] = []

    # Calculate span hashes based on the original statement before modification
    for s_start, s_end in spans:
        span_bytes = statement[s_start:s_end].encode("utf-8")
        h = hashlib.sha256(span_bytes).hexdigest()
        redacted_records.append(
            RedactedSpan(
                start=s_start,
                end=s_end,
                sha256=h,
                hash=f"sha256:{h}",
            )
        )

    # Apply redactions in reverse offset order so earlier indices remain valid
    result = statement
    for s_start, s_end in reversed(spans):
        result = result[:s_start] + placeholder + result[s_end:]

    return result, redacted_records


def decide_task_disposition(
    task_id: str,
    findings: list[dict[str, Any]],
    *,
    gate_flag: bool | None = None,
    problem_statement: str | None = None,
    explicit_spans: list[tuple[int, int]] | None = None,
    issue_text_is_the_fix: bool = False,
    rescan_fn: Callable[[str, str], dict[str, Any] | list[dict[str, Any]]] | None = None,
    manifest: dict[str, Any] | None = None,
    world_version: str | None = None,
    recompute_world_version_fn: Callable[[dict[str, Any]], str] | None = None,
) -> TaskDispositionResult:
    """Decide disposition for a single task according to §5.5 rules.

    - 'clean': no gate findings.
    - 'excluded':
      * non-D0 gate findings (no automatic removal exists for other detectors).
      * D0 leak is the task ("the issue text is the fix": redaction > MAX_REDACTION_FRACTION
        or leaves < MIN_REMAINING_CHARS non-whitespace chars).
      * D0 leak re-scan is still dirty after redaction (all firing detectors named).
    - 'repaired':
      * D0 leak with removable span redacted, re-scan clean.
    """
    if gate_flag is False and not findings:
        return TaskDispositionResult(
            task_id=task_id,
            disposition="clean",
            detectors=[],
            reason="gate passed",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
        )

    # Filter for gate-level findings
    gate_findings = [
        f for f in findings
        if f.get("severity") == "gate" and f.get("visibility", "agent_visible") != "image_only"
    ]

    if not gate_findings:
        return TaskDispositionResult(
            task_id=task_id,
            disposition="clean",
            detectors=[],
            reason="gate passed",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
        )

    fired_detectors = sorted(list({str(f.get("detector", "")) for f in gate_findings if f.get("detector")}))

    # 1. Non-D0 detectors: no automatic removal exists in sealer -> excluded
    non_d0 = [d for d in fired_detectors if d != "D0"]
    if non_d0:
        return TaskDispositionResult(
            task_id=task_id,
            disposition="excluded",
            detectors=fired_detectors,
            reason=f"unsupported detector with no automatic removal: {', '.join(non_d0)}",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
        )

    # 2. Only D0 fired: evaluate if the leak *is* the task or can be repaired
    if issue_text_is_the_fix:
        return TaskDispositionResult(
            task_id=task_id,
            disposition="excluded",
            detectors=["D0"],
            reason="the leak is the task: issue text is the fix",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
        )

    if problem_statement is None:
        # Without problem statement, we cannot redact -> must exclude
        return TaskDispositionResult(
            task_id=task_id,
            disposition="excluded",
            detectors=["D0"],
            reason="problem statement unavailable for leak repair",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
        )

    # Identify spans to redact
    if explicit_spans is not None:
        spans = explicit_spans
    else:
        evidence_list: list[str] = []
        for f in gate_findings:
            if f.get("detector") == "D0":
                ev = f.get("evidence", [])
                if isinstance(ev, list):
                    evidence_list.extend(str(item) for item in ev)
                elif isinstance(ev, str):
                    evidence_list.append(ev)
        spans = find_spans_in_text(problem_statement, evidence_list)

    if not spans:
        # D0 fired but no matching spans could be found to remove
        return TaskDispositionResult(
            task_id=task_id,
            disposition="excluded",
            detectors=["D0"],
            reason="the leak is the task: leaking span cannot be removed without destroying problem statement",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
        )

    # Check fraction of problem statement removed
    total_span_chars = sum(s_end - s_start for s_start, s_end in spans)
    stmt_len = len(problem_statement)
    fraction = total_span_chars / stmt_len if stmt_len > 0 else 1.0

    # Simulate redaction to check remaining text
    redacted_text, redacted_spans = redact_problem_statement(problem_statement, spans)
    non_ws_remaining = len(re.sub(r"\s+", "", redacted_text.replace("[REDACTED]", "")))

    if fraction > MAX_REDACTION_FRACTION or non_ws_remaining < MIN_REMAINING_CHARS:
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
        # Default: if no re-scan function provided, cannot verify repair holds
        return TaskDispositionResult(
            task_id=task_id,
            disposition="excluded",
            detectors=["D0"],
            reason="re-scan verification not configured; disposition unverified",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
        )

    rescan_output = rescan_fn(task_id, redacted_text)
    if isinstance(rescan_output, dict):
        rescan_findings = rescan_output.get("findings", [])
    elif isinstance(rescan_output, list):
        rescan_findings = rescan_output
    else:
        raise MalformedGateOutputError(f"Unexpected re-scan output type: {type(rescan_output)}")

    rescan_gate_findings = [
        f for f in rescan_findings
        if f.get("severity") == "gate" and f.get("visibility", "agent_visible") != "image_only"
    ]

    if rescan_gate_findings:
        # Re-scan still fires -> excluded with EVERY detector that fired
        rescan_detectors = sorted(list({str(f.get("detector", "")) for f in rescan_gate_findings if f.get("detector")}))
        return TaskDispositionResult(
            task_id=task_id,
            disposition="excluded",
            detectors=rescan_detectors,
            reason=f"re-scan still dirty after redaction: {', '.join(rescan_detectors)} fired",
            world_version=world_version or (manifest.get("world_root") if manifest else None),
            redacted_spans=[],
        )

    # 4. Re-scan is clean -> repaired!
    new_version = world_version
    if manifest is not None:
        dispositions_list = manifest.setdefault("dispositions", [])
        dispositions_list.append({
            "kind": "repaired",
            "detector": "D0",
            "detail": f"problem_statement_redacted: {len(redacted_spans)} span(s)",
        })
        if recompute_world_version_fn:
            new_version = recompute_world_version_fn(manifest)
        elif "world_root" in manifest:
            # Deterministically derive new world version for repaired world
            h = hashlib.blake2s(key=b"world-repaired")
            h.update(str(manifest.get("world_root", "")).encode("utf-8"))
            for span in redacted_spans:
                h.update(span.sha256.encode("utf-8"))
            new_version = f"blake3:{h.hexdigest()}"
            manifest["world_root"] = new_version
        else:
            h = hashlib.sha256(f"{task_id}:repaired:{len(redacted_spans)}".encode("utf-8")).hexdigest()
            new_version = f"blake3:{h}"

    return TaskDispositionResult(
        task_id=task_id,
        disposition="repaired",
        detectors=["D0"],
        reason="D0 leak repaired: problem statement redacted and re-scan clean",
        world_version=new_version,
        redacted_spans=redacted_spans,
        redacted_statement=redacted_text,
    )


def parse_gate_output_data(data: Any) -> list[dict[str, Any]]:
    """Strictly parse raw gate output data into a normalized list of report dicts.

    Raises MalformedGateOutputError on malformed input.
    """
    if isinstance(data, list):
        reports = []
        for idx, item in enumerate(data):
            if not isinstance(item, dict):
                raise MalformedGateOutputError(f"Entry {idx} in gate output list is not an object: {item}")
            task_id = item.get("task_id") or item.get("instance_id")
            if not task_id or not isinstance(task_id, str):
                raise MalformedGateOutputError(f"Entry {idx} missing valid task_id / instance_id: {item}")
            if "findings" not in item:
                raise MalformedGateOutputError(f"Entry '{task_id}' missing 'findings' field")
            if not isinstance(item["findings"], list):
                raise MalformedGateOutputError(f"Entry '{task_id}' has non-list findings")
            reports.append(item)
        return reports

    if isinstance(data, dict):
        if "schema" in data and ("instance_id" in data or "task_id" in data):
            # Single sealcheck report
            task_id = data.get("task_id") or data.get("instance_id")
            if not isinstance(data.get("findings"), list):
                raise MalformedGateOutputError(f"Single report '{task_id}' has non-list findings")
            return [data]

        if "tasks" in data and isinstance(data["tasks"], list):
            return parse_gate_output_data(data["tasks"])

        if "reports" in data and isinstance(data["reports"], list):
            return parse_gate_output_data(data["reports"])

        # Mapping of task_id -> report
        reports = []
        for key, val in data.items():
            if not isinstance(val, dict):
                raise MalformedGateOutputError(f"Report for task '{key}' is not an object: {val}")
            item = dict(val)
            item.setdefault("task_id", key)
            if "findings" not in item:
                raise MalformedGateOutputError(f"Report for task '{key}' missing 'findings' field")
            if not isinstance(item["findings"], list):
                raise MalformedGateOutputError(f"Report for task '{key}' has non-list findings")
            reports.append(item)
        return reports

    raise MalformedGateOutputError(f"Gate output must be a list or dict, got {type(data)}")


def load_gate_output(gate_source: str | Path) -> list[dict[str, Any]]:
    """Load and parse gate output from file or directory.

    Raises MalformedGateOutputError on missing files, malformed JSON, or schema errors.
    """
    path = Path(gate_source)
    if not path.exists():
        raise MalformedGateOutputError(f"Gate output path does not exist: {path}")

    if path.is_file():
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as exc:
            raise MalformedGateOutputError(f"Failed to read gate output file '{path}': {exc}") from exc

        try:
            data = json.loads(content)
        except Exception as exc:
            raise MalformedGateOutputError(f"Gate output file '{path}' contains invalid JSON: {exc}") from exc

        return parse_gate_output_data(data)

    if path.is_dir():
        reports: list[dict[str, Any]] = []
        json_files = sorted(path.glob("*.json"))
        if not json_files:
            raise MalformedGateOutputError(f"No JSON gate reports found in directory: {path}")
        for jf in json_files:
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
            except Exception as exc:
                raise MalformedGateOutputError(f"Invalid JSON in gate report file '{jf}': {exc}") from exc
            parsed = parse_gate_output_data(data)
            reports.extend(parsed)
        return reports

    raise MalformedGateOutputError(f"Unsupported path type: {path}")


def process_dispositions(
    gate_source: str | Path | list[dict[str, Any]] | dict[str, Any],
    out_path: str | Path | None = None,
    tasks_dir: str | Path | None = None,
    rescan_fn: Callable[[str, str], dict[str, Any] | list[dict[str, Any]]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Process gate outputs for all tasks, decide dispositions, and atomically emit dispositions.json.

    Returns (disposition_entries, summary).
    Raises MalformedGateOutputError on malformed input.
    Raises MissingDispositionError if any task lacks a disposition.
    """
    if isinstance(gate_source, (str, Path)):
        reports = load_gate_output(gate_source)
    else:
        reports = parse_gate_output_data(gate_source)

    if not reports:
        raise MalformedGateOutputError("Gate output contains no tasks")

    # Map reports by task_id to ensure every task has exactly one disposition
    tasks_base = Path(tasks_dir) if tasks_dir else None
    results: list[TaskDispositionResult] = []

    for report in reports:
        task_id = report.get("task_id") or report.get("instance_id")
        if not task_id:
            raise MalformedGateOutputError(f"Report missing task_id: {report}")

        findings = report.get("findings", [])
        gate_flag = report.get("gate")

        # Load task metadata / problem statement / manifest if tasks_dir is available
        stmt_text = report.get("problem_statement")
        manifest_data = report.get("manifest")
        task_json_data = report.get("task_json")
        w_version = report.get("world_version")

        task_dir_path = (tasks_base / task_id) if tasks_base else None
        if task_dir_path and task_dir_path.exists():
            stmt_file = task_dir_path / "agent" / "problem_statement.md"
            if stmt_text is None and stmt_file.is_file():
                stmt_text = stmt_file.read_text(encoding="utf-8")

            manifest_file = task_dir_path / "manifest.json"
            if manifest_data is None and manifest_file.is_file():
                try:
                    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
                except Exception:
                    manifest_data = None

            task_file = task_dir_path / "task.json"
            if task_json_data is None and task_file.is_file():
                try:
                    task_json_data = json.loads(task_file.read_text(encoding="utf-8"))
                except Exception:
                    task_json_data = None

        if w_version is None and manifest_data:
            w_version = manifest_data.get("world_root")

        # Setup re-scan handler if task on disk and sealcheck available
        effective_rescan = rescan_fn
        if effective_rescan is None and report.get("rescan_fn"):
            effective_rescan = report["rescan_fn"]

        disp_res = decide_task_disposition(
            task_id=task_id,
            findings=findings,
            gate_flag=gate_flag,
            problem_statement=stmt_text,
            explicit_spans=report.get("explicit_spans"),
            issue_text_is_the_fix=report.get("issue_text_is_the_fix", False),
            rescan_fn=effective_rescan,
            manifest=manifest_data,
            world_version=w_version,
        )

        # If repaired and task directory exists on disk, persist changes
        if disp_res.disposition == "repaired" and task_dir_path and task_dir_path.exists():
            if disp_res.redacted_statement is not None:
                stmt_file = task_dir_path / "agent" / "problem_statement.md"
                stmt_file.parent.mkdir(parents=True, exist_ok=True)
                stmt_file.write_text(disp_res.redacted_statement, encoding="utf-8")

            if disp_res.redacted_spans:
                redacted_json_file = task_dir_path / "problem_statement_redacted.json"
                spans_dict = [s.to_dict() for s in disp_res.redacted_spans]
                redacted_json_file.write_text(json.dumps({"spans": spans_dict}, indent=2), encoding="utf-8")

            if manifest_data:
                manifest_file = task_dir_path / "manifest.json"
                manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        results.append(disp_res)

    # Verify no task lacks a disposition
    for res in results:
        if not res.disposition:
            raise MissingDispositionError(f"Task '{res.task_id}' lacks a disposition")

    # Output for N tasks always has N entries; sorted and stable
    results.sort(key=lambda r: r.task_id)
    entries = [r.to_dict() for r in results]

    # Compute summary
    summary_counts: dict[str, int] = {"clean": 0, "repaired": 0, "excluded": 0}
    detector_counts: dict[str, int] = {}
    for r in results:
        summary_counts[r.disposition] = summary_counts.get(r.disposition, 0) + 1
        for d in r.detectors:
            detector_counts[d] = detector_counts.get(d, 0) + 1

    summary = {
        "total_tasks": len(results),
        "dispositions": summary_counts,
        "detectors": dict(sorted(detector_counts.items())),
    }

    # Atomic write to dispositions.json if out_path requested
    if out_path:
        out_dest = Path(out_path)
        out_dest.parent.mkdir(parents=True, exist_ok=True)

        # Use temporary file in the same directory to guarantee atomic rename
        fd, tmp_file_str = tempfile.mkstemp(dir=out_dest.parent, prefix="dispositions_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2)
                f.write("\n")
            os.replace(tmp_file_str, out_dest)
        except Exception:
            if os.path.exists(tmp_file_str):
                os.remove(tmp_file_str)
            raise

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

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1

    try:
        entries, summary = process_dispositions(
            gate_source=args.gate_output,
            out_path=args.out,
            tasks_dir=args.tasks_dir,
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
