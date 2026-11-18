"""Scoring tool for Hermetic E3 blind leak seeding.

Runs sealcheck on every seeded world and compares results against the private
answer key, printing aggregate numbers (recall, precision, per-channel counts).
Per-case details are displayed ONLY when the explicit --reveal flag is provided.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

MAX_KEY_BYTES: int = 16 * 1024 * 1024
READ_CHUNK_BYTES: int = 64 * 1024


@dataclass(frozen=True, slots=True)
class CaseScoreResult:
    """Evaluation outcome for a single seeded world."""

    case_id: str
    channel: str
    is_leak: bool
    detected: bool
    outcome: str  # TP, FN, TN, FP, ERROR
    findings_count: int


@dataclass(frozen=True, slots=True)
class AggregateScoreReport:
    """Aggregate accuracy metrics across all evaluated blind cases."""

    total_cases: int
    total_leaks: int
    detected_leaks: int
    total_decoys: int
    false_alarms: int
    recall: float
    precision: float
    per_channel: dict[str, dict[str, Any]]
    cases: list[CaseScoreResult]


def find_sealcheck_bin(custom_path: Path | str | None = None) -> Path:
    """Locate the hermetic-sealcheck binary securely."""
    if custom_path is not None:
        p = Path(custom_path)
        if p.is_file() and os.access(p, os.X_OK):
            return p.resolve()
        raise FileNotFoundError("Specified sealcheck binary not found or not executable")

    env_val = os.environ.get("HERMETIC_SEALCHECK_BIN")
    if env_val:
        ep = Path(env_val)
        if ep.is_file() and os.access(ep, os.X_OK):
            return ep.resolve()

    which = shutil.which("hermetic-sealcheck")
    if which:
        return Path(which).resolve()

    # Common workspace and target locations
    repo_root = Path(__file__).resolve().parents[2]
    roots = [
        Path("target"),
        repo_root / "target",
        Path.home() / "hermetic" / "cargo-target" / repo_root.name,
    ]
    if os.environ.get("CARGO_TARGET_DIR"):
        roots.append(Path(os.environ["CARGO_TARGET_DIR"]))

    for root in roots:
        for profile in ("debug", "release"):
            candidate = root / profile / "hermetic-sealcheck"
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate.resolve()

    raise FileNotFoundError(
        "Could not find hermetic-sealcheck binary. Build it or provide --sealcheck path."
    )


def load_private_key(key_path: Path) -> dict[str, Any]:
    """Read and validate the private answer key file."""
    if not key_path.exists():
        raise FileNotFoundError("Key file not found")
    if key_path.is_symlink():
        raise PermissionError("Key file is a symlink; symlinks are refused")

    st = key_path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("Key file must be a regular file")
    if st.st_size > MAX_KEY_BYTES:
        raise ValueError(f"Key file size ({st.st_size} bytes) exceeds limit")

    # Mode 0600 verification
    file_mode = st.st_mode & 0o777
    if file_mode != 0o600:
        # Note: Do not expose host username, just report mode
        sys.stderr.write(f"Warning: answer key permissions are 0o{file_mode:o}, expected 0o600\n")

    # Bounded read
    chunks: list[bytes] = []
    total = 0
    fd = os.open(str(key_path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        while True:
            chunk = os.read(fd, READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_KEY_BYTES:
                raise ValueError("Key file exceeded read budget")
    finally:
        os.close(fd)

    content = b"".join(chunks).decode("utf-8")
    data = json.loads(content)
    if "cases" not in data or not isinstance(data["cases"], list):
        raise ValueError("Invalid answer key schema: missing 'cases' list")
    return data


def scan_single_world(
    sealcheck_bin: Path | str,
    world_dir: Path,
    task_dir: Path,
    base_tree_dir: Path,
    timeout: float = 60.0,
) -> tuple[bool, int, list[dict]]:
    """Run sealcheck on a seeded world root.

    Returns:
        (gate_detected, return_code, findings_list)
    """
    cmd = [
        str(sealcheck_bin),
        "scan",
        "--task",
        str(task_dir),
        "--base-tree",
        str(base_tree_dir),
        "--root",
        str(world_dir),
        "--root-visibility",
        "agent_visible",
        "--format",
        "json",
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
        )
        rc = proc.returncode
        findings: list[dict] = []
        try:
            payload = json.loads(proc.stdout.decode("utf-8", errors="replace"))
            findings = payload.get("findings", [])
        except Exception:
            pass

        gate_detected = (rc == 2) or any(
            f.get("severity") == "gate" and f.get("visibility", "agent_visible") == "agent_visible"
            for f in findings
        )
        return (gate_detected, rc, findings)
    except subprocess.TimeoutExpired:
        return (False, -1, [])
    except Exception:
        return (False, -1, [])


def evaluate_blind_cases(
    key_data: dict[str, Any],
    sealcheck_bin: Path | str | None = None,
    scanner_fn: Callable[[Path, Path, Path], tuple[bool, int, list[dict]]] | None = None,
) -> AggregateScoreReport:
    """Evaluate all blind cases from key data against sealcheck scanner."""
    cases_raw = key_data["cases"]
    resolved_bin = None
    if scanner_fn is None:
        resolved_bin = find_sealcheck_bin(sealcheck_bin)

    results: list[CaseScoreResult] = []

    for c in cases_raw:
        case_id = c["case_id"]
        channel = c.get("channel", "unknown")
        is_leak = bool(c["is_leak"])
        world_dir = Path(c["world_dir"])
        task_dir = Path(c["task_dir"])
        base_tree_dir = Path(c["base_tree_dir"])

        if scanner_fn is not None:
            detected, rc, findings = scanner_fn(world_dir, task_dir, base_tree_dir)
        else:
            assert resolved_bin is not None
            detected, rc, findings = scan_single_world(
                resolved_bin, world_dir, task_dir, base_tree_dir
            )

        if rc not in (0, 2):
            outcome = "ERROR"
        elif is_leak and detected:
            outcome = "TP"
        elif is_leak and not detected:
            outcome = "FN"
        elif not is_leak and not detected:
            outcome = "TN"
        else:
            outcome = "FP"

        results.append(
            CaseScoreResult(
                case_id=case_id,
                channel=channel,
                is_leak=is_leak,
                detected=detected,
                outcome=outcome,
                findings_count=len(findings),
            )
        )

    # Calculate overall metrics
    tp = sum(1 for r in results if r.outcome == "TP")
    fn = sum(1 for r in results if r.outcome == "FN")
    tn = sum(1 for r in results if r.outcome == "TN")
    fp = sum(1 for r in results if r.outcome == "FP")

    total_leaks = tp + fn
    detected_leaks = tp
    total_decoys = tn + fp
    false_alarms = fp

    recall = (detected_leaks / total_leaks) if total_leaks > 0 else 0.0
    precision = (detected_leaks / (detected_leaks + false_alarms)) if (detected_leaks + false_alarms) > 0 else 0.0

    # Calculate per-channel metrics
    all_channels = sorted(list({r.channel for r in results}))
    per_channel: dict[str, dict[str, Any]] = {}
    for ch in all_channels:
        ch_results = [r for r in results if r.channel == ch]
        ch_tp = sum(1 for r in ch_results if r.outcome == "TP")
        ch_fn = sum(1 for r in ch_results if r.outcome == "FN")
        ch_tn = sum(1 for r in ch_results if r.outcome == "TN")
        ch_fp = sum(1 for r in ch_results if r.outcome == "FP")
        ch_leaks = ch_tp + ch_fn
        ch_decoys = ch_tn + ch_fp
        ch_recall = (ch_tp / ch_leaks) if ch_leaks > 0 else 0.0
        ch_precision = (ch_tp / (ch_tp + ch_fp)) if (ch_tp + ch_fp) > 0 else 0.0

        per_channel[ch] = {
            "planted": ch_leaks,
            "detected": ch_tp,
            "missed": ch_fn,
            "decoys": ch_decoys,
            "false_alarms": ch_fp,
            "recall": ch_recall,
            "precision": ch_precision,
        }

    return AggregateScoreReport(
        total_cases=len(results),
        total_leaks=total_leaks,
        detected_leaks=detected_leaks,
        total_decoys=total_decoys,
        false_alarms=false_alarms,
        recall=recall,
        precision=precision,
        per_channel=per_channel,
        cases=results,
    )


def format_report_text(report: AggregateScoreReport, reveal: bool = False) -> str:
    """Format scoring report in terminal-friendly text."""
    lines: list[str] = [
        "============================================================",
        "Hermetic E3: Blind Seeding Evaluation Results",
        "============================================================",
        f"Total Cases Evaluated: {report.total_cases}",
        f"Planted Leaks:         {report.total_leaks}",
        f"Detected Leaks:        {report.detected_leaks}",
        f"Decoys (Clean):        {report.total_decoys}",
        f"False Alarms:          {report.false_alarms}",
        "",
        f"Overall Recall:        {report.recall * 100:.1f}% ({report.detected_leaks} / {report.total_leaks})",
        f"Overall Precision:     {report.precision * 100:.1f}%",
        "",
        "Per-Channel Breakdown:",
        "-" * 72,
        f"{'Channel':<18} {'Planted':>8} {'Detected':>9} {'Recall':>9} {'Decoys':>8} {'False+':>8}",
        "-" * 72,
    ]

    for ch, stats in sorted(report.per_channel.items()):
        rec_str = f"{stats['recall'] * 100:.1f}%" if stats["planted"] > 0 else "N/A"
        lines.append(
            f"{ch:<18} {stats['planted']:>8} {stats['detected']:>9} {rec_str:>9} {stats['decoys']:>8} {stats['false_alarms']:>8}"
        )

    lines.append("-" * 72)

    if reveal:
        lines.append("")
        lines.append("Per-Case Details (--reveal):")
        lines.append("-" * 72)
        lines.append(f"{'Case ID':<32} {'Channel':<16} {'Type':<8} {'Outcome':<8} {'Detected':<8}")
        lines.append("-" * 72)
        for r in report.cases:
            t_str = "LEAK" if r.is_leak else "DECOY"
            det_str = "YES" if r.detected else "NO"
            lines.append(f"{r.case_id:<32} {r.channel:<16} {t_str:<8} {r.outcome:<8} {det_str:<8}")
        lines.append("-" * 72)

    lines.append("============================================================")
    return "\n".join(lines)


def run_score_blind(
    key_path: Path,
    sealcheck_bin: Path | str | None = None,
    reveal: bool = False,
    output_fn: Callable[[str], None] | None = None,
    scanner_fn: Callable[[Path, Path, Path], tuple[bool, int, list[dict]]] | None = None,
) -> AggregateScoreReport:
    """Execute score_blind evaluation and output results."""
    echo = output_fn if output_fn is not None else (lambda s: sys.stdout.write(s + "\n"))
    key_data = load_private_key(key_path)
    report = evaluate_blind_cases(key_data, sealcheck_bin=sealcheck_bin, scanner_fn=scanner_fn)
    formatted = format_report_text(report, reveal=reveal)
    echo(formatted)
    return report


def main() -> None:
    """CLI entrypoint for `python -m hermetic_e3.score_blind`."""
    parser = argparse.ArgumentParser(
        prog="hermetic_e3.score_blind",
        description="Score sealcheck accuracy on blind-seeded fixture worlds.",
    )
    parser.add_argument(
        "--key",
        type=Path,
        default=Path.home() / ".hermetic-e3-blind" / "key.json",
        help="Path to private answer key JSON file (default: ~/.hermetic-e3-blind/key.json)",
    )
    parser.add_argument(
        "--sealcheck",
        type=Path,
        default=None,
        help="Path to hermetic-sealcheck binary (defaults to auto-detection)",
    )
    parser.add_argument(
        "--reveal",
        action="store_true",
        default=False,
        help="Reveal per-case details (defaults to aggregate numbers only)",
    )
    args = parser.parse_args()

    try:
        run_score_blind(
            key_path=args.key,
            sealcheck_bin=args.sealcheck,
            reveal=args.reveal,
        )
    except Exception as exc:
        sys.stderr.write(f"Error: {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
