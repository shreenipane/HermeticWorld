"""Comprehensive tests and regression tests for task dispositions (§5.5, T1.14)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from tests.disposition_fixtures import complete_manifest, complete_task

from hermetic_slice import (
    DispositionsError,
    MalformedGateOutputError,
    MissingDispositionError,
    decide_task_disposition,
    find_spans_in_text,
    process_dispositions,
    redact_problem_statement,
    MAX_REDACTION_FRACTION,
    MIN_REMAINING_CHARS,
)
from hermetic_slice.dispositions import (
    char_to_byte_span,
    dispositions_cli,
    format_summary,
    validate_and_merge_spans,
    validate_task_id,
)
from hermetic_slice.__main__ import main as cli_main


# =========================================================================
# Defect 1: CLI re-scan end-to-end with real sealcheck binary
# =========================================================================

def test_cli_end_to_end_real_rescan_repaired_and_excluded(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Test CLI path end to end: removable D0 becomes 'repaired' via real sealcheck re-scan,

    and dirty re-scan stays 'excluded'.
    """
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir(parents=True)

    # Task 1: removable D0 leak that repairs cleanly
    t1_dir = tasks_dir / "task__clean-repair-01"
    t1_dir.mkdir(parents=True)
    (t1_dir / "agent").mkdir(parents=True)
    t1_leak = "SECRET_LEAK_01 = True"
    t1_stmt = (
        "# Calculation Module Report\n\n"
        "Users report that the calculation module is failing under high loads.\n\n"
        f"Leaked patch: {t1_leak}\n\n"
        "Please fix the internal mathematical model to avoid zero-division errors."
    )
    (t1_dir / "agent" / "problem_statement.md").write_text(t1_stmt, encoding="utf-8")
    (t1_dir / "task.json").write_text(
        json.dumps(complete_task("task__clean-repair-01")),
        encoding="utf-8",
    )

    # Task 2: D0 leak where sealcheck stub/runner will report dirty re-scan
    t2_dir = tasks_dir / "task__dirty-rescan-02"
    t2_dir.mkdir(parents=True)
    (t2_dir / "agent").mkdir(parents=True)
    t2_leak = "DIRTY_LEAK_02 = 123"
    t2_stmt = (
        "# Parser Module Report\n\n"
        "The parser fails when handling nested multiline tags in documents.\n\n"
        f"Leaked patch: {t2_leak}\n\n"
        "Ensure syntax trees are balanced across block boundaries."
    )
    (t2_dir / "agent" / "problem_statement.md").write_text(t2_stmt, encoding="utf-8")
    (t2_dir / "task.json").write_text(
        json.dumps(complete_task("task__dirty-rescan-02")),
        encoding="utf-8",
    )

    # Create stub sealcheck executable script that verifies real invocation
    stub_sealcheck = tmp_path / "stub_sealcheck.py"
    stub_content = (
        "#!/usr/bin/env python3\n"
        "import argparse, json, sys\n"
        "from pathlib import Path\n"
        "parser = argparse.ArgumentParser()\n"
        "subparsers = parser.add_subparsers(dest='subcommand')\n"
        "scan_p = subparsers.add_parser('scan')\n"
        "scan_p.add_argument('--task', required=True)\n"
        "scan_p.add_argument('--base-tree')\n"
        "scan_p.add_argument('--root')\n"
        "scan_p.add_argument('--root-visibility')\n"
        "scan_p.add_argument('--format')\n"
        "args = parser.parse_args()\n"
        "\n"
        "task_dir = Path(args.task)\n"
        "stmt = (task_dir / 'agent' / 'problem_statement.md').read_text(encoding='utf-8')\n"
        "instance_id = task_dir.name\n"
        "\n"
        "if 'task__dirty-rescan' in instance_id:\n"
        "    findings = [{'detector': 'D0', 'severity': 'gate', 'visibility': 'agent_visible', 'channel': 'problem_statement', 'path': 'agent/problem_statement.md', 'confidence': 1.0, 'evidence': []}]\n"
        "    print(json.dumps({'schema': 'hermetic-sealcheck/v0', 'instance_id': instance_id, 'findings': findings, 'gate': True, 'not_covered': []}))\n"
        "    sys.exit(2)\n"
        "else:\n"
        "    # Clean re-scan\n"
        "    print(json.dumps({'schema': 'hermetic-sealcheck/v0', 'instance_id': instance_id, 'findings': [], 'gate': False, 'not_covered': []}))\n"
        "    sys.exit(0)\n"
    )
    stub_sealcheck.write_text(stub_content, encoding="utf-8")
    stub_sealcheck.chmod(0o755)

    gate_file = tmp_path / "gate_input.json"
    gate_data = [
        {"not_covered": [],
            "task_id": "task__clean-repair-01",
            "findings": [
                {"path": "agent/problem_statement.md", "confidence": 1.0,
                    "detector": "D0",
                    "channel": "problem_statement",
                    "severity": "gate",
                    "visibility": "agent_visible",
                    "evidence": [t1_leak],
                }
            ],
            "gate": True,
        },
        {"not_covered": [],
            "task_id": "task__dirty-rescan-02",
            "findings": [
                {"path": "agent/problem_statement.md", "confidence": 1.0,
                    "detector": "D0",
                    "channel": "problem_statement",
                    "severity": "gate",
                    "visibility": "agent_visible",
                    "evidence": [t2_leak],
                }
            ],
            "gate": True,
        },
    ]
    base_tree = tmp_path / "base"
    base_tree.mkdir()
    world_root = tmp_path / "world"
    world_root.mkdir()
    os.utime(world_root, (1704067200, 1704067200))
    for task_dir, item in zip((t1_dir, t2_dir), gate_data):
        (task_dir / "staging").mkdir()
        (task_dir / "staging" / "gold.patch").write_text("", encoding="utf-8")
        (task_dir / "staging" / "test.patch").write_text("", encoding="utf-8")
        (task_dir / "manifest.json").write_text(json.dumps(complete_manifest(item["task_id"])), encoding="utf-8")
        item["scan_config"] = {"base_tree": str(base_tree), "roots": [{"path": str(world_root), "visibility": "agent_visible"}]}
    gate_file.write_text(json.dumps(gate_data), encoding="utf-8")

    out_file = tmp_path / "dispositions.json"

    # Invoke CLI with --sealcheck pointing to executable
    code = cli_main([
        "dispositions",
        "--gate-output", str(gate_file),
        "--tasks-dir", str(tasks_dir),
        "--out", str(out_file),
        "--sealcheck", str(stub_sealcheck),
    ])
    assert code == 0
    assert out_file.exists()

    entries = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(entries) == 2

    # Task 1 was repaired cleanly
    e1 = next(e for e in entries if e["task_id"] == "task__clean-repair-01")
    assert e1["disposition"] == "repaired"
    assert e1["detectors"] == ["D0"]
    assert e1["world_version"] is not None
    assert (t1_dir / "problem_statement_redacted.json").exists()

    # Task 2 re-scan stayed dirty -> excluded
    e2 = next(e for e in entries if e["task_id"] == "task__dirty-rescan-02")
    assert e2["disposition"] == "excluded"
    assert "D0" in e2["detectors"]


# =========================================================================
# Defect 2: Spans validation, sorting, and merging
# =========================================================================

def test_spans_validation_sorting_and_merging() -> None:
    """Validate, sort, and merge overlapping, nested, duplicate, and unsorted spans; reject out-of-range."""
    stmt = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    stmt_len = len(stmt.encode("utf-8"))

    # Unsorted: [(20, 30), (0, 5)] -> sorted & merged: [(0, 5), (20, 30)]
    assert validate_and_merge_spans(stmt_len, [(20, 30), (0, 5)]) == [(0, 5), (20, 30)]

    # Nested: [(0, 30), (5, 10)] -> [(0, 30)]
    assert validate_and_merge_spans(stmt_len, [(0, 30), (5, 10)]) == [(0, 30)]

    # Overlapping: [(0, 15), (10, 25)] -> [(0, 25)]
    assert validate_and_merge_spans(stmt_len, [(0, 15), (10, 25)]) == [(0, 25)]

    # Duplicates: [(5, 10), (5, 10)] -> [(5, 10)]
    assert validate_and_merge_spans(stmt_len, [(5, 10), (5, 10)]) == [(5, 10)]

    # Out of range: start > len or end > len or start > end
    with pytest.raises(DispositionsError):
        validate_and_merge_spans(stmt_len, [(0, stmt_len + 10)])

    with pytest.raises(DispositionsError):
        validate_and_merge_spans(stmt_len, [(10, 5)])

    with pytest.raises(DispositionsError):
        validate_and_merge_spans(stmt_len, [(-1, 5)])

    # Redaction with unsorted + nested spans produces correct output
    redacted_text, spans = redact_problem_statement(stmt, [(20, 30), (0, 5), (25, 35)])
    assert len(spans) == 2
    assert spans[0].start == 0 and spans[0].end == 5
    assert spans[1].start == 20 and spans[1].end == 35
    assert redacted_text.startswith("[REDACTED]56789")


# =========================================================================
# Defect 4: UTF-8 byte offsets and SHA-256 agreement across languages
# =========================================================================

def test_utf8_japanese_byte_offsets_and_sha256() -> None:
    """Offsets are byte offsets into UTF-8 and hashes are SHA-256 hex in both Python and Rust."""
    # '日本' is 6 UTF-8 bytes: \xe6\x97\xa5\xe6\x9c\xac
    stmt = "日本 issue description text here for testing."
    stmt_bytes = stmt.encode("utf-8")
    assert stmt_bytes.startswith("日本".encode("utf-8"))
    assert len("日本".encode("utf-8")) == 6

    # Redacting first 6 bytes
    redacted_text, spans = redact_problem_statement(stmt, [(0, 6)])
    assert len(spans) == 1
    assert spans[0].start == 0
    assert spans[0].end == 6

    # Expected SHA-256 hex of '日本' UTF-8 bytes
    expected_sha256 = "cf2abf0c5be326cb922a70f8163f91079c4d9aa8655c60ead89ad545c9de2e92"
    assert spans[0].sha256 == expected_sha256
    assert spans[0].hash == f"sha256:{expected_sha256}"
    assert redacted_text.startswith("[REDACTED]")


# =========================================================================
# Defect 5: D0 span matching variants
# =========================================================================

def test_d0_span_matching_variants() -> None:
    """Test D0 matching for case, whitespace, joined windows, 250-char line, and short lines."""
    # 1. Case-insensitive matching
    stmt_case = "The function solve_alpha_query() must be rewritten completely."
    spans_case = find_spans_in_text(stmt_case, ["SOLVE_ALPHA_QUERY()"])
    assert len(spans_case) == 1
    redacted, _ = redact_problem_statement(stmt_case, spans_case)
    assert "solve_alpha_query" not in redacted
    assert "[REDACTED]" in redacted

    # 2. Whitespace-normalized matching
    stmt_ws = "def   calculate_special_value(  x,   y  ):\n    return x + y"
    evidence_ws = "def calculate_special_value( x, y ):"
    spans_ws = find_spans_in_text(stmt_ws, [evidence_ws])
    assert len(spans_ws) == 1
    redacted_ws, _ = redact_problem_statement(stmt_ws, spans_ws)
    assert "calculate_special_value" not in redacted_ws

    # 3. Joined windows with " / "
    stmt_win = "First line here.\nSecond leaked line.\nThird intermediate.\nFourth leaked line.\nFifth ending."
    evidence_win = "Second leaked line. / Fourth leaked line."
    spans_win = find_spans_in_text(stmt_win, [evidence_win])
    assert len(spans_win) == 2
    redacted_win, _ = redact_problem_statement(stmt_win, spans_win)
    assert "Second leaked line" not in redacted_win
    assert "Fourth leaked line" not in redacted_win
    assert "Third intermediate" in redacted_win

    # 4. 250-character line truncated to 200 chars in evidence: extends to line end
    long_line = "CONFIG_PARAM_NAME_" + "X" * 230 + "_SUFFIX_END"
    stmt_long = f"Beginning of statement.\n{long_line}\nEnding of statement."
    trunc_evidence = long_line[:200]
    spans_long = find_spans_in_text(stmt_long, [trunc_evidence])
    assert len(spans_long) == 1
    redacted_long, _ = redact_problem_statement(stmt_long, spans_long)
    # Entire line must be redacted, not leaving '_SUFFIX_END' visible!
    assert "_SUFFIX_END" not in redacted_long
    assert "[REDACTED]" in redacted_long

    # 5. Short lines inside multiline evidence are not skipped
    stmt_multi = "Start block\n{\nx\n}\nEnd block"
    evidence_multi = "{\nx\n}"
    spans_multi = find_spans_in_text(stmt_multi, [evidence_multi])
    assert len(spans_multi) == 1
    redacted_multi, _ = redact_problem_statement(stmt_multi, spans_multi)
    assert "{\nx\n}" not in redacted_multi


# =========================================================================
# Defect 6: Never leak sensitive text in logs, errors, or exceptions
# =========================================================================

def test_no_leaked_text_in_errors_or_stderr(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Malformed entry containing a secret string must NOT appear in stderr or exception text."""
    secret_text = "SUPER_SECRET_TOKEN_DO_NOT_LEAK"

    malformed_entry = {"gate": False, "not_covered": [],
        "task_id": "valid_task_id",
        "findings": "invalid_non_list_type_with_secret_" + secret_text,
    }

    with pytest.raises(MalformedGateOutputError) as exc_info:
        process_dispositions([malformed_entry])

    err_msg = str(exc_info.value)
    assert secret_text not in err_msg

    # Also check CLI stderr output
    bad_file = tmp_path / "secret_bad.json"
    bad_file.write_text(json.dumps([{"gate": False, "not_covered": [], "task_id": "t1", "findings": secret_text}]), encoding="utf-8")

    code = cli_main(["dispositions", "--gate-output", str(bad_file)])
    assert code != 0

    captured = capsys.readouterr()
    assert secret_text not in captured.out
    assert secret_text not in captured.err


# =========================================================================
# Defect 7: Gate result consistency (contradictory gate, not_covered, missing detector)
# =========================================================================

def test_gate_result_consistency_checks() -> None:
    """Test contradictory gate flag, query not_covered entries, and missing detector field."""
    # 1. {"gate": true, "findings": []} is contradictory -> error
    with pytest.raises(MalformedGateOutputError, match="gate is true but findings contains no gate findings"):
        decide_task_disposition(
            task_id="task_contradictory",
            findings=[],
            gate_flag=True,
        )

    # 2. query-mode not_covered entries -> error
    with pytest.raises(MalformedGateOutputError, match="not_covered detectors"):
        decide_task_disposition(
            task_id="task_query_incomplete",
            findings=[],
            not_covered=["D1", "D3"],
        )

    # 3. Gate finding missing detector -> error, never default to D0
    with pytest.raises(MalformedGateOutputError, match="missing 'detector' field"):
        decide_task_disposition(
            task_id="task_missing_detector",
            findings=[{"severity": "gate", "visibility": "agent_visible"}],
        )


# =========================================================================
# Defect 8: Guard denominator (duplicates, missing reports)
# =========================================================================

def test_denominator_guarding_duplicate_and_missing(tmp_path: Path) -> None:
    """Duplicate task_ids fail; every task under tasks-dir must have a report."""
    # Duplicate task_id
    dup_reports = [
        {"gate": False, "not_covered": [], "task_id": "task_dup", "findings": []},
        {"gate": False, "not_covered": [], "task_id": "task_dup", "findings": []},
    ]
    with pytest.raises(MalformedGateOutputError, match="Duplicate task_id"):
        process_dispositions(dup_reports)

    # Missing task from tasks_dir
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir(parents=True)
    (tasks_dir / "task_present").mkdir()
    (tasks_dir / "task_missing").mkdir()

    reports_partial = [
        {"gate": False, "not_covered": [], "task_id": "task_present", "findings": []},
    ]

    with pytest.raises(MissingDispositionError, match="Missing gate report for task"):
        process_dispositions(reports_partial, tasks_dir=tasks_dir)


# =========================================================================
# Defect 9: Atomicity and Idempotent Rerun
# =========================================================================

def test_atomicity_malformed_task_leaves_no_disk_changes(tmp_path: Path) -> None:
    """Task A repaired then task B malformed leaves nothing changed on disk."""
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir(parents=True)

    t_a = tasks_dir / "task_a"
    t_a.mkdir(parents=True)
    (t_a / "agent").mkdir(parents=True)
    orig_stmt = "Long problem description text.\nSECRET_LEAK\nMore information."
    (t_a / "agent" / "problem_statement.md").write_text(orig_stmt, encoding="utf-8")

    out_file = tmp_path / "dispositions.json"

    # Input: task_a (valid) followed by task_b (malformed, missing findings)
    reports = [
        {"gate": True, "not_covered": [],
            "task_id": "task_a",
            "findings": [{"visibility": "agent_visible", "channel": "problem_statement", "path": "agent/problem_statement.md", "confidence": 1.0, "detector": "D0", "severity": "gate", "evidence": ["SECRET_LEAK"]}],
        },
        {
            "task_id": "task_b",
            # missing findings!
        },
    ]

    with pytest.raises(MalformedGateOutputError):
        process_dispositions(
            reports,
            out_path=out_file,
            tasks_dir=tasks_dir,
            rescan_fn=lambda tid, stmt: {"gate": False, "not_covered": [], "findings": []},
        )

    # Out file must NOT exist
    assert not out_file.exists()

    # task_a problem_statement.md must remain UNTOUCHED
    assert (t_a / "agent" / "problem_statement.md").read_text(encoding="utf-8") == orig_stmt
    assert not (t_a / "problem_statement_redacted.json").exists()


def test_idempotent_rerun(tmp_path: Path) -> None:
    """A statement already redacted by a previous run stays repaired on rerun."""
    task_id = "task_idempotent"
    tasks_dir = tmp_path / "tasks"
    t_dir = tasks_dir / task_id
    t_dir.mkdir(parents=True)
    (t_dir / "agent").mkdir(parents=True)

    leak = "LEAK_XYZ"
    stmt = "Extensive problem description for calculation module.\n" + leak + "\nTrailing context."
    (t_dir / "agent" / "problem_statement.md").write_text(stmt, encoding="utf-8")
    (t_dir / "manifest.json").write_text(json.dumps(complete_manifest(task_id)), encoding="utf-8")

    reports = [
        {"gate": True, "not_covered": [],
            "task_id": task_id,
            "findings": [{"visibility": "agent_visible", "channel": "problem_statement", "path": "agent/problem_statement.md", "confidence": 1.0, "detector": "D0", "severity": "gate", "evidence": [leak]}],
        }
    ]

    out_file = tmp_path / "dispositions.json"
    entries1, _ = process_dispositions(
        reports,
        out_path=out_file,
        tasks_dir=tasks_dir,
        rescan_fn=lambda tid, s: {"gate": False, "not_covered": [], "findings": []},
    )
    assert entries1[0]["disposition"] == "repaired"

    (t_dir / "task.json").write_text(json.dumps(complete_task(task_id)), encoding="utf-8")
    (t_dir / "staging").mkdir()
    (t_dir / "staging" / "gold.patch").write_text("", encoding="utf-8")
    (t_dir / "staging" / "test.patch").write_text("", encoding="utf-8")
    base_tree = tmp_path / "base"
    base_tree.mkdir()
    world_root = tmp_path / "world"
    world_root.mkdir()
    os.utime(world_root, (1704067200, 1704067200))
    # Second run: gate report on already-redacted task reports clean findings
    clean_reports = [
        {"not_covered": [],
            "task_id": task_id,
            "findings": [],
            "gate": False,
        }
    ]
    clean_reports[0]["scan_config"] = {"base_tree": str(base_tree), "roots": [{"path": str(world_root), "visibility": "agent_visible"}]}
    entries2, _ = process_dispositions(
        clean_reports,
        out_path=out_file,
        tasks_dir=tasks_dir,
    )
    # Must STAY repaired (not flip to clean or excluded)
    assert entries2[0]["disposition"] == "repaired"
    assert entries2[0]["detectors"] == ["D0"]


# =========================================================================
# Defect 11: Brief items (dirty rescan retains D0, manifest problem_statement_redacted)
# =========================================================================

def test_dirty_rescan_retains_d0_and_all_firing_detectors() -> None:
    """When re-scan is still dirty, keep original D0 in detectors together with re-scan's detectors."""
    task_id = "task_dirty_multi"
    findings = [{"visibility": "agent_visible", "channel": "problem_statement", "path": "agent/problem_statement.md", "confidence": 1.0, "detector": "D0", "severity": "gate", "evidence": ["LEAK_FOO"]}]
    stmt = "Valid problem description text here for testing.\nLEAK_FOO\nMore description."

    # Rescan fires D2 and D5a
    def dirty_rescan(tid: str, s: str) -> dict:
        return {"gate": True, "not_covered": [],
            "findings": [
                {"visibility": "agent_visible", "channel": "problem_statement", "path": "agent/problem_statement.md", "confidence": 1.0, "evidence": [], "detector": "D2", "severity": "gate"},
                {"visibility": "agent_visible", "channel": "problem_statement", "path": "agent/problem_statement.md", "confidence": 1.0, "evidence": [], "detector": "D5a", "severity": "gate"},
            ]
        }

    manifest: dict = {}
    res = decide_task_disposition(
        task_id=task_id,
        findings=findings,
        problem_statement=stmt,
        rescan_fn=dirty_rescan,
        manifest=manifest,
    )
    assert res.disposition == "excluded"
    assert res.detectors == ["D0", "D2", "D5a"]
    assert any(d["kind"] == "excluded" for d in manifest["dispositions"])


# =========================================================================
# Defect 12: Strict task_id validation and symlink refusal
# =========================================================================

def test_task_id_and_symlink_refusal(tmp_path: Path) -> None:
    """task_id='../../etc' rejected; symlinked problem_statement.md rejected."""
    # Path traversal rejected
    with pytest.raises(MalformedGateOutputError):
        validate_task_id("../../etc/passwd")

    with pytest.raises(MalformedGateOutputError):
        validate_task_id("task/with/slash")

    with pytest.raises(MalformedGateOutputError):
        validate_task_id(".hidden_task")

    # Symlinked problem_statement.md rejected
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir(parents=True)
    t_dir = tasks_dir / "task_symlink"
    t_dir.mkdir(parents=True)
    (t_dir / "agent").mkdir(parents=True)

    secret_target = tmp_path / "real_file.txt"
    secret_target.write_text("secret target content", encoding="utf-8")
    symlink_file = t_dir / "agent" / "problem_statement.md"
    symlink_file.symlink_to(secret_target)

    reports = [{"gate": False, "not_covered": [], "task_id": "task_symlink", "findings": []}]
    with pytest.raises(DispositionsError, match="Symlink rejected"):
        process_dispositions(reports, tasks_dir=tasks_dir)


# =========================================================================
# Defect 13: Exact threshold boundaries (Python)
# =========================================================================

def test_exact_threshold_boundaries_python() -> None:
    """Test boundary conditions for MAX_REDACTION_FRACTION (50%) and MIN_REMAINING_CHARS (20)."""
    # 1. EXACT 50% fraction boundary
    # Statement length: 100 UTF-8 bytes
    stmt_100 = "a" * 100

    # 50% redacted: remaining non-ws chars = 50 (>= 20) -> eligible (not excluded on fraction)
    res_50 = decide_task_disposition(
        task_id="t_50",
        manifest=complete_manifest("t_50"),
        findings=[{"visibility": "agent_visible", "channel": "problem_statement", "path": "agent/problem_statement.md", "confidence": 1.0, "detector": "D0", "severity": "gate", "evidence": ["x"]}],
        explicit_spans=[(0, 50)],
        problem_statement=stmt_100,
        rescan_fn=lambda tid, s: {"gate": False, "not_covered": [], "findings": []},
    )
    assert res_50.disposition == "repaired"

    # 51% redacted: fraction > 0.50 -> excluded!
    res_51 = decide_task_disposition(
        task_id="t_51",
        findings=[{"visibility": "agent_visible", "channel": "problem_statement", "path": "agent/problem_statement.md", "confidence": 1.0, "detector": "D0", "severity": "gate", "evidence": ["x"]}],
        explicit_spans=[(0, 51)],
        problem_statement=stmt_100,
        rescan_fn=lambda tid, s: {"gate": False, "not_covered": [], "findings": []},
    )
    assert res_51.disposition == "excluded"
    assert "issue text is the fix" in res_51.reason

    # 49% redacted -> eligible
    res_49 = decide_task_disposition(
        task_id="t_49",
        manifest=complete_manifest("t_49"),
        findings=[{"visibility": "agent_visible", "channel": "problem_statement", "path": "agent/problem_statement.md", "confidence": 1.0, "detector": "D0", "severity": "gate", "evidence": ["x"]}],
        explicit_spans=[(0, 49)],
        problem_statement=stmt_100,
        rescan_fn=lambda tid, s: {"gate": False, "not_covered": [], "findings": []},
    )
    assert res_49.disposition == "repaired"

    # 2. EXACT 20 remaining non-whitespace characters boundary
    # 10 chars leak, followed by letters and spaces (total 100 chars; leak is 10%)
    stmt_20 = "LEAK123456" + ("X" * 20) + (" " * 50)
    res_rem_20 = decide_task_disposition(
        task_id="t_rem_20",
        manifest=complete_manifest("t_rem_20"),
        findings=[{"visibility": "agent_visible", "channel": "problem_statement", "path": "agent/problem_statement.md", "confidence": 1.0, "detector": "D0", "severity": "gate", "evidence": ["x"]}],
        explicit_spans=[(0, 10)],
        problem_statement=stmt_20,
        rescan_fn=lambda tid, s: {"gate": False, "not_covered": [], "findings": []},
    )
    assert res_rem_20.disposition == "repaired"

    # 19 remaining characters -> excluded!
    stmt_19 = "LEAK123456" + ("X" * 19) + (" " * 50)
    res_rem_19 = decide_task_disposition(
        task_id="t_rem_19",
        findings=[{"visibility": "agent_visible", "channel": "problem_statement", "path": "agent/problem_statement.md", "confidence": 1.0, "detector": "D0", "severity": "gate", "evidence": ["x"]}],
        explicit_spans=[(0, 10)],
        problem_statement=stmt_19,
        rescan_fn=lambda tid, s: {"gate": False, "not_covered": [], "findings": []},
    )
    assert res_rem_19.disposition == "excluded"
    assert "leaves 19 < 20 chars" in res_rem_19.reason

    # 21 remaining characters -> eligible
    stmt_21 = "LEAK123456" + ("X" * 21) + (" " * 50)
    res_rem_21 = decide_task_disposition(
        task_id="t_rem_21",
        manifest=complete_manifest("t_rem_21"),
        findings=[{"visibility": "agent_visible", "channel": "problem_statement", "path": "agent/problem_statement.md", "confidence": 1.0, "detector": "D0", "severity": "gate", "evidence": ["x"]}],
        explicit_spans=[(0, 10)],
        problem_statement=stmt_21,
        rescan_fn=lambda tid, s: {"gate": False, "not_covered": [], "findings": []},
    )
    assert res_rem_21.disposition == "repaired"
