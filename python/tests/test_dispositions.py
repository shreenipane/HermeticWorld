"""Tests for task dispositions (§5.5, T1.14)."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from hermetic_slice import (
    MalformedGateOutputError,
    MissingDispositionError,
    decide_task_disposition,
    find_spans_in_text,
    process_dispositions,
    redact_problem_statement,
    MAX_REDACTION_FRACTION,
    MIN_REMAINING_CHARS,
)
from hermetic_slice.dispositions import dispositions_cli, format_summary
from hermetic_slice.__main__ import main as cli_main


def test_d0_leak_with_removable_span_repaired(tmp_path: Path) -> None:
    """D0 leak with a removable span: redacted, re-scan clean, 'repaired',

    problem_statement_redacted recorded without the leaked text.
    """
    task_id = "test-task-d0-repair"
    task_dir = tmp_path / task_id
    task_dir.mkdir(parents=True)
    agent_dir = task_dir / "agent"
    agent_dir.mkdir(parents=True)

    leaked_snippet = "SECRET_FIX_FUNCTION = lambda x: x * 42"
    problem_statement = (
        "# Calculation Module Issue\n\n"
        "Users report that the calculation module is failing to produce the correct scaled output "
        "when multiple factors are combined in sequence.\n\n"
        f"Proposed patch snippet: {leaked_snippet}\n\n"
        "Please investigate the mathematical transformation and fix the scaling factor."
    )
    (agent_dir / "problem_statement.md").write_text(problem_statement, encoding="utf-8")

    manifest_data = {
        "spec_version": "hermetic-world/v1",
        "task_id": task_id,
        "world_root": "blake3:0000000000000000000000000000000000000000000000000000000000000001",
        "dispositions": [],
    }
    (task_dir / "manifest.json").write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    gate_findings = [
        {
            "detector": "D0",
            "channel": "problem_statement",
            "path": "agent/problem_statement.md",
            "severity": "gate",
            "visibility": "agent_visible",
            "confidence": 1.0,
            "evidence": [leaked_snippet],
        }
    ]

    # Re-scan returns clean findings
    def mock_rescan(tid: str, redacted_stmt: str) -> dict:
        assert tid == task_id
        assert leaked_snippet not in redacted_stmt
        return {"schema": "hermetic-sealcheck/v0", "findings": [], "gate": False}

    gate_output = [
        {
            "task_id": task_id,
            "findings": gate_findings,
            "gate": True,
        }
    ]

    out_file = tmp_path / "dispositions.json"
    entries, summary = process_dispositions(
        gate_source=gate_output,
        out_path=out_file,
        tasks_dir=tmp_path,
        rescan_fn=mock_rescan,
    )

    assert len(entries) == 1
    entry = entries[0]
    assert entry["task_id"] == task_id
    assert entry["disposition"] == "repaired"
    assert entry["detectors"] == ["D0"]
    assert "clean" in entry["reason"]
    assert entry["world_version"] is not None
    assert entry["world_version"] != manifest_data["world_root"]

    # Verify problem_statement.md is updated with redaction placeholder
    updated_stmt = (agent_dir / "problem_statement.md").read_text(encoding="utf-8")
    assert leaked_snippet not in updated_stmt
    assert "[REDACTED]" in updated_stmt

    # Verify problem_statement_redacted.json contains offsets and hash, NEVER the text
    redacted_json_file = task_dir / "problem_statement_redacted.json"
    assert redacted_json_file.exists()
    redacted_json = json.loads(redacted_json_file.read_text(encoding="utf-8"))
    assert "spans" in redacted_json
    assert len(redacted_json["spans"]) == 1
    span_info = redacted_json["spans"][0]
    assert "start" in span_info
    assert "end" in span_info
    assert "hash" in span_info
    assert "sha256" in span_info

    # Crucial security assertion: leaked text must NEVER be logged/recorded
    redacted_json_str = json.dumps(redacted_json)
    assert leaked_snippet not in redacted_json_str
    assert leaked_snippet not in json.dumps(entry)


def test_d0_issue_text_is_the_fix_excluded() -> None:
    """Issue text is the fix: 'excluded', D0 named (§5.5)."""
    task_id = "task-text-is-fix"

    # Case A: Redaction removes > 50% of the problem statement
    leak_text = "def solve_issue(): return True\n" * 5
    short_context = "Fix: "
    problem_statement = short_context + leak_text

    findings = [
        {
            "detector": "D0",
            "channel": "problem_statement",
            "severity": "gate",
            "visibility": "agent_visible",
            "evidence": [leak_text],
        }
    ]

    res = decide_task_disposition(
        task_id=task_id,
        findings=findings,
        problem_statement=problem_statement,
        rescan_fn=lambda tid, stmt: {"findings": []},
    )

    assert res.disposition == "excluded"
    assert res.detectors == ["D0"]
    assert "issue text is the fix" in res.reason

    # Case B: Remaining characters < MIN_REMAINING_CHARS
    almost_all_leak = "A" * 15 + " " + "FIX_COMMAND_LINE"
    findings_b = [
        {
            "detector": "D0",
            "channel": "problem_statement",
            "severity": "gate",
            "visibility": "agent_visible",
            "evidence": ["FIX_COMMAND_LINE"],
        }
    ]
    res_b = decide_task_disposition(
        task_id=task_id,
        findings=findings_b,
        problem_statement=almost_all_leak,
        rescan_fn=lambda tid, stmt: {"findings": []},
    )
    assert res_b.disposition == "excluded"
    assert res_b.detectors == ["D0"]

    # Case C: Explicit issue_text_is_the_fix flag
    res_c = decide_task_disposition(
        task_id=task_id,
        findings=findings_b,
        problem_statement="A long problem statement with more than 100 characters describing the issue...",
        issue_text_is_the_fix=True,
    )
    assert res_c.disposition == "excluded"
    assert res_c.detectors == ["D0"]


def test_non_d0_detector_without_automatic_removal_excluded() -> None:
    """Non-D0 detector with no automatic removal: 'excluded' with that detector named."""
    # Test D1
    findings_d1 = [
        {
            "detector": "D1",
            "channel": "git",
            "path": ".git",
            "severity": "gate",
            "visibility": "agent_visible",
            "evidence": ["commit beyond base commit"],
        }
    ]
    res_d1 = decide_task_disposition(task_id="task-d1", findings=findings_d1)
    assert res_d1.disposition == "excluded"
    assert res_d1.detectors == ["D1"]
    assert "no automatic removal" in res_d1.reason

    # Test D2
    findings_d2 = [
        {
            "detector": "D2",
            "channel": "file",
            "path": "solution.py",
            "severity": "gate",
            "visibility": "agent_visible",
            "evidence": ["post-cutoff solution hash"],
        }
    ]
    res_d2 = decide_task_disposition(task_id="task-d2", findings=findings_d2)
    assert res_d2.disposition == "excluded"
    assert res_d2.detectors == ["D2"]

    # Test multiple non-D0 detectors plus D0
    findings_multi = [
        {"detector": "D0", "severity": "gate", "visibility": "agent_visible"},
        {"detector": "D5a", "severity": "gate", "visibility": "agent_visible"},
        {"detector": "D2", "severity": "gate", "visibility": "agent_visible"},
    ]
    res_multi = decide_task_disposition(task_id="task-multi", findings=findings_multi)
    assert res_multi.disposition == "excluded"
    assert res_multi.detectors == ["D0", "D2", "D5a"]


def test_rescan_still_dirty_after_redaction_excluded() -> None:
    """Re-scan still dirty after redaction: 'excluded', all detectors listed."""
    task_id = "task-rescan-dirty"
    leaked_line = "patch_line_alpha = 1"
    problem_stmt = (
        "This is an extensive problem description that describes the bug in detail.\n"
        "Here is a note with leak: " + leaked_line + "\n"
        "And here is more explanatory text describing expected versus actual behavior."
    )

    findings = [
        {
            "detector": "D0",
            "channel": "problem_statement",
            "severity": "gate",
            "visibility": "agent_visible",
            "evidence": [leaked_line],
        }
    ]

    # Mock re-scan returning that D0 and D2 still fired
    def dirty_rescan(tid: str, stmt: str) -> dict:
        return {
            "schema": "hermetic-sealcheck/v0",
            "findings": [
                {"detector": "D0", "severity": "gate", "visibility": "agent_visible"},
                {"detector": "D2", "severity": "gate", "visibility": "agent_visible"},
            ],
            "gate": True,
        }

    res = decide_task_disposition(
        task_id=task_id,
        findings=findings,
        problem_statement=problem_stmt,
        rescan_fn=dirty_rescan,
    )

    assert res.disposition == "excluded"
    assert res.detectors == ["D0", "D2"]
    assert "still dirty" in res.reason


def test_clean_task_and_n_entries_sorted_and_stable(tmp_path: Path) -> None:
    """Clean task listed as 'clean'; output for N tasks always has N entries; sorted and stable."""
    gate_output = [
        {
            "task_id": "zeta_task",
            "findings": [],
            "gate": False,
            "world_version": "blake3:zeta0000",
        },
        {
            "task_id": "alpha_task",
            "findings": [
                {"detector": "D1", "severity": "gate", "visibility": "agent_visible"}
            ],
            "gate": True,
        },
        {
            "task_id": "beta_task",
            "findings": [],
            "gate": False,
            "world_version": "blake3:beta0000",
        },
    ]

    out_file = tmp_path / "dispositions.json"
    entries, summary = process_dispositions(
        gate_source=gate_output,
        out_path=out_file,
    )

    assert len(entries) == 3
    # Check sorted by task_id
    assert [e["task_id"] for e in entries] == ["alpha_task", "beta_task", "zeta_task"]

    # Check clean task structure
    beta = entries[1]
    assert beta["task_id"] == "beta_task"
    assert beta["disposition"] == "clean"
    assert beta["detectors"] == []
    assert beta["reason"] == "gate passed"
    assert beta["world_version"] == "blake3:beta0000"

    zeta = entries[2]
    assert zeta["task_id"] == "zeta_task"
    assert zeta["disposition"] == "clean"

    alpha = entries[0]
    assert alpha["task_id"] == "alpha_task"
    assert alpha["disposition"] == "excluded"
    assert alpha["detectors"] == ["D1"]

    assert summary["total_tasks"] == 3
    assert summary["dispositions"]["clean"] == 2
    assert summary["dispositions"]["excluded"] == 1
    assert summary["detectors"]["D1"] == 1

    # Verify file written to disk matches
    disk_entries = json.loads(out_file.read_text(encoding="utf-8"))
    assert disk_entries == entries


def test_malformed_gate_output_no_panic_no_partial_file(tmp_path: Path) -> None:
    """Malformed gate output: clear error, no panic, no partial file."""
    out_file = tmp_path / "dispositions.json"

    # Case 1: Corrupted non-JSON file
    bad_json_file = tmp_path / "bad.json"
    bad_json_file.write_text("{ unclosed json: ", encoding="utf-8")

    with pytest.raises(MalformedGateOutputError):
        process_dispositions(gate_source=bad_json_file, out_path=out_file)
    assert not out_file.exists()

    # Case 2: Missing findings key
    missing_findings = [{"task_id": "task1"}]
    with pytest.raises(MalformedGateOutputError):
        process_dispositions(gate_source=missing_findings, out_path=out_file)
    assert not out_file.exists()

    # Case 3: Non-list findings
    non_list_findings = [{"task_id": "task1", "findings": "invalid_string"}]
    with pytest.raises(MalformedGateOutputError):
        process_dispositions(gate_source=non_list_findings, out_path=out_file)
    assert not out_file.exists()

    # Case 4: Non-existent gate path
    with pytest.raises(MalformedGateOutputError):
        process_dispositions(gate_source=tmp_path / "non_existent.json", out_path=out_file)
    assert not out_file.exists()


def test_cli_subcommand(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """Test CLI subcommand via python hermetic_slice dispositions."""
    gate_file = tmp_path / "gate_input.json"
    gate_data = [
        {"task_id": "t1", "findings": [], "gate": False},
        {"task_id": "t2", "findings": [{"detector": "D6", "severity": "gate"}], "gate": True},
    ]
    gate_file.write_text(json.dumps(gate_data), encoding="utf-8")

    out_file = tmp_path / "out_dispositions.json"

    code = cli_main(["dispositions", "--gate-output", str(gate_file), "--out", str(out_file)])
    assert code == 0
    assert out_file.exists()

    captured = capsys.readouterr()
    assert "Dispositions summary:" in captured.out
    assert "clean:    1" in captured.out
    assert "excluded: 1" in captured.out
    assert "D6: 1" in captured.out

    # Test error exit on malformed gate output
    bad_file = tmp_path / "corrupt.json"
    bad_file.write_text("invalid json", encoding="utf-8")
    err_code = cli_main(["dispositions", "--gate-output", str(bad_file)])
    assert err_code == 1
