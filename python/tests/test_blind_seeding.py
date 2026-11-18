"""Offline test suite for guided blind leak seeding and scoring (Hermetic E3).

Verifies planting into all 8 channels, harmless decoys, key file privacy (mode 0600,
outside repo, leak text never printed), scoring known-answer (aggregate vs reveal),
and Ctrl-C safety (leaves nothing half-written).
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from hermetic_e3.fixtures import FixtureTask, get_fixture_tasks, materialize_task
from hermetic_e3.score_blind import (
    AggregateScoreReport,
    evaluate_blind_cases,
    format_report_text,
    load_private_key,
    run_score_blind,
)
from hermetic_e3.seed_leaks import (
    CHANNELS,
    CHANNEL_IDS,
    plant_seed,
    run_seeding_wizard,
)


class ScriptedPerson:
    """Simulates a non-technical person entering answers to wizard prompts."""

    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)
        self.index = 0
        self.prompts_seen: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts_seen.append(prompt)
        if self.index >= len(self.answers):
            raise EOFError(f"Scripted answers exhausted for prompt: {prompt!r}")
        val = self.answers[self.index]
        self.index += 1
        if isinstance(val, BaseException):
            raise val
        return val


class OutputCollector:
    """Collects all lines printed by wizard or scorer."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, text: str) -> None:
        self.lines.append(text)

    def full_text(self) -> str:
        return "\n".join(self.lines)


# ---------------------------------------------------------------------------
# Test 1: Planting into all 8 channels
# ---------------------------------------------------------------------------


def test_planting_all_eight_channels(tmp_path: Path) -> None:
    """Verify that a scripted person can plant leaks into all 8 distinct channels."""
    blind_dir = tmp_path / "blind_workspace"
    worlds_dir = blind_dir / "seeded_worlds"
    key_file = blind_dir / "answer_key.json"

    # We will test 10 tasks, covering channels 1 through 8, plus 2 decoys
    # For each task:
    # 1) Action: "1" (leak)
    # 2) Leak text: unique leak text
    # 3) Channel: channel number (1 through 8)
    answers: list[str] = []
    expected_channels = [
        "code_comment",
        "docs_readme",
        "config_value",
        "test_file",
        "file_name",
        "archive_member",
        "sqlite_row",
        "patch_file",
        "code_comment",
        "docs_readme",
    ]

    for i in range(10):
        ch_idx = (i % 8) + 1
        answers.extend([
            "1",  # plant a secret leak
            f"SECRET_LEAK_CHANNEL_{ch_idx}_VAL_{i}",  # leak text
            str(ch_idx),  # channel number
        ])

    person = ScriptedPerson(answers)
    collector = OutputCollector()

    saved_key = run_seeding_wizard(
        count=10,
        worlds_dir=worlds_dir,
        key_file=key_file,
        input_fn=person,
        output_fn=collector,
    )

    assert saved_key == key_file
    assert key_file.exists()

    # Verify mode 0600 on the key file
    st = key_file.stat()
    assert (st.st_mode & 0o777) == 0o600

    # Load and verify key content
    key_data = json.loads(key_file.read_text(encoding="utf-8"))
    assert key_data["total_cases"] == 10
    cases = key_data["cases"]
    assert len(cases) == 10

    # Check each channel's planted artifact in the world
    for idx, (c, expected_ch) in enumerate(zip(cases, expected_channels)):
        assert c["channel"] == expected_ch
        assert c["is_leak"] is True
        world_root = Path(c["world_dir"])
        assert world_root.is_dir()
        target_path = world_root / c["target_path"]
        assert target_path.exists()

        leak_str = f"SECRET_LEAK_CHANNEL_{(idx % 8) + 1}_VAL_{idx}"
        assert c["leak_text"] == leak_str

        # Channel-specific verification
        if expected_ch == "code_comment":
            content = target_path.read_text(encoding="utf-8")
            assert leak_str in content
            assert "# SOLUTION NOTE:" in content
        elif expected_ch == "docs_readme":
            content = target_path.read_text(encoding="utf-8")
            assert leak_str in content
            assert "## Implementation Solution Notes" in content
        elif expected_ch == "config_value":
            content = target_path.read_text(encoding="utf-8")
            assert leak_str in content
            assert "SECRET_TARGET_VALUE" in content
        elif expected_ch == "test_file":
            content = target_path.read_text(encoding="utf-8")
            assert leak_str in content
            assert "def test_secret_solution():" in content
        elif expected_ch == "file_name":
            assert leak_str in target_path.read_text(encoding="utf-8")
            assert "leak_" in target_path.name
        elif expected_ch == "archive_member":
            import zipfile
            with zipfile.ZipFile(target_path, "r") as zf:
                assert "solution_notes.txt" in zf.namelist()
                member_bytes = zf.read("solution_notes.txt")
                assert leak_str.encode("utf-8") in member_bytes
        elif expected_ch == "sqlite_row":
            import sqlite3
            conn = sqlite3.connect(str(target_path))
            try:
                cur = conn.execute("SELECT note FROM secret_notes")
                rows = cur.fetchall()
                assert any(leak_str in r[0] for r in rows)
            finally:
                conn.close()
        elif expected_ch == "patch_file":
            content = target_path.read_text(encoding="utf-8")
            assert leak_str in content


# ---------------------------------------------------------------------------
# Test 2: Harmless decoys (measuring false positives)
# ---------------------------------------------------------------------------


def test_harmless_decoys_planted_correctly(tmp_path: Path) -> None:
    """Verify that harmless decoys can be planted to measure false positive rate."""
    blind_dir = tmp_path / "blind_workspace_decoys"
    worlds_dir = blind_dir / "seeded_worlds"
    key_file = blind_dir / "key.json"

    # 10 tasks: 5 leaks, 5 decoys
    answers: list[str] = []
    for i in range(10):
        if i % 2 == 0:
            # Leak
            answers.extend([
                "1",
                f"LEAK_SECRET_{i}",
                "1",  # code_comment
            ])
        else:
            # Decoy
            answers.extend([
                "2",  # harmless decoy
                f"BENIGN_DECOY_NOTE_{i}",
                "2",  # docs_readme
            ])

    person = ScriptedPerson(answers)
    collector = OutputCollector()

    run_seeding_wizard(
        count=10,
        worlds_dir=worlds_dir,
        key_file=key_file,
        input_fn=person,
        output_fn=collector,
    )

    key_data = json.loads(key_file.read_text(encoding="utf-8"))
    cases = key_data["cases"]

    leaks = [c for c in cases if c["is_leak"]]
    decoys = [c for c in cases if not c["is_leak"]]

    assert len(leaks) == 5
    assert len(decoys) == 5

    for d in decoys:
        assert d["is_leak"] is False
        world_root = Path(d["world_dir"])
        target_file = world_root / d["target_path"]
        assert target_file.exists()
        assert "BENIGN_DECOY_NOTE" in target_file.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Test 3: Key file privacy (mode 0600, outside repo, secret text never printed)
# ---------------------------------------------------------------------------


def test_key_file_privacy_and_never_printed(tmp_path: Path) -> None:
    """Verify private mode 0600 outside repo, and that leak strings are NEVER printed."""
    blind_dir = tmp_path / ".hermetic-e3-blind"
    worlds_dir = blind_dir / "worlds"
    key_file = blind_dir / "private_key.json"

    secret_marker = "TOP_SECRET_RECALL_PROBE_CANARY_XYZ987"

    answers = [
        "1",  # leak
        secret_marker,
        "1",  # channel 1
    ]
    # For remaining 9 tasks, just skip them
    for _ in range(9):
        answers.append("3")  # skip

    person = ScriptedPerson(answers)
    collector = OutputCollector()

    run_seeding_wizard(
        count=10,
        worlds_dir=worlds_dir,
        key_file=key_file,
        input_fn=person,
        output_fn=collector,
    )

    out_text = collector.full_text()

    # Strict privacy assertions:
    # 1. Secret text must NEVER appear in stdout / wizard output
    assert secret_marker not in out_text, "Secret leak text must NEVER be printed to terminal!"

    # 2. Key file must be mode 0600
    st = key_file.stat()
    assert (st.st_mode & 0o777) == 0o600

    # 3. Key file parent must be 0700
    parent_st = key_file.parent.stat()
    assert (parent_st.st_mode & 0o777) == 0o700

    # 4. Key path is shown once in output
    assert str(key_file) in out_text
    assert out_text.count(str(key_file)) == 1


# ---------------------------------------------------------------------------
# Test 4: Scoring known-answer (aggregate vs reveal)
# ---------------------------------------------------------------------------


def test_scoring_known_answer_aggregate_and_reveal(tmp_path: Path) -> None:
    """Verify score_blind computes exact metrics and conceals details unless --reveal."""
    key_file = tmp_path / "mock_key.json"

    # Create dummy world dirs
    world_1 = tmp_path / "w1"
    world_2 = tmp_path / "w2"
    world_3 = tmp_path / "w3"
    world_4 = tmp_path / "w4"
    for w in (world_1, world_2, world_3, world_4):
        w.mkdir()

    mock_key_data = {
        "schema": "hermetic-e3-blind-key/v1",
        "total_cases": 4,
        "cases": [
            {
                "case_id": "case_tp_leak",
                "task_id": "task_1",
                "task_dir": str(tmp_path),
                "base_tree_dir": str(tmp_path),
                "world_dir": str(world_1),
                "is_leak": True,
                "channel": "code_comment",
                "target_path": "service.py",
                "leak_text": "leak1",
            },
            {
                "case_id": "case_fn_leak",
                "task_id": "task_2",
                "task_dir": str(tmp_path),
                "base_tree_dir": str(tmp_path),
                "world_dir": str(world_2),
                "is_leak": True,
                "channel": "docs_readme",
                "target_path": "README.md",
                "leak_text": "leak2",
            },
            {
                "case_id": "case_tn_decoy",
                "task_id": "task_3",
                "task_dir": str(tmp_path),
                "base_tree_dir": str(tmp_path),
                "world_dir": str(world_3),
                "is_leak": False,
                "channel": "config_value",
                "target_path": "config.py",
                "leak_text": "decoy3",
            },
            {
                "case_id": "case_fp_decoy",
                "task_id": "task_4",
                "task_dir": str(tmp_path),
                "base_tree_dir": str(tmp_path),
                "world_dir": str(world_4),
                "is_leak": False,
                "channel": "test_file",
                "target_path": "test.py",
                "leak_text": "decoy4",
            },
        ],
    }

    # Write key file mode 0600
    fd = os.open(str(key_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(mock_key_data, f)

    # Mock scanner providing known outcomes:
    # w1 -> gate detected (TP)
    # w2 -> clean (FN)
    # w3 -> clean (TN)
    # w4 -> gate detected (FP)
    def mock_scanner(w_dir: Path, t_dir: Path, b_dir: Path) -> tuple[bool, int, list[dict]]:
        if w_dir == world_1:
            return (True, 2, [{"severity": "gate", "visibility": "agent_visible"}])
        elif w_dir == world_2:
            return (False, 0, [])
        elif w_dir == world_3:
            return (False, 0, [])
        elif w_dir == world_4:
            return (True, 2, [{"severity": "gate", "visibility": "agent_visible"}])
        return (False, 0, [])

    # 1. Run without --reveal (default)
    collector_default = OutputCollector()
    report = run_score_blind(
        key_file,
        reveal=False,
        output_fn=collector_default,
        scanner_fn=mock_scanner,
    )

    assert report.total_cases == 4
    assert report.total_leaks == 2
    assert report.detected_leaks == 1
    assert report.total_decoys == 2
    assert report.false_alarms == 1
    assert report.recall == 0.5  # 1 / 2
    assert report.precision == 0.5  # 1 / (1 + 1)

    text_default = collector_default.full_text()
    assert "Overall Recall:        50.0% (1 / 2)" in text_default
    assert "Overall Precision:     50.0%" in text_default
    assert "Per-Channel Breakdown:" in text_default
    assert "code_comment" in text_default
    assert "docs_readme" in text_default
    assert "config_value" in text_default
    assert "test_file" in text_default

    # Detail concealment check:
    assert "Per-Case Details" not in text_default
    assert "case_tp_leak" not in text_default
    assert "case_fn_leak" not in text_default
    assert "case_tn_decoy" not in text_default
    assert "case_fp_decoy" not in text_default

    # 2. Run with --reveal
    collector_reveal = OutputCollector()
    report_reveal = run_score_blind(
        key_file,
        reveal=True,
        output_fn=collector_reveal,
        scanner_fn=mock_scanner,
    )

    text_reveal = collector_reveal.full_text()
    assert "Per-Case Details (--reveal):" in text_reveal
    assert "case_tp_leak" in text_reveal
    assert "case_fn_leak" in text_reveal
    assert "case_tn_decoy" in text_reveal
    assert "case_fp_decoy" in text_reveal


# ---------------------------------------------------------------------------
# Test 5: Ctrl-C leaves nothing half-written
# ---------------------------------------------------------------------------


def test_ctrl_c_leaves_nothing_half_written(tmp_path: Path) -> None:
    """Verify that an interrupted session (Ctrl-C) removes temporary incomplete files."""
    blind_dir = tmp_path / "blind_ctrl_c"
    worlds_dir = blind_dir / "worlds"
    key_file = blind_dir / "key.json"

    # Scripted person simulates KeyboardInterrupt on task 2
    answers: list[Any] = [
        "1",  # task 1: plant leak
        "LEAK_TASK_1",
        "1",  # code_comment
        KeyboardInterrupt("User pressed Ctrl-C"),
    ]

    person = ScriptedPerson(answers)
    collector = OutputCollector()

    with pytest.raises(KeyboardInterrupt):
        run_seeding_wizard(
            count=10,
            worlds_dir=worlds_dir,
            key_file=key_file,
            input_fn=person,
            output_fn=collector,
        )

    # Check that no temporary files or unfinished directories are left
    all_files = list(worlds_dir.rglob("*"))
    for p in all_files:
        assert not p.name.endswith(".tmp"), f"Incomplete temp file found: {p}"

    # Also verify that key_file was not half-written if cancelled before completion
    # (Key is only finalized when all tasks are complete)
    assert not (blind_dir / "key.json.tmp").exists()
    assert "Wizard cancelled" in collector.full_text()


# ---------------------------------------------------------------------------
# Test 6: Symlink refusal in key loading
# ---------------------------------------------------------------------------


def test_symlink_refusal_for_key_file(tmp_path: Path) -> None:
    """Verify that symlinked key files are strictly refused."""
    real_key = tmp_path / "real_key.json"
    real_key.write_text('{"cases": []}', encoding="utf-8")
    symlink_key = tmp_path / "symlink_key.json"
    symlink_key.symlink_to(real_key)

    with pytest.raises(PermissionError, match="symlinks are refused"):
        load_private_key(symlink_key)


# ---------------------------------------------------------------------------
# Test 7: Wrapper script properties
# ---------------------------------------------------------------------------


def test_wrapper_script_properties() -> None:
    """Verify scripts/e3-seed-leaks.sh exists, is executable, and contains valid bash."""
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "e3-seed-leaks.sh"
    assert script_path.exists()

    # Ensure executable permissions 0o755
    st = script_path.stat()
    if not (st.st_mode & stat.S_IXUSR):
        os.chmod(str(script_path), st.st_mode | 0o755)

    content = script_path.read_text(encoding="utf-8")
    assert "#!/usr/bin/env bash" in content
    assert "python3 -m hermetic_e3.seed_leaks" in content


# ---------------------------------------------------------------------------
# Test 8: Output hygiene (no forbidden mentions)
# ---------------------------------------------------------------------------


def test_output_hygiene_and_plain_language() -> None:
    """Verify plain-language instructions, no jargon, and no forbidden tokens."""
    from hermetic_e3.seed_leaks import WIZARD_WELCOME

    # Plain language check
    assert "What is a \"leak\"?" in WIZARD_WELCOME
    assert "Examples of leaks:" in WIZARD_WELCOME
    assert "Pressing Ctrl-C at any time safely cancels" in WIZARD_WELCOME

    # Ensure no AI tool or model names are mentioned
    lower_welcome = WIZARD_WELCOME.lower()
    for forbidden in ("chatgpt", "openai", "claude", "gemini", "copilot", "llm", "model"):
        assert forbidden not in lower_welcome, f"Forbidden mention: {forbidden}"


# ---------------------------------------------------------------------------
# Test 9: Tasks directory discovery and bounded loading
# ---------------------------------------------------------------------------


def test_tasks_dir_loading(tmp_path: Path) -> None:
    """Verify get_fixture_tasks loads custom task directories safely."""
    custom_tasks = tmp_path / "custom_tasks"
    custom_tasks.mkdir()

    # Create 10 fake task worlds
    for i in range(10):
        td = custom_tasks / f"custom_task_{i}"
        (td / "staging").mkdir(parents=True)
        (td / "agent").mkdir(parents=True)
        (td / "base_tree").mkdir(parents=True)

        task_meta = {
            "instance_id": f"custom_task_{i}",
            "base_commit": "base_commit_0",
            "repo": f"custom/task_{i}",
            "cutoffs": {
                "t_world": "2026-01-01T00:00:00Z",
                "t_clock": "2026-01-01T00:00:00Z",
                "discarded": [],
            },
        }
        (td / "task.json").write_text(json.dumps(task_meta))
        (td / "agent" / "problem_statement.md").write_text(
            f"Task {i} solves an important issue.\nDetailed notes."
        )
        (td / "staging" / "gold.patch").write_text(
            "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n+SECRET_PATCH_LINE\n"
        )
        (td / "base_tree" / "f.py").write_text("def f(): pass\n")

    tasks = get_fixture_tasks(count=10, tasks_dir=custom_tasks)
    assert len(tasks) == 10
    assert tasks[0].task_id == "custom_task_0"
    assert "SECRET_PATCH_LINE" in tasks[0].default_leak


# ---------------------------------------------------------------------------
# Test 10: Real sealcheck binary execution (if available)
# ---------------------------------------------------------------------------


def test_real_sealcheck_end_to_end_on_seeded_world(tmp_path: Path) -> None:
    """Verify real hermetic-sealcheck binary detects planted leak and passes decoy."""
    from hermetic_e3.score_blind import find_sealcheck_bin, scan_single_world

    try:
        bin_path = find_sealcheck_bin()
    except FileNotFoundError:
        pytest.skip("hermetic-sealcheck binary not available in workspace")

    task = get_fixture_tasks(1)[0]
    task_dir = materialize_task(task, tmp_path / "fixtures")
    base_tree_dir = task_dir / "base_tree"

    # World 1: Plant leak into code_comment
    world_leak = tmp_path / "world_leak"
    shutil.copytree(str(base_tree_dir), str(world_leak))
    plant_seed(world_leak, "code_comment", task.default_leak)

    detected_leak, rc_leak, findings_leak = scan_single_world(
        bin_path, world_leak, task_dir, base_tree_dir
    )
    assert detected_leak is True
    assert rc_leak == 2

    # World 2: Plant harmless decoy into docs_readme
    world_decoy = tmp_path / "world_decoy"
    shutil.copytree(str(base_tree_dir), str(world_decoy))
    plant_seed(world_decoy, "docs_readme", task.default_decoy)

    detected_decoy, rc_decoy, findings_decoy = scan_single_world(
        bin_path, world_decoy, task_dir, base_tree_dir
    )
    assert detected_decoy is False
    assert rc_decoy == 0
