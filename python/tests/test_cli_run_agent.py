"""Unit tests for run-agent CLI subcommand."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from hermetic_slice.__main__ import main


def test_cli_run_agent_missing_tasks_dir(tmp_path: Path) -> None:
    nonexistent = tmp_path / "no_such_tasks_dir"
    runs_dir = tmp_path / "runs"
    exit_code = main(["run-agent", "--tasks-dir", str(nonexistent), "--runs-dir", str(runs_dir)])
    assert exit_code == 1


def test_cli_run_agent_missing_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir()
    runs_dir = tmp_path / "runs"
    monkeypatch.delenv("HERMETIC_GEMINI_KEY_FILE", raising=False)
    exit_code = main(["run-agent", "--tasks-dir", str(tasks_dir), "--runs-dir", str(runs_dir)])
    assert exit_code == 1


def test_cli_run_agent_unknown_only_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir()
    runs_dir = tmp_path / "runs"
    key_file = tmp_path / "gemini.key"
    key_file.write_text("test-key\n", encoding="utf-8")
    monkeypatch.setenv("HERMETIC_GEMINI_KEY_FILE", str(key_file))

    exit_code = main([
        "run-agent",
        "--tasks-dir", str(tasks_dir),
        "--runs-dir", str(runs_dir),
        "--only", "nonexistent-task-id",
    ])
    assert exit_code == 1
