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


def test_cli_run_agent_applies_or_refuses_a_run_spec(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    import json
    import hermetic_slice.runner as runner_mod
    from test_world_runspec import SPEC

    tasks_dir = tmp_path / "tasks"
    (tasks_dir / "t1").mkdir(parents=True)
    (tasks_dir / "t1" / "task.json").write_text("{}")
    key_file = tmp_path / "gemini.key"
    key_file.write_text("test-key\n", encoding="utf-8")
    monkeypatch.setenv("HERMETIC_GEMINI_KEY_FILE", str(key_file))
    seen = []

    def fake_run_task(task_dir, **kwargs):
        seen.append(kwargs.get("runspec"))
        return {"status": "error", "agent": {}}

    monkeypatch.setattr(runner_mod, "run_task", fake_run_task)
    good = tmp_path / "spec.json"
    good.write_text(json.dumps(SPEC))
    main(["run-agent", "--tasks-dir", str(tasks_dir), "--runs-dir", str(tmp_path / "runs"),
          "--run-spec", str(good)])
    assert seen == [SPEC]

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(dict(SPEC, uid=-1)))
    link = tmp_path / "link.json"
    link.symlink_to(good)
    for path in (bad, link, tmp_path / "absent.json"):
        seen.clear()
        rc = main(["run-agent", "--tasks-dir", str(tasks_dir), "--runs-dir", str(tmp_path / "runs"),
                   "--run-spec", str(path)])
        assert rc == 1 and seen == [], path
        assert "Refused run spec" in capsys.readouterr().err
