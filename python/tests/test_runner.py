"""run_task keeps a run record when extraction or grading fails (no Docker needed)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import hermetic_slice.runner as runner
from hermetic_slice.agent_loop import Limits
from hermetic_slice.extract import ExtractError
from hermetic_slice.model_client import ModelReply


class SubmitModel:
    model = "fake-model"

    def generate(self, system: str, messages: list[dict[str, str]]) -> ModelReply:
        return ModelReply(
            text="```bash\necho HERMETIC_SUBMIT\n```",
            finish_reason="STOP",
            usage={"totalTokenCount": 7},
            latency_s=0.0,
            attempts=1,
        )


def _task_dir(tmp_path: Path) -> Path:
    task_dir = tmp_path / "x__y-1"
    (task_dir / "agent").mkdir(parents=True)
    (task_dir / "index").mkdir()
    (task_dir / "world").mkdir()
    (task_dir / "task.json").write_text(json.dumps({
        "instance_id": "x__y-1",
        "base_commit": "abc",
        "cutoffs": {"t_world": "2020-01-01T00:00:00Z", "t_clock": "2020-01-02T00:00:00Z"},
    }), encoding="utf-8")
    (task_dir / "agent" / "problem_statement.md").write_text("fix it", encoding="utf-8")
    (task_dir / "index" / "index-report.json").write_text("{}", encoding="utf-8")
    (task_dir / "world" / "probe.json").write_text('{"all_ok": true}', encoding="utf-8")
    return task_dir


@pytest.fixture
def fake_world(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    stopped: list[str] = []
    monkeypatch.setattr(runner, "start_world", lambda *a, **k: SimpleNamespace(agent_container="agent-c"))
    monkeypatch.setattr(runner, "world_exec", lambda *a, **k: (0, ""))
    monkeypatch.setattr(runner, "stop_world", lambda w: stopped.append(w.agent_container))
    return stopped


def _never_grade(*_a: Any, **_k: Any) -> dict[str, Any]:
    raise AssertionError("grade_fn must not run after a failed extraction")


def test_extract_failure_still_writes_run_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_world: list[str]) -> None:
    def boom(*_a: Any, **_k: Any):
        raise ExtractError("patch_too_large")

    monkeypatch.setattr(runner, "extract_patch", boom)
    record = runner.run_task(
        _task_dir(tmp_path), model=SubmitModel(), grade_fn=_never_grade,
        run_dir=tmp_path / "run", limits=Limits(max_steps=3),
    )

    saved = json.loads((tmp_path / "run" / "run.json").read_text(encoding="utf-8"))
    assert saved == record
    assert saved["status"] == "error"
    assert saved["error"].startswith("extract_failed: ")
    assert "patch_too_large" in saved["error"]
    assert saved["agent"]["agent_status"] == "submitted"
    assert saved["agent"]["usage_totals"]["totalTokenCount"] == 7
    assert fake_world == ["agent-c"]


def test_grade_failure_still_writes_run_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_world: list[str]) -> None:
    monkeypatch.setattr(runner, "extract_patch", lambda *a, **k: ("diff --git a/f b/f\n", {"files_changed": 1}))

    def bad_grade(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise RuntimeError("grader exploded")

    record = runner.run_task(
        _task_dir(tmp_path), model=SubmitModel(), grade_fn=bad_grade,
        run_dir=tmp_path / "run", limits=Limits(max_steps=3),
    )

    assert record["status"] == "error"
    assert record["error"] == "grade_failed: grader exploded"
    assert record["extract"] == {"files_changed": 1}
    assert (tmp_path / "run" / "patch.diff").read_text(encoding="utf-8") == "diff --git a/f b/f\n"
    assert fake_world == ["agent-c"]
