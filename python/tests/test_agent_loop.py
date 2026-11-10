"""Unit tests for agent loop logic."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from hermetic_slice.agent_loop import Limits, run_agent
from hermetic_slice.model_client import ModelError, ModelReply


class ScriptedModel:
    def __init__(self, responses: list[str | Exception]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, list[dict[str, str]]]] = []

    def generate(self, system: str, messages: list[dict[str, str]]) -> ModelReply:
        self.calls.append((system, [dict(m) for m in messages]))
        if not self.responses:
            raise RuntimeError("No more scripted responses")
        resp = self.responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return ModelReply(
            text=resp,
            finish_reason="STOP",
            usage={"totalTokenCount": 50, "promptTokenCount": 30, "candidatesTokenCount": 20},
            latency_s=0.1,
            attempts=1,
        )


def test_agent_loop_normal_run(tmp_path: Path) -> None:
    traj_file = tmp_path / "trajectory.jsonl"
    executed_commands: list[str] = []

    def fake_exec(cmd: str, timeout: int) -> tuple[int, str]:
        executed_commands.append(cmd)
        if cmd == "ls -la":
            return (0, "total 0\n-rw-r--r-- 1 root root 0 foo.py\n")
        elif "sed" in cmd:
            return (0, "")
        return (0, "ok")

    model = ScriptedModel([
        "Let's explore:\n```bash\nls -la\n```",
        "Now let's fix:\n```bash\nsed -i 's/a/b/' foo.py\n```",
        "Done:\n```bash\necho HERMETIC_SUBMIT\n```",
    ])

    res = run_agent(model, fake_exec, "Fix bug in foo.py", trajectory_path=traj_file)

    assert res.status == "submitted"
    assert res.submitted is True
    assert res.steps == 3
    # Check that echo HERMETIC_SUBMIT was NOT executed
    assert "echo HERMETIC_SUBMIT" not in executed_commands
    assert executed_commands == ["ls -la", "sed -i 's/a/b/' foo.py"]

    # Trajectory validation
    assert traj_file.exists()
    lines = [json.loads(line) for line in traj_file.read_text(encoding="utf-8").splitlines()]
    assert len(lines) > 0
    for entry in lines:
        assert "step" in entry
        assert "role" in entry
        assert "text" in entry
        assert "command" in entry
        assert "thought" not in entry


def test_agent_loop_format_errors_and_limit(tmp_path: Path) -> None:
    traj_file = tmp_path / "trajectory.jsonl"

    def fake_exec(cmd: str, timeout: int) -> tuple[int, str]:
        return (0, "output")

    # 5 responses with no or multiple bash blocks
    invalid_responses = [
        "No bash block here at all.",
        "Two blocks:\n```bash\ncmd1\n```\nand\n```bash\ncmd2\n```",
        "Still no block",
        "Another one without block",
        "Fifth bad block",
    ]
    model = ScriptedModel(invalid_responses)

    limits = Limits(max_consecutive_format_errors=5)
    res = run_agent(model, fake_exec, "problem", limits=limits, trajectory_path=traj_file)

    assert res.status == "format_error_limit"
    assert res.steps == 5
    assert res.submitted is False


def test_agent_loop_step_limit(tmp_path: Path) -> None:
    def fake_exec(cmd: str, timeout: int) -> tuple[int, str]:
        return (0, "ok")

    responses = [f"Step {i}\n```bash\necho {i}\n```" for i in range(10)]
    model = ScriptedModel(responses)

    limits = Limits(max_steps=3)
    res = run_agent(model, fake_exec, "problem", limits=limits)

    assert res.status == "step_limit"
    assert res.steps == 3


def test_agent_loop_output_truncation(tmp_path: Path) -> None:
    traj_file = tmp_path / "trajectory.jsonl"
    long_output = "X" * 200

    def fake_exec(cmd: str, timeout: int) -> tuple[int, str]:
        return (0, long_output)

    model = ScriptedModel([
        "Run long command:\n```bash\necho long\n```",
        "Submit:\n```bash\necho HERMETIC_SUBMIT\n```",
    ])

    limits = Limits(max_output_chars=50)
    res = run_agent(model, fake_exec, "problem", limits=limits, trajectory_path=traj_file)

    assert res.status == "submitted"
    # Inspect user observation in the second model call
    last_user_msg = model.calls[1][1][-1]["text"]
    assert "[... 150 characters elided ...]" in last_user_msg
    assert last_user_msg.startswith("<returncode>0</returncode>\n<output>\n" + "X" * 25)


def test_agent_loop_history_elision(tmp_path: Path) -> None:
    traj_file = tmp_path / "trajectory.jsonl"

    def fake_exec(cmd: str, timeout: int) -> tuple[int, str]:
        # Return ~60,000 characters
        return (0, "Y" * 60_000)

    # 12 turns, each creating >60k characters => total characters will exceed 600,000
    responses = [f"Step {i}\n```bash\necho {i}\n```" for i in range(12)]
    responses.append("Done\n```bash\necho HERMETIC_SUBMIT\n```")
    model = ScriptedModel(responses)

    limits = Limits(max_output_chars=100_000)
    res = run_agent(model, fake_exec, "problem", limits=limits, trajectory_path=traj_file)

    assert res.status == "submitted"
    assert res.history_elided is True
    # In the final call to model, the earliest observations should have had their output elided
    final_messages = model.calls[-1][1]
    observations = [m for m in final_messages if m["role"] == "user" and "<output>" in m["text"]]
    assert len(observations) == 12
    # The first (12 - 10) = 2 observations should contain [output elided to save context]
    assert "[output elided to save context]" in observations[0]["text"]
    assert "[output elided to save context]" in observations[1]["text"]
    # The last 10 observations should have normal output
    assert "[output elided to save context]" not in observations[-1]["text"]


def test_agent_loop_model_error() -> None:
    def fake_exec(cmd: str, timeout: int) -> tuple[int, str]:
        return (0, "ok")

    model = ScriptedModel([
        ModelError(500, "Internal Server Error"),
    ])

    res = run_agent(model, fake_exec, "problem")
    assert res.status == "model_error"
    assert "500" in (res.error or "")
