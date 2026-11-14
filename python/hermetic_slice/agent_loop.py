"""SWE-agent style text protocol agent loop for hermetic execution."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import time
from typing import Any, Callable

from hermetic_slice.date_sentinel import DateSentinel
from hermetic_slice.model_client import ModelError, ModelReply

AGENT_PRELUDE = (
    "if [ -f /opt/miniconda3/etc/profile.d/conda.sh ]; then . /opt/miniconda3/etc/profile.d/conda.sh; conda activate testbed 2>/dev/null || true; fi\n"
    "cd /testbed\n"
)

SYSTEM_PROMPT = """You're a software engineer working in a Linux container at /testbed, which holds a Python repository. Your job is to fix the issue described by the user by editing the repository's source files. Then:
- Every response must contain exactly one fenced ```bash block, holding one command or one &&-chained command, plus a short explanation.
- Each command runs in a new shell, starting in /testbed, so cd and env vars don't persist.
- There is no internet. pip can install only from a local mirror of the env's existing packages.
- Don't modify or add tests, and don't touch .git.
- Interactive tools (editors, pagers) don't work. Use sed, cat <<'EOF' and python -c.
- When you're done, reply with exactly ```bash
echo HERMETIC_SUBMIT
```. You can't continue after submitting."""


def instance_prompt(problem_statement: str) -> str:
    """Format the user turn prompt for a task instance."""
    return (
        f"Issue Description:\n"
        f"{problem_statement}\n\n"
        "Instructions:\n"
        "Please fix the issue following this workflow: explore, reproduce, fix, verify, then submit.\n"
        "Remember to reply with exactly one fenced ```bash block containing your command.\n"
        "When finished, submit by replying with exactly:\n"
        "```bash\necho HERMETIC_SUBMIT\n```"
    )


@dataclass
class Limits:
    """Execution and safety limits for an agent run."""

    max_steps: int = 60
    max_total_tokens: int = 4_000_000
    max_wall_s: float = 5400.0
    command_timeout_s: int = 180
    max_output_chars: int = 10000
    max_consecutive_format_errors: int = 5


@dataclass
class AgentResult:
    """Outcome and usage summary of an agent run."""

    status: str
    steps: int
    usage_totals: dict[str, int]
    wall_s: float
    submitted: bool
    error: str | None = None
    history_elided: bool = False


def _append_trajectory(path: Path | None, record: dict[str, Any]) -> None:
    """Append a single record line to trajectory.jsonl if path is given."""
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
            f.flush()


def run_agent(
    model: Any,
    exec_fn: Callable[[str, int], tuple[int, str]],
    problem_statement: str,
    *,
    limits: Limits | None = None,
    trajectory_path: Path | None = None,
    sentinel: DateSentinel | None = None,
) -> AgentResult:
    """Run the agent interaction loop against model and exec_fn.

    With ``sentinel`` (D12, TR-SEC-5), every text sent to the model (system prompt, task
    prompt, format-error turns) is scanned as ``prompt`` and every command output returned
    from the world, before truncation, as ``observation``.
    """
    if limits is None:
        limits = Limits()

    start_time = time.monotonic()
    total_tokens = 0
    usage_totals: dict[str, int] = {
        "promptTokenCount": 0,
        "candidatesTokenCount": 0,
        "totalTokenCount": 0,
        "thoughtsTokenCount": 0,
    }

    step = 0
    consecutive_format_errors = 0
    submitted = False
    status = "completed"
    error_msg: str | None = None
    history_elided = False

    init_prompt = instance_prompt(problem_statement)
    if sentinel is not None:
        sentinel.scan_text("prompt", SYSTEM_PROMPT)
        sentinel.scan_text("prompt", init_prompt)
    messages: list[dict[str, str]] = [
        {"role": "user", "text": init_prompt}
    ]

    _append_trajectory(trajectory_path, {
        "step": 0,
        "role": "user",
        "text": init_prompt,
        "command": None,
        "returncode": None,
        "output_chars": None,
        "elided": False,
        "usage": None,
        "latency_s": None,
        "t": time.time(),
    })

    while True:
        # Check limits before invoking model
        elapsed = time.monotonic() - start_time
        if step >= limits.max_steps:
            status = "step_limit"
            break
        if total_tokens >= limits.max_total_tokens:
            status = "token_limit"
            break
        if elapsed >= limits.max_wall_s:
            status = "time_limit"
            break

        try:
            reply: ModelReply = model.generate(SYSTEM_PROMPT, messages)
        except ModelError as exc:
            status = "model_error"
            error_msg = str(exc)
            break
        except Exception as exc:
            status = "model_error"
            error_msg = f"Unexpected model error: {exc}"
            break

        step += 1

        # Accumulate usage tokens
        if reply.usage:
            cand_tokens = reply.usage.get("totalTokenCount", 0)
            total_tokens += cand_tokens
            for k in ("promptTokenCount", "candidatesTokenCount", "totalTokenCount", "thoughtsTokenCount"):
                if k in reply.usage:
                    usage_totals[k] = usage_totals.get(k, 0) + reply.usage[k]

        # Parse bash block(s)
        blocks = re.findall(r"```bash\s*\n(.*?)\n```", reply.text, re.S)

        if len(blocks) != 1:
            consecutive_format_errors += 1
            _append_trajectory(trajectory_path, {
                "step": step,
                "role": "model",
                "text": reply.text,
                "command": None,
                "returncode": None,
                "output_chars": None,
                "elided": False,
                "usage": reply.usage,
                "latency_s": reply.latency_s,
                "t": time.time(),
            })

            if consecutive_format_errors >= limits.max_consecutive_format_errors:
                status = "format_error_limit"
                break

            fmt_error_text = (
                "Your response must contain exactly one ```bash block holding one command or one &&-chained command."
            )
            if sentinel is not None:
                sentinel.scan_text("prompt", fmt_error_text)
            messages.append({"role": "model", "text": reply.text})
            messages.append({"role": "user", "text": fmt_error_text})

            _append_trajectory(trajectory_path, {
                "step": step,
                "role": "user",
                "text": fmt_error_text,
                "command": None,
                "returncode": None,
                "output_chars": None,
                "elided": False,
                "usage": None,
                "latency_s": None,
                "t": time.time(),
            })
            continue

        # Exactly one block
        consecutive_format_errors = 0
        cmd = blocks[0].strip()

        _append_trajectory(trajectory_path, {
            "step": step,
            "role": "model",
            "text": reply.text,
            "command": cmd,
            "returncode": None,
            "output_chars": None,
            "elided": False,
            "usage": reply.usage,
            "latency_s": reply.latency_s,
            "t": time.time(),
        })

        if cmd == "echo HERMETIC_SUBMIT":
            status = "submitted"
            submitted = True
            messages.append({"role": "model", "text": reply.text})
            break

        # Execute command
        code, raw_output = exec_fn(cmd, limits.command_timeout_s)
        if sentinel is not None:
            sentinel.scan_text("observation", raw_output)

        # Output truncation
        raw_len = len(raw_output)
        if raw_len > limits.max_output_chars:
            half = limits.max_output_chars // 2
            elided_count = raw_len - (half * 2)
            output_body = (
                raw_output[:half]
                + f"\n[... {elided_count} characters elided ...]\n"
                + raw_output[-half:]
            )
            output_elided = True
        else:
            output_body = raw_output
            output_elided = False

        if code in (124, 137):
            output_body += f"\nCommand timed out after {limits.command_timeout_s} seconds."

        observation = f"<returncode>{code}</returncode>\n<output>\n{output_body}\n</output>"

        messages.append({"role": "model", "text": reply.text})
        messages.append({"role": "user", "text": observation})

        # History elision check
        total_chars = sum(len(m.get("text", "")) for m in messages)
        if total_chars > 600_000:
            obs_indices = [
                i for i, m in enumerate(messages)
                if m["role"] == "user" and "<output>" in m["text"] and "</output>" in m["text"]
            ]
            if len(obs_indices) > 10:
                for idx in obs_indices[:-10]:
                    old_text = messages[idx]["text"]
                    new_text = re.sub(
                        r"<output>.*?</output>",
                        "<output>\n[output elided to save context]\n</output>",
                        old_text,
                        flags=re.DOTALL,
                    )
                    messages[idx]["text"] = new_text
                history_elided = True

        _append_trajectory(trajectory_path, {
            "step": step,
            "role": "user",
            "text": observation,
            "command": cmd,
            "returncode": code,
            "output_chars": raw_len,
            "elided": output_elided,
            "usage": None,
            "latency_s": None,
            "t": time.time(),
        })

        # Post-execution limits check
        elapsed = time.monotonic() - start_time
        if total_tokens >= limits.max_total_tokens:
            status = "token_limit"
            break
        if elapsed >= limits.max_wall_s:
            status = "time_limit"
            break
        if step >= limits.max_steps:
            status = "step_limit"
            break

    wall_s = time.monotonic() - start_time
    return AgentResult(
        status=status,
        steps=step,
        usage_totals=usage_totals,
        wall_s=wall_s,
        submitted=submitted,
        error=error_msg,
        history_elided=history_elided,
    )
