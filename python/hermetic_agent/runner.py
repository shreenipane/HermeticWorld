"""Bounded optional mini-swe-agent runner with world-clock message records."""

import os
import sys
from contextlib import contextmanager
import time

from hermetic_safe_io import open_parent
from .errors import HarnessError, LimitError, ProtocolError
from .model import MAX_HISTORY_BYTES, MAX_MESSAGES
from .protocol import parse_json
from .task import read_input, clock_value

MAX_RUN_SECONDS = 5400
MAX_STEPS = 250
DEFAULT_STEPS = 60
# JSON escaping can use six bytes per history byte, plus message metadata.
MAX_TRAJECTORY_BYTES = 64 * 1024 * 1024


def configured_steps():
    value = os.environ.get("HERMETIC_AGENT_STEPS")
    if value is None:
        return DEFAULT_STEPS
    if (not 1 <= len(value) <= len(str(MAX_STEPS)) or not value.isascii()
            or not value.isdecimal() or not 0 < int(value) <= MAX_STEPS):
        raise LimitError("Step limit")
    return int(value)


@contextmanager
def _upstream(config_dir):
    if "minisweagent" in sys.modules:
        raise ProtocolError("Harness dependency must be imported in a fresh process")
    # Pin and inspect the supplied existing private directory before upstream startup.
    directory, _ = open_parent(os.path.join(config_dir, ".env"))
    try:
        if os.fstat(directory).st_mode & 0o777 != 0o700:
            raise ProtocolError("Configuration directory must be private")
        config_path = f"/proc/self/fd/{directory}"
        # Create an empty upstream config on the pinned directory, refusing any prior entry.
        descriptor = os.open(".env", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=directory)
        os.close(descriptor)
        settings = {"MSWEA_GLOBAL_CONFIG_DIR": config_path, "MSWEA_CONFIG_DIR": config_path,
                    "MSWEA_SILENT_STARTUP": "1"}
        previous = {key: os.environ.get(key) for key in settings}
        os.environ.update(settings)
        try:
            import minisweagent
            from minisweagent.agents.default import DefaultAgent, LimitsExceeded
        except ImportError:
            raise ProtocolError("Install the pinned harness extra") from None
        else:
            if minisweagent.__version__ != "1.17.4":
                raise ProtocolError("Unsupported harness dependency version")
            yield DefaultAgent, LimitsExceeded
        finally:
            for name, old in previous.items():
                if old is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = old
    finally:
        os.close(directory)


def run(model, environment, task: str, *, config_dir: str, step_limit: int = DEFAULT_STEPS, sentinel=None):
    if type(step_limit) is not int or not 0 < step_limit <= MAX_STEPS:
        raise LimitError("Step limit")
    if not isinstance(task, str) or len(task.encode()) > 1024 * 1024:
        raise LimitError("Task byte limit")
    timestamp = clock_value(model.config.t_clock)
    if sentinel is not None:
        sentinel.scan_text("prompt", task)
    with _upstream(config_dir) as (DefaultAgent, LimitsExceeded):
        template = parse_json(read_input(os.path.join(os.path.dirname(__file__), "swebench.json")))
        template["step_limit"] = step_limit
        started = time.monotonic()
        limit_reason = "steps_exhausted"
        for component in (model, environment):
            if hasattr(component, "set_run_deadline"):
                component.set_run_deadline(started + MAX_RUN_SECONDS)

        class WorldAgent(DefaultAgent):
            def add_message(self, role, content, **kwargs):
                # No arbitrary metadata or upstream timestamp is copied into a trajectory.
                if len(self.messages) >= MAX_MESSAGES or sum(len(m["content"].encode()) for m in self.messages) + len(content.encode()) > MAX_HISTORY_BYTES:
                    raise LimitError("Trajectory limit")
                if sentinel is not None and role in ("system", "user"):
                    sentinel.scan_text("prompt", content)
                self.messages.append({"role": role, "content": content, "timestamp": timestamp})

            def step(self):
                nonlocal limit_reason
                if time.monotonic() - started >= MAX_RUN_SECONDS:
                    limit_reason = "time_exhausted"
                    raise LimitsExceeded("Run deadline exceeded")
                return super().step()

        agent = WorldAgent(model, environment, **template)
        try:
            status, _ = agent.run(task)
        except LimitsExceeded:
            status = "LimitsExceeded"
        except HarnessError:
            raise
        if status == "LimitsExceeded":
            res = {"status": "unresolved", "reason": limit_reason, "messages": agent.messages}
        else:
            res = {"status": status, "messages": agent.messages}
        if sentinel is not None:
            res["date_sentinel"] = sentinel.summary().to_dict()
            res["date_leak_observed"] = sentinel.summary().date_leak_observed
        return res
