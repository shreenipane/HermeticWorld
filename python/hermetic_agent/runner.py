"""Bounded optional mini-swe-agent runner with world-clock message records."""

import os
import time

from hermetic_safe_io import open_parent
from .errors import HarnessError, LimitError, ProtocolError
from .model import MAX_HISTORY_BYTES, MAX_MESSAGES
from .protocol import parse_json
from .task import read_input, clock_value

MAX_RUN_SECONDS = 5400
MAX_STEPS = 250
MAX_TRAJECTORY_BYTES = 16 * 1024 * 1024


def run(model, environment, task: str, *, config_dir: str, step_limit: int = 60):
    if type(step_limit) is not int or not 0 < step_limit <= MAX_STEPS:
        raise LimitError("Step limit")
    if not isinstance(task, str) or len(task.encode()) > 1024 * 1024:
        raise LimitError("Task byte limit")
    timestamp = clock_value(model.config.t_clock)
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
        old_config = os.environ.get("MSWEA_GLOBAL_CONFIG_DIR")
        old_silent = os.environ.get("MSWEA_SILENT_STARTUP")
        os.environ["MSWEA_GLOBAL_CONFIG_DIR"] = config_path
        os.environ["MSWEA_SILENT_STARTUP"] = "1"
        try:
            import minisweagent
            from minisweagent.agents.default import DefaultAgent, LimitsExceeded
        except ImportError:
            raise ProtocolError("Install the pinned harness extra") from None
        finally:
            for name, old in (("MSWEA_GLOBAL_CONFIG_DIR", old_config), ("MSWEA_SILENT_STARTUP", old_silent)):
                if old is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = old
        if minisweagent.__version__ != "1.17.4":
            raise ProtocolError("Unsupported harness dependency version")
    finally:
        os.close(directory)
    template = parse_json(read_input(os.path.join(os.path.dirname(__file__), "swebench.json")))
    template["step_limit"] = step_limit
    started = time.monotonic()
    for component in (model, environment):
        if hasattr(component, "set_run_deadline"):
            component.set_run_deadline(started + MAX_RUN_SECONDS)

    class WorldAgent(DefaultAgent):
        def add_message(self, role, content, **kwargs):
            # No arbitrary metadata or upstream timestamp is copied into a trajectory.
            if len(self.messages) >= MAX_MESSAGES or sum(len(m["content"].encode()) for m in self.messages) + len(content.encode()) > MAX_HISTORY_BYTES:
                raise LimitError("Trajectory limit")
            self.messages.append({"role": role, "content": content, "timestamp": timestamp})

        def step(self):
            if time.monotonic() - started >= MAX_RUN_SECONDS:
                raise LimitsExceeded("Run deadline exceeded")
            return super().step()

    agent = WorldAgent(model, environment, **template)
    try:
        status, _ = agent.run(task)
    except HarnessError:
        raise
    return {"status": status, "messages": agent.messages}
