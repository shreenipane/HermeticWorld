"""Run a task through the local gateway and AgentVM execd."""

import argparse
import json

from hermetic_safe_io import atomic_write
from .environment import ExecdEnvironment
from .errors import HarnessError, ProtocolError
from .model import HermeticGatewayModel
from .runner import run, MAX_TRAJECTORY_BYTES
from .task import read_input, task_clock
from .journal import CommandJournal, validate_output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "task", "vsock", "cwd", "config-dir", "trajectory", "command-log"):
        parser.add_argument("--" + name, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--gateway")
    choice.add_argument("--script", help="Offline smoke only: JSON list of bash commands")
    parser.add_argument("--model", default="pinned")
    args = parser.parse_args()
    try:
        clock = task_clock(args.manifest)
        task = read_input(args.task).decode("utf-8")
        if args.script:
            from .scripted import ScriptedModel
            from .protocol import parse_json
            model = ScriptedModel(parse_json(read_input(args.script)), t_clock=clock)
        else:
            model = HermeticGatewayModel(args.gateway, args.model, t_clock=clock)
        if validate_output(args.trajectory) == validate_output(args.command_log):
            raise ProtocolError("Trajectory and command log must be distinct")
        journal = CommandJournal(args.command_log, t_clock=clock)
        environment = ExecdEnvironment(args.vsock, cwd=args.cwd, journal=journal)
        result = run(model, environment, task, config_dir=args.config_dir)
        raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        if len(raw) > MAX_TRAJECTORY_BYTES:
            raise HarnessError("Trajectory byte limit")
        atomic_write(args.trajectory, raw + b"\n")
        return 0 if result["status"] == "Submitted" else 2
    except (HarnessError, UnicodeError, OSError, ValueError):
        print("Harness refused run")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
