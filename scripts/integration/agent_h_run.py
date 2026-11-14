"""Retain a fresh private directory for a manager-run sealed-task VM session."""

import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).absolute().parent))
from agent_h_image import TOP, command, MAX_BUILD_SECONDS, MIN_GUEST_CLOCK, MAX_GUEST_CLOCK
from hermetic_agent.task import clock_value, task_clock, read_input
from hermetic_agent.model import HermeticGatewayModel
from smoke_work import create_work

MAX_SESSION_SECONDS = 5700


def run(argv):
    if len(argv) != 1:
        raise ValueError()
    env = dict(os.environ)
    for key in ("HERMETIC_ROOTFS", "HERMETIC_AGENT_MANIFEST", "HERMETIC_AGENT_TASK",
                "HERMETIC_FC_BIN", "HERMETIC_KERNEL", "HERMETIC_AGENT_PYTHON",
                "HERMETIC_AGENT_GATEWAY", "HERMETIC_AGENT_MODEL"):
        if not env.get(key):
            raise ValueError()
    clock = task_clock(env["HERMETIC_AGENT_MANIFEST"])
    epoch = clock_value(clock)
    if not MIN_GUEST_CLOCK <= epoch <= MAX_GUEST_CLOCK:
        raise ValueError("Guest clock outside boot range")
    read_input(env["HERMETIC_AGENT_TASK"]).decode("utf-8")
    # Validate the endpoint before creating a directory or starting any subprocess.
    HermeticGatewayModel(env["HERMETIC_AGENT_GATEWAY"], env["HERMETIC_AGENT_MODEL"], t_clock=clock)
    parent, _, directory, work = create_work(__file__, argv[0])
    try:
        os.mkdir("config", 0o700, dir_fd=directory)
        env.update(HERMETIC_AGENT_WORK=work, HERMETIC_AGENT_TOP=str(TOP),
                   HERMETIC_AGENT_T_CLOCK=str(epoch))
        env["CARGO_TARGET_DIR"] = str(TOP / ".review/cargo-target")
        command(["cargo", "test", "--offline", "--locked", "-p", "hermetic-vmm",
                 "--features", "dev-unjailed", "--test", "agent_h_task", "--no-run"],
                env=env, timeout=MAX_BUILD_SECONDS)
        command(["cargo", "test", "--offline", "--locked", "-p", "hermetic-vmm",
                 "--features", "dev-unjailed", "--test", "agent_h_task",
                 "runs_sealed_task_through_host_harness", "--", "--ignored", "--exact", "--nocapture"],
                env=env, timeout=MAX_SESSION_SECONDS)
        print("Task submitted; trajectory.json and commands.jsonl retained (grading required)")
        return 0
    finally:
        os.close(directory)
        os.close(parent)


if __name__ == "__main__":
    try:
        raise SystemExit(run(sys.argv[1:]))
    except Exception:
        raise SystemExit("Task VM run refused; any created run directory is retained") from None
