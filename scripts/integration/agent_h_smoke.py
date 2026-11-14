"""Offline host harness stage of the owner-run AgentVM smoke."""

import argparse
import os

from hermetic_agent.environment import ExecdEnvironment
from hermetic_agent.errors import HarnessError
from hermetic_agent.journal import CommandJournal
from hermetic_agent.runner import run
from hermetic_agent.scripted import ScriptedModel
from hermetic_agent.task import task_clock
from hermetic_safe_io import atomic_write

MAX_SMOKE_STREAM_BYTES = 1024 * 1024


def smoke(vsock, manifest, work):
    clock = task_clock(manifest)
    journal = CommandJournal(os.path.join(work, "commands.jsonl"), t_clock=clock)
    environment = ExecdEnvironment(vsock, cwd="/testbed", journal=journal)
    model = ScriptedModel([
        "pwd",
        "cat calc.py",
        "sed -i 's/return a - b/return a + b/' calc.py",
        "echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT",
    ], t_clock=clock)
    result = run(model, environment, "Fix add(a, b) so that it adds its arguments.",
                 config_dir=os.path.join(work, "config"))
    if result["status"] != "Submitted":
        raise HarnessError("Smoke task did not submit")
    # Extraction output is untrusted until the host validator accepts it, after VM teardown.
    extracted = environment.execute(
        "/sbin/hermetic-extract-agent --base /smoke/base --work /testbed --class patch: "
        "--out /tmp/agent.h.hext --report /tmp/agent.h.report.json")
    if extracted["returncode"] != 0:
        raise HarnessError("Smoke extraction failed")
    reply = environment._client.call({"type":"download", "path":"/tmp/agent.h.hext"})
    data = reply.get("data")
    if (set(reply) != {"type","data"} or reply.get("type") != "download"
            or not isinstance(data, list) or len(data) > MAX_SMOKE_STREAM_BYTES
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in data)):
        raise HarnessError("Smoke stream refused")
    atomic_write(os.path.join(work, "changes.hext"), bytes(data))
    import json
    atomic_write(os.path.join(work, "trajectory.json"), json.dumps(result, sort_keys=True).encode() + b"\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vsock", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--work", required=True)
    args = parser.parse_args()
    try:
        smoke(args.vsock, args.manifest, args.work)
    except (HarnessError, OSError, ValueError):
        raise SystemExit("Agent smoke refused") from None
