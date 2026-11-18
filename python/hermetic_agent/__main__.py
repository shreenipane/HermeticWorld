"""Run a task through the local gateway and AgentVM execd."""

import argparse
import json

from hermetic_safe_io import atomic_write
from .environment import ExecdEnvironment
from .errors import HarnessError, ProtocolError
from .model import HermeticGatewayModel
from .runner import run, configured_steps, MAX_TRAJECTORY_BYTES
from .task import read_input, task_clock
from .journal import CommandJournal, validate_output


def _default_sentinel():
    import datetime as _dt
    import socket
    from pathlib import Path
    from hermetic_slice.date_sentinel import DateSentinel

    names = [n for n in {socket.gethostname(), socket.getfqdn()} if n and n != "localhost"]
    home = str(Path.home())
    paths = [home] if len(home) > 1 else []
    return DateSentinel(
        _dt.datetime.now(_dt.timezone.utc).date(), host_names=names, host_paths=paths
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "task", "vsock", "cwd", "config-dir", "trajectory", "command-log"):
        parser.add_argument("--" + name, required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--gateway")
    choice.add_argument("--script", help="Offline smoke only: JSON list of bash commands")
    parser.add_argument("--model", default="pinned")
    parser.add_argument("--sentinel-summary", help="Path to write harness date sentinel summary JSON")
    parser.add_argument("--gateway-sentinel", help="Path to gateway date sentinel summary JSON to merge")
    parser.add_argument("--probe-output", help="Path to guest clock/escape probe output JSON-lines file")
    parser.add_argument("--run-json", help="Path to write run.json")
    parser.add_argument("--evidence-json", help="Path to write hermetic-run-evidence/v1 JSON")
    parser.add_argument("--firecracker", help="Path to Firecracker binary")
    parser.add_argument("--firecracker-build", help="Path to Firecracker build record")
    parser.add_argument("--pinned-lock", help="Path to pinned Firecracker lock")
    args = parser.parse_args()
    try:
        step_limit = configured_steps()
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
        sentinel = _default_sentinel()
        journal = CommandJournal(args.command_log, t_clock=clock)
        environment = ExecdEnvironment(args.vsock, cwd=args.cwd, journal=journal, sentinel=sentinel)
        result = run(model, environment, task, config_dir=args.config_dir, step_limit=step_limit, sentinel=sentinel)
        raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        if len(raw) > MAX_TRAJECTORY_BYTES:
            raise HarnessError("Trajectory byte limit")
        atomic_write(args.trajectory, raw + b"\n")
        if args.sentinel_summary:
            harness_summary = sentinel.summary().to_dict()
            atomic_write(args.sentinel_summary, json.dumps(harness_summary, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        if args.run_json or args.evidence_json:
            from pathlib import Path
            from hermetic_slice.date_sentinel import merge_summaries
            extra_summaries = []
            if args.gateway_sentinel:
                try:
                    gw_bytes = Path(args.gateway_sentinel).read_bytes()
                    extra_summaries.append(json.loads(gw_bytes.decode("utf-8")))
                except Exception:
                    # A requested but unreadable gateway summary must fail closed.
                    extra_summaries.append(None)
            merged = merge_summaries([sentinel.summary(), *extra_summaries])
            date_leak = merged["date_leak_observed"]

            probe_verdict = "failed"
            if args.probe_output:
                try:
                    probe_raw = Path(args.probe_output).read_bytes()
                    records = [json.loads(l) for l in probe_raw.decode("utf-8").splitlines() if l.strip()]
                    canary_blocked = any(r.get("probe") == "kernel_canary" and r.get("result") == "blocked" for r in records)
                    all_passed = bool(records) and all(
                        r.get("result") == "blocked" or (r.get("probe") == "clock_pairing_hc" and r.get("result") == "unavailable" and canary_blocked)
                        for r in records
                    )
                    probe_verdict = "passed" if all_passed else "failed"
                except Exception:
                    probe_verdict = "failed"

            run_record = {
                "schema": "hermetic-slice-run/v0-unsigned",
                "instance_id": "mode-h-task",
                "seal_level": "repo_only",
                "agent_mode": "H",
                "clock": "real",
                "grader_isolation": "clean_container",
                "deployment": "single_host",
                "status": "completed" if (result["status"] == "Submitted" or (result["status"] == "unresolved" and result.get("reason") in ("steps_exhausted", "time_exhausted"))) else "error",
                "date_leak_observed": date_leak,
                "date_sentinel": merged,
                "probe_verdict": probe_verdict,
                "escape_probe_result": probe_verdict,
                "trajectory": validate_output(args.trajectory),
                "command_log": validate_output(args.command_log),
            }
            if args.run_json:
                atomic_write(args.run_json, json.dumps(run_record, indent=2, sort_keys=True).encode("utf-8") + b"\n")
            if args.evidence_json:
                import hashlib
                from hermetic_classifier.evidence import build_run_evidence, parse_probe_lines, host_facts

                run_raw = json.dumps(run_record, indent=2, sort_keys=True).encode("utf-8")
                run_digest = f"sha256:{hashlib.sha256(run_raw).hexdigest()}"
                probe_recs = None
                if args.probe_output:
                    try:
                        probe_recs = parse_probe_lines(Path(args.probe_output).read_bytes())
                    except Exception:
                        probe_recs = None
                hf = None
                if args.firecracker and args.firecracker_build and args.pinned_lock:
                    try:
                        hf = host_facts(args.firecracker, args.firecracker_build, args.pinned_lock)
                    except Exception:
                        hf = None
                ev = build_run_evidence(
                    run_digest=run_digest,
                    world_sealed=True,
                    host=hf,
                    clockprobe=probe_recs,
                    date_leak_observed=date_leak,
                )
                atomic_write(args.evidence_json, json.dumps(ev, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        return 0 if (result["status"] == "Submitted" or
                     (result["status"] == "unresolved" and
                      result.get("reason") in ("steps_exhausted", "time_exhausted"))) else 2
    except (HarnessError, UnicodeError, OSError, ValueError):
        print("Harness refused run")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
