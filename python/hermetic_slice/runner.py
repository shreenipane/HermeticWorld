"""Runner orchestration for hermetic agent runs."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import secrets
from typing import Any, Callable

from hermetic_slice.agent_loop import AGENT_PRELUDE, AgentResult, Limits, run_agent
from hermetic_slice.date_sentinel import DateSentinel, merge_summaries
from hermetic_slice.dockerutil import run_docker
from hermetic_slice.extract import extract_patch
from hermetic_slice.world import start_world, stop_world, world_exec


def _sha256_of_file(path: Path) -> str | None:
    """Compute sha256 hex digest of file if it exists, else None."""
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _default_sentinel() -> DateSentinel:
    """D12 sentinel for the real run day, this host's name and home directory."""
    import datetime as _dt
    import socket

    names = [n for n in {socket.gethostname(), socket.getfqdn()} if n and n != "localhost"]
    home = str(Path.home())
    paths = [home] if len(home) > 1 else []
    return DateSentinel(
        _dt.datetime.now(_dt.timezone.utc).date(), host_names=names, host_paths=paths
    )


def load_run_exemptions(task_dir: Path | str) -> tuple[str, list[str]]:
    """Derive substrate_at_t and exemption_list from authoritative exemption entries."""
    task_p = Path(task_dir)
    exemptions_path = task_p / "seal" / "exemptions.json"
    if not exemptions_path.exists():
        exemptions_path = task_p / "exemptions.json"
    exemption_list: list[str] = []
    substrate_at_t = "full"
    if exemptions_path.exists():
        try:
            ex_data = json.loads(exemptions_path.read_text(encoding="utf-8"))
            if isinstance(ex_data, dict):
                raw_entries = ex_data.get("exemptions")
                if raw_entries is None and "exemption_list" in ex_data:
                    raw_entries = ex_data["exemption_list"]
            elif isinstance(ex_data, list):
                raw_entries = ex_data
            else:
                raise ValueError("invalid exemptions format")

            if raw_entries is None or not isinstance(raw_entries, list):
                raise ValueError("exemptions entries must be a list")

            paths: list[str] = []
            for entry in raw_entries:
                if isinstance(entry, dict) and "path" in entry and isinstance(entry["path"], str):
                    paths.append(entry["path"])
                elif isinstance(entry, str):
                    paths.append(entry)
                else:
                    raise ValueError("invalid exemption entry")

            exemption_list = sorted(list(set(paths)))
            substrate_at_t = "partial" if exemption_list else "full"
        except Exception:
            exemption_list = []
            substrate_at_t = "none"
    return substrate_at_t, exemption_list


def run_task(
    task_dir: Path,
    *,
    model: Any,
    grade_fn: Callable[..., dict[str, Any]],
    run_dir: Path,
    image_tag_format: str = "hermetic/{id}:sealed",
    limits: Limits | None = None,
    sentinel: DateSentinel | None = None,
    extra_sentinel_summaries: list[dict[str, Any]] | None = None,
    runspec: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute one task inside sealed world, extract patch, grade, and record results.

    ``runspec`` (a derived ``hermetic_runspec`` spec) is applied to the agent
    container: user, groups, working directory, environment, limits, dropped
    capabilities.

    ``date_leak_observed`` is the D12 result: the harness sentinel (prompts and
    observations; default real date = today UTC, host name and home directory) merged with
    ``extra_sentinel_summaries`` (e.g. the gateway's ``date_sentinel.json``).
    """
    task_dir = Path(task_dir)
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    if limits is None:
        limits = Limits()
    if sentinel is None:
        sentinel = _default_sentinel()

    # 1. Read task.json and ONLY agent/problem_statement.md.
    task_path = task_dir / "task.json"
    task_json = json.loads(task_path.read_text(encoding="utf-8"))
    instance_id = task_json.get("instance_id", task_dir.name)

    problem_stmt_path = task_dir / "agent" / "problem_statement.md"
    problem_statement = problem_stmt_path.read_text(encoding="utf-8")

    sealed_image = (
        image_tag_format.format(id=instance_id)
        if "{id}" in image_tag_format
        else image_tag_format
    )

    # 2. Check that index/index-report.json and world/probe.json exist, and probe.json has all_ok: true.
    index_report_path = task_dir / "index" / "index-report.json"
    probe_path = task_dir / "world" / "probe.json"
    probe_ok = False
    if probe_path.exists():
        try:
            probe_data = json.loads(probe_path.read_text(encoding="utf-8"))
            probe_ok = probe_data.get("all_ok") is True
        except Exception:
            probe_ok = False

    def build_record(
        *,
        agent: dict[str, Any],
        status: str,
        error: str | None,
        sealed_image_id: str = "",
        digests: dict[str, Any] | None = None,
        extract: dict[str, Any] | None = None,
        grade: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        substrate_at_t, exemption_list = load_run_exemptions(task_dir)

        date_sentinel = merge_summaries([sentinel.summary(), *(extra_sentinel_summaries or [])])
        record: dict[str, Any] = {
            "schema": "hermetic-slice-run/v0-unsigned",
            "instance_id": instance_id,
            "seal_level": "repo_only",
            "agent_mode": "H",
            "clock": "real",
            "grader_isolation": "clean_container",
            "deployment": "single_host",
            "substrate_at_t": substrate_at_t,
            "exemption_list": exemption_list,
            "task": {
                "t_world": task_json.get("cutoffs", {}).get("t_world") or task_json.get("t_world"),
                "t_clock": task_json.get("cutoffs", {}).get("t_clock") or task_json.get("t_clock"),
                "base_commit": task_json.get("base_commit", ""),
            },
            "model": {
                "model": getattr(model, "model", str(model)),
                "limits": asdict(limits),
            },
            "agent": agent,
            "images": {
                "sealed_image": sealed_image,
                "sealed_image_id": sealed_image_id,
            },
            "digests": digests or {},
            "extract": extract or {},
            "grade": grade or {},
            "status": status,
            "error": error,
            "date_leak_observed": date_sentinel["date_leak_observed"],
            "date_sentinel": date_sentinel,
            "notes": "Phase 0: unsigned; transcript audit not run",
        }
        (run_dir / "run.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        return record

    if not index_report_path.exists() or not probe_ok:
        return build_record(
            agent={"agent_status": "world_not_ready", "steps": 0, "usage_totals": {}, "wall_s": 0.0},
            status="error",
            error="world_not_ready",
        )

    short_id = instance_id.replace("__", "-").replace("_", "-")[:20]
    rand_suffix = secrets.token_hex(4)
    world_name = f"hermetic-run-{short_id}-{rand_suffix}"

    world = None
    try:
        # 3. start_world
        world = start_world(task_json, sealed_image, task_dir / "index", name=world_name,
                            runspec=runspec)

        # 4. exec_fn = lambda cmd, timeout: world_exec(world, AGENT_PRELUDE + cmd, timeout=timeout)
        def exec_fn(cmd: str, timeout: int) -> tuple[int, str]:
            return world_exec(world, AGENT_PRELUDE + cmd, timeout=timeout)

        # 5. Run run_agent
        trajectory_path = run_dir / "trajectory.jsonl"
        agent_res: AgentResult = run_agent(
            model,
            exec_fn,
            problem_statement,
            limits=limits,
            trajectory_path=trajectory_path,
            sentinel=sentinel,
        )
        agent_info = {
            "agent_status": agent_res.status,
            "steps": agent_res.steps,
            "usage_totals": agent_res.usage_totals,
            "wall_s": agent_res.wall_s,
        }

        # 6. Extract patch from agent container BEFORE stop_world
        try:
            patch_text, extract_report = extract_patch(
                world.agent_container,
                sealed_image,
                run_dir,
            )
        except Exception as exc:
            # Keep the run on record: agent status and usage survive a harness failure.
            return build_record(
                agent=agent_info, status="error", error=f"extract_failed: {exc}",
                extract={"error": str(exc)},
            )

        patch_path = run_dir / "patch.diff"
        patch_path.write_text(patch_text, encoding="utf-8")

        # 7. grade_fn returns grade dict
        grade_out_dir = run_dir / "grade"
        grade_out_dir.mkdir(parents=True, exist_ok=True)
        try:
            grade_res = grade_fn(
                task_dir,
                patch_text,
                image=sealed_image,
                out_dir=grade_out_dir,
            )
        except Exception as exc:
            return build_record(
                agent=agent_info, status="error", error=f"grade_failed: {exc}",
                extract=extract_report, grade={"error": str(exc)},
            )

        # Retrieve sealed image ID from docker
        sealed_image_id = ""
        try:
            inspect_out = run_docker(["image", "inspect", "--format", "{{.Id}}", sealed_image], check=True)
            sealed_image_id = inspect_out.decode("utf-8").strip()
        except Exception:
            sealed_image_id = ""

        # Compute digests
        digests = {
            "seal/report.json": _sha256_of_file(task_dir / "seal" / "report.json"),
            "seal/exemptions.json": _sha256_of_file(task_dir / "seal" / "exemptions.json") or _sha256_of_file(task_dir / "exemptions.json"),
            "seal/substrate-inventory.json": _sha256_of_file(task_dir / "seal" / "substrate-inventory.json") or _sha256_of_file(task_dir / "substrate-inventory.json"),
            "index/index-report.json": _sha256_of_file(task_dir / "index" / "index-report.json"),
            "world/probe.json": _sha256_of_file(task_dir / "world" / "probe.json"),
            "trajectory.jsonl": _sha256_of_file(trajectory_path),
            "patch.diff": _sha256_of_file(patch_path),
        }

        # grade() reports test names per bucket; the run record keeps counts (grade.json has the names).
        def _count(bucket: str, outcome: str) -> int:
            return len(grade_res.get(bucket, {}).get(outcome, []))

        grade_dict = {
            "status": grade_res.get("status"),
            "resolution": grade_res.get("resolution"),
            "resolved": grade_res.get("resolved", False),
            "f2p_success": _count("f2p", "success"),
            "f2p_failure": _count("f2p", "failure"),
            "p2p_success": _count("p2p", "success"),
            "p2p_failure": _count("p2p", "failure"),
            "findings": grade_res.get("findings", []),
            "patch_sha256": grade_res.get("patch_sha256"),
            "test_exit_code": grade_res.get("test_exit_code"),
        }

        # 8. Write run.json
        return build_record(
            agent=agent_info,
            status="completed" if agent_res.error is None else "error",
            error=agent_res.error,
            sealed_image_id=sealed_image_id,
            digests=digests,
            extract=extract_report,
            grade=grade_dict,
        )

    finally:
        if world is not None:
            try:
                stop_world(world)
            except Exception:
                pass
