"""Command line interface for hermetic_slice."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

from hermetic_slice.eval_spec import load_eval_rows, prepare_eval_script, write_eval_spec
from hermetic_slice.grader import oracle_check
from hermetic_slice.http import make_http_get
from hermetic_slice.image_sealer import seal_image
from hermetic_slice.intake import IntakeError, intake_task, load_verified
from hermetic_slice.pkg_index import build_index, env_info
from hermetic_slice.repo_sealer import VerificationError, rmtree_force, seal_repo
from hermetic_slice.world import probe, start_world, stop_world
import time


def main(argv: list[str] | None = None) -> int:
    """Run hermetic_slice CLI commands."""
    parser = argparse.ArgumentParser(prog="hermetic_slice")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    seal_parser = subparsers.add_parser("seal-repo", help="Seal a repository")
    seal_parser.add_argument("--src", type=Path, required=True, help="Path to source repo")
    seal_parser.add_argument("--base", required=True, help="Base commit SHA")
    seal_parser.add_argument("--dest", type=Path, required=True, help="Path to destination repo")
    seal_parser.add_argument("--t-clock", required=True, help="Clock cutoff in ISO8601")

    intake_parser = subparsers.add_parser("intake", help="Intake SWE-bench tasks")
    intake_parser.add_argument("--tasks", type=Path, required=True, help="Path to tasks file")
    intake_parser.add_argument("--out", type=Path, required=True, help="Output directory")
    intake_parser.add_argument("--cache", type=Path, required=True, help="Cache directory")

    seal_images_parser = subparsers.add_parser("seal-images", help="Seal SWE-bench task images")
    seal_images_parser.add_argument("--tasks-dir", type=Path, required=True, help="Directory containing task directories")
    seal_images_parser.add_argument("--work", type=Path, required=True, help="Directory for working files")
    seal_images_parser.add_argument("--only", action="append", default=None, help="Optional instance IDs to process")

    build_index_parser = subparsers.add_parser("build-index", help="Build frozen package index for tasks")
    build_index_parser.add_argument("--tasks-dir", type=Path, required=True, help="Directory containing task directories")
    build_index_parser.add_argument("--cache", type=Path, required=True, help="Cache directory for HTTP downloads")
    build_index_parser.add_argument("--only", action="append", default=None, help="Optional instance IDs to process")

    world_probe_parser = subparsers.add_parser("world-probe", help="Probe world isolation and package index for tasks")
    world_probe_parser.add_argument("--tasks-dir", type=Path, required=True, help="Directory containing task directories")
    world_probe_parser.add_argument("--only", action="append", default=None, help="Optional instance IDs to process")
    world_probe_parser.add_argument("--image-tag-format", default="hermetic/{id}:sealed", help="Format for sealed image tag")

    run_agent_parser = subparsers.add_parser("run-agent", help="Run model agent on tasks")
    run_agent_parser.add_argument("--tasks-dir", type=Path, required=True, help="Directory containing task directories")
    run_agent_parser.add_argument("--runs-dir", type=Path, required=True, help="Directory for storing run outputs")
    run_agent_parser.add_argument("--model", default="gemma-4-31b-it", help="Model name")
    run_agent_parser.add_argument("--provider", choices=["gemini", "openrouter"], default="gemini", help="Model API to call; openrouter accepts only ':free' models")
    run_agent_parser.add_argument("--only", action="append", default=None, help="Optional instance IDs to process")
    run_agent_parser.add_argument("--max-steps", type=int, default=60, help="Maximum agent steps")
    run_agent_parser.add_argument("--image-tag-format", default="hermetic/{id}:sealed", help="Format for sealed image tag")

    fetch_parser = subparsers.add_parser("fetch-eval-specs", help="Fetch official eval specs and write to staging")
    fetch_parser.add_argument("--tasks-dir", type=Path, required=True, help="Directory containing task directories")
    fetch_parser.add_argument("--cache", type=Path, required=True, help="Cache directory")
    fetch_parser.add_argument("--only", action="append", default=None, help="Optional instance ID to process")

    oracle_parser = subparsers.add_parser("oracle", help="Run oracle checks for tasks")
    oracle_parser.add_argument("--tasks-dir", type=Path, required=True, help="Directory containing task directories")
    oracle_parser.add_argument("--only", action="append", default=None, help="Optional instance ID to process")
    oracle_parser.add_argument("--image-tag-format", default="hermetic/{id}:sealed", help="Image tag format")

    e3_basetrees_parser = subparsers.add_parser("e3-basetrees", help="Extract base trees from sealed images")
    e3_basetrees_parser.add_argument("--tasks-dir", type=Path, required=True, help="Directory containing task directories")
    e3_basetrees_parser.add_argument("--out", type=Path, required=True, help="Output directory for base trees")
    e3_basetrees_parser.add_argument("--only", nargs="*", action="extend", default=None, help="Optional instance IDs to process")

    e3_build_parser = subparsers.add_parser("e3-build", help="Build E3 leak corpus")
    e3_build_parser.add_argument("--tasks-dir", type=Path, required=True, help="Directory containing task directories")
    e3_build_parser.add_argument("--base-trees", type=Path, required=True, help="Directory containing base trees")
    e3_build_parser.add_argument("--out", type=Path, required=True, help="Output directory for corpus")
    e3_build_parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic corpus generation")

    e3_run_parser = subparsers.add_parser("e3-run", help="Run E3 accuracy evaluation against sealcheck")
    e3_run_parser.add_argument("--corpus", type=Path, required=True, help="Directory containing leak corpus")
    e3_run_parser.add_argument("--tasks-dir", type=Path, required=True, help="Directory containing task directories")
    e3_run_parser.add_argument("--base-trees", type=Path, required=True, help="Directory containing base trees")
    e3_run_parser.add_argument("--sealcheck", type=str, required=True, help="Path to sealcheck binary or stub")
    e3_run_parser.add_argument("--out", type=Path, required=True, help="Output directory for metrics and results")
    e3_run_parser.add_argument("--blind", type=Path, default=None, help="Optional directory containing blind cases")

    dispositions_parser = subparsers.add_parser("dispositions", help="Process gate outputs and emit dispositions.json (§5.5)")
    dispositions_parser.add_argument("--gate-output", "-i", type=Path, required=True, help="Path to gate output JSON or directory")
    dispositions_parser.add_argument("--out", "-o", type=Path, default=Path("dispositions.json"), help="Output path for dispositions.json")
    dispositions_parser.add_argument("--tasks-dir", type=Path, default=None, help="Optional directory containing task folders")

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if (exc.code == 0 or exc.code is None) else 1

    if args.subcommand == "seal-repo":
        try:
            t_clock = datetime.fromisoformat(args.t_clock)
            if t_clock.tzinfo is None or t_clock.tzinfo.utcoffset(t_clock) is None:
                raise ValueError(f"--t-clock must be timezone-aware: {args.t_clock}")
            t_clock = t_clock.astimezone(timezone.utc)
            report = seal_repo(
                src=args.src,
                base_commit=args.base,
                dest=args.dest,
                t_clock=t_clock,
            )
            print(json.dumps(asdict(report), indent=2))
            return 0
        except VerificationError as exc:
            print(f"Verification error: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    if args.subcommand == "intake":
        tasks_file = args.tasks
        if not tasks_file.exists():
            print(f"Error: Tasks file {tasks_file} does not exist", file=sys.stderr)
            return 1

        lines = [line.strip() for line in tasks_file.read_text(encoding="utf-8").splitlines()]
        task_ids = [line for line in lines if line and not line.startswith("#")]

        token = os.environ.get("GITHUB_TOKEN")
        http_get = make_http_get(args.cache, token=token)

        try:
            rows = load_verified(http_get, args.cache)
        except Exception as exc:
            print(f"Error loading verified dataset: {exc}", file=sys.stderr)
            return 1

        has_failure = False
        for task_id in task_ids:
            try:
                if task_id not in rows:
                    raise IntakeError(f"Unknown instance_id: {task_id}")

                task_dir = intake_task(task_id, rows, http_get, args.cache, args.out)
                task_data = json.loads((task_dir / "task.json").read_text(encoding="utf-8"))

                t_world = task_data["cutoffs"]["t_world"]
                t_clock = task_data["cutoffs"]["t_clock"]
                issue_source = task_data.get("issue_source", "none")
                n_warnings = len(task_data.get("warnings", []))
                print(f"{task_id}  {t_world}  {t_clock}  {issue_source}  {n_warnings}")
            except Exception as exc:
                print(f"Error processing {task_id}: {exc}", file=sys.stderr)
                has_failure = True

        return 1 if has_failure else 0

    if args.subcommand == "fetch-eval-specs":
        tasks_dir = args.tasks_dir
        if not tasks_dir.exists():
            print(f"Error: Tasks directory {tasks_dir} does not exist", file=sys.stderr)
            return 1

        existing_dirs = {d.name: d for d in sorted(tasks_dir.iterdir()) if d.is_dir() and (d / "task.json").exists()}
        only_set = set(args.only) if args.only is not None else None
        if only_set is not None:
            unknown_ids = only_set - set(existing_dirs.keys())
            if unknown_ids:
                print(f"Error: Unknown instance ID(s): {', '.join(sorted(unknown_ids))}", file=sys.stderr)
                return 1

        token = os.environ.get("GITHUB_TOKEN")
        http_get = make_http_get(args.cache, token=token)
        try:
            rows = load_eval_rows(http_get, args.cache)
        except Exception as exc:
            print(f"Error loading official verified dataset: {exc}", file=sys.stderr)
            return 1

        target_dirs = [d for name, d in existing_dirs.items() if (only_set is None or name in only_set)]
        has_failure = False
        for tdir in target_dirs:
            inst_id = tdir.name
            if inst_id not in rows:
                print(f"Error: Instance ID {inst_id} not found in dataset rows", file=sys.stderr)
                return 1
            try:
                row = rows[inst_id]
                spec = write_eval_spec(tdir, row)
                _, removed_lines = prepare_eval_script(row["eval_script"])
                removed_line = removed_lines[0].strip() if removed_lines else ""
                print(f"{inst_id}  {spec['log_parser']}  {removed_line}")
            except Exception as exc:
                print(f"Error processing eval spec for {inst_id}: {exc}", file=sys.stderr)
                has_failure = True

        return 1 if has_failure else 0

    if args.subcommand == "oracle":
        tasks_dir = args.tasks_dir
        if not tasks_dir.exists():
            print(f"Error: Tasks directory {tasks_dir} does not exist", file=sys.stderr)
            return 1

        existing_dirs = {d.name: d for d in sorted(tasks_dir.iterdir()) if d.is_dir() and (d / "task.json").exists()}
        only_set = set(args.only) if args.only is not None else None
        if only_set is not None:
            unknown_ids = only_set - set(existing_dirs.keys())
            if unknown_ids:
                print(f"Error: Unknown instance ID(s): {', '.join(sorted(unknown_ids))}", file=sys.stderr)
                return 1

        target_dirs = [d for name, d in existing_dirs.items() if (only_set is None or name in only_set)]
        has_failure = False
        for tdir in target_dirs:
            inst_id = tdir.name
            image = args.image_tag_format.format(id=inst_id.lower())
            t0 = time.time()
            try:
                res = oracle_check(tdir, image=image, out_root=tdir / "oracle")
                secs = f"{time.time() - t0:.2f}"
                oracle_ok = res["oracle_ok"]
                gold = res["gold_resolved"]
                empty_f2p_all_fail = res["empty_f2p_all_fail"]
                gold_f2p_fail = len(res["gold_f2p_failures"])
                gold_p2p_fail = len(res["gold_p2p_failures"])
                print(f"{inst_id}  {oracle_ok}  {gold}  {empty_f2p_all_fail}  {gold_f2p_fail}  {gold_p2p_fail}  {secs}")
                if not oracle_ok:
                    has_failure = True
            except Exception as exc:
                print(f"Error running oracle check for {inst_id}: {exc}", file=sys.stderr)
                has_failure = True

        return 1 if has_failure else 0

    if args.subcommand == "seal-images":
        tasks_dir = args.tasks_dir
        if not tasks_dir.exists():
            print(f"Error: Tasks directory {tasks_dir} does not exist", file=sys.stderr)
            return 1

        work_dir = args.work
        work_dir.mkdir(parents=True, exist_ok=True)

        if args.only is not None:
            requested_ids: list[str] = list(args.only)

            unknown_ids: list[str] = []
            for req_id in requested_ids:
                tdir = tasks_dir / req_id
                if not (tdir.is_dir() and (tdir / "task.json").exists()):
                    unknown_ids.append(req_id)

            if unknown_ids:
                for bad_id in unknown_ids:
                    print(f"Error: Unknown or missing task directory for --only ID: {bad_id}", file=sys.stderr)
                return 1

            seen_ids = set()
            task_dirs = []
            for req_id in requested_ids:
                if req_id not in seen_ids:
                    seen_ids.add(req_id)
                    task_dirs.append(tasks_dir / req_id)
        else:
            task_dirs = [
                d for d in sorted(tasks_dir.iterdir())
                if d.is_dir() and (d / "task.json").exists()
            ]

        has_failure = False
        for tdir in task_dirs:
            instance_id = tdir.name
            task_work = work_dir / instance_id
            if task_work.exists():
                rmtree_force(task_work)
            task_work.mkdir(parents=True, exist_ok=True)

            try:
                report = seal_image(tdir, task_work)
                before = report["before"]
                head_was_base = before["head_is_base"]
                extra_commits = len(before["extra_commits"])
                gold_lines_count = report["gold_lines_checked"]
                status = report.get("status", "sealed")
                sealed_image = report["sealed_image"]
                print(f"{instance_id}  {head_was_base}  {extra_commits}  {gold_lines_count}  {status}  {sealed_image}")
            except Exception as exc:
                has_failure = True
                report_file = tdir / "seal" / "report.json"
                problems = []
                if report_file.exists():
                    try:
                        rep = json.loads(report_file.read_text(encoding="utf-8"))
                        before = rep.get("before", {})
                        head_was_base = before.get("head_is_base", False)
                        extra_commits = len(before.get("extra_commits", []))
                        gold_lines_count = rep.get("gold_lines_checked", 0)
                        status = rep.get("status", "failed")
                        sealed_image = rep.get("sealed_image", "")
                        problems = rep.get("problems", [])
                        print(f"{instance_id}  {head_was_base}  {extra_commits}  {gold_lines_count}  {status}  {sealed_image}")
                        for p in problems:
                            print(f"  problem: {p}")
                    except Exception:
                        print(f"{instance_id}  False  0  0  failed  ")
                else:
                    print(f"{instance_id}  False  0  0  failed  ")
                print(f"Error sealing {instance_id}: {exc}", file=sys.stderr)

        return 1 if has_failure else 0

    if args.subcommand == "build-index":
        tasks_dir = args.tasks_dir
        if not tasks_dir.exists():
            print(f"Error: Tasks directory {tasks_dir} does not exist", file=sys.stderr)
            return 1

        all_tasks = {
            d.name: d
            for d in sorted(tasks_dir.iterdir())
            if d.is_dir() and (d / "task.json").exists()
        }

        if args.only is not None:
            task_dirs = []
            for tid in args.only:
                if tid not in all_tasks:
                    print(f"Error: Unknown instance_id: {tid}", file=sys.stderr)
                    return 1
                task_dirs.append(all_tasks[tid])
        else:
            task_dirs = list(all_tasks.values())

        http_get = make_http_get(args.cache)
        has_failure = False

        for tdir in task_dirs:
            instance_id = tdir.name
            try:
                task = json.loads((tdir / "task.json").read_text(encoding="utf-8"))
                image = task["image"]
                env = env_info(image)
                index_dir = tdir / "index"
                report = build_index(task, env, http_get, index_dir)
                totals = report.get("totals", {})
                served_packages = totals.get("served_packages", 0)
                served_files = totals.get("served_files", 0)
                newer_than_t_world = totals.get("newer_than_t_world", 0)
                excluded_str = ",".join(report.get("excluded", [])) or "none"
                print(f"{instance_id}  {served_packages}  {served_files}  {newer_than_t_world}  {excluded_str}")
            except Exception as exc:
                print(f"Error building index for {instance_id}: {exc}", file=sys.stderr)
                has_failure = True

        return 1 if has_failure else 0

    if args.subcommand == "world-probe":
        tasks_dir = args.tasks_dir
        if not tasks_dir.exists():
            print(f"Error: Tasks directory {tasks_dir} does not exist", file=sys.stderr)
            return 1

        all_tasks = {
            d.name: d
            for d in sorted(tasks_dir.iterdir())
            if d.is_dir() and (d / "task.json").exists()
        }

        if args.only is not None:
            task_dirs = []
            for tid in args.only:
                if tid not in all_tasks:
                    print(f"Error: Unknown instance_id: {tid}", file=sys.stderr)
                    return 1
                task_dirs.append(all_tasks[tid])
        else:
            task_dirs = list(all_tasks.values())

        has_failure = False

        for tdir in task_dirs:
            instance_id = tdir.name
            world = None
            try:
                task = json.loads((tdir / "task.json").read_text(encoding="utf-8"))
                index_dir = tdir / "index"
                report_path = index_dir / "index-report.json"
                if not report_path.exists():
                    raise FileNotFoundError(f"Missing index-report.json in {index_dir}")
                report = json.loads(report_path.read_text(encoding="utf-8"))

                sealed_image = args.image_tag_format.format(id=instance_id)
                world_name = f"hermetic-world-{instance_id.replace('__', '-').replace('_', '-')}"

                world = start_world(task, sealed_image, index_dir, name=world_name)
                probe_res = probe(world, task, report)

                probe_path = tdir / "world" / "probe.json"
                probe_path.parent.mkdir(parents=True, exist_ok=True)
                probe_path.write_text(json.dumps(probe_res, indent=2), encoding="utf-8")

                all_ok = probe_res.get("all_ok", False)
                failed_checks_list = [
                    k for k, v in probe_res.items()
                    if k != "all_ok" and isinstance(v, dict) and not v.get("ok")
                ]
                failed_checks_str = ",".join(failed_checks_list) if failed_checks_list else "none"

                print(f"{instance_id}  {all_ok}  {failed_checks_str}")
                if not all_ok:
                    has_failure = True
            except Exception as exc:
                print(f"Error probing world for {instance_id}: {exc}", file=sys.stderr)
                has_failure = True
            finally:
                if world is not None:
                    try:
                        stop_world(world)
                    except Exception:
                        pass

        return 1 if has_failure else 0

    if args.subcommand == "run-agent":
        tasks_dir = args.tasks_dir
        if not tasks_dir.exists():
            print(f"Error: Tasks directory {tasks_dir} does not exist", file=sys.stderr)
            return 1

        all_tasks = {
            d.name: d
            for d in sorted(tasks_dir.iterdir())
            if d.is_dir() and (d / "task.json").exists()
        }

        if args.only is not None:
            task_dirs = []
            for tid in args.only:
                if tid not in all_tasks:
                    print(f"Error: Unknown instance_id: {tid}", file=sys.stderr)
                    return 1
                task_dirs.append(all_tasks[tid])
        else:
            task_dirs = list(all_tasks.values())

        from hermetic_slice.model_client import GeminiClient, ModelError, OpenRouterClient, load_api_key
        from hermetic_slice.agent_loop import Limits
        from hermetic_slice.runner import run_task

        try:
            if args.provider == "openrouter":
                model_client = OpenRouterClient(args.model, load_api_key(var="HERMETIC_OPENROUTER_KEY_FILE"))
            else:
                model_client = GeminiClient(args.model, load_api_key())
        except ModelError as exc:
            print(f"Error loading API key: {exc}", file=sys.stderr)
            return 1

        from hermetic_slice.grader import grade as grade_fn

        limits = Limits(max_steps=args.max_steps)

        runs_dir = args.runs_dir
        runs_dir.mkdir(parents=True, exist_ok=True)

        has_failure = False
        for tdir in task_dirs:
            instance_id = tdir.name
            timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            task_run_dir = runs_dir / instance_id / timestamp_str
            task_run_dir.mkdir(parents=True, exist_ok=True)

            try:
                record = run_task(
                    tdir,
                    model=model_client,
                    grade_fn=grade_fn,
                    run_dir=task_run_dir,
                    image_tag_format=args.image_tag_format,
                    limits=limits,
                )

                agent_info = record.get("agent", {})
                agent_status = agent_info.get("agent_status", "unknown")
                steps = agent_info.get("steps", 0)
                usage_totals = agent_info.get("usage_totals", {})
                total_tokens = usage_totals.get("totalTokenCount", 0)
                wall_s = agent_info.get("wall_s", 0.0)

                grade_info = record.get("grade", {})
                resolution = grade_info.get("resolution", "unresolved")

                print(f"{instance_id}  {agent_status}  {steps}  {total_tokens}  {resolution}  {wall_s:.1f}")

                if record.get("status") == "error":
                    has_failure = True
            except Exception as exc:
                print(f"Error running task {instance_id}: {exc}", file=sys.stderr)
                has_failure = True

        return 1 if has_failure else 0

    if args.subcommand == "e3-basetrees":
        from hermetic_slice.e3 import extract_basetrees

        try:
            extract_basetrees(args.tasks_dir, args.out, only=args.only)
            return 0
        except Exception as exc:
            print(f"Error extracting basetrees: {exc}", file=sys.stderr)
            return 1

    if args.subcommand == "e3-build":
        from hermetic_slice.e3 import build_corpus

        try:
            build_corpus(args.tasks_dir, args.base_trees, args.out, seed=args.seed)
            return 0
        except Exception as exc:
            print(f"Error building corpus: {exc}", file=sys.stderr)
            return 1

    if args.subcommand == "e3-run":
        from hermetic_slice.e3 import run_e3

        try:
            run_e3(
                args.corpus,
                args.tasks_dir,
                args.base_trees,
                args.sealcheck,
                args.out,
                blind_dir=args.blind,
            )
            return 0
        except Exception as exc:
            print(f"Error running e3: {exc}", file=sys.stderr)
            return 1

    if args.subcommand == "dispositions":
        from hermetic_slice.dispositions import (
            format_summary,
            MalformedGateOutputError,
            MissingDispositionError,
            process_dispositions,
        )

        try:
            _, summary = process_dispositions(
                gate_source=args.gate_output,
                out_path=args.out,
                tasks_dir=args.tasks_dir,
            )
            print(format_summary(summary))
            return 0
        except (MalformedGateOutputError, MissingDispositionError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"Fatal error processing dispositions: {exc}", file=sys.stderr)
            return 2

    return 1


if __name__ == "__main__":
    sys.exit(main())
