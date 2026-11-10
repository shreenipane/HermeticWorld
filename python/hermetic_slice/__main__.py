"""Command line interface for hermetic_slice."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

from hermetic_slice.http import make_http_get
from hermetic_slice.image_sealer import _rmtree, seal_image
from hermetic_slice.intake import IntakeError, intake_task, load_verified
from hermetic_slice.pkg_index import build_index, env_info
from hermetic_slice.repo_sealer import VerificationError, seal_repo
from hermetic_slice.world import probe, start_world, stop_world


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
    seal_images_parser.add_argument("--only", nargs="*", default=None, help="Optional instance IDs to process")

    build_index_parser = subparsers.add_parser("build-index", help="Build frozen package index for tasks")
    build_index_parser.add_argument("--tasks-dir", type=Path, required=True, help="Directory containing task directories")
    build_index_parser.add_argument("--cache", type=Path, required=True, help="Cache directory for HTTP downloads")
    build_index_parser.add_argument("--only", action="append", default=None, help="Optional instance IDs to process")

    world_probe_parser = subparsers.add_parser("world-probe", help="Probe world isolation and package index for tasks")
    world_probe_parser.add_argument("--tasks-dir", type=Path, required=True, help="Directory containing task directories")
    world_probe_parser.add_argument("--only", action="append", default=None, help="Optional instance IDs to process")
    world_probe_parser.add_argument("--image-tag-format", default="hermetic/{id}:sealed", help="Format for sealed image tag")

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

    if args.subcommand == "seal-images":
        tasks_dir = args.tasks_dir
        if not tasks_dir.exists():
            print(f"Error: Tasks directory {tasks_dir} does not exist", file=sys.stderr)
            return 1

        work_dir = args.work
        work_dir.mkdir(parents=True, exist_ok=True)

        only_set = set(args.only) if args.only is not None else None
        task_dirs = []
        for d in sorted(tasks_dir.iterdir()):
            if d.is_dir() and (d / "task.json").exists():
                if only_set is None or d.name in only_set:
                    task_dirs.append(d)

        has_failure = False
        for tdir in task_dirs:
            instance_id = tdir.name
            task_work = work_dir / instance_id
            if task_work.exists():
                _rmtree(task_work)
            task_work.mkdir(parents=True, exist_ok=True)

            try:
                report = seal_image(tdir, task_work)
                before = report["before"]
                head_was_base = before["head_is_base"]
                extra_commits = len(before["extra_commits"])
                gold_lines_count = report["gold_lines_checked"]
                before_after_status = "unsealed→sealed"
                sealed_image = report["sealed_image"]
                print(f"{instance_id}  {head_was_base}  {extra_commits}  {gold_lines_count}  {before_after_status}  {sealed_image}")
            except Exception as exc:
                print(f"Error sealing {instance_id}: {exc}", file=sys.stderr)
                has_failure = True

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

    return 1


if __name__ == "__main__":
    sys.exit(main())
