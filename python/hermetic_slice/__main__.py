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
from hermetic_slice.image_sealer import seal_image
from hermetic_slice.intake import IntakeError, intake_task, load_verified
from hermetic_slice.repo_sealer import VerificationError, rmtree_force, seal_repo


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

    return 1


if __name__ == "__main__":
    sys.exit(main())
