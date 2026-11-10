"""Command line interface for hermetic_slice."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from hermetic_slice.repo_sealer import VerificationError, seal_repo


def main(argv: list[str] | None = None) -> int:
    """Run hermetic_slice CLI commands."""
    parser = argparse.ArgumentParser(prog="hermetic_slice")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    seal_parser = subparsers.add_parser("seal-repo", help="Seal a repository")
    seal_parser.add_argument("--src", type=Path, required=True, help="Path to source repo")
    seal_parser.add_argument("--base", required=True, help="Base commit SHA")
    seal_parser.add_argument("--dest", type=Path, required=True, help="Path to destination repo")
    seal_parser.add_argument("--t-clock", required=True, help="Clock cutoff in ISO8601")

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

    return 1


if __name__ == "__main__":
    sys.exit(main())
