
"""CLI entrypoint for Hermetic World Experiment E7."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from hermetic_e7.compare import compare_worlds, format_report
from hermetic_e7.tree import HermeticError, build_manifest, seal_world

MAX_CLI_ARGS: int = 32


class _SafeArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that raises ValueError instead of exiting with code 2."""

    def error(self, message: str) -> None:
        raise ValueError(message)


def _build_parser() -> _SafeArgumentParser:
    parser = _SafeArgumentParser(prog="hermetic_e7", add_help=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    manifest_parser = subparsers.add_parser("manifest", help="Seal a directory into a manifest JSON")
    manifest_parser.add_argument("dir", help="World directory to hash")
    manifest_parser.add_argument("--output", "-o", help="Optional output directory to write manifest.json and d7-recipe.json")
    manifest_parser.add_argument("--build-record", help="Optional path to build record")

    compare_parser = subparsers.add_parser("compare", help="Compare two world directories")
    compare_parser.add_argument("dir_a", help="First world directory")
    compare_parser.add_argument("dir_b", help="Second world directory")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run CLI command: exit 0 reproducible/manifest ok, 2 differs, 1 error."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if len(raw_args) > MAX_CLI_ARGS:
        print(f"error: too many CLI arguments (max {MAX_CLI_ARGS})", file=sys.stderr)
        return 1

    parser = _build_parser()
    try:
        args = parser.parse_args(raw_args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except SystemExit as exc:
        return 0 if exc.code == 0 else 1

    try:
        if args.command == "manifest":
            if getattr(args, "output", None):
                manifest = seal_world(args.dir, args.output, build_record=getattr(args, "build_record", None))
            else:
                manifest = build_manifest(args.dir)
            print(json.dumps(manifest, sort_keys=True, indent=2))
            return 0
        if args.command == "compare":
            report = compare_worlds(args.dir_a, args.dir_b)
            print(format_report(report))
            return 0 if report.reproducible else 2
        print(f"error: unknown command '{args.command}'", file=sys.stderr)
        return 1
    except HermeticError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


