
"""CLI entrypoint for Detector D7: python -m hermetic_d7 --shipped PATH --rebuilt PATH."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import NoReturn

from hermetic_d7.compare import build_error_report, compare_artifacts, format_report_json
from hermetic_d7.normalise import CliUsageError, HermeticD7Error


class _SafeArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that raises a typed CliUsageError instead of calling sys.exit(2)."""

    def error(self, message: str) -> NoReturn:
        raise CliUsageError(message)


def _build_parser() -> _SafeArgumentParser:
    parser = _SafeArgumentParser(
        prog="python -m hermetic_d7",
        description="Compare shipped and rebuilt artifacts for Hermetic World Detector D7.",
        add_help=True,
    )
    parser.add_argument(
        "--shipped",
        required=True,
        help="Path to the shipped artifact (directory, .whl, .zip, .tar, or .tar.gz).",
    )
    parser.add_argument(
        "--rebuilt",
        required=True,
        help="Path to the rebuilt artifact (directory, .whl, .zip, .tar, or .tar.gz).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the D7 CLI and return 0 (identical), 2 (differs), or 1 (error)."""
    args_list = list(argv) if argv is not None else sys.argv[1:]
    if args_list[:1] == ["--deep-audit"]:
        from hermetic_d7.deep_audit import run_deep_audit_cli

        deep = run_deep_audit_cli(args_list[1:])
        print(format_report_json(deep))
        return {"identical": 0, "differs": 2}.get(deep["verdict"], 1)
    parser = _build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 0
        return 0 if code == 0 else 1
    except HermeticD7Error as exc:
        report = build_error_report(None, None, exc)
        print(format_report_json(report))
        return 1

    report = compare_artifacts(args.shipped, args.rebuilt)
    print(format_report_json(report))

    verdict = report.get("verdict")
    if verdict == "identical":
        return 0
    if verdict == "differs":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())


