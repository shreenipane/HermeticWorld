"""Command-line interface for hermetic_assert_flow."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from hermetic_assert_flow.errors import FlowError
from hermetic_assert_flow.flow import analyze_flow
from hermetic_assert_flow.io_utils import atomic_write_bytes, read_regular_file_bounded
from hermetic_assert_flow.limits import MAX_LINE_NUMBER, MAX_REACHED_ARGS, MAX_IDENTIFIER_LENGTH
from hermetic_assert_flow.sites import validate_test_function_name
from hermetic_assert_flow.io_utils import _validate_path_str

MAX_CLI_ARGS = 2 * MAX_REACHED_ARGS + 8
MAX_CLI_ARGUMENT_LENGTH = 4096


class _HermeticArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that raises FlowError instead of exiting or printing host paths."""

    def error(self, message: str) -> None:
        raise FlowError("Invalid CLI arguments", code="CLI_ARGUMENT_ERROR")


def _parse_positive_line(raw: str) -> int:
    if not raw or len(raw) > 16 or not raw.isascii() or not raw.isdigit():
        raise FlowError("raising-line must be a positive integer", code="INVALID_RAISING_LINE")
    value = int(raw, 10)
    if value < 1 or value > MAX_LINE_NUMBER:
        raise FlowError(
            f"raising-line must be between 1 and {MAX_LINE_NUMBER}",
            code="INVALID_RAISING_LINE",
        )
    return value


def format_result_json(eligible: list[str], gave_up: bool, reason: str | None) -> str:
    """Serialize analysis output as deterministic, locale-independent JSON."""
    payload = {
        "eligible": list(eligible),
        "gave_up": bool(gave_up),
        "reason": reason,
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=True)


def run_cli(argv: Sequence[str] | None = None) -> int:
    """Execute the CLI and return an integer exit code (0 on success, 1 on FlowError)."""
    parser = _HermeticArgumentParser(
        prog="hermetic_assert_flow",
        add_help=False,
        allow_abbrev=False,
    )
    parser.add_argument("--file", dest="file_path", required=True)
    parser.add_argument("--function", dest="function", required=True)
    parser.add_argument("--raising-line", dest="raising_line", required=True)
    parser.add_argument("--reached", dest="reached", action="append", default=[])
    parser.add_argument("--output", dest="output_path", default=None)

    try:
        raw_args = sys.argv if argv is None else argv
        if len(raw_args) > MAX_CLI_ARGS + (1 if argv is None else 0):
            raise FlowError("CLI argument count exceeds cap", code="CLI_ARGUMENT_ERROR")
        arguments = list(raw_args[1:] if argv is None else raw_args)
        if any(not isinstance(item, str) or len(item) > MAX_CLI_ARGUMENT_LENGTH for item in arguments):
            raise FlowError("CLI argument exceeds cap", code="CLI_ARGUMENT_ERROR")
        args = parser.parse_args(arguments)
        validate_test_function_name(args.function)
        _validate_path_str(args.file_path)
        if args.output_path is not None:
            _validate_path_str(args.output_path)
        raising_line = _parse_positive_line(args.raising_line)
        reached: list[str] = list(args.reached)
        if len(reached) > MAX_REACHED_ARGS:
            raise FlowError(
                f"Number of --reached arguments exceeds cap of {MAX_REACHED_ARGS}",
                code="TOO_MANY_REACHED_SITES",
            )

        if any(not value or len(value) > MAX_IDENTIFIER_LENGTH for value in reached):
            raise FlowError("Invalid reached site ID", code="INVALID_SITE_ID")
        source_bytes = read_regular_file_bounded(args.file_path)
        result = analyze_flow(
            source=source_bytes,
            function=args.function,
            raising_line=raising_line,
            reached_site_ids=reached,
        )
        rendered = format_result_json(result.eligible, result.gave_up, result.reason) + "\n"

        if args.output_path is not None:
            atomic_write_bytes(args.output_path, rendered.encode("utf-8"))
        else:
            sys.stdout.write(rendered)
            sys.stdout.flush()
        return 0
    except FlowError as exc:
        err_payload = json.dumps(
            {"code": exc.code, "error": str(exc)},
            sort_keys=True,
            ensure_ascii=True,
        )
        sys.stderr.write(err_payload + "\n")
        sys.stderr.flush()
        return 1
