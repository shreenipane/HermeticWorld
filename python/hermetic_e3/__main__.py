
"""Command-line interface for Hermetic World Experiment E3.

Usage:
    python -m hermetic_e3 --truth F --findings F --seed N [--min-recall N --min-precision N]

Exit codes:
    0 - Exit criterion passed
    2 - Exit criterion failed
    1 - Typed error (invalid arguments, file security error, size limit, schema error)
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, NoReturn, Sequence

from hermetic_e3 import (
    CliArgumentError,
    DEFAULT_BOOTSTRAP_ITERATIONS,
    HermeticE3Error,
    MAX_CLI_ARGS,
    MAX_VALIDATION_DEPTH,
    PERMILLE_SCALE,
    RangeError,
    evaluate,
    load_findings,
    load_ground_truth,
)


class _StrictArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that raises CliArgumentError instead of calling sys.exit(2)."""

    def error(self, message: str) -> NoReturn:
        raise CliArgumentError(message)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        raise CliArgumentError(message.strip() if message else f"CLI exited with status {status}")


def _parse_strict_int(raw: str, flag_name: str) -> int:
    """Parse a strict base-10 integer string without whitespace tricks or floats."""
    if not isinstance(raw, str) or len(raw) == 0 or len(raw) > 32:
        raise CliArgumentError(f"Invalid integer for {flag_name}: {raw!r}")
    stripped = raw.strip()
    if stripped != raw:
        raise CliArgumentError(f"Invalid integer for {flag_name}: {raw!r}")
    try:
        return int(raw, 10)
    except ValueError as exc:
        raise CliArgumentError(f"Invalid integer for {flag_name}: {raw!r}") from exc


def _parse_threshold_arg(raw: str, flag_name: str) -> int:
    """Parse an integer per-mille threshold in [0, 1000]."""
    value = _parse_strict_int(raw, flag_name)
    if value < 0 or value > PERMILLE_SCALE:
        raise RangeError(
            f"{flag_name} ({value}) must be between 0 and {PERMILLE_SCALE}"
        )
    return value


def _build_parser() -> _StrictArgumentParser:
    parser = _StrictArgumentParser(
        prog="hermetic_e3",
        description="Evaluate sealcheck leak findings against Hermetic E3 ground truth.",
        add_help=False,
    )
    parser.add_argument("--truth", required=True, help="Path to ground-truth JSON file")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument("--seed", required=True, help="Integer RNG seed for bootstrap CI")
    parser.add_argument(
        "--min-recall",
        required=False,
        default=None,
        help="Minimum required recall per-mille (0..1000) for 'real' leaks",
    )
    parser.add_argument(
        "--min-precision",
        required=False,
        default=None,
        help="Minimum required precision per-mille (0..1000) for 'real' leaks",
    )
    parser.add_argument(
        "--bootstrap-iterations",
        required=False,
        default=None,
        help=f"Bootstrap resample count B (default: {DEFAULT_BOOTSTRAP_ITERATIONS})",
    )
    return parser


def _assert_no_floats(obj: Any, depth: int = 0) -> None:
    """Verify recursively (bounded by MAX_VALIDATION_DEPTH) that no float exists in output."""
    if depth > MAX_VALIDATION_DEPTH:
        raise HermeticE3Error("Report nesting depth exceeded validation cap")
    if isinstance(obj, float):
        raise HermeticE3Error("Float value forbidden in stored results")
    if isinstance(obj, dict):
        for key, value in tuple(obj.items())[:MAX_CLI_ARGS]:
            _assert_no_floats(key, depth + 1)
            _assert_no_floats(value, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for item in obj[:200_000]:
            _assert_no_floats(item, depth + 1)


def run_cli(
    argv: Sequence[str] | None = None,
    *,
    stdout: Any = None,
    stderr: Any = None,
) -> int:
    """Execute the CLI with given argv and streams; return exit code 0, 1, or 2."""
    out_stream = sys.stdout if stdout is None else stdout
    err_stream = sys.stderr if stderr is None else stderr
    args_list = list(sys.argv[1:] if argv is None else argv)

    try:
        if len(args_list) > MAX_CLI_ARGS:
            raise CliArgumentError(
                f"Argument count ({len(args_list)}) exceeds cap {MAX_CLI_ARGS}"
            )
        parser = _build_parser()
        parsed = parser.parse_args(args_list)

        seed = _parse_strict_int(parsed.seed, "--seed")
        min_recall = (
            None
            if parsed.min_recall is None
            else _parse_threshold_arg(parsed.min_recall, "--min-recall")
        )
        min_precision = (
            None
            if parsed.min_precision is None
            else _parse_threshold_arg(parsed.min_precision, "--min-precision")
        )
        bootstrap_iterations = (
            DEFAULT_BOOTSTRAP_ITERATIONS
            if parsed.bootstrap_iterations is None
            else _parse_strict_int(parsed.bootstrap_iterations, "--bootstrap-iterations")
        )

        leaks = load_ground_truth(parsed.truth)
        findings = load_findings(parsed.findings)
        report = evaluate(
            leaks,
            findings,
            seed=seed,
            bootstrap_iterations=bootstrap_iterations,
            min_recall_permille=min_recall,
            min_precision_permille=min_precision,
        )
        payload = report.to_dict()
        _assert_no_floats(payload)
        out_stream.write(json.dumps(payload, sort_keys=True, indent=2, allow_nan=False) + "\n")
        return 0 if report.exit_criterion.passed else 2

    except HermeticE3Error as exc:
        err_payload = {
            "error": {
                "code": exc.error_code,
                "type": type(exc).__name__,
                "message": str(exc),
            }
        }
        err_stream.write(
            json.dumps(err_payload, sort_keys=True, indent=2, allow_nan=False) + "\n"
        )
        return 1
    except Exception as exc:  # Defensive boundary: never emit an unhandled traceback.
        wrapped = HermeticE3Error(f"Unexpected internal error: {exc}")
        err_payload = {
            "error": {
                "code": wrapped.error_code,
                "type": type(wrapped).__name__,
                "message": str(wrapped),
            }
        }
        err_stream.write(
            json.dumps(err_payload, sort_keys=True, indent=2, allow_nan=False) + "\n"
        )
        return 1


def main() -> None:
    """Entry point for `python -m hermetic_e3`."""
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()


