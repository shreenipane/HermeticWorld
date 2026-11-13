
"""CLI entry point for python -m hermetic_calibrate."""

from __future__ import annotations

import argparse
import sys
from typing import NoReturn, Sequence

from hermetic_calibrate.calibrate import (
    DEFAULT_MAX_FALSE_ALARM,
    DEFAULT_MIN_CLEAN_SAMPLES,
    DEFAULT_MIN_LEAK_SAMPLES,
    DEFAULT_MIN_RECALL,
    DEFAULT_STABILITY_DENOMINATOR,
    DEFAULT_STABILITY_NUMERATOR,
    CalibrationConfig,
    CalibrationError,
    ConfigError,
    calibrate_file,
    format_result_json,
)

MAX_CLI_ARGS: int = 64


class _HelpExit(Exception):
    """Internal control-flow signal when --help is requested."""

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.text = text


class _StrictArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that raises typed ConfigError instead of exiting with code 2."""

    def error(self, message: str) -> NoReturn:
        raise ConfigError(message)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if status == 0:
            raise _HelpExit(message or self.format_help())
        raise ConfigError(message or "Invalid CLI arguments")


def _parse_strict_cli_int(raw: str) -> int:
    """Parse base-10 integer CLI arguments without accepting floats or whitespace."""
    if not raw or raw != raw.strip():
        raise argparse.ArgumentTypeError(f"Invalid integer value: {raw!r}")
    try:
        return int(raw, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid integer value: {raw!r}") from exc


def _build_parser() -> _StrictArgumentParser:
    parser = _StrictArgumentParser(
        prog="hermetic_calibrate",
        description="Calibrate sealcheck detector thresholds on labelled samples.",
    )
    parser.add_argument(
        "--samples",
        required=True,
        type=str,
        help="Path to input JSON file containing labelled detector samples.",
    )
    parser.add_argument(
        "--max-false-alarm",
        type=_parse_strict_cli_int,
        default=DEFAULT_MAX_FALSE_ALARM,
        help=(
            "Maximum allowed false-alarm rate in per-mille 0..1000 "
            f"(default: {DEFAULT_MAX_FALSE_ALARM})."
        ),
    )
    parser.add_argument(
        "--min-recall",
        type=_parse_strict_cli_int,
        default=DEFAULT_MIN_RECALL,
        help=(
            "Minimum required recall in per-mille 0..1000 "
            f"(default: {DEFAULT_MIN_RECALL})."
        ),
    )
    parser.add_argument(
        "--min-leak-samples",
        type=_parse_strict_cli_int,
        default=DEFAULT_MIN_LEAK_SAMPLES,
        help=(
            "Minimum leak samples required per detector "
            f"(default: {DEFAULT_MIN_LEAK_SAMPLES})."
        ),
    )
    parser.add_argument(
        "--min-clean-samples",
        type=_parse_strict_cli_int,
        default=DEFAULT_MIN_CLEAN_SAMPLES,
        help=(
            "Minimum clean samples required per detector "
            f"(default: {DEFAULT_MIN_CLEAN_SAMPLES})."
        ),
    )
    parser.add_argument(
        "--stability-numerator",
        type=_parse_strict_cli_int,
        default=DEFAULT_STABILITY_NUMERATOR,
        help=(
            "Numerator for integer stability ratio check max * denom > min * num "
            f"(default: {DEFAULT_STABILITY_NUMERATOR})."
        ),
    )
    parser.add_argument(
        "--stability-denominator",
        type=_parse_strict_cli_int,
        default=DEFAULT_STABILITY_DENOMINATOR,
        help=(
            "Denominator for integer stability ratio check max * denom > min * num "
            f"(default: {DEFAULT_STABILITY_DENOMINATOR})."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run CLI calibration. Returns 0 if all detectors calibrated, 2 otherwise, 1 on error."""
    try:
        raw_argv = sys.argv[1:] if argv is None else argv
        if len(raw_argv) > MAX_CLI_ARGS:
            raise ConfigError(f"Too many CLI arguments (max {MAX_CLI_ARGS})")
        arg_list = list(raw_argv)

        parser = _build_parser()
        args = parser.parse_args(arg_list)

        config = CalibrationConfig(
            max_false_alarm=args.max_false_alarm,
            min_recall=args.min_recall,
            min_leak_samples=args.min_leak_samples,
            min_clean_samples=args.min_clean_samples,
            stability_numerator=args.stability_numerator,
            stability_denominator=args.stability_denominator,
        )
        result = calibrate_file(args.samples, config)
        sys.stdout.write(format_result_json(result) + "\n")

        detectors = result["detectors"]
        every_detector_calibrated = all(
            detectors[name]["threshold"] is not None for name in detectors
        )
        return 0 if every_detector_calibrated else 2
    except _HelpExit as exc:
        sys.stdout.write(exc.text)
        return 0
    except CalibrationError as exc:
        sys.stderr.write(f"error [{exc.code}]: {exc}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"error [unexpected_error]: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())


