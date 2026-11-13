"""CLI entry point for hermetic_probe_eval."""

from __future__ import annotations

import argparse
import json
import sys

from .evaluate import HermeticProbeEvalError, ProbeVerdict, evaluate_probe_file


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _SafeArgumentParser(
        prog="hermetic_probe_eval",
        description="Evaluate escape probe results fail-closed.",
        add_help=False,
    )
    parser.add_argument("--results", required=True)

    try:
        args = parser.parse_args(argv)
        report = evaluate_probe_file(results_path=args.results)
    except HermeticProbeEvalError as exc:
        sys.stderr.write(f"error [{exc.code}]: {exc.message}\n")
        return 1
    except ValueError:
        sys.stderr.write("error [CLI_ARGUMENT_ERROR]: invalid command-line arguments\n")
        return 1
    except Exception:
        sys.stderr.write("error [INTERNAL_ERROR]: unexpected failure\n")
        return 1

    out = json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sys.stdout.write(out + "\n")
    if report.verdict == ProbeVerdict.PASS.value:
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
