"""CLI entry point for hermetic_npm_cut."""

from __future__ import annotations

import argparse
import sys

from .cut import HermeticNpmCutError, cut_packument_files


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _SafeArgumentParser(
        prog="hermetic_npm_cut",
        description="Filter npm packument at world cutoff timestamp.",
        add_help=False,
    )
    parser.add_argument("--packument", required=True)
    parser.add_argument("--cutoff", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--report", required=True)

    try:
        args = parser.parse_args(argv)
        cut_packument_files(
            packument_path=args.packument,
            cutoff=args.cutoff,
            out_path=args.out,
            report_path=args.report,
        )
    except HermeticNpmCutError as exc:
        sys.stderr.write(f"error [{exc.code}]: {exc.message}\n")
        return 1
    except ValueError:
        sys.stderr.write("error [CLI_ARGUMENT_ERROR]: invalid command-line arguments\n")
        return 1
    except Exception:
        sys.stderr.write("error [INTERNAL_ERROR]: unexpected failure\n")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
