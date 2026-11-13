"""CLI entry point for hermetic_conda_cut."""

from __future__ import annotations

import argparse
import sys

from .cut import HermeticCondaCutError, cut_repodata_files


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _SafeArgumentParser(
        prog="hermetic_conda_cut",
        description="Filter conda repodata.json at world cutoff timestamp.",
        add_help=False,
        allow_abbrev=False,
    )
    parser.add_argument("--repodata", required=True)
    parser.add_argument("--cutoff", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--report", required=True)

    try:
        args = parser.parse_args(argv)
        cut_repodata_files(
            repodata_path=args.repodata,
            cutoff=args.cutoff,
            out_path=args.out,
            report_path=args.report,
        )
    except HermeticCondaCutError as exc:
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
