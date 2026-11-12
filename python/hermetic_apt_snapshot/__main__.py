"""CLI entry point for hermetic_apt_snapshot."""

from __future__ import annotations

import argparse
import json
import sys

from .select import HermeticAptSnapshotError, select_apt_snapshot


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def _split_csv(raw: str) -> list[str]:
    if raw == "":
        return []
    return raw.split(",")


def main(argv: list[str] | None = None) -> int:
    parser = _SafeArgumentParser(
        prog="hermetic_apt_snapshot",
        description="Select APT snapshot ID and generate deb822 sources file.",
        add_help=False,
    )
    parser.add_argument("--dist", required=True)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--components", required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--cutoff", required=True)
    parser.add_argument("--signed-by", required=True)

    try:
        args = parser.parse_args(argv)
        result = select_apt_snapshot(
            dist=args.dist,
            suite=args.suite,
            components=_split_csv(args.components),
            architectures=_split_csv(args.arch),
            cutoff=args.cutoff,
            signed_by=args.signed_by,
        )
    except HermeticAptSnapshotError as exc:
        sys.stderr.write(f"error [{exc.code}]: {exc.message}\n")
        return 1
    except ValueError:
        sys.stderr.write("error [CLI_ARGUMENT_ERROR]: invalid command-line arguments\n")
        return 1
    except Exception:
        sys.stderr.write("error [INTERNAL_ERROR]: unexpected failure\n")
        return 1

    out = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sys.stdout.write(out + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
