"""CLI entry point for hermetic_runspec."""

from __future__ import annotations

import argparse
import json
import sys

from .derive import HermeticRunSpecError, derive_runspec_from_files


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _SafeArgumentParser(
        prog="hermetic_runspec",
        description="Derive deterministic microVM run spec from OCI image config.",
        add_help=False,
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--passwd", required=True)
    parser.add_argument("--group", required=True)
    parser.add_argument("--overrides", required=True)

    try:
        args = parser.parse_args(argv)
        runspec = derive_runspec_from_files(
            config_path=args.config,
            passwd_path=args.passwd,
            group_path=args.group,
            overrides_path=args.overrides,
        )
    except HermeticRunSpecError as exc:
        sys.stderr.write(f"error [{exc.code}]: {exc.message}\n")
        return 1
    except ValueError:
        sys.stderr.write("error [CLI_ARGUMENT_ERROR]: invalid command-line arguments\n")
        return 1
    except Exception:
        sys.stderr.write("error [INTERNAL_ERROR]: unexpected failure\n")
        return 1

    out = json.dumps(runspec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sys.stdout.write(out + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
