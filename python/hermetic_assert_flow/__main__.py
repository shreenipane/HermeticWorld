"""Module entrypoint for `python -m hermetic_assert_flow`."""

import sys

from hermetic_assert_flow.cli import run_cli

if __name__ == "__main__":
    raise SystemExit(run_cli(sys.argv[1:]))
