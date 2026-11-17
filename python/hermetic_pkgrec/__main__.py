"""Executable entry point for python -m hermetic_pkgrec."""

from __future__ import annotations

import sys

from hermetic_pkgrec.cli import main

if __name__ == "__main__":
    sys.exit(main())
