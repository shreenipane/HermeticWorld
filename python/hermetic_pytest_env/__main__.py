
from __future__ import annotations

import sys

from .scan import ScanError, scan


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or any(a in ("-h", "--help") for a in args):
        sys.stderr.write("usage: python -m hermetic_pytest_env SITE_DIR [SITE_DIR ...]\n")
        return 1

    try:
        inv = scan(args)
    except ScanError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    sys.stdout.write(inv.to_json() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


