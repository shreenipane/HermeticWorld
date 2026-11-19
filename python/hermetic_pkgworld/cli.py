"""Command-line interface for hermetic_pkgworld.

Computes package evidence required by WorldManifest:
PackagesRecord {closure_root, baseline_month, baseline_root}.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from hermetic_pkgworld.evidence import compute_package_evidence
from hermetic_pkgworld.errors import PkgWorldError


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="hermetic_pkgworld",
        description="Compute WorldManifest package evidence {closure_root, baseline_month, baseline_root}",
        allow_abbrev=False,
    )
    parser.add_argument(
        "closure_pos",
        nargs="?",
        metavar="CLOSURE_DIR",
        help="Path to frozen Layer-1 closure directory",
    )
    parser.add_argument(
        "baseline_pos",
        nargs="?",
        metavar="BASELINE_DIR",
        help="Path to frozen Layer-2 baseline store directory",
    )
    parser.add_argument(
        "--closure",
        "--pkg-closure",
        dest="closure_opt",
        help="Path to frozen Layer-1 closure directory",
    )
    parser.add_argument(
        "--baseline",
        "--pkg-baseline",
        dest="baseline_opt",
        help="Path to frozen Layer-2 baseline store directory",
    )
    parser.add_argument(
        "--cutoff",
        "--expected-cutoff",
        dest="cutoff",
        help="Expected package cutoff timestamp (RFC 3339 UTC)",
    )
    parser.add_argument(
        "--no-verify-files",
        dest="verify_files",
        action="store_false",
        default=True,
        help="Skip reading on-disk artifact bytes (manifest-only check)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    closure_dir = args.closure_opt or args.closure_pos
    baseline_dir = args.baseline_opt or args.baseline_pos

    if not closure_dir:
        sys.stderr.write("Error: Missing required closure directory (--closure or positional)\n")
        return 1
    if not baseline_dir:
        sys.stderr.write("Error: Missing required baseline directory (--baseline or positional)\n")
        return 1

    try:
        record = compute_package_evidence(
            closure_dir,
            baseline_dir,
            expected_pkg_cutoff=args.cutoff,
            verify_files=args.verify_files,
        )
        sys.stdout.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
        sys.stdout.flush()
        return 0
    except PkgWorldError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"Unexpected error: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
