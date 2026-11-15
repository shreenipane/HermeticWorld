
"""CLI entrypoint for Detector D10: python -m hermetic_d10 --root DIR --t-clock RFC3339."""

from __future__ import annotations

import argparse
import json
import os
import sys

from hermetic_d10.carriers import (
    MAX_ARCHIVE_MEMBERS,
    MAX_DECOMPRESSED_BYTES,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_NESTING_DEPTH,
    MAX_TOTAL_BYTES_READ,
    HermeticD10Error,
    InvalidTimestampError,
    ScanCaps,
    parse_rfc3339_utc,
)
from hermetic_d10.scan import scan_tree


class _CLIArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that raises InvalidTimestampError instead of SystemExit(2)."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise InvalidTimestampError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _CLIArgumentParser(
        prog="python -m hermetic_d10",
        description="Hermetic World Detector D10: scan archives and metadata for post-cutoff dates.",
    )
    parser.add_argument(
        "--root",
        required=True,
        help="Root directory of the task image to scan.",
    )
    parser.add_argument(
        "--t-clock",
        required=True,
        help="Cutoff timestamp in RFC 3339 format (e.g. 2025-05-01T00:00:00Z).",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=MAX_FILES,
        help=f"Maximum regular files to scan (default: {MAX_FILES}).",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=MAX_TOTAL_BYTES_READ,
        help=f"Maximum total bytes read across tree (default: {MAX_TOTAL_BYTES_READ}).",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=MAX_FILE_BYTES,
        help=f"Maximum bytes per regular file (default: {MAX_FILE_BYTES}).",
    )
    parser.add_argument(
        "--max-decompressed-bytes",
        type=int,
        default=MAX_DECOMPRESSED_BYTES,
        help=f"Maximum decompressed bytes per archive (default: {MAX_DECOMPRESSED_BYTES}).",
    )
    parser.add_argument(
        "--max-members",
        type=int,
        default=MAX_ARCHIVE_MEMBERS,
        help=f"Maximum archive members inspected (default: {MAX_ARCHIVE_MEMBERS}).",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=MAX_NESTING_DEPTH,
        help=f"Maximum archive nesting depth (default: {MAX_NESTING_DEPTH}).",
    )
    parser.add_argument(
        "--provenance",
        default=None,
        help="Sealer provenance manifest (hermetic.d10.provenance/1); every WARC record must match it.",
    )
    return parser


def _read_provenance(path: str) -> bytes:
    """Read the manifest without following symlinks, within its byte cap."""
    from hermetic_safe_io import open_regular

    from hermetic_d10.provenance import MAX_PROVENANCE_BYTES, ProvenanceError

    try:
        fd = open_regular(path, MAX_PROVENANCE_BYTES)
    except (OSError, ValueError, TypeError):
        raise ProvenanceError("provenance manifest refused (missing, symlink or not a regular file)") from None
    try:
        data = b""
        while len(data) <= MAX_PROVENANCE_BYTES:
            chunk = os.read(fd, MAX_PROVENANCE_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    if len(data) > MAX_PROVENANCE_BYTES:
        raise ProvenanceError("provenance manifest exceeds byte cap")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        clock_dt = parse_rfc3339_utc(args.t_clock)
        caps = ScanCaps(
            max_files=args.max_files,
            max_total_bytes_read=args.max_bytes,
            max_file_bytes=args.max_file_bytes,
            max_decompressed_bytes=args.max_decompressed_bytes,
            max_archive_members=args.max_members,
            max_nesting_depth=args.max_depth,
        )
        result = scan_tree(args.root, clock_dt, caps=caps)
        provenance = None
        if args.provenance is not None:
            from hermetic_d10.provenance import verify_provenance

            provenance = verify_provenance(result, _read_provenance(args.provenance), clock_dt)
    except HermeticD10Error as exc:
        err_payload = {
            "detector": "D10",
            "verdict": "error",
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
            },
        }
        print(json.dumps(err_payload, indent=2))
        return 1

    if provenance is None:
        print(result.to_json())
    else:
        combined = json.loads(result.to_json())
        combined["provenance"] = provenance
        print(json.dumps(combined, indent=2, sort_keys=True))
        if provenance["verdict"] == "error":
            return 1
        if provenance["verdict"] == "gate":
            return 2
    if result.has_cap_error():
        return 1
    if result.verdict == "gate":
        return 2
    # Fail closed: a scan that skipped any payload (malformed or unreadable data,
    # internal errors) cannot certify the tree as clean.
    if not result.is_complete():
        return 1
    if result.verdict == "gate":
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())


