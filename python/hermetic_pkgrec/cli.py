"""Command line interface for hermetic_pkgrec."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from hermetic_pkgrec.errors import PkgRecError
from hermetic_pkgrec.freeze import freeze_world
from hermetic_pkgrec.manifest import Manifest
from hermetic_pkgrec.server import RecordingProxyServer
from hermetic_pkgrec.store import RecordingStore
from hermetic_pkgrec.upstream import HttpUpstreamClient


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hermetic_pkgrec",
        description="Layer 1 recording index proxy and frozen world-root builder.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: record
    record_parser = subparsers.add_parser("record", help="Start recording index proxy.")
    record_parser.add_argument("--cutoff", required=True, help="Package cutoff ISO8601 UTC timestamp.")
    record_parser.add_argument("--upstream", required=True, help="Upstream simple index URL.")
    record_parser.add_argument("--store", required=True, help="Directory for content-addressed store.")
    record_parser.add_argument("--manifest", required=True, help="File path to record manifest JSON.")
    record_parser.add_argument("--listen", required=True, help="Listen address in format 127.0.0.1:PORT.")
    record_parser.add_argument("--yank-table", default=None, help="Optional historical yanks JSON table.")
    record_parser.add_argument("--misses", default=None, help="Optional file path to log 404 misses.")
    record_parser.add_argument(
        "--allow-insecure-upstream",
        action="store_true",
        help="Allow non-HTTPS upstream (for local test fixtures only).",
    )
    record_parser.add_argument(
        "--file-host",
        action="append",
        dest="file_hosts",
        default=None,
        help="Allowlisted file host (e.g. files.pythonhosted.org). May be specified multiple times.",
    )

    # Subcommand: freeze
    freeze_parser = subparsers.add_parser("freeze", help="Freeze recorded packages into world root.")
    freeze_parser.add_argument("--store", required=True, help="Directory holding content-addressed store.")
    freeze_parser.add_argument("--manifest", required=True, help="Manifest file path.")
    freeze_parser.add_argument("--out", required=True, help="Target frozen world-root directory.")
    freeze_parser.add_argument("--misses", default=None, help="Optional misses log file path.")

    return parser


def run_record(args: argparse.Namespace) -> int:
    listen = args.listen
    if ":" not in listen:
        sys.stderr.write("Error: --listen must be in format IP:PORT (e.g. 127.0.0.1:8080)\n")
        return 1

    host, _, port_str = listen.partition(":")
    try:
        port = int(port_str)
        if port < 0 or port > 65535:
            raise ValueError
    except ValueError:
        sys.stderr.write("Error: Invalid port number.\n")
        return 1

    manifest_path = Path(args.manifest)
    if manifest_path.is_file():
        manifest = Manifest.load(manifest_path)
    else:
        manifest = Manifest(cutoff=args.cutoff)

    yank_table = None
    if args.yank_table:
        try:
            with open(args.yank_table, "r", encoding="utf-8") as f:
                yank_table = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            sys.stderr.write(f"Error reading yank table: {exc}\n")
            return 1

    store = RecordingStore(args.store)
    upstream = HttpUpstreamClient(
        args.upstream,
        file_hosts=args.file_hosts,
        allow_insecure=args.allow_insecure_upstream,
    )

    server = RecordingProxyServer(
        (host, port),
        upstream=upstream,
        store=store,
        manifest=manifest,
        cutoff=args.cutoff,
        manifest_path=manifest_path,
        yank_table=yank_table,
        miss_log_path=args.misses,
    )

    bound_port = server.server_address[1]
    sys.stdout.write(f"Listening on {host}:{bound_port}\n")
    sys.stdout.flush()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        manifest.save(manifest_path)
    return 0


def run_freeze(args: argparse.Namespace) -> int:
    try:
        freeze_world(
            store_dir=args.store,
            manifest_path=args.manifest,
            out_dir=args.out,
            misses_path=args.misses,
        )
        return 0
    except PkgRecError as exc:
        sys.stderr.write(f"Freeze error: {exc.message}\n")
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.command == "record":
        return run_record(args)
    if args.command == "freeze":
        return run_freeze(args)
    return 1
