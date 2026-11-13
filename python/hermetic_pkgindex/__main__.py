
"""CLI entrypoint for running the Hermetic World PyPI Simple server."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import logging
import signal
import sys
import threading

from hermetic_pkgindex.server import HermeticHTTPServer
from hermetic_pkgindex.store import FrozenStore, MissLog, PkgIndexError


def parse_bind_address(bind: str) -> tuple[str, int]:
    """Parse HOST:PORT (or [IPV6]:PORT) into (host, port)."""
    value = bind.strip()
    if not value:
        raise ValueError("Bind address must not be empty.")

    if value.startswith("["):
        end_bracket = value.find("]")
        if end_bracket == -1 or end_bracket + 2 > len(value) or value[end_bracket + 1] != ":":
            raise ValueError(f"Invalid IPv6 bind address: {bind!r}")
        host = value[1:end_bracket]
        port_str = value[end_bracket + 2 :]
    else:
        if value.count(":") != 1:
            raise ValueError(f"Bind address must be HOST:PORT, got {bind!r}")
        host, _, port_str = value.partition(":")

    if not host or not port_str.isdigit():
        raise ValueError(f"Invalid host or port in bind address: {bind!r}")

    port = int(port_str)
    if port < 0 or port > 65535:
        raise ValueError(f"Port out of range (0-65535): {port}")
    return host, port


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="hermetic_pkgindex",
        description="Serve a frozen PyPI Simple Repository (PEP 503 / PEP 691) offline.",
    )
    parser.add_argument(
        "--store",
        required=True,
        help="Path to the frozen store root directory.",
    )
    parser.add_argument(
        "--bind",
        required=True,
        help="Bind address in HOST:PORT format (e.g. 127.0.0.1:8080).",
    )
    parser.add_argument(
        "--misses",
        required=True,
        help="Path to the JSON-lines miss log file.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the hermetic_pkgindex server until interrupted."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    parser = build_arg_parser()
    try:
        args = parser.parse_args(argv)
        host, port = parse_bind_address(args.bind)
        store = FrozenStore(args.store)
        miss_log = MissLog(args.misses)
        server = HermeticHTTPServer((host, port), store=store, miss_log=miss_log)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        return code
    except (ValueError, OSError, PkgIndexError) as exc:
        logging.getLogger("hermetic_pkgindex").error("Startup failed: %s", exc)
        return 2

    stop_event = threading.Event()

    def _signal_handler(signum: int, _frame: object) -> None:
        stop_event.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

    actual_host, actual_port = server.server_address[:2]
    logging.getLogger("hermetic_pkgindex").info(
        "Serving %s on http://%s:%d (misses -> %s)",
        store.root,
        actual_host,
        actual_port,
        miss_log.path,
    )

    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


