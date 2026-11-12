"""CLI entry point for hermetic_tlspolicy."""

from __future__ import annotations

import argparse
import json
import sys

from .policy import (
    HermeticTlsPolicyError,
    decide_from_file,
    leaf_window_rfc3339,
    method_policy,
)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _SafeArgumentParser(
        prog="hermetic_tlspolicy",
        description="NetVM TLS leaf window and hostname/method policy.",
        add_help=False,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    win_parser = subparsers.add_parser("window", add_help=False)
    win_parser.add_argument("--t-clock", type=int, required=True)

    dec_parser = subparsers.add_parser("decide", add_help=False)
    dec_parser.add_argument("--hosts", required=True)
    dec_parser.add_argument("--port", type=int, required=True)
    dec_parser.add_argument("--sni", default=None)
    dec_parser.add_argument("--host", default=None)
    dec_parser.add_argument("--tls", action="store_true")
    dec_parser.add_argument("--ech", action="store_true")

    meth_parser = subparsers.add_parser("method", add_help=False)
    meth_parser.add_argument("--method", required=True)

    try:
        args = parser.parse_args(argv)
        if args.command == "window":
            payload = leaf_window_rfc3339(args.t_clock)
        elif args.command == "decide":
            decision = decide_from_file(
                hosts_path=args.hosts,
                sni=args.sni,
                host_header=args.host,
                port=args.port,
                is_tls=args.tls,
                has_ech=args.ech,
            )
            payload = decision.to_dict()
        elif args.command == "method":
            status = method_policy(args.method)
            payload = {
                "method": args.method,
                "status": status,
                "action": "forward" if status == 200 else "reject",
            }
        else:
            raise ValueError("unknown command")
    except HermeticTlsPolicyError as exc:
        sys.stderr.write(f"error [{exc.code}]: {exc.message}\n")
        return 1
    except ValueError:
        sys.stderr.write("error [CLI_ARGUMENT_ERROR]: invalid command-line arguments\n")
        return 1
    except Exception:
        sys.stderr.write("error [INTERNAL_ERROR]: unexpected failure\n")
        return 1

    out = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sys.stdout.write(out + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
