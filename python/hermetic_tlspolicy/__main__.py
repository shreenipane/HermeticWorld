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
    parse_cli_int,
)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _SafeArgumentParser(
        prog="hermetic_tlspolicy",
        description="NetVM TLS leaf window and hostname/method policy.",
        add_help=False,
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    win_parser = subparsers.add_parser("window", add_help=False, allow_abbrev=False)
    win_parser.add_argument("--t-clock", required=True)

    dec_parser = subparsers.add_parser("decide", add_help=False, allow_abbrev=False)
    dec_parser.add_argument("--hosts", required=True)
    dec_parser.add_argument("--port", required=True)
    dec_parser.add_argument("--sni", default=None)
    dec_parser.add_argument("--host", default=None)
    dec_parser.add_argument("--tls", action="store_true")
    dec_parser.add_argument("--ech", action="store_true")

    meth_parser = subparsers.add_parser("method", add_help=False, allow_abbrev=False)
    meth_parser.add_argument("--method", required=True)

    try:
        args = parser.parse_args(argv)
        if args.command == "window":
            payload = leaf_window_rfc3339(parse_cli_int(args.t_clock))
        elif args.command == "decide":
            decision = decide_from_file(
                hosts_path=args.hosts,
                sni=args.sni,
                host_header=args.host,
                port=parse_cli_int(args.port),
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
        # ASCII-only output: argv may carry undecodable bytes that cannot be written as UTF-8.
        out = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except HermeticTlsPolicyError as exc:
        sys.stderr.write(f"error [{exc.code}]: {exc.message}\n")
        return 1
    except ValueError:
        sys.stderr.write("error [CLI_ARGUMENT_ERROR]: invalid command-line arguments\n")
        return 1
    except Exception:
        sys.stderr.write("error [INTERNAL_ERROR]: unexpected failure\n")
        return 1

    sys.stdout.write(out + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
