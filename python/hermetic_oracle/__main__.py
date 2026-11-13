
import argparse

import json

import sys

from typing import List, Optional



from hermetic_oracle.analyse import OracleError, run_oracle_from_paths





def main(argv: Optional[List[str]] = None) -> int:

    parser = argparse.ArgumentParser(prog="hermetic_oracle", add_help=False)

    parser.add_argument("--runs", nargs=6, required=True)

    parser.add_argument("--f2p", required=True)

    parser.add_argument("--p2p", required=True)



    try:

        args = parser.parse_args(argv)

    except SystemExit:

        sys.stderr.write("error: invalid command-line arguments\n")

        return 1



    try:

        report = run_oracle_from_paths(

            run_paths=list(args.runs),

            f2p_path=args.f2p,

            p2p_path=args.p2p,

        )

    except OracleError as exc:

        sys.stderr.write(f"error: {exc}\n")

        return 1



    sys.stdout.write(

        json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"

    )

    if report["result"] == "valid":

        return 0

    return 2





if __name__ == "__main__":

    sys.exit(main())

