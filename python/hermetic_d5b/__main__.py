
import argparse

import json

import sys

from typing import List, Optional



from hermetic_d5b.check import run_check_from_paths

from hermetic_d5b.model import D5bError





def main(argv: Optional[List[str]] = None) -> int:

    parser = argparse.ArgumentParser(prog="hermetic_d5b", add_help=False)

    parser.add_argument("--inventory", required=True)

    parser.add_argument("--metadata", required=True)

    parser.add_argument("--cutoff", required=True)

    parser.add_argument("--mode", required=True)

    parser.add_argument("--exemptions", required=False, default=None)



    try:

        args = parser.parse_args(argv)

    except SystemExit:

        sys.stderr.write("error: invalid command-line arguments\n")

        return 1



    try:

        report = run_check_from_paths(

            inventory_path=args.inventory,

            metadata_path=args.metadata,

            cutoff=args.cutoff,

            mode=args.mode,

            exemptions_path=args.exemptions,

        )

    except D5bError as exc:

        sys.stderr.write(f"error: {exc}\n")

        return 1



    output = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    sys.stdout.write(output + "\n")

    if report["result"] == "gate":

        return 2

    return 0





if __name__ == "__main__":

    sys.exit(main())

