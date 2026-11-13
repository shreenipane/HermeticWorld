
import argparse

import sys

from typing import List, Optional



from hermetic_yank.simple_index import YankError, run_yank_rewrite_from_paths





def main(argv: Optional[List[str]] = None) -> int:

    parser = argparse.ArgumentParser(prog="hermetic_yank", add_help=False)

    parser.add_argument("--page", required=True)

    parser.add_argument("--yanks", required=True)

    parser.add_argument("--cutoff", required=True)

    parser.add_argument("--out", required=True)

    parser.add_argument("--report", required=True)



    try:

        args = parser.parse_args(argv)

    except SystemExit:

        sys.stderr.write("error: invalid command-line arguments\n")

        return 1



    try:

        run_yank_rewrite_from_paths(

            page_path=args.page,

            yanks_path=args.yanks,

            cutoff=args.cutoff,

            out_path=args.out,

            report_path=args.report,

        )

    except YankError as exc:

        sys.stderr.write(f"error: {exc}\n")

        return 1



    return 0





if __name__ == "__main__":

    sys.exit(main())

