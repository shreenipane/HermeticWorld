"""Build a frozen offline mirror from a recipe and digest-named blob directory."""

import sys

from .cut import CutError
from .mirror import build_mirror_files


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: python -m hermetic_ecosystem_cut RECIPE BLOB_ROOT OUTPUT", file=sys.stderr)
        return 2
    try:
        recipe, blobs, output = sys.argv[1:]
        digest = build_mirror_files(recipe, blobs, output)
    except CutError:
        print("offline mirror build failed", file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
