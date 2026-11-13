#!/usr/bin/env bash
# Integration build script for the guest kernel.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <tarball-path> <output-directory>" >&2
  exit 1
fi

# All validation and output writes use the same no-follow descriptor helpers as
# kernel-build. The pinned debian base and hermetic/kernel-builder:6.1-v1 tag
# are defined there; build-record.json is printed only after a verified build.
# BASE_IMAGE=debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC \
  /usr/bin/python3 -I -B - "$1" "$2" <<'PYTHON'
from pathlib import Path
import sys
sys.path.insert(0, str(Path('python').absolute()))
from hermetic_slice.guest_kernel import KernelError, integration_build

try:
    sys.stdout.buffer.write(integration_build(Path(sys.argv[1]), Path(sys.argv[2])))
except (KernelError, OSError, ValueError):
    raise SystemExit("kernel integration build failed; see kernel-build.stderr.log") from None
PYTHON
