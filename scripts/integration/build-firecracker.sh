#!/usr/bin/env bash
# Source fetch and immutable builder preparation are separate, explicit steps.
set -euo pipefail
top="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export PYTHONPATH="$top/python" PYTHONDONTWRITEBYTECODE=1
exec /usr/bin/python3 -B -m hermetic_slice.firecracker_build "$@"
