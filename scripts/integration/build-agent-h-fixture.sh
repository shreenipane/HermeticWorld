#!/usr/bin/env bash
# Build and retain the development fixture; the destination must be fresh.
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
exec /usr/bin/python3 -I -B "$top/scripts/integration/agent_h_image.py" fixture "$@"
