#!/usr/bin/env bash
# Build and retain the development Mode G fixture; the destination must be fresh.
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
exec /usr/bin/python3 -I -B "$top/scripts/integration/agent_g_image.py" fixture "$@"
