#!/usr/bin/env bash
# Usage: convert-agent-h-task.sh SEALED_RUN INSTANCE FRESH_DIR
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
exec /usr/bin/python3 -I -B "$top/scripts/integration/agent_h_image.py" sealed "$@"
