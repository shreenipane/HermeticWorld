#!/usr/bin/env bash
# Development runner without a jailer; only the prepared manager VM host may run it.
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
exec /usr/bin/python3 -I -B "$top/scripts/integration/agent_h_run.py" "$@"
