#!/usr/bin/env bash
# Run the Python test suite under Linux (WSL), where Docker is available.
# From Windows:  wsl -d Ubuntu -- bash "/mnt/c/<path to repo>/scripts/test-linux.sh" [pytest args]
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" PYTHONDONTWRITEBYTECODE=1
cd "$(dirname "$0")/.."
exec uv run --no-project --with pytest python -m pytest python/tests -q -p no:cacheprovider "$@"
