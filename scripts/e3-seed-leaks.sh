#!/usr/bin/env bash
# Short wrapper script for Hermetic E3 blind leak seeding wizard.
set -euo pipefail

TOP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$TOP_DIR/python${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

exec python3 -m hermetic_e3.seed_leaks "$@"
