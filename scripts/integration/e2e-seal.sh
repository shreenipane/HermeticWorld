#!/usr/bin/env bash
# Usage and host prerequisites: scripts/integration/E2E_SEAL.md.
set -euo pipefail
top="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
exec /usr/bin/python3 -I -B "$top/scripts/integration/e2e_seal.py" "$@"
