#!/usr/bin/env bash
# Runner command implementing the CommandRunner contract around grader-vm-smoke.sh.
# Usage: grader-vm-runner.sh RUN_ID TEST_FILE OUT_DISK
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
exec bash "$top/scripts/integration/grader-vm-smoke.sh" "$@"

