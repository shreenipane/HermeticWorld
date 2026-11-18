#!/usr/bin/env bash
# Integration differential smoke test (needs KVM and dev-unjailed GraderVM runner).
# Usage: scripts/integration/grader-differential-smoke.sh [WORK_DIR]
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"

smoke_main() {
WORK="${HERMETIC_SMOKE_WORK:?}"
U="${HOME:?}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$U/hermetic/cargo-target/$(basename "$top")}"

FC="${HERMETIC_FC_BIN:-$U/.hermetic/tools/firecracker-1.18.0/firecracker}"
KERNEL="${HERMETIC_KERNEL:-$U/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}"

[ -e "$FC" ] && FC="$(readlink -f "$FC")" || true
[ -e "$KERNEL" ] && KERNEL="$(readlink -f "$KERNEL")" || true
export HERMETIC_FC_BIN="$FC"
export HERMETIC_KERNEL="$KERNEL"

if [ -n "${HERMETIC_FIRECRACKER_LOCK:-}" ]; then
  FC_LOCK="$HERMETIC_FIRECRACKER_LOCK"
  [ -e "$FC_LOCK" ] && FC_LOCK="$(readlink -f "$FC_LOCK")" || true
  export HERMETIC_FIRECRACKER_LOCK="$FC_LOCK"
fi

RUNNER="$(readlink -f "$top/scripts/integration/grader-vm-runner.sh")"
export HERMETIC_DIFFERENTIAL_VM_RUNNER="$RUNNER"

echo "=== Running differential VM test (gold patch -> resolved) ==="
export HERMETIC_DIFFERENTIAL_VM_EXPECT="resolved"
python3 -m pytest -v python/tests/test_mutants_differential_vm.py

echo "=== Running differential VM test (empty patch -> unresolved) ==="
export HERMETIC_DIFFERENTIAL_VM_EXPECT="unresolved"
python3 -m pytest -v python/tests/test_mutants_differential_vm.py

echo "grader differential smoke: ok"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/grader-differential-smoke.sh" "$@"
fi
