#!/usr/bin/env bash
# Offline owner-run development smoke. Requires a sealed fixture AgentVM image;
# see python/hermetic_agent/README.md for its contents and input manifest.
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
smoke_main() {
  WORK="${HERMETIC_SMOKE_WORK:?}"
  umask 022
  : "${HERMETIC_AGENT_MANIFEST:?set the fixture world manifest}"
  : "${HERMETIC_ROOTFS:?set the sealed fixture AgentVM image}"
  FC="$(readlink -f "${HERMETIC_FC_BIN:?set the pinned Firecracker executable}")"
  KERNEL="$(readlink -f "${HERMETIC_KERNEL:?set the pinned kernel image}")"
  LOCK="$(readlink -f "${HERMETIC_FIRECRACKER_LOCK:?set the pinned Firecracker build lock}")"
  PYTHON="$(readlink -f "${HERMETIC_AGENT_PYTHON:?set the interpreter with hermetic-agent[mini] installed}")"
  export HERMETIC_FC_BIN="$FC" HERMETIC_KERNEL="$KERNEL" HERMETIC_FIRECRACKER_LOCK="$LOCK" HERMETIC_AGENT_PYTHON="$PYTHON"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$top/.review/cargo-target}"
  export HERMETIC_AGENT_WORK="$WORK" HERMETIC_AGENT_TOP="$top"
  HERMETIC_AGENT_T_CLOCK="$(PYTHONPATH="$top/python" PYTHONDONTWRITEBYTECODE=1 "$HERMETIC_AGENT_PYTHON" -c \
    'import sys; from hermetic_agent.task import task_clock, clock_value; print(clock_value(task_clock(sys.argv[1])))' "$HERMETIC_AGENT_MANIFEST")"
  export HERMETIC_AGENT_T_CLOCK
  mkdir -m 0700 "$WORK/config" "$WORK/published"
  cargo build --release -q -p hermetic-extract
  timeout 400 cargo test -q -p hermetic-vmm --features dev-unjailed --test agent_h \
    boots_agent_runs_harness_and_collects_untrusted_extraction -- --ignored --exact --nocapture
  FIX="$top/scripts/integration/fixtures/grader-task"
  "$CARGO_TARGET_DIR/release/hermetic-extract-validate" --stream "$WORK/changes.hext" \
    --base "$FIX/repo" --out "$WORK/published/gold" --class patch --config "$FIX/extract-config.json" \
    > "$WORK/validate-report.json"
  cmp "$FIX/repo/tests/test_calc.py" "$WORK/published/gold/tests/test_calc.py"
  cp -r "$FIX/repo" "$WORK/published/empty"
  HERMETIC_GRADER_PUBLISHED_ROOT="$WORK/published" \
    bash scripts/integration/grader-vm-smoke.sh "$WORK/grader"
  echo "agent-h smoke: ok (remote patch, validated extraction, empty unresolved, patch resolved)"
}
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/agent-h-smoke.sh" "$@"
fi
