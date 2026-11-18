#!/usr/bin/env bash
# Development Harbor backend smoke test (offline, KVM, nested VM).
# Runs a Harbor separate-verifier task through the sealed Hermetic World:
#   1. Agent produces artifact (calc.py) inside the sealed environment
#   2. ExtractorVM extracts only declared artifacts (calc.py) under safe I/O
#   3. GraderVM runs the separate verifier under supervisor isolation
#   4. Checks Harbor reward outputs: gold artifact -> reward 1.0, empty -> reward 0.0.
#
# Usage: scripts/integration/harbor-smoke.sh [WORK_DIR]  (from worktree root)
set -euo pipefail

top="$(git rev-parse --show-toplevel)"
cd "$top"

smoke_main() {
  WORK="${HERMETIC_SMOKE_WORK:?}"
  U="${HOME:?}"

  # Resolve symlinked paths with readlink -f per task requirements
  hermetic_home="${HERMETIC_HOME:-$(readlink -f "$U/.hermetic")}"

  if [ -n "${HERMETIC_FC_BIN:-}" ]; then
    FC="$(readlink -f "$HERMETIC_FC_BIN")"
  else
    FC="$(readlink -f "$hermetic_home/tools/firecracker-1.18.0/firecracker")"
  fi

  if [ -n "${HERMETIC_FIRECRACKER_LOCK:-}" ]; then
    FC_LOCK="$(readlink -f "$HERMETIC_FIRECRACKER_LOCK")"
  else
    FC_LOCK="$(readlink -f "$hermetic_home/fcbuild/firecracker-1.18.0.lock")"
  fi

  if [ -n "${HERMETIC_KERNEL:-}" ]; then
    KERNEL="$(readlink -f "$HERMETIC_KERNEL")"
  else
    KERNEL="$(readlink -f "$hermetic_home/cache/kernel-out-20261113-6.6b/vmlinux")"
  fi

  export HERMETIC_FC_BIN="$FC"
  export HERMETIC_FIRECRACKER_LOCK="$FC_LOCK"
  export HERMETIC_KERNEL="$KERNEL"

  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$U/hermetic/cargo-target/$(basename "$top")}"
  VENV="${HERMETIC_VENV:-$U/Heavy Coding/Projects/Hermetic World/python/.venv}"
  FIX="$top/scripts/integration/fixtures/grader-task"
  T=1700000000

  umask 022

  # 1. Build required host/guest binaries
  cargo build --release -q -p hermetic-extract -p hermetic-grader-supervisor -p hermetic-grader-result
  BIN="$CARGO_TARGET_DIR/release"

  # 2. Setup separate test directories for gold and empty runs
  for variant in gold empty; do
    D="$WORK/$variant"
    mkdir -m 0700 "$D" "$D/agent" "$D/verifier" "$D/logs"

    # Task configuration with separate verifier and declared artifact
    cat > "$D/task.toml" <<TOML
schema_version = "1.4"

[task]
name = "harbor-smoke-$variant"
artifacts = ["calc.py"]

[verifier]
environment_mode = "separate"
test_command = "python3 -m pytest -q tests/test_calc.py"
timeout_sec = 60
TOML

    # Prepare agent workspace
    cp "$FIX/repo/calc.py" "$D/agent/calc.py"
    if [ "$variant" = "gold" ]; then
      (cd "$D/agent" && patch -s -p1 < "$FIX/gold.patch" || true)
    fi

    # Prepare clean verifier sandbox (containing tests, but clean base calc.py)
    mkdir -p "$D/verifier/tests"
    cp "$FIX/repo/tests/test_calc.py" "$D/verifier/tests/"

    # Execute Harbor verification through the sealed backend bridge
    /usr/bin/python3 -I - "$top/python" "$D/task.toml" "$D/agent" "$D/verifier" "$D/logs" "$T" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])

from hermetic_harbor.task import load_task_config
from hermetic_harbor.verifier import run_harbor_verification

task_toml = Path(sys.argv[2])
agent_dir = Path(sys.argv[3])
verifier_dir = Path(sys.argv[4])
logs_dir = Path(sys.argv[5])
t_clock = int(sys.argv[6])

cfg = load_task_config(task_toml)
result = run_harbor_verification(
    task_config=cfg,
    agent_work_dir=agent_dir,
    verifier_tree_dir=verifier_dir,
    logs_dir=logs_dir,
    t_clock=t_clock,
)
print(f"status={result.status} reward={result.reward} extracted={result.extracted_artifacts}")
PY

    # Check reward.txt output
    REWARD_FILE="$D/logs/verifier/reward.txt"
    if [ ! -f "$REWARD_FILE" ]; then
      echo "harbor smoke FAILED: $variant missing reward.txt" >&2
      exit 1
    fi

    REWARD="$(tr -d '[:space:]' < "$REWARD_FILE")"
    if [ "$variant" = "gold" ]; then
      if [ "$REWARD" != "1.0" ]; then
        echo "harbor smoke FAILED: gold expected reward 1.0, got $REWARD" >&2
        exit 1
      fi
    else
      if [ "$REWARD" != "0.0" ]; then
        echo "harbor smoke FAILED: empty expected reward 0.0, got $REWARD" >&2
        exit 1
      fi
    fi
  done

  echo "harbor smoke: ok (separate verifier: gold artifact reward 1.0, empty artifact reward 0.0)"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/harbor-smoke.sh" "$@"
fi
