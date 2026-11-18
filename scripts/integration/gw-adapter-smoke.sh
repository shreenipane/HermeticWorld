#!/usr/bin/env bash
# Manager-run development smoke for gateway provider adapters in the nested VM.
# Usage from worktree root: bash scripts/integration/gw-adapter-smoke.sh [WORK_DIR]
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"

smoke_main() {
  WORK="${HERMETIC_SMOKE_WORK:?supply work directory}"
  U="${HOME:?}"

  FC_BIN="${HERMETIC_FC_BIN:?set measured patched Firecracker binary}"
  FC_LOCK="${HERMETIC_FIRECRACKER_LOCK:?set measured patched Firecracker build lock}"
  KERNEL="${HERMETIC_KERNEL:-$U/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}"

  # Resolve symlinked paths with readlink -f
  HERMETIC_FC_BIN="$(readlink -f "$FC_BIN")"
  HERMETIC_FIRECRACKER_LOCK="$(readlink -f "$FC_LOCK")"
  HERMETIC_KERNEL="$(readlink -f "$KERNEL")"
  export HERMETIC_FC_BIN HERMETIC_FIRECRACKER_LOCK HERMETIC_KERNEL

  [ -x "$HERMETIC_FC_BIN" ] || { echo "Firecracker binary not executable: $HERMETIC_FC_BIN" >&2; exit 2; }
  [ -f "$HERMETIC_FIRECRACKER_LOCK" ] || { echo "Firecracker lock file not found: $HERMETIC_FIRECRACKER_LOCK" >&2; exit 2; }
  [ -f "$HERMETIC_KERNEL" ] || { echo "Kernel image not found: $HERMETIC_KERNEL" >&2; exit 2; }

  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$top/target/gw-smoke}"
  mkdir -m 0700 -p "$WORK/logs" "$WORK/config"

  # 1. Build hermetic-gateway
  cargo build --release -q -p hermetic-gateway
  GW_BIN="$CARGO_TARGET_DIR/release/hermetic-gateway"
  [ -x "$GW_BIN" ] || GW_BIN="$top/target/release/hermetic-gateway"

  # 2. Run offline provider adapter tests
  cargo test -q -p hermetic-gateway --test test_openai_adapter

  echo "gw-adapter smoke: ok (openai adapter verified, paths resolved)"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  if [ "$#" -ge 1 ]; then
    WORK="$1"
    mkdir -m 0700 -p "$WORK"
    HERMETIC_SMOKE_WORK="$WORK" smoke_main
  else
    exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/gw-adapter-smoke.sh" "$@"
  fi
fi
