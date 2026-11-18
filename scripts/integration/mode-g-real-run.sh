#!/usr/bin/env bash
# Mode G Real Run Driver (TR-GW-1..9, TR-NET-3, TR-CLI)
#
# Drives a real Mode G task with an autonomous agent against a configured model upstream.
# The upstream URL, model ID, and API key file path are configured strictly at runtime.
# The API key file must exist on the host, be a regular file with mode 0600,
# and is never read or echoed by this script, nor copied into any VM, image, log or record.
set -euo pipefail

top="$(git rev-parse --show-toplevel)"
cd "$top"

# 1. Enforce required runtime upstream configuration
if [ -z "${HERMETIC_UPSTREAM_URL:-}" ]; then
  echo "error: HERMETIC_UPSTREAM_URL is required (e.g. https://integrate.api.nvidia.com/v1)" >&2
  exit 1
fi

if [ -z "${HERMETIC_UPSTREAM_MODEL:-}" ]; then
  echo "error: HERMETIC_UPSTREAM_MODEL is required (e.g. a gpt-oss model id)" >&2
  exit 1
fi

if [ -z "${HERMETIC_UPSTREAM_KEY_FILE:-}" ]; then
  echo "error: HERMETIC_UPSTREAM_KEY_FILE is required" >&2
  exit 1
fi

# 2. Strict validation of key file (host only, mode 0600, regular file, no symlinks)
KEY_FILE="$HERMETIC_UPSTREAM_KEY_FILE"
if [ -L "$KEY_FILE" ]; then
  echo "error: HERMETIC_UPSTREAM_KEY_FILE must not be a symlink: $KEY_FILE" >&2
  exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
  echo "error: HERMETIC_UPSTREAM_KEY_FILE does not exist or is not a regular file: $KEY_FILE" >&2
  exit 1
fi

KEY_PERMS="$(stat -c %a "$KEY_FILE" 2>/dev/null || stat -f %Lp "$KEY_FILE" 2>/dev/null)"
if [ "$KEY_PERMS" != "600" ]; then
  echo "error: HERMETIC_UPSTREAM_KEY_FILE must have mode 0600 (got 0$KEY_PERMS)" >&2
  exit 1
fi

# 3. Resolve required Firecracker VMM artifacts
FC="$(readlink -f "${HERMETIC_FC_BIN:?set HERMETIC_FC_BIN}")"
FC_LOCK="$(readlink -f "${HERMETIC_FIRECRACKER_LOCK:?set HERMETIC_FIRECRACKER_LOCK}")"
KERNEL="$(readlink -f "${HERMETIC_KERNEL:?set HERMETIC_KERNEL}")"

export HERMETIC_FC_BIN="$FC"
export HERMETIC_FIRECRACKER_LOCK="$FC_LOCK"
export HERMETIC_KERNEL="$KERNEL"

if [ -n "${HERMETIC_ROOTFS:-}" ]; then
  export HERMETIC_ROOTFS="$(readlink -f "$HERMETIC_ROOTFS")"
fi

# 4. Build release CLI
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$top/.review/cargo-target}"
export CARGO_TARGET_DIR
cargo build --release -q -p hermetic-cli
CLI="$CARGO_TARGET_DIR/release/hermetic"

# 5. World and task arguments
WORLD="${1:-${HERMETIC_WORLD:-$top/scripts/integration/fixtures/grader-task/repo}}"
TASK_ID="${2:-${HERMETIC_TASK:-fixture-task}}"
RUN_DIR="${HERMETIC_RUN_DIR:-$top/.review/mode-g-real-run}"
mkdir -m 0700 -p "$RUN_DIR"

echo "mode-g-real-run: running Mode G with upstream: $HERMETIC_UPSTREAM_URL model: $HERMETIC_UPSTREAM_MODEL"

# 6. Execute hermetic run in Mode G
"$CLI" run \
  --world "$WORLD" \
  --task "$TASK_ID" \
  --mode g \
  --run-dir "$RUN_DIR" \
  --model "$HERMETIC_UPSTREAM_MODEL" \
  --upstream-url "$HERMETIC_UPSTREAM_URL" \
  --upstream-key-file "$KEY_FILE"

echo "mode-g-real-run: ok (verdict in $RUN_DIR/verdict.json)"
