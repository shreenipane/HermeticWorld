#!/usr/bin/env bash
# Development state-task live grading and snapshot smoke test.
# Requires /dev/kvm, pinned Firecracker, guest kernel, and rootfs.
# Usage: scripts/integration/state-smoke.sh [WORK_DIR]  (run from the worktree root)
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
smoke_main() {
WORK="${HERMETIC_SMOKE_WORK:?}"
U="${HOME:?}"
KERNEL="${HERMETIC_KERNEL:-$U/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}"
FC="${HERMETIC_FC_BIN:?set measured patched Firecracker binary}"
LOCK="${HERMETIC_FIRECRACKER_LOCK:?set measured patched Firecracker build lock}"
if [ -e "$KERNEL" ] || [ -L "$KERNEL" ]; then KERNEL="$(readlink -f "$KERNEL")"; fi
if [ -e "$FC" ] || [ -L "$FC" ]; then FC="$(readlink -f "$FC")"; fi
if [ -e "$LOCK" ] || [ -L "$LOCK" ]; then LOCK="$(readlink -f "$LOCK")"; fi
export HERMETIC_KERNEL="$KERNEL"
export HERMETIC_FC_BIN="$FC"
export HERMETIC_FIRECRACKER_LOCK="$LOCK"
export CARGO_TARGET_DIR="$U/hermetic/cargo-target/$(basename "$top")"
umask 022

# 1. Build rootfs and static binaries via boot-smoke
(
  export HERMETIC_SMOKE_WORK="$WORK/first"
  mkdir -p "$HERMETIC_SMOKE_WORK"
  source scripts/integration/boot-smoke.sh
  smoke_main
)

# 2. Run guest snapshot restore and attached drive test
export HERMETIC_ROOTFS="$WORK/first/rootfs.img"
cargo test -p hermetic-vmm --features dev-unjailed --test guest \
  resumes_guest_snapshot_with_peerless_tap_and_attached_drive -- --exact --ignored --nocapture

echo "state smoke: ok (snapshot created, restored with peerless tap, tests drive attached)"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/state-smoke.sh" "$@"
fi
