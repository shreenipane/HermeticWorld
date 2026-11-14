#!/usr/bin/env bash
# Owner-run development check; requires KVM and the pinned boot-smoke inputs.
# Usage from the worktree root: bash scripts/integration/reboot-smoke.sh /tmp/hermetic-reboot-smoke
# WORK must not exist; all smoke artifacts stay in that new private directory.
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
WORK="${1:?supply a new absolute work directory}"
if [ "$#" -ne 1 ] || [[ "$WORK" != /* ]]; then
  echo 'reboot smoke: invalid work directory' >&2
  exit 2
fi
/usr/bin/python3 -I - "$top/python" "$WORK" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[1])
from hermetic_safe_io import open_parent
try:
    directory, leaf = open_parent(sys.argv[2])
    try:
        os.mkdir(leaf, 0o700, dir_fd=directory)
    finally:
        os.close(directory)
except (OSError, ValueError):
    print('reboot smoke: work directory refused', file=sys.stderr)
    raise SystemExit(2)
PY
umask 077
export CARGO_TARGET_DIR="$HOME/hermetic/cargo-target/$(basename "$top")"
# Builds static inputs and a sealed base, and proves the first-boot path.
# The parent owns these artifacts until the touched-disk reboot finishes.
# Standalone boot-smoke's wrapper removes them immediately on success.
(
  export HERMETIC_SMOKE_WORK="$WORK/first"
  mkdir "$HERMETIC_SMOKE_WORK"
  source scripts/integration/boot-smoke.sh
  smoke_main
)
BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
PIN="$(/usr/bin/python3 -I - "$top/python" "$BIN" "$WORK/trusted.cpio" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from hermetic_slice.initramfs import build_initramfs
print(build_initramfs(sys.argv[2] + '/hermetic-execd', sys.argv[2] + '/hermetic-init', sys.argv[3], 1700000000))
PY
)"
export HERMETIC_FC_BIN="${HERMETIC_FC_BIN:-$HOME/.hermetic/tools/firecracker-1.18.0/firecracker}"
export HERMETIC_KERNEL="${HERMETIC_KERNEL:-$HOME/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}"
export HERMETIC_ROOTFS="$WORK/first/rootfs.img"
export HERMETIC_INITRD="$WORK/trusted.cpio" HERMETIC_INITRD_SHA256="$PIN"
export HERMETIC_REBOOT_RECORD_OUT="$WORK/reboot-record.json"
cargo test -p hermetic-vmm --features dev-unjailed --test guest \
  reboots_touched_disk_with_trusted_initramfs -- --exact --ignored --nocapture
