#!/usr/bin/env bash
# Snapshot restore and pause/resume smoke test under clock-hiding (offline, KVM, dev-unjailed).
# Verifies pause, snapshot creation, resume, snapshot load and clock invariance.
# Usage: scripts/integration/snapshot-smoke.sh [WORK_DIR]   (run from the worktree root)
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
T=1700000000
umask 022

# 1. Static execd + sealcheck, rootfs tree, image with D4.
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q \
  -p hermetic-sealcheck -p hermetic-clockprobe -p hermetic-escapeprobe --target x86_64-unknown-linux-gnu
bash scripts/build-trusted-execd.sh
BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
install -m 0700 "$BIN/hermetic-sealcheck" "$WORK/sealcheck"
TREE="$WORK/tree"; rm -rf "$TREE"
for d in sbin bin dev proc sys dev/pts dev/shm tmp run etc/hermetic work \
         mnt/hermetic-overlay mnt/hermetic-root; do mkdir -p "$TREE/$d"; done
install -m 0755 "$BIN/hermetic-execd" "$TREE/sbin/hermetic-execd"
install -m 0755 "$BIN/hermetic-init" "$TREE/sbin/hermetic-init"
install -m 0755 /usr/bin/busybox "$TREE/bin/busybox"
cat > "$TREE/etc/hermetic/run-spec.json" <<JSON
{"env":{"PATH":"/bin","LANG":"C"},"workdir":"/work","uid":0,"gid":0,
 "entrypoint":[],"command":[],"hostname":"world","resolv_conf":"nameserver 10.0.0.1\n",
 "resources":{"vcpus":1,"memory_mib":256,"disk_mib":64,"wall_time_s":60}}
JSON
find "$TREE" -exec touch -h -d @$T {} +
/usr/bin/python3 -I - "$top/python" "$TREE" "$WORK/rootfs.img" "$WORK/sealcheck" "$WORK" <<'PY'
import sys, json
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hermetic_slice.rootfs import build_rootfs
r = build_rootfs(Path(sys.argv[2]), Path(sys.argv[3]),
    t_clock=datetime.fromtimestamp(1700000000, timezone.utc), world_id="snapshot-smoke",
    sealcheck_bin=Path(sys.argv[4]), work_dir=Path(sys.argv[5]))
print(json.dumps({k: r[k] for k in ("image", "sha256", "d4")}))
PY
chmod 0400 "$WORK/rootfs.img"

# 2. Boot, pause, snapshot, resume via dev-unjailed runner.
HERMETIC_FC_BIN="$FC" HERMETIC_FIRECRACKER_LOCK="$LOCK" HERMETIC_KERNEL="$KERNEL" HERMETIC_ROOTFS="$WORK/rootfs.img" \
  cargo test -p hermetic-vmm --features dev-unjailed --test guest pauses_resumes_and_snapshots_guest_under_clock_hiding \
  -- --exact --ignored --nocapture
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/snapshot-smoke.sh" "$@"
fi
