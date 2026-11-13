#!/usr/bin/env bash
# Development boot smoke test: build an execd rootfs (D4-checked), boot it with
# Firecracker through hermetic-vmm's dev-unjailed runner (no jailer), and query
# execd's status frame. Development only: no jailer, namespace or cgroup isolation.
# Usage: scripts/integration/boot-smoke.sh [WORK_DIR]   (run from the worktree root)
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
smoke_main() {
WORK="${HERMETIC_SMOKE_WORK:?}"
U="${HOME:?}"
KERNEL="${HERMETIC_KERNEL:-$U/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}"
FC_SRC="$U/.hermetic/tools/firecracker/release-v1.18.0-x86_64/firecracker-v1.18.0-x86_64"
FC_DIR="$U/.hermetic/tools/firecracker-1.18.0"
FC_SHA=b33f46cd6d88834cf6a4f8d184f08f219809c636236bffd286d233a60602a2ba
export CARGO_TARGET_DIR="$U/hermetic/cargo-target/$(basename "$top")"
T=1700000000

# 0. Pinned Firecracker (verified against vmm/firecracker.lock.json), basename 'firecracker'.
if [ ! -x "$FC_DIR/firecracker" ]; then
  echo "$FC_SHA  $FC_SRC" | sha256sum -c --quiet
  mkdir -p "$FC_DIR"; chmod 0755 "$FC_DIR"
  install -m 0755 "$FC_SRC" "$FC_DIR/firecracker"
fi
echo "$FC_SHA  $FC_DIR/firecracker" | sha256sum -c --quiet

# 1. Static execd + sealcheck, rootfs tree, image with D4.
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q \
  -p hermetic-sealcheck --target x86_64-unknown-linux-gnu
bash scripts/build-trusted-execd.sh
BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
umask 022
install -m 0700 "$BIN/hermetic-sealcheck" "$WORK/sealcheck"
TREE="$WORK/tree"; rm -rf "$TREE"
for d in sbin bin dev proc sys dev/pts dev/shm tmp run etc/hermetic work \
         mnt/hermetic-overlay mnt/hermetic-root; do mkdir -p "$TREE/$d"; done
install -m 0755 "$BIN/hermetic-execd" "$TREE/sbin/hermetic-execd"
install -m 0755 "$BIN/hermetic-init" "$TREE/sbin/hermetic-init"   # early read-only /proc, then exec execd
install -m 0755 /usr/bin/busybox "$TREE/bin/busybox"   # static; trivial command
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
    t_clock=datetime.fromtimestamp(1700000000, timezone.utc), world_id="boot-smoke",
    sealcheck_bin=Path(sys.argv[4]), work_dir=Path(sys.argv[5]))
print(json.dumps({k: r[k] for k in ("image", "sha256", "d4")}))
PY
chmod 0400 "$WORK/rootfs.img"
echo "$WORK/rootfs.img" | grep -q . && ls -l "$WORK/rootfs.img"

# 2+3. Boot via dev-unjailed runner (owner-run ignored test): kernel mounts the base
# read-only and devtmpfs, init=/sbin/hermetic-init mounts read-only /proc and execs
# execd, which sets the clock first. The test reads the status frame and runs one command.
HERMETIC_FC_BIN="$FC_DIR/firecracker" HERMETIC_KERNEL="$KERNEL" HERMETIC_ROOTFS="$WORK/rootfs.img" \
  "$U/.hermetic/bin/rust-gate" --exclude hermetic-common --exclude hermetic-gateway \
  --exclude hermetic-sealcheck --exclude hermetic-trust --exclude hermetic-world-server \
  --exclude tiny_http --features dev-unjailed --test guest boots_guest_and_reads_guest_clock \
  -- --ignored --nocapture

}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/boot-smoke.sh" "$@"
fi
