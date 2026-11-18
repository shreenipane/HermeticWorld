#!/usr/bin/env bash
# Development escape smoke test: build an execd rootfs with hermetic-escapeprobe
# (D4-checked), boot it with Firecracker through hermetic-vmm's dev-unjailed runner
# (no jailer), run the full guest root escape probe, and aggregate on the host.
# Usage: scripts/integration/escape-smoke.sh [WORK_DIR]   (run from the worktree root)
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
smoke_main() {
WORK="${HERMETIC_SMOKE_WORK:?}"
U="${HOME:?}"
KERNEL="${HERMETIC_KERNEL:-$U/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}"
FC="${HERMETIC_FC_BIN:?set measured patched Firecracker binary}"
: "${HERMETIC_FIRECRACKER_LOCK:?set measured patched Firecracker build lock}"

# Resolve symlinked paths with readlink -f
KERNEL="$(readlink -f "$KERNEL")"
FC="$(readlink -f "$FC")"
HERMETIC_FIRECRACKER_LOCK="$(readlink -f "$HERMETIC_FIRECRACKER_LOCK")"

export CARGO_TARGET_DIR="$U/hermetic/cargo-target/$(basename "$top")"
T=1700000000

# 1. Static execd, sealcheck, escapeprobe, rootfs tree, image with D4.
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q \
  -p hermetic-sealcheck -p hermetic-clockprobe -p hermetic-escapeprobe --target x86_64-unknown-linux-gnu
bash scripts/build-trusted-execd.sh
BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
umask 022
install -m 0700 "$BIN/hermetic-sealcheck" "$WORK/sealcheck"
TREE="$WORK/tree"; rm -rf "$TREE"
for d in sbin bin dev proc sys dev/pts dev/shm tmp run etc/hermetic work \
         mnt/hermetic-overlay mnt/hermetic-root; do mkdir -p "$TREE/$d"; done
install -m 0755 "$BIN/hermetic-execd" "$TREE/sbin/hermetic-execd"
install -m 0755 "$BIN/hermetic-escapeprobe" "$TREE/sbin/hermetic-escapeprobe"
install -m 0755 "$BIN/hermetic-init" "$TREE/sbin/hermetic-init"
install -m 0755 /usr/bin/busybox "$TREE/bin/busybox"
cat > "$TREE/etc/hermetic/run-spec.json" <<JSON
{"env":{"PATH":"/bin","LANG":"C"},"workdir":"/work","uid":0,"gid":0,
 "entrypoint":[],"command":[],"hostname":"world","resolv_conf":"nameserver 10.0.0.1\n",
 "resources":{"vcpus":1,"memory_mib":256,"disk_mib":64,"wall_time_s":180}}
JSON
find "$TREE" -exec touch -h -d @$T {} +
/usr/bin/python3 -I - "$top/python" "$TREE" "$WORK/rootfs.img" "$WORK/sealcheck" "$WORK" <<'PY'
import sys, json
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hermetic_slice.rootfs import build_rootfs
r = build_rootfs(Path(sys.argv[2]), Path(sys.argv[3]),
    t_clock=datetime.fromtimestamp(1700000000, timezone.utc), world_id="escape-smoke",
    sealcheck_bin=Path(sys.argv[4]), work_dir=Path(sys.argv[5]))
print(json.dumps({k: r[k] for k in ("image", "sha256", "d4")}))
PY
chmod 0400 "$WORK/rootfs.img"
echo "$WORK/rootfs.img" | grep -q . && ls -l "$WORK/rootfs.img"

# 2. Boot via dev-unjailed runner and run guest escape probe test
HERMETIC_ESCAPE_AGGREGATOR="$BIN/hermetic-escapeprobe" \
HERMETIC_FC_BIN="$FC" \
HERMETIC_FIRECRACKER_LOCK="$HERMETIC_FIRECRACKER_LOCK" \
HERMETIC_KERNEL="$KERNEL" \
HERMETIC_ROOTFS="$WORK/rootfs.img" \
  "$U/.hermetic/bin/rust-gate" --exclude hermetic-common --exclude hermetic-gateway \
  --exclude hermetic-sealcheck --exclude hermetic-trust --exclude hermetic-world-server \
  --exclude tiny_http --features dev-unjailed --test guest runs_guest_escape_probe \
  -- --ignored --nocapture
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/escape-smoke.sh" "$@"
fi
