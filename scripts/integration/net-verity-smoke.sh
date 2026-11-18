#!/usr/bin/env bash
# NetVM dm-verity smoke test (run by manager in nested VM with KVM)
# Tests that NetVM boots with dm-verity read-only root and serves the world,
# and that a one-byte-modified data or hash image fails closed before or during boot.
# Takes: HERMETIC_FC_BIN, HERMETIC_FIRECRACKER_LOCK, HERMETIC_KERNEL
# Usage: scripts/integration/net-verity-smoke.sh [WORK_DIR]   (run from the worktree root)
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
smoke_main() {
WORK="${HERMETIC_SMOKE_WORK:?}"
U="${HOME:?}"
FC="${HERMETIC_FC_BIN:?set measured patched Firecracker binary}"
FC="$(readlink -f "$FC")"
LOCK="${HERMETIC_FIRECRACKER_LOCK:?set measured patched Firecracker build lock}"
LOCK="$(readlink -f "$LOCK")"
KERNEL="${HERMETIC_KERNEL:-$U/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}"
KERNEL="$(readlink -f "$KERNEL")"
export HERMETIC_FC_BIN="$FC"
export HERMETIC_FIRECRACKER_LOCK="$LOCK"
export HERMETIC_KERNEL="$KERNEL"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$top/target/net-verity-smoke}"
T=1700000000
FIX="$top/scripts/integration/net-fixture"

for tap in hwtap-agent hwtap-net; do
  [ -e "/sys/class/net/$tap" ] || { echo "missing host tap $tap (see BOOT_NOTES.md)" >&2; exit 2; }
done
# The runner verifies the measured build lock and held executable before launch.

echo "=== NetVM dm-verity smoke ==="
echo "Work dir: $WORK"
echo "Firecracker: $FC"
echo "Kernel: $KERNEL"
echo "Lock: $LOCK"

# 1. Static guest binaries, sealcheck and the host WorldServer.
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q --target x86_64-unknown-linux-gnu \
  -p hermetic-execd -p hermetic-sealcheck -p hermetic-netvm-core
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q --target x86_64-unknown-linux-gnu \
  -p hermetic-netvm-core --example netvm_fetch
cargo build --release -q -p hermetic-world-server
cargo build --release -q -p hermetic-netvm-core --example netvm_tls_fixture
BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
umask 022
install -m 0700 "$BIN/hermetic-sealcheck" "$WORK/sealcheck"
install -m 0700 "$CARGO_TARGET_DIR/release/hermetic-world-server" "$WORK/world-server"

# 2. Fixture world store, private copy (WorldServer wants owner-only directories).
rm -rf "$WORK/store" "$WORK/world-log"; cp -r "$FIX/store" "$WORK/store"
find "$WORK/store" -type d -exec chmod 0700 {} +; find "$WORK/store" -type f -exec chmod 0600 {} +
mkdir -m 0700 "$WORK/world-log"

# 3. AgentVM rootfs: execd configures eth0 and the resolver before readiness.
TREE="$WORK/agent-tree"; rm -rf "$TREE"
for d in sbin bin dev proc sys dev/pts dev/shm tmp run etc/hermetic work \
         mnt/hermetic-overlay mnt/hermetic-root; do mkdir -p "$TREE/$d"; done
install -m 0755 "$BIN/hermetic-execd" "$TREE/sbin/hermetic-execd"
install -m 0755 "$BIN/hermetic-init" "$TREE/sbin/hermetic-init"
install -m 0755 /usr/bin/busybox "$TREE/bin/busybox"
cat > "$TREE/etc/hermetic/run-spec.json" <<JSON
{"env":{"PATH":"/bin","LANG":"C"},"workdir":"/work","uid":0,"gid":0,
 "entrypoint":[],"command":[],"hostname":"world","resolv_conf":"nameserver 10.0.2.3\noptions ndots:0\n",
 "network":{"address":"10.0.2.15","prefix":32,"gateway":"10.0.2.3","mtu":1500},
 "resources":{"vcpus":1,"memory_mib":256,"disk_mib":64,"wall_time_s":60}}
JSON
install -m 0755 "$BIN/examples/netvm_fetch" "$TREE/bin/hermetic-https-fetch"
"$CARGO_TARGET_DIR/release/examples/netvm_tls_fixture" "$WORK" "$TREE" "$FIX/dns.json"
install -m 0444 "$WORK/ca.der" "$TREE/etc/hermetic/ca.der"
install -m 0444 "$WORK/unrelated.der" "$TREE/etc/hermetic/unrelated.der"
find "$TREE" -exec touch -h -d @$T {} +

# 4. Both images (D4-checked ext4; the NetVM image with dm-verity hash tree from hermetic_slice.netvm).
rm -f "$WORK/agent.img" "$WORK/netvm.img" "$WORK/netvm-verity.img"
/usr/bin/python3 -I - "$top/python" "$WORK" "$BIN/hermetic-netvm" "$FIX/dns.json" <<'PY'
import sys, json
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hermetic_slice.rootfs import build_rootfs
from hermetic_slice.netvm import build_netvm_image
work = Path(sys.argv[2]); t = datetime.fromtimestamp(1700000000, timezone.utc)
tls_id = json.loads((work / "tls-identity.json").read_text())
a = build_rootfs(work / "agent-tree", work / "agent.img", t_clock=t, world_id="net-smoke-agent",
                 sealcheck_bin=work / "sealcheck", work_dir=work)
n = build_netvm_image(work / "netvm-tree", work / "netvm.img", netvm_bin=Path(sys.argv[3]),
                      busybox_bin=Path("/usr/bin/busybox"), dns_table=Path(sys.argv[4]), t_clock=t,
                      world_id="net-smoke-netvm", tls_identity=tls_id, sealcheck_bin=work / "sealcheck", work_dir=work)
for r in (a, n):
    print(json.dumps({k: r[k] for k in ("image", "sha256", "d4")}))
(work / "netvm-verity.json").write_text(json.dumps(n["verity"]))
PY
chmod 0400 "$WORK/agent.img" "$WORK/netvm.img"
if [ -f "$WORK/netvm-verity.img" ]; then
  chmod 0400 "$WORK/netvm-verity.img"
fi

# 5. Offline verification test via cargo test verity
cargo test -p hermetic-vmm --test verity -- --nocapture

# 6. Outcome 1: NetVM boots from the verity image with the pinned root hash and serves the world.
umask 077
if \
HERMETIC_FC_BIN="$FC" HERMETIC_FIRECRACKER_LOCK="$LOCK" HERMETIC_KERNEL="$KERNEL" HERMETIC_ROOTFS="$WORK/agent.img" \
HERMETIC_NETVM_ROOTFS="$WORK/netvm.img" HERMETIC_NETVM_VERITY="$WORK/netvm-verity.img" \
HERMETIC_WORLD_SERVER_BIN="$WORK/world-server" \
HERMETIC_WORLD_STORE="$WORK/store" HERMETIC_NET_WORK="$WORK" \
  cargo test -p hermetic-vmm --features dev-unjailed --test net_guest \
  netvm_serves_world_to_agent_and_drops_everything_else -- --ignored --nocapture \
  >"$WORK/net-verity-smoke-serves-world.log" 2>&1; then
  cat "$WORK/net-verity-smoke-serves-world.log"
else
  result=$?
  cat "$WORK/net-verity-smoke-serves-world.log" >&2
  echo "Smoke failed: NetVM did not boot and serve the world from verity image; retained in $WORK" >&2
  exit "$result"
fi

# 7. Outcome 2: A one-byte-modified image fails to boot (or kernel/VMM refuses device) with a clear result.
if \
HERMETIC_FC_BIN="$FC" \
HERMETIC_FIRECRACKER_LOCK="$LOCK" \
HERMETIC_KERNEL="$KERNEL" \
HERMETIC_NETVM_ROOTFS="$WORK/netvm.img" \
HERMETIC_NETVM_VERITY="$WORK/netvm-verity.img" \
  cargo test -p hermetic-vmm --features dev-unjailed --test net_guest \
  netvm_boots_with_dm_verity_and_corrupt_images_fail -- --nocapture \
  >"$WORK/net-verity-smoke-corruption.log" 2>&1; then
  cat "$WORK/net-verity-smoke-corruption.log"
else
  result=$?
  cat "$WORK/net-verity-smoke-corruption.log" >&2
  echo "Smoke failed: corrupt verity image did not fail closed; retained in $WORK" >&2
  exit "$result"
fi

echo "=== NetVM dm-verity smoke passed ==="
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
# Check boot access before creating artifacts or starting any process.
/usr/bin/python3 -I - <<'CHECK'
import os
try:
    for path in ("/dev/kvm", "/dev/net/tun"):
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        os.close(fd)
except OSError:
    raise SystemExit("OPEN: cannot open /dev/kvm or /dev/net/tun; run on the prepared host")
CHECK
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/net-verity-smoke.sh" "$@"
fi
