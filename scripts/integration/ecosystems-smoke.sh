#!/usr/bin/env bash
# Development two-VM ecosystems smoke test (no jailer): NetVM with hermetic-netvm as
# PID 1 on tap hwtap-net, AgentVM with execd as PID 1 on tap hwtap-agent (both on
# bridge hwbr0, which has no IP and no forwarding), and a host WorldServer serving
# npm, crates.io, and Go modules over NetVM vsock port 5001.
# Usage: scripts/integration/ecosystems-smoke.sh [WORK_DIR]   (run from the worktree root)
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
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$top/target/ecosystems-smoke}"
T=1700000000
FIX="$top/scripts/integration/net-fixture"

for tap in hwtap-agent hwtap-net; do
  [ -e "/sys/class/net/$tap" ] || { echo "missing host tap $tap (see BOOT_NOTES.md)" >&2; exit 2; }
done

# 1. Static guest binaries, sealcheck and the host WorldServer.
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q --target x86_64-unknown-linux-gnu \
  -p hermetic-execd -p hermetic-sealcheck -p hermetic-netvm-core
cargo build --release -q -p hermetic-world-server
cargo build --release -q -p hermetic-netvm-core --example netvm_tls_fixture
BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
umask 022
install -m 0700 "$BIN/hermetic-sealcheck" "$WORK/sealcheck"
install -m 0700 "$CARGO_TARGET_DIR/release/hermetic-world-server" "$WORK/world-server"

# 2. Fixture world store with npm, crates, Go modules.
rm -rf "$WORK/store" "$WORK/world-log"
mkdir -m 0700 "$WORK/store" "$WORK/world-log"
cp -r "$FIX/store/"* "$WORK/store/" 2>/dev/null || true
find "$WORK/store" -type d -exec chmod 0700 {} +; find "$WORK/store" -type f -exec chmod 0600 {} +

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

"$CARGO_TARGET_DIR/release/examples/netvm_tls_fixture" "$WORK" "$TREE" "$FIX/dns.json"
install -m 0444 "$WORK/ca.der" "$TREE/etc/hermetic/ca.der"
find "$TREE" -exec touch -h -d @$T {} +

# 4. Images (D4-checked ext4).
rm -f "$WORK/agent.img" "$WORK/netvm.img"
/usr/bin/python3 -I - "$top/python" "$WORK" "$BIN/hermetic-netvm" "$FIX/dns.json" <<'PY'
import sys, json
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hermetic_slice.rootfs import build_rootfs
from hermetic_slice.netvm import build_netvm_image
work = Path(sys.argv[2]); t = datetime.fromtimestamp(1700000000, timezone.utc)
a = build_rootfs(work / "agent-tree", work / "agent.img", t_clock=t, world_id="ecosystems-smoke-agent",
                 sealcheck_bin=work / "sealcheck", work_dir=work)
n = build_netvm_image(work / "netvm-tree", work / "netvm.img", netvm_bin=Path(sys.argv[3]),
                      busybox_bin=Path("/usr/bin/busybox"), dns_table=Path(sys.argv[4]), t_clock=t,
                      world_id="ecosystems-smoke-netvm", tls_identity=json.loads((work / "tls-identity.json").read_text()),
                      sealcheck_bin=work / "sealcheck", work_dir=work)
for r in (a, n):
    print(json.dumps({k: r[k] for k in ("image", "sha256", "d4")}))
PY
chmod 0400 "$WORK/agent.img" "$WORK/netvm.img"

# 5. Boot both VMs and run the ecosystems test suite (owner-run ignored test).
umask 077
if \
HERMETIC_FC_BIN="$FC" HERMETIC_KERNEL="$KERNEL" HERMETIC_ROOTFS="$WORK/agent.img" \
HERMETIC_NETVM_ROOTFS="$WORK/netvm.img" HERMETIC_WORLD_SERVER_BIN="$WORK/world-server" \
HERMETIC_WORLD_STORE="$WORK/store" HERMETIC_NET_WORK="$WORK" \
  cargo test -p hermetic-vmm --features dev-unjailed --test ecosystems_guest \
  ecosystems_guest_vm_installs_packages_over_netvm -- --ignored --nocapture \
  >"$WORK/ecosystems-smoke-test.log" 2>&1; then
  cat "$WORK/ecosystems-smoke-test.log"
else
  result=$?
  cat "$WORK/ecosystems-smoke-test.log" >&2
  echo "Ecosystems smoke failed; test log retained in $WORK" >&2
  exit "$result"
fi
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
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/ecosystems-smoke.sh" "$@"
fi
