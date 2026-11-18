#!/usr/bin/env bash
# Mode G development two-VM smoke test (no jailer): NetVM with hermetic-netvm
# as PID 1 on tap hwtap-net, AgentVM with execd as PID 1 on tap hwtap-agent, and
# hermetic-gateway forwarding model API calls over NetVM's vsock port 5002 to a fake
# upstream answering one model call.
# Usage: scripts/integration/agent-g-smoke.sh [WORK_DIR]   (run from the worktree root)
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"

smoke_main() {
  WORK="${HERMETIC_SMOKE_WORK:?}"
  U="${HOME:?}"
  KERNEL="${HERMETIC_KERNEL:-$U/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}"
  FC="${HERMETIC_FC_BIN:?set measured patched Firecracker binary}"
  FC_LOCK="${HERMETIC_FIRECRACKER_LOCK:?set measured patched Firecracker build lock}"

  # Resolve symlinked paths with readlink -f
  FC="$(readlink -f "$FC")"
  FC_LOCK="$(readlink -f "$FC_LOCK")"
  KERNEL="$(readlink -f "$KERNEL")"

  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$top/target/agent-g-smoke}"
  T=1700000000

  for tap in hwtap-agent hwtap-net; do
    [ -e "/sys/class/net/$tap" ] || { echo "missing host tap $tap (see BOOT_NOTES.md)" >&2; exit 2; }
  done

  # 1. Static guest binaries, sealcheck, helper tools and host hermetic-gateway.
  RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q --target x86_64-unknown-linux-gnu \
    -p hermetic-execd -p hermetic-sealcheck -p hermetic-netvm-core
  cargo build --release -q -p hermetic-gateway
  cargo build --release -q -p hermetic-netvm-core --example netvm_tls_fixture

  BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
  umask 022
  install -m 0700 "$BIN/hermetic-sealcheck" "$WORK/sealcheck"
  install -m 0700 "$CARGO_TARGET_DIR/release/hermetic-gateway" "$WORK/hermetic-gateway"

  # 2. AgentVM rootfs: execd configures eth0 and the resolver before readiness.
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

  # 3. Mode G DNS table with world host and model gateway host.
  cat > "$WORK/dns.json" <<JSON
{"records": [
  {"name": "files.example", "a": ["10.9.0.1"], "aaaa": []},
  {"name": "api.anthropic.com", "a": ["10.9.0.2"], "aaaa": []}
]}
JSON
  "$CARGO_TARGET_DIR/release/examples/netvm_tls_fixture" "$WORK" "$TREE" "$WORK/dns.json"
  install -m 0444 "$WORK/ca.der" "$TREE/etc/hermetic/ca.der"
  install -m 0444 "$WORK/unrelated.der" "$TREE/etc/hermetic/unrelated.der"
  find "$TREE" -exec touch -h -d @$T {} +

  # 4. Build AgentVM rootfs and NetVM rootfs with gateway routing config.
  rm -f "$WORK/agent.img" "$WORK/netvm.img"
  /usr/bin/python3 -I - "$top/python" "$WORK" "$BIN/hermetic-netvm" "$WORK/dns.json" <<'PY'
import sys, json
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hermetic_slice.rootfs import build_rootfs
from hermetic_slice.netvm import build_netvm_image
work = Path(sys.argv[2]); t = datetime.fromtimestamp(1700000000, timezone.utc)
a = build_rootfs(work / "agent-tree", work / "agent.img", t_clock=t, world_id="mode-g-agent",
                 sealcheck_bin=work / "sealcheck", work_dir=work)
n = build_netvm_image(work / "netvm-tree", work / "netvm.img", netvm_bin=Path(sys.argv[3]),
                      busybox_bin=Path("/usr/bin/busybox"), dns_table=Path(sys.argv[4]), t_clock=t,
                      world_id="mode-g-netvm",
                      tls_identity=json.loads((work / "tls-identity.json").read_text()),
                      gateway={"host": "api.anthropic.com", "port": 5002},
                      sealcheck_bin=work / "sealcheck", work_dir=work)
for r in (a, n):
    print(json.dumps({k: r[k] for k in ("image", "sha256", "d4")}))
PY
  chmod 0400 "$WORK/agent.img" "$WORK/netvm.img"

  # 5. Boot both VMs and run the Mode G model path assertions through execd.
  umask 077
  if \
  HERMETIC_FC_BIN="$FC" HERMETIC_KERNEL="$KERNEL" HERMETIC_ROOTFS="$WORK/agent.img" \
  HERMETIC_NETVM_ROOTFS="$WORK/netvm.img" HERMETIC_MODE_G_WORK="$WORK" \
  HERMETIC_GATEWAY_BIN="$WORK/hermetic-gateway" HERMETIC_FIRECRACKER_LOCK="$FC_LOCK" \
    cargo test -p hermetic-vmm --features dev-unjailed --test agent_g \
    netvm_forwards_agent_model_calls_to_gateway_and_signs_record -- --ignored --nocapture \
    >"$WORK/agent-g-smoke-test.log" 2>&1; then
    cat "$WORK/agent-g-smoke-test.log"
    echo "agent-g smoke: ok (model call forwarded to gateway, responses sanitized, gateway log head signed in run record)"
  else
    result=$?
    cat "$WORK/agent-g-smoke-test.log" >&2
    echo "Smoke failed; test log and diagnostics retained in $WORK" >&2
    exit "$result"
  fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
/usr/bin/python3 -I - <<'CHECK'
import os
try:
    for path in ("/dev/kvm", "/dev/net/tun"):
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        os.close(fd)
except OSError:
    raise SystemExit("OPEN: cannot open /dev/kvm or /dev/net/tun; run on the prepared host")
CHECK
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/agent-g-smoke.sh" "$@"
fi
