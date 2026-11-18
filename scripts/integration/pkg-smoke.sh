#!/usr/bin/env bash
# Development two-VM package mirrors smoke test (no jailer): NetVM with hermetic-netvm
# as PID 1 on tap hwtap-net, AgentVM with execd as PID 1 on tap hwtap-agent (both on
# bridge hwbr0, which has no IP and no forwarding), and a host WorldServer serving
# static package mirrors for PyPI, conda, Debian/Ubuntu and git over NetVM vsock port 5001.
# Usage: scripts/integration/pkg-smoke.sh [WORK_DIR]   (run from the worktree root)
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
smoke_main() {
WORK="${HERMETIC_SMOKE_WORK:?}"
U="${HOME:?}"
KERNEL="$(readlink -f "${HERMETIC_KERNEL:-$U/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}")"
FC="$(readlink -f "${HERMETIC_FC_BIN:?set measured patched Firecracker binary}")"
LOCK="$(readlink -f "${HERMETIC_FIRECRACKER_LOCK:?set measured patched Firecracker build lock}")"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$top/target/pkg-smoke}"
T=1700000000
FIX="$top/scripts/integration/net-fixture"

AGENT_TAP="${HERMETIC_AGENT_TAP:-hwtap-agent}"
NET_TAP="${HERMETIC_NET_TAP:-hwtap-net}"
for tap in "$AGENT_TAP" "$NET_TAP"; do
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

# 2. Fixture world store, private copy.
rm -rf "$WORK/store" "$WORK/world-log"; cp -r "$FIX/store" "$WORK/store"
find "$WORK/store" -type d -exec chmod 0700 {} +; find "$WORK/store" -type f -exec chmod 0600 {} +
mkdir -m 0700 "$WORK/world-log"

# Build static package mirrors (PyPI, conda, Debian/Ubuntu, git) via hermetic_ecosystem_cut.mirror
/usr/bin/python3 -I - "$top/python" "$WORK" <<'PY'
import hashlib, json, pathlib, sys
sys.path.insert(0, sys.argv[1])
from hermetic_ecosystem_cut.mirror import build_mirror_files

work = pathlib.Path(sys.argv[2])
blob_root = work / 'blobs'
blob_root.mkdir(mode=0o700, exist_ok=True)
encode = lambda v: json.dumps(v, sort_keys=True, separators=(',', ':')).encode('utf-8')
def blob(body):
    digest = hashlib.sha256(body).hexdigest()
    (blob_root / digest).write_bytes(body)
    return digest

body = b'offline package artifact\n'
digest = blob(body)
cutoff = '2023-04-01T00:00:00Z'
cutoff_ms = 1680307200000

packages = [
    {
        'ecosystem': 'pypi-simple',
        'name': 'pkg-demo',
        'metadata': blob(encode({
            'meta': {'api-version': '1.1'},
            'name': 'pkg-demo',
            'files': [
                {'filename': 'pkg_demo-1.0.0.tar.gz', 'hashes': {'sha256': digest}, 'size': len(body), 'upload-time': cutoff}
            ]
        })),
        'artifacts': {'pkg_demo-1.0.0.tar.gz': digest}
    },
    {
        'ecosystem': 'conda',
        'name': 'conda.anaconda.org/channel/linux-64',
        'metadata': blob(encode({
            'info': {'subdir': 'linux-64'},
            'repodata_version': 1,
            'packages': {
                'demo-1.0.0.tar.bz2': {'name': 'demo', 'version': '1.0.0', 'build': '0', 'timestamp': cutoff_ms, 'sha256': digest}
            },
            'packages.conda': {}
        })),
        'artifacts': {'demo-1.0.0.tar.bz2': digest}
    },
    {
        'ecosystem': 'apt',
        'name': 'snapshot.ubuntu.com/ubuntu/20230301T000000Z',
        'metadata': blob(encode({
            'dist': 'ubuntu',
            'suite': 'jammy',
            'snapshot_id': '20230301T000000Z',
            'files': {
                'dists/jammy/InRelease': {'sha256': digest, 'content_type': 'text/plain'},
                'pool/main/d/demo/demo_1.0.0_amd64.deb': {'sha256': digest, 'content_type': 'application/vnd.debian.binary-package'}
            }
        })),
        'artifacts': {
            'dists/jammy/InRelease': digest,
            'pool/main/d/demo/demo_1.0.0_amd64.deb': digest
        }
    },
    {
        'ecosystem': 'git',
        'name': 'github.com/example/demo.git',
        'metadata': blob(b'1111111111111111111111111111111111111111\trefs/heads/main\n'),
        'artifacts': {
            'HEAD': blob(b'ref: refs/heads/main\n'),
            'info/refs': blob(b'1111111111111111111111111111111111111111\trefs/heads/main\n'),
            'objects/info/packs': blob(b'P pack-1111111111111111111111111111111111111111.pack\n'),
            'objects/pack/pack-1111111111111111111111111111111111111111.pack': digest,
            'objects/pack/pack-1111111111111111111111111111111111111111.idx': digest,
        }
    }
]

recipe = work / 'recipe.json'
recipe.write_bytes(encode({'cutoff': cutoff, 'packages': packages}))
build_mirror_files(recipe, blob_root, work / 'pkg-world')
import shutil
for child in (work / 'pkg-world' / 'store').iterdir():
    dest = work / 'store' / child.name
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(child, dest)
PY
find "$WORK/store" -type d -exec chmod 0700 {} +; find "$WORK/store" -type f -exec chmod 0600 {} +

# 3. AgentVM rootfs
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
cat > "$WORK/dns.json" <<'JSON'
{"records": [
  {"name": "files.example", "a": ["10.9.0.1"], "aaaa": []},
  {"name": "pypi.org", "a": ["10.9.0.1"], "aaaa": []},
  {"name": "conda.anaconda.org", "a": ["10.9.0.1"], "aaaa": []},
  {"name": "snapshot.ubuntu.com", "a": ["10.9.0.1"], "aaaa": []},
  {"name": "snapshot.debian.org", "a": ["10.9.0.1"], "aaaa": []},
  {"name": "github.com", "a": ["10.9.0.1"], "aaaa": []}
]}
JSON
"$CARGO_TARGET_DIR/release/examples/netvm_tls_fixture" "$WORK" "$TREE" "$WORK/dns.json"
install -m 0444 "$WORK/ca.der" "$TREE/etc/hermetic/ca.der"
find "$TREE" -exec touch -h -d @$T {} +

# 4. Images
rm -f "$WORK/agent.img" "$WORK/netvm.img"
/usr/bin/python3 -I - "$top/python" "$WORK" "$BIN/hermetic-netvm" "$WORK/dns.json" <<'PY'
import sys, json
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hermetic_slice.rootfs import build_rootfs
from hermetic_slice.netvm import build_netvm_image
work = Path(sys.argv[2]); t = datetime.fromtimestamp(1700000000, timezone.utc)
a = build_rootfs(work / "agent-tree", work / "agent.img", t_clock=t, world_id="pkg-smoke-agent",
                 sealcheck_bin=work / "sealcheck", work_dir=work)
n = build_netvm_image(work / "netvm-tree", work / "netvm.img", netvm_bin=Path(sys.argv[3]),
                      busybox_bin=Path("/usr/bin/busybox"), dns_table=Path(sys.argv[4]), t_clock=t,
                      world_id="pkg-smoke-netvm", tls_identity=json.loads((work / "tls-identity.json").read_text()), sealcheck_bin=work / "sealcheck", work_dir=work)
for r in (a, n):
    print(json.dumps({k: r[k] for k in ("image", "sha256", "d4")}))
PY
chmod 0400 "$WORK/agent.img" "$WORK/netvm.img"

# 5. Boot both VMs and run pkg mirrors smoke test
umask 077
if \
HERMETIC_FC_BIN="$FC" HERMETIC_FIRECRACKER_LOCK="$LOCK" HERMETIC_KERNEL="$KERNEL" \
HERMETIC_ROOTFS="$WORK/agent.img" HERMETIC_NETVM_ROOTFS="$WORK/netvm.img" \
HERMETIC_WORLD_SERVER_BIN="$WORK/world-server" HERMETIC_WORLD_STORE="$WORK/store" \
HERMETIC_NET_WORK="$WORK" HERMETIC_AGENT_TAP="$AGENT_TAP" HERMETIC_NET_TAP="$NET_TAP" \
HERMETIC_PKG_GUEST_REQUIRED=1 \
  cargo test -p hermetic-vmm --features dev-unjailed --test pkg_guest \
  pkg_guest_vm_serves_pkg_mirrors_to_agent -- --nocapture \
  >"$WORK/pkg-smoke-test.log" 2>&1; then
  cat "$WORK/pkg-smoke-test.log"
  if grep -q "skipped:" "$WORK/pkg-smoke-test.log"; then
    echo "Pkg smoke failed: test skipped prerequisites" >&2
    exit 1
  fi
else
  result=$?
  cat "$WORK/pkg-smoke-test.log" >&2
  echo "Pkg smoke failed; test log and VM/execd diagnostics retained in $WORK" >&2
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
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/pkg-smoke.sh" "$@"
fi
