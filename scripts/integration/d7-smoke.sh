#!/usr/bin/env bash
# Offline owner-run development smoke test for D7 VM-isolated builder (Phase 1 D7 remaining).
# Runs inside the nested VM with KVM and pinned Firecracker, kernel and rootfs.
# Usage from worktree root: scripts/integration/d7-smoke.sh [WORK_DIR]
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
smoke_main() {
WORK="${HERMETIC_SMOKE_WORK:?}"
U="${HOME:?}"
FC="${HERMETIC_FC_BIN:?set measured patched Firecracker binary}"
: "${HERMETIC_FIRECRACKER_LOCK:?set measured patched Firecracker build lock}"
KERNEL="${HERMETIC_KERNEL:-$U/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}"
export CARGO_TARGET_DIR="$U/hermetic/cargo-target/$(basename "$top")"
T=1700000000
umask 022

# 1. Static binaries: sealcheck, execd, init
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q \
  -p hermetic-sealcheck -p hermetic-execd --bin hermetic-init --bin hermetic-sealcheck \
  --bin hermetic-execd --target x86_64-unknown-linux-gnu
bash scripts/build-trusted-execd.sh
BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
install -m 0700 "$BIN/hermetic-sealcheck" "$WORK/sealcheck"

# 2. Build D4-checked rootfs image
TREE="$WORK/tree"; rm -rf "$TREE"
for d in sbin bin dev proc sys tmp run etc/hermetic work mnt/hermetic-overlay; do
  mkdir -p "$TREE/$d"
done
install -m 0755 "$BIN/hermetic-execd" "$TREE/sbin/hermetic-execd"
install -m 0755 "$BIN/hermetic-init" "$TREE/sbin/hermetic-init"
install -m 0755 /usr/bin/busybox "$TREE/bin/busybox"
cat > "$TREE/etc/hermetic/run-spec.json" <<JSON
{"env":{"PATH":"/bin:/usr/bin","LANG":"C"},"workdir":"/work","uid":0,"gid":0,
 "entrypoint":[],"command":[],"hostname":"d7-builder","resolv_conf":"",
 "resources":{"vcpus":1,"memory_mib":256,"disk_mib":64,"wall_time_s":120}}
JSON
find "$TREE" -exec touch -h -d @$T {} +
/usr/bin/python3 -I - "$top/python" "$TREE" "$WORK/rootfs.img" "$WORK/sealcheck" "$WORK" <<'PY'
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hermetic_slice.rootfs import build_rootfs
r = build_rootfs(Path(sys.argv[2]), Path(sys.argv[3]),
    t_clock=datetime.fromtimestamp(1700000000, timezone.utc), world_id="d7-smoke",
    sealcheck_bin=Path(sys.argv[4]), work_dir=Path(sys.argv[5]))
assert r["d4"] == "pass", r
PY
chmod 0400 "$WORK/rootfs.img"

# 3. Create VM config JSON
FC_RESOLVED="$(readlink -f "$FC")"
LOCK_RESOLVED="$(readlink -f "$HERMETIC_FIRECRACKER_LOCK")"
KERNEL_RESOLVED="$(readlink -f "$KERNEL")"

cat > "$WORK/vm-config.json" <<JSON
{
  "firecracker_bin": "$FC_RESOLVED",
  "kernel_image": "$KERNEL_RESOLVED",
  "rootfs_image": "$WORK/rootfs.img",
  "firecracker_lock": "$LOCK_RESOLVED",
  "t_clock": $T,
  "vcpus": 1,
  "memory_mib": 256,
  "build_timeout_s": 120.0
}
JSON

# 4. Create fixture worlds: identical and differing
# Identical world:
mkdir -p "$WORK/world-identical/src/pkg" "$WORK/world-identical/dist/pkg"
printf 'val = 42\n' > "$WORK/world-identical/src/pkg/mod.py"
printf 'val = 42\n' > "$WORK/world-identical/dist/pkg/mod.py"
cat > "$WORK/world-identical/d7-recipe.json" <<JSON
{"schema": "hermetic.d7.recipe/1", "entries": [
  {"id": "pkg", "artifact": "dist/pkg", "source": "src/pkg", "builder": "copy", "args": []}
]}
JSON

# Differing world:
mkdir -p "$WORK/world-diff/src/pkg" "$WORK/world-diff/dist/pkg"
printf 'val = 42\n' > "$WORK/world-diff/src/pkg/mod.py"
printf 'val = 99\n' > "$WORK/world-diff/dist/pkg/mod.py"
cat > "$WORK/world-diff/d7-recipe.json" <<JSON
{"schema": "hermetic.d7.recipe/1", "entries": [
  {"id": "pkg", "artifact": "dist/pkg", "source": "src/pkg", "builder": "copy", "args": []}
]}
JSON

# 5. Run D7 deep audit on identical rebuild -> exit 0, verdict identical
set +e
PYTHONPATH="$top/python" python3 -m hermetic_d7 --deep-audit \
  "$WORK/world-identical" d7-recipe.json --vm-config "$WORK/vm-config.json" > "$WORK/identical-report.json"
rc_identical=$?
set -e
if [ "$rc_identical" -ne 0 ] || ! grep -q '"verdict": "identical"' "$WORK/identical-report.json"; then
  echo "D7 VM smoke FAILED: identical rebuild expected rc=0 and verdict identical, got rc=$rc_identical" >&2
  cat "$WORK/identical-report.json" >&2
  exit 1
fi

# 6. Run D7 deep audit on differing rebuild -> exit 2, verdict differs
set +e
PYTHONPATH="$top/python" python3 -m hermetic_d7 --deep-audit \
  "$WORK/world-diff" d7-recipe.json --vm-config "$WORK/vm-config.json" > "$WORK/diff-report.json"
rc_diff=$?
set -e
if [ "$rc_diff" -ne 2 ] || ! grep -q '"verdict": "differs"' "$WORK/diff-report.json"; then
  echo "D7 VM smoke FAILED: differing rebuild expected rc=2 and verdict differs, got rc=$rc_diff" >&2
  cat "$WORK/diff-report.json" >&2
  exit 1
fi

echo "d7 smoke: ok (throwaway microVM, identical rebuild exit 0, differing rebuild exit 2)"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/d7-smoke.sh" "$@"
fi
