#!/usr/bin/env bash
# Development GraderVM smoke test (offline, KVM, no jailer). For the fixture task it
# builds byte-identical D4-checked grader images per variant with the patch applied on the
# host, boots each image through hermetic-vmm's dev-unjailed runner with
# init=/sbin/hermetic-grader-init (no vsock, no network), waits for the guest to power
# off, checks the guest clock line against hermetic.t, collects the 1 MiB result drive
# and validates R0/R1/R2 on the host with hermetic-grader-verdict:
#   empty patch -> unresolved (f2p_failed), gold patch -> resolved.
# Development only. See BOOT_NOTES.md, "Grader VM".
# Usage: scripts/integration/grader-vm-smoke.sh [WORK_DIR]   (run from the worktree root)
# Needs: /dev/kvm, docker with the local image python:3.12-alpine (never pulled), the
# project venv (pure-Python pytest copied into the guest tree), mke2fs >= 1.47.1, patch,
# Firecracker staged by boot-smoke.sh, the 6.6 kernel build.
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
smoke_main() {
WORK="${HERMETIC_SMOKE_WORK:?}"
U="${HOME:?}"
export CARGO_TARGET_DIR="$U/hermetic/cargo-target/$(basename "$top")"
VENV="${HERMETIC_VENV:-$U/Heavy Coding/Projects/Hermetic World/python/.venv}"
FC="${HERMETIC_FC_BIN:-$U/.hermetic/tools/firecracker-1.18.0/firecracker}"
KERNEL="${HERMETIC_KERNEL:-$U/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}"
[ -e "$FC" ] && FC="$(readlink -f "$FC")" || true
[ -e "$KERNEL" ] && KERNEL="$(readlink -f "$KERNEL")" || true
if [ -n "${HERMETIC_FIRECRACKER_LOCK:-}" ]; then
  FC_LOCK="$HERMETIC_FIRECRACKER_LOCK"
  [ -e "$FC_LOCK" ] && FC_LOCK="$(readlink -f "$FC_LOCK")" || true
  export HERMETIC_FIRECRACKER_LOCK="$FC_LOCK"
fi
BASE_IMAGE=python:3.12-alpine
FIX="$top/scripts/integration/fixtures/grader-task"
T=1700000000
F2P=tests/test_calc.py::test_add
P2P=tests/test_calc.py::test_double
VS="$(printf 'grader-smoke-variant-set' | sha256sum | cut -d' ' -f1)"
umask 022

# 0. Static guest binaries and host tools.
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q \
  -p hermetic-grader-supervisor -p hermetic-grader-result -p hermetic-sealcheck \
  -p hermetic-execd --bin hermetic-grader-init --bin hermetic-grader-supervisor \
  --bin hermetic-grader-verdict --bin hermetic-sealcheck \
  --target x86_64-unknown-linux-gnu
BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
install -m 0700 "$BIN/hermetic-sealcheck" "$WORK/sealcheck"
SP="$(ls -d "$VENV"/lib/python3*/site-packages)"
# Build the boot test binary once (dev-unjailed runner); it runs once per image below.
cargo test -q -p hermetic-vmm --features dev-unjailed --test guest --no-run 2>/dev/null

if [ ! -f "$WORK/base.tar" ]; then
  cid="$(docker create --pull never --network none "$BASE_IMAGE" /bin/true)"
  docker export "$cid" > "$WORK/base.tar"
  docker rm "$cid" > /dev/null
fi

for v in empty gold; do
  D="$WORK/$v"
  mkdir "$D" "$D/host"   # fails on reuse: pass a fresh WORK_DIR
  chmod 0700 "$D/host"
  for r in R0 R1 R2; do
    TREE="$D/$r/tree"; IMG="$D/$r/img"
    mkdir -p "$TREE" "$IMG"; chmod 0700 "$IMG"
    tar -C "$TREE" -xf "$WORK/base.tar"
    GSP="$TREE/usr/local/lib/python3.12/site-packages"
    for p in _pytest pytest pluggy iniconfig packaging pygments py.py; do cp -r "$SP/$p" "$GSP/"; done
    cp -r "$SP"/{pytest,pluggy,iniconfig,packaging,pygments}-*.dist-info "$GSP/"
    mkdir "$GSP/hermetic_grader_records"
    cp python/hermetic_grader_records/{__init__,plugin,record,supervisor}.py "$GSP/hermetic_grader_records/"
    cp python/hermetic_safe_io.py "$GSP/"
    cp "$FIX/hermetic_run_probe.py" "$GSP/"
    find "$GSP" -name __pycache__ -type d -prune -exec rm -r {} +
    mkdir -p "$TREE/work" "$TREE/etc/hermetic/grader"
    if [ -n "${HERMETIC_GRADER_PUBLISHED_ROOT:-}" ]; then
      cp -r "$HERMETIC_GRADER_PUBLISHED_ROOT/$v" "$TREE/work/repo"
    else
      cp -r "$FIX/repo" "$TREE/work/repo"
      (cd "$TREE/work/repo" && patch -s -p1 < "$FIX/$v.patch")
    fi
    install -m 0755 "$BIN/hermetic-grader-supervisor" "$TREE/sbin/hermetic-grader-supervisor"
    install -m 0755 "$BIN/hermetic-grader-init" "$TREE/sbin/hermetic-grader-init"
    # The launcher supplies a dedicated record fd and applies the runner plan.
    cat > "$TREE/etc/hermetic/grader/run.json" <<JSON
{"argv":["/usr/local/bin/python3.12","-s","-m","pytest","-p","no:cacheprovider","-q","$F2P","$P2P"],
 "env":{},"sandbox":{"t_clock":$T,"required_pytest_plugins":["hermetic_run_probe"]},
 "cwd":"/work/repo","deadline_seconds":120,"expected_test_ids":["$F2P","$P2P"],
 "variant_set":"$VS"}
JSON
    find "$TREE" -exec touch -h -d @$T {} +
    /usr/bin/python3 -I - "$top/python" "$TREE" "$IMG/grader.img" "$WORK/sealcheck" "$IMG" <<'PY'
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hermetic_slice.rootfs import build_rootfs
r = build_rootfs(Path(sys.argv[2]), Path(sys.argv[3]),
    t_clock=datetime.fromtimestamp(1700000000, timezone.utc), world_id="grader-smoke",
    sealcheck_bin=Path(sys.argv[4]), work_dir=Path(sys.argv[5]))
assert r["d4"] == "pass", r
PY
    chmod 0400 "$IMG/grader.img"
    rm -rf "$TREE"
  done
  # Check all three sealed images before executing any tests. No label or nonce
  # is baked in; only the supervisor's result drive receives host boot input.
  cmp -s "$D/R0/img/grader.img" "$D/R1/img/grader.img"
  cmp -s "$D/R0/img/grader.img" "$D/R2/img/grader.img"
  sha256sum "$D"/R{0,1,2}/img/grader.img > "$D/host/image-sha256.txt"
  for r in R0 R1 R2; do
    IMG="$D/$r/img"
    # Boot, wait for power-off, check the clock line, collect the result drive.
    HERMETIC_FC_BIN="$FC" HERMETIC_KERNEL="$KERNEL" \
    HERMETIC_GRADER_ROOTFS="$IMG/grader.img" HERMETIC_GRADER_RESULT_OUT="$D/host/$r.img" \
    HERMETIC_GRADER_RUN="$r" \
      timeout 400 cargo test -q -p hermetic-vmm --features dev-unjailed --test guest \
      boots_grader_and_collects_result_drive -- --ignored --nocapture --exact 2>&1 \
      | grep -E '^grader serial:|^grader timeout:|test result:|panicked'
    [ -s "$D/host/$r.img" ] || { echo "grader VM FAILED for $v $r" >&2; exit 1; }
  done

  set +e
  "$BIN/hermetic-grader-verdict" --r0 "$D/host/R0.img" --r1 "$D/host/R1.img" \
    --r2 "$D/host/R2.img" --plan "$FIX/plan.json" > "$D/verdict.json"
  rc=$?
  set -e
  echo "$v: verdict rc=$rc $(cat "$D/verdict.json")"
  if [ "$v" = empty ]; then
    want_rc=2; want='"status":"unresolved","reasons":["f2p_failed"]'
  else
    want_rc=0; want='"status":"resolved","reasons":[]'
  fi
  if [ "$rc" != "$want_rc" ] || ! grep -qF "$want" "$D/verdict.json"; then
    echo "grader VM smoke FAILED for $v: expected rc=$want_rc and $want" >&2
    exit 1
  fi
done
echo "grader VM smoke: ok (empty patch unresolved, gold patch resolved, clock = hermetic.t)"

}

run_one() {
  local run_id="$1"
  local test_file="$2"
  local out_disk="$3"

  case "$run_id" in
    R0|R1|R2|R3|base|gold|empty) ;;
    *) echo "invalid run_id: $run_id" >&2; exit 2 ;;
  esac

  if [ ! -f "$test_file" ] || [ -L "$test_file" ]; then
    echo "test_file must be an existing regular non-symlink file: $test_file" >&2
    exit 2
  fi

  test_file="$(readlink -f "$test_file")"
  local out_dir
  out_dir="$(dirname "$out_disk")"
  if [ ! -d "$out_dir" ]; then
    echo "out_disk directory must exist: $out_dir" >&2
    exit 2
  fi
  out_disk="$(readlink -f "$out_dir")/$(basename "$out_disk")"

  local patch_name="gold.patch"
  if [ "$run_id" = "empty" ] || [ "$run_id" = "base" ]; then
    patch_name="empty.patch"
  elif [ "${HERMETIC_DIFFERENTIAL_VM_EXPECT:-}" = "unresolved" ]; then
    patch_name="empty.patch"
  fi

  local grader_run="$run_id"
  case "$run_id" in
    base|gold|empty) grader_run="R0" ;;
  esac

  local U="${HOME:?}"
  local target_dir="${CARGO_TARGET_DIR:-$U/hermetic/cargo-target/$(basename "$top")}"
  export CARGO_TARGET_DIR="$target_dir"
  local venv="${HERMETIC_VENV:-$top/python/.venv}"
  if [ ! -d "$venv" ]; then
    venv="$U/Heavy Coding/Projects/Hermetic World/python/.venv"
  fi
  local fc="${HERMETIC_FC_BIN:-$U/.hermetic/tools/firecracker-1.18.0/firecracker}"
  local kernel="${HERMETIC_KERNEL:-$U/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}"
  [ -e "$fc" ] && fc="$(readlink -f "$fc")" || true
  [ -e "$kernel" ] && kernel="$(readlink -f "$kernel")" || true
  if [ -n "${HERMETIC_FIRECRACKER_LOCK:-}" ]; then
    local fc_lock="$HERMETIC_FIRECRACKER_LOCK"
    [ -e "$fc_lock" ] && fc_lock="$(readlink -f "$fc_lock")" || true
    export HERMETIC_FIRECRACKER_LOCK="$fc_lock"
  fi

  local base_image=python:3.12-alpine
  local fix="$top/scripts/integration/fixtures/grader-task"
  local t_clock=1700000000
  local vs
  vs="$(sha256sum "$test_file" | cut -d' ' -f1)"

  local work
  work="$(mktemp -d "${TMPDIR:-/tmp}/hw-grun-XXXXXX")"
  chmod 0700 "$work"
  trap "rm -rf '$work'" EXIT

  umask 022

  RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q \
    -p hermetic-grader-supervisor -p hermetic-grader-result -p hermetic-sealcheck \
    -p hermetic-execd --bin hermetic-grader-init --bin hermetic-grader-supervisor \
    --bin hermetic-grader-verdict --bin hermetic-sealcheck \
    --target x86_64-unknown-linux-gnu
  local bin="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
  install -m 0700 "$bin/hermetic-sealcheck" "$work/sealcheck"
  local sp
  sp="$(ls -d "$venv"/lib/python3*/site-packages)"
  cargo test -q -p hermetic-vmm --features dev-unjailed --test guest --no-run 2>/dev/null

  local cid
  cid="$(docker create --pull never --network none "$base_image" /bin/true)"
  trap 'docker rm -f "'"$cid"'" >/dev/null 2>&1 || true; rm -rf "'"$work"'"' EXIT
  docker export "$cid" > "$work/base.tar"
  docker rm "$cid" > /dev/null
  trap 'rm -rf "'"$work"'"' EXIT

  local tree="$work/tree"
  local img="$work/img"
  mkdir -p "$tree" "$img"
  chmod 0700 "$img"
  tar -C "$tree" -xf "$work/base.tar"

  local gsp="$tree/usr/local/lib/python3.12/site-packages"
  for p in _pytest pytest pluggy iniconfig packaging pygments py.py; do cp -r "$sp/$p" "$gsp/"; done
  cp -r "$sp"/{pytest,pluggy,iniconfig,packaging,pygments}-*.dist-info "$gsp/"
  mkdir "$gsp/hermetic_grader_records"
  cp python/hermetic_grader_records/{__init__,plugin,record,supervisor}.py "$gsp/hermetic_grader_records/"
  cp python/hermetic_safe_io.py "$gsp/"
  cp "$fix/hermetic_run_probe.py" "$gsp/"
  find "$gsp" -name __pycache__ -type d -prune -exec rm -r {} +
  mkdir -p "$tree/work" "$tree/etc/hermetic/grader"

  if [ -n "${HERMETIC_GRADER_PUBLISHED_ROOT:-}" ]; then
    local v_name="gold"
    if [ "$patch_name" = "empty.patch" ]; then v_name="empty"; fi
    cp -r "$HERMETIC_GRADER_PUBLISHED_ROOT/$v_name" "$tree/work/repo"
  else
    cp -r "$fix/repo" "$tree/work/repo"
    (cd "$tree/work/repo" && patch -s -p1 < "$fix/$patch_name")
  fi

  cp "$test_file" "$tree/work/repo/tests/test_calc.py"

  install -m 0755 "$bin/hermetic-grader-supervisor" "$tree/sbin/hermetic-grader-supervisor"
  install -m 0755 "$bin/hermetic-grader-init" "$tree/sbin/hermetic-grader-init"

  /usr/bin/python3 -c '
import ast, json, sys
test_file = sys.argv[1]
with open(test_file, "r", encoding="utf-8") as f:
    tree = ast.parse(f.read())
tids = []
for n in tree.body:
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_"):
        tids.append(f"tests/test_calc.py::{n.name}")
    elif isinstance(n, ast.ClassDef):
        for m in n.body:
            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name.startswith("test_"):
                tids.append(f"tests/test_calc.py::{n.name}::{m.name}")
if not tids:
    tids = ["tests/test_calc.py::test_add", "tests/test_calc.py::test_double"]
vs = sys.argv[2]
out_path = sys.argv[3]
t_clock = int(sys.argv[4])
doc = {
  "argv": ["/usr/local/bin/python3.12", "-s", "-m", "pytest", "-p", "no:cacheprovider", "-q"] + tids,
  "env": {},
  "sandbox": {"t_clock": t_clock, "required_pytest_plugins": ["hermetic_run_probe"]},
  "cwd": "/work/repo",
  "deadline_seconds": 120,
  "expected_test_ids": tids,
  "variant_set": vs
}
with open(out_path, "w", encoding="utf-8") as f:
  json.dump(doc, f, separators=(",", ":"))
' "$test_file" "$vs" "$tree/etc/hermetic/grader/run.json" "$t_clock"

  find "$tree" -exec touch -h -d @$t_clock {} +
  /usr/bin/python3 -I - "$top/python" "$tree" "$img/grader.img" "$work/sealcheck" "$img" <<'PY'
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hermetic_slice.rootfs import build_rootfs
r = build_rootfs(Path(sys.argv[2]), Path(sys.argv[3]),
    t_clock=datetime.fromtimestamp(1700000000, timezone.utc), world_id="grader-smoke",
    sealcheck_bin=Path(sys.argv[4]), work_dir=Path(sys.argv[5]))
assert r["d4"] == "pass", r
PY
  chmod 0400 "$img/grader.img"
  rm -rf "$tree"

  HERMETIC_FC_BIN="$fc" HERMETIC_KERNEL="$kernel" \
  HERMETIC_GRADER_ROOTFS="$img/grader.img" HERMETIC_GRADER_RESULT_OUT="$work/result.img" \
  HERMETIC_GRADER_RUN="$grader_run" \
    timeout 400 cargo test -q -p hermetic-vmm --features dev-unjailed --test guest \
    boots_grader_and_collects_result_drive -- --ignored --nocapture --exact 2>&1 \
    | grep -E '^grader serial:|^grader timeout:|test result:|panicked'

  [ -s "$work/result.img" ] || { echo "grader VM FAILED for $run_id" >&2; exit 1; }
  cp "$work/result.img" "$out_disk"
  chmod 0600 "$out_disk"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  if [ "$#" -eq 3 ]; then
    run_one "$1" "$2" "$3"
  else
    exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/grader-vm-smoke.sh" "$@"
  fi
fi
