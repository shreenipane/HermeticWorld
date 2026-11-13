#!/usr/bin/env bash
# Development grader smoke test (offline). For a tiny fixture task it builds one grader
# tree and one D4-checked grader image per variant (empty patch, gold patch), runs the
# real grading chain in that tree with no network:
#   hermetic-grader-supervisor -> pytest + hermetic_grader_records plugin (HGR1 records)
#   -> 1 MiB HGRD result disk
# for runs R0, R1 and R2, and validates the result disks on the host with
# hermetic-grader-verdict (strict parser + differential verdict).
#
# The grader VM itself is not booted: there is no grader-mode PID 1 yet (see
# BOOT_NOTES.md, "Grader smoke"). The run uses an offline container built from the
# same tree instead. Development only.
# Usage: scripts/integration/grader-smoke.sh [WORK_DIR]   (run from the worktree root)
# Needs: docker with the local image python:3.12-alpine (never pulled), the project venv
# (pure-Python pytest copied into the guest tree), mke2fs >= 1.47.1, patch.
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
U="${HOME:?}"
WORK="${1:-$(mktemp -d /tmp/hermetic-grader-smoke.XXXXXX)}"
mkdir -p "$WORK"; chmod 0700 "$WORK"
export CARGO_TARGET_DIR="$U/hermetic/cargo-target/$(basename "$top")"
VENV="${HERMETIC_VENV:-$U/Heavy Coding/Projects/Hermetic World/python/.venv}"
BASE_IMAGE=python:3.12-alpine
FIX="$top/scripts/integration/fixtures/grader-task"
T=1700000000
F2P=tests/test_calc.py::test_add
P2P=tests/test_calc.py::test_double
VS="$(printf 'grader-smoke-variant-set' | sha256sum | cut -d' ' -f1)"
umask 022

# 0. Static binaries (the supervisor runs inside the grader tree).
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q \
  -p hermetic-grader-supervisor -p hermetic-grader-result -p hermetic-sealcheck \
  --target x86_64-unknown-linux-gnu
BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
install -m 0700 "$BIN/hermetic-sealcheck" "$WORK/sealcheck"
SP="$(ls -d "$VENV"/lib/python3*/site-packages)"

# Base userland: the local python:3.12-alpine image, exported offline.
if [ ! -f "$WORK/base.tar" ]; then
  cid="$(docker create --pull never --network none "$BASE_IMAGE" /bin/true)"
  docker export "$cid" > "$WORK/base.tar"
  docker rm "$cid" > /dev/null
fi

for v in empty gold; do
  D="$WORK/$v"; TREE="$D/tree"
  mkdir "$D" "$TREE" "$D/img" "$D/out" "$D/host"   # fails on reuse: pass a fresh WORK_DIR
  chmod 0700 "$D/img" "$D/out" "$D/host"
  tar -C "$TREE" -xf "$WORK/base.tar"
  GSP="$TREE/usr/local/lib/python3.12/site-packages"
  for p in _pytest pytest pluggy iniconfig packaging pygments py.py; do cp -r "$SP/$p" "$GSP/"; done
  cp -r "$SP"/{pytest,pluggy,iniconfig,packaging,pygments}-*.dist-info "$GSP/"
  mkdir "$GSP/hermetic_grader_records"
  cp python/hermetic_grader_records/{__init__,plugin,record,supervisor}.py "$GSP/hermetic_grader_records/"
  cp python/hermetic_safe_io.py "$GSP/"
  find "$GSP" -name __pycache__ -type d -prune -exec rm -r {} +
  # The work under test: base repo plus the variant's patch, tests baked in.
  mkdir -p "$TREE/work" "$TREE/etc/hermetic/grader"
  cp -r "$FIX/repo" "$TREE/work/repo"
  (cd "$TREE/work/repo" && patch -s -p1 < "$FIX/$v.patch")
  install -m 0755 "$BIN/hermetic-grader-supervisor" "$TREE/sbin/hermetic-grader-supervisor"
  # Runner settings (TR-GR-4): python -s, plugin autoload off, result plugin via -p.
  # The plugin requires a result fd >= 3, while the supervisor hands the pipe over on
  # fd 2; the shell moves it to fd 3 and discards stderr (see BOOT_NOTES.md).
  for r in R0 R1 R2; do
    cat > "$TREE/etc/hermetic/grader/run-$r.json" <<JSON
{"argv":["/bin/busybox","sh","-c","exec 3>&2 2>/dev/null; exec /usr/local/bin/python3.12 -s -m pytest -p hermetic_grader_records.plugin -p no:cacheprovider -q $F2P $P2P"],
 "env":{"PATH":"/usr/local/bin:/usr/bin:/bin","LANG":"C.UTF-8","HOME":"/tmp","HERMETIC_RESULT_FD":"3",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD":"1","PYTHONDONTWRITEBYTECODE":"1"},
 "cwd":"/work/repo","deadline_seconds":120,"expected_test_ids":["$F2P","$P2P"],
 "run":"$r","variant_set":"$VS"}
JSON
  done
  find "$TREE" -exec touch -h -d @$T {} +

  # 1. Grader image with the existing tooling (D4 before publication).
  /usr/bin/python3 -I - "$top/python" "$TREE" "$D/img/grader.img" "$WORK/sealcheck" "$D/img" <<'PY'
import sys, json
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hermetic_slice.rootfs import build_rootfs
r = build_rootfs(Path(sys.argv[2]), Path(sys.argv[3]),
    t_clock=datetime.fromtimestamp(1700000000, timezone.utc), world_id="grader-smoke",
    sealcheck_bin=Path(sys.argv[4]), work_dir=Path(sys.argv[5]))
assert r["d4"] == "pass", r
print(json.dumps({k: r[k] for k in ("image", "sha256", "d4", "size_bytes")}))
PY

  # 2. Grading: the same tree, no network, read-only, unprivileged, no capabilities.
  TAG="hermetic/grader-smoke-$v:dev-$$"
  tar -C "$TREE" -c . | docker import - "$TAG" > /dev/null
  for r in R0 R1 R2; do
    timeout 300 docker run --rm --pull never --network none --read-only --tmpfs /tmp:rw,mode=1777 \
      --cap-drop ALL --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
      -v "$D/out:/out" "$TAG" /sbin/hermetic-grader-supervisor \
      --config "/etc/hermetic/grader/run-$r.json" --result-disk "/out/$r.img"
    install -m 0600 "$D/out/$r.img" "$D/host/$r.img"
  done
  docker rmi "$TAG" > /dev/null

  # 3. Host-side validation: strict result-disk parser and differential verdict.
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
    echo "grader smoke FAILED for $v: expected rc=$want_rc and $want" >&2
    exit 1
  fi
done
echo "grader smoke: ok (empty patch unresolved, gold patch resolved)"
