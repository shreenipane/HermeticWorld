#!/usr/bin/env bash
# Nested VM evaluation smoke test for hermetic-cli (TR-CLI, TR-VMM, TR-EXT, TR-GR).
# Seals the fixture task and runs it in the nested VM using Firecracker.
# Run by the manager in the nested VM with /dev/kvm.
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"

smoke_main() {
  umask 022
  WORK="${HERMETIC_SMOKE_WORK:?}"

  # 1. Resolve inputs with readlink -f as required
  FC="$(readlink -f "${HERMETIC_FC_BIN:?set HERMETIC_FC_BIN}")"
  FC_LOCK="$(readlink -f "${HERMETIC_FIRECRACKER_LOCK:?set HERMETIC_FIRECRACKER_LOCK}")"
  KERNEL="$(readlink -f "${HERMETIC_KERNEL:?set HERMETIC_KERNEL}")"

  export HERMETIC_FC_BIN="$FC"
  export HERMETIC_FIRECRACKER_LOCK="$FC_LOCK"
  export HERMETIC_KERNEL="$KERNEL"

  # 2. Build release CLI, sealcheck and trust
  export CARGO_TARGET_DIR="$HOME/hermetic/cargo-target/$(basename "$top")"
  RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q \
    -p hermetic-cli -p hermetic-sealcheck -p hermetic-trust \
    -p hermetic-clockprobe \
    --target x86_64-unknown-linux-gnu
  # hermetic-execd and hermetic-init (a binary of the hermetic-execd crate) come from the trusted build.
  bash scripts/build-trusted-execd.sh
  # Static guest binaries the sealer installs (passed through by hermetic seal).
  export HERMETIC_GUEST_BIN_DIR="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
  CLI="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/hermetic"
  install -m 0700 "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/hermetic-sealcheck" "$WORK/sealcheck"
  SEALCHECK="$WORK/sealcheck"
  export HERMETIC_SEALCHECK_BIN="${HERMETIC_SEALCHECK_BIN:-$SEALCHECK}"
  install -m 0700 "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/hermetic-trust" "$WORK/trust"
  TRUST="$WORK/trust"
  export HERMETIC_TRUST_BIN="${HERMETIC_TRUST_BIN:-$TRUST}"

  # 3. Setup work directories with mode 0700
  SEALED_WORLD="$WORK/sealed-world"
  RUN_DIR="$WORK/run"
  mkdir -m 0700 -p "$SEALED_WORLD" "$RUN_DIR"
  export HERMETIC_RUN_DIR="$RUN_DIR"

  # 4. Seal fixture task
  FIXTURE_SRC="$top/scripts/integration/fixtures/grader-task/repo"
  TASK_ID="fixture-task"

  # Use repo's real sealer binary
  export HERMETIC_SEALER_BIN="$(readlink -f "${HERMETIC_SEALER_BIN:-$top/scripts/hermetic-sealer}")"

  PACKAGES_RECORD="$WORK/packages-record.json"
  SUBSTRATE_FILE="$WORK/substrate.json"
  echo "cli-run smoke: generating real packages record and substrate fixtures..."
  /usr/bin/python3 -I - "$top" "$WORK" "$PACKAGES_RECORD" "$SUBSTRATE_FILE" "$FIXTURE_SRC" << 'PY'
import hashlib
import json
import sys
from pathlib import Path

top = Path(sys.argv[1])
work = Path(sys.argv[2])
packages_record_path = Path(sys.argv[3])
substrate_path = Path(sys.argv[4])
fixture_src = Path(sys.argv[5])

sys.path.insert(0, str(top / "python"))

from hermetic_pkgrec.manifest import Manifest
from hermetic_pkgrec.freeze import freeze_world

# 1. Produce real frozen package root with hermetic_pkgrec
store_dir = work / "pkg_store"
store_dir.mkdir(parents=True, exist_ok=True)
pkg_manifest_path = work / "pkg_manifest.json"
frozen_pkg_root = work / "frozen_pkg_root"

pkg_manifest = Manifest(cutoff="2020-01-01T00:00:00Z")
pkg_manifest.save(pkg_manifest_path)
freeze_world(store_dir, pkg_manifest_path, frozen_pkg_root)

# Deterministic closure root from real frozen package root
hasher = hashlib.sha256()
for p in sorted(frozen_pkg_root.rglob("*")):
    rel = p.relative_to(frozen_pkg_root).as_posix()
    if p.is_file():
        hasher.update(f"file:{rel}:{hashlib.sha256(p.read_bytes()).hexdigest()}\n".encode())
    elif p.is_dir():
        hasher.update(f"dir:{rel}\n".encode())
closure_root = f"sha256:{hasher.hexdigest()}"

# Real baseline root from manifest
manifest_bytes = pkg_manifest_path.read_bytes()
baseline_root = f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}"

packages_record = {
    "closure_root": closure_root,
    "baseline_month": "2020-01",
    "baseline_root": baseline_root,
}
packages_record_path.write_text(json.dumps(packages_record, indent=2) + "\n")

# 2. Substrate: the sealer takes the D5b inventory of the rootfs it stages. The
# fixture rootfs holds only static binaries and no package databases, so an empty
# inventory is allowed explicitly; it records no substrate and substrate_at_t "none".
substrate_path.write_text(json.dumps(
    {"schema": "hermetic-sealer-substrate-request/v1", "allow_empty": True}, indent=2) + "\n")
PY

  echo "cli-run smoke: sealing fixture..."
  "$CLI" seal \
    --src "$FIXTURE_SRC" \
    --out "$SEALED_WORLD" \
    --t-clock "2020-01-01T00:00:00Z" \
    --world-id "$TASK_ID" \
    --seal-level repo_only \
    --packages-record "$PACKAGES_RECORD" \
    --substrate "$SUBSTRATE_FILE"

  echo "cli-run smoke: verifying sealed bundle..."
  "$CLI" verify-bundle "$SEALED_WORLD"

  # AgentVM rootfs image produced by real sealer
  echo "cli-run smoke: using rootfs from sealed world..."
  ROOTFS_IMG="$SEALED_WORLD/rootfs.img"
  chmod 0600 "$ROOTFS_IMG"
  export HERMETIC_ROOTFS="$ROOTFS_IMG"

  # Build fixture agent volume for Mode H
  echo "cli-run smoke: building fixture agent volume..."
  AGENT_VOLUME_IMG="$WORK/agent_volume.img"
  AGENT_VOLUME_META="$WORK/agent_volume_meta.json"
  /usr/bin/python3 -I - "$top" "$WORK" "$AGENT_VOLUME_IMG" "$FIXTURE_SRC/../gold.patch" "$AGENT_VOLUME_META" << 'PY'
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

top = Path(sys.argv[1])
work = Path(sys.argv[2])
out_img = Path(sys.argv[3])
gold_patch_path = Path(sys.argv[4])
meta_path = Path(sys.argv[5])

sys.path.insert(0, str(top / "python"))
from hermetic_slice.agent_volume import build_agent_volume_image

gold_patch_bytes = gold_patch_path.read_bytes()
run_script = b"""#!/bin/sh
set -e
cd /testbed
if [ -f /opt/agent/gold.patch ]; then
  if command -v patch >/dev/null 2>&1; then
    patch -p1 < /opt/agent/gold.patch
  elif [ -x /bin/busybox ] && /bin/busybox patch --help >/dev/null 2>&1; then
    /bin/busybox patch -p1 < /opt/agent/gold.patch
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c '
p = "/testbed/calc.py"
s = open(p).read().replace("return a - b", "return a + b")
open(p, "w").write(s)
'
  else
    sed -i 's/return a - b/return a + b/' /testbed/calc.py
  fi
else
  sed -i 's/return a - b/return a + b/' /testbed/calc.py
fi
"""

agent_files = {
    "run": (run_script, 0o755),
    "gold.patch": (gold_patch_bytes, 0o644),
}
t_clock = datetime.fromisoformat("2020-01-01T00:00:00+00:00")
res = build_agent_volume_image(
    tree=work / "agent_tree",
    out_image=out_img,
    files=agent_files,
    t_clock=t_clock,
    world_id="fixture-task",
    size_mib=16,
)
meta_path.write_text(json.dumps(res, indent=2))
PY
  chmod 0600 "$AGENT_VOLUME_IMG"
  export HERMETIC_AGENT_VOLUME="$(readlink -f "$AGENT_VOLUME_IMG")"

  # Trusted ExtractorVM image: hermetic-extract-init and the extract agent (static),
  # built with the D4 guard. The run never boots the task rootfs for extraction.
  echo "cli-run smoke: building trusted extractor image..."
  RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q \
    -p hermetic-extract-agent --bin hermetic-extract-init --bin hermetic-extract-agent \
    --target x86_64-unknown-linux-gnu
  EXTRACTOR_IMG="$WORK/extractor.img"
  /usr/bin/python3 -I - "$top/python" "$WORK/extractor_tree" "$EXTRACTOR_IMG" \
    "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/hermetic-extract-init" \
    "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/hermetic-extract-agent" \
    "$SEALCHECK" "$WORK" <<'PY'
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hermetic_slice.extractor import build_extractor_image

r = build_extractor_image(
    tree=Path(sys.argv[2]),
    out_image=Path(sys.argv[3]),
    extractor_bin=Path(sys.argv[4]),
    agent_bin=Path(sys.argv[5]),
    t_clock=datetime.fromisoformat("2020-01-01T00:00:00+00:00"),
    world_id="fixture-task-extractor",
    sealcheck_bin=Path(sys.argv[6]),
    work_dir=Path(sys.argv[7]),
)
assert r["d4"] == "pass", r
PY
  chmod 0400 "$EXTRACTOR_IMG"
  export HERMETIC_EXTRACTOR_IMAGE="$(readlink -f "$EXTRACTOR_IMG")"

  # Generate throwaway test signing key in work directory
  echo "cli-run smoke: generating test signing key..."
  KEY_PK8="$WORK/test_key.pk8"
  KEY_PUB="$WORK/test_key.pub"
  /usr/bin/python3 -I - "$KEY_PK8" "$KEY_PUB" << 'PY'
import sys
from pathlib import Path

pk8_path = Path(sys.argv[1])
pub_path = Path(sys.argv[2])

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    key = ed25519.Ed25519PrivateKey.generate()
    pk8_bytes = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
except Exception:
    import subprocess
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-outform", "DER", "-out", str(pk8_path)],
        check=True,
    )
    pub_der = subprocess.run(
        ["openssl", "pkey", "-in", str(pk8_path), "-inform", "DER", "-pubout", "-outform", "DER"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    pub_bytes = pub_der[-32:]
    pk8_bytes = pk8_path.read_bytes()

pk8_path.write_bytes(pk8_bytes)
pk8_path.chmod(0o600)
pub_path.write_bytes(pub_bytes)
pub_path.chmod(0o644)
PY
  export HERMETIC_SIGNING_KEY="$KEY_PK8"

  # 5. Execute run (in nested L1 VM if HERMETIC_NESTED_SSH is set, otherwise locally)
  echo "cli-run smoke: running task..."
  run_rc=0
  if [ -n "${HERMETIC_NESTED_SSH:-}" ]; then
    echo "cli-run smoke: running inside nested L1 VM via SSH..."
    read -ra SSH_PARTS <<< "$HERMETIC_NESTED_SSH"
    if [ "${SSH_PARTS[0]}" = "ssh" ]; then
      SSH=( "${SSH_PARTS[@]}" )
    else
      SSH=( ssh "${SSH_PARTS[@]}" )
    fi

    L1_RUN_ID="$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4().hex)')"
    L1_RUN_DIR="/var/tmp/hermetic-cli/run-$L1_RUN_ID"

    envs=(HERMETIC_TSC_KHZ="${HERMETIC_TSC_KHZ:-2688000}" HERMETIC_RUN_DIR="$L1_RUN_DIR" HERMETIC_PYTHON="${HERMETIC_L1_PYTHON:-/usr/bin/python3.11}")
    dirs=()
    for p in "$CLI" "$SEALED_WORLD" "$WORK"; do
      [ -e "$p" ] && dirs+=("$(dirname "$p")")
      [ -d "$p" ] && dirs+=("$p")
    done
    while IFS='=' read -r k v; do
      envs+=("$k=$v")
      [ -e "$v" ] && dirs+=("$(dirname "$v")")
      [ -d "$v" ] && dirs+=("$v")
    done < <(env | grep '^HERMETIC_' | grep -v '^HERMETIC_TSC_KHZ=' | grep -v '^HERMETIC_NESTED_SSH=' | grep -v '^HERMETIC_RUN_DIR=' | grep -v '^HERMETIC_PYTHON=')
    mapfile -t dirs < <(printf '%s\n' "${dirs[@]}" | sort -u)

    "${SSH[@]}" 'sudo -n mkdir -p /var/tmp/hermetic-cli && sudo -n chown root:root /var/tmp/hermetic-cli && sudo -n chmod 0755 /var/tmp/hermetic-cli'
    # The jailer joins the agent VM to the empty network namespace "isolated-0"
    # (host provisioning on a real deployment host); create it in the L1 VM.
    "${SSH[@]}" '[ -e /run/netns/isolated-0 ] || sudo -n ip netns add isolated-0'
    # Unpack as root without the archive's owners: the root-run jailer only accepts
    # images, kernels and binaries owned by root (or by the running user).
    tar cf - --absolute-names --exclude="$RUN_DIR" --exclude="$RUN_DIR/*" "${dirs[@]}" 2>/dev/null | "${SSH[@]}" 'sudo -n tar xpf - --absolute-names --no-same-owner 2>/dev/null; true'
    "${SSH[@]}" "sudo -n tee /var/tmp/hermetic-cli/.nested-hermetic > /dev/null && sudo -n chmod 0755 /var/tmp/hermetic-cli/.nested-hermetic" < "$CLI"
    # The VMM refuses images whose ancestor directories another user could change:
    # make every ancestor of the transferred paths root-owned and not group/other
    # writable in the disposable L1 VM (sticky /tmp-style directories are accepted).
    for d in "${dirs[@]}"; do
      a="$d"
      while [ "$a" != "/" ] && [ -n "$a" ]; do
        "${SSH[@]}" "[ -k $(printf '%q' "$a") ] || { sudo -n chown root:root $(printf '%q' "$a") && sudo -n chmod go-w $(printf '%q' "$a"); }" 2>/dev/null || true
        a="$(dirname "$a")"
      done
    done

    q=$(printf '%q ' env "${envs[@]}" /var/tmp/hermetic-cli/.nested-hermetic run --world "$SEALED_WORLD" --task "$TASK_ID" --agent-mode H)
    # The production runner launches VMs through the jailer, which needs root; the L1
    # VM is a disposable nested host where the smoke has passwordless sudo.
    "${SSH[@]}" "cd /var/tmp/hermetic-cli && sudo -n $q" || run_rc=$?

    "${SSH[@]}" "[ -d '$L1_RUN_DIR' ] && sudo -n tar -C '$L1_RUN_DIR' -cf - . 2>/dev/null" | tar -C "$RUN_DIR" -xpf - --no-same-owner 2>/dev/null || true
    "${SSH[@]}" "sudo -n rm -rf '$L1_RUN_DIR'"
    # Remove this run's copy of the work directory from the L1 VM (its disk is
    # small and every run transfers a fresh copy).
    "${SSH[@]}" "sudo -n rm -rf $(printf '%q' "$WORK")" || true
  else
    echo "cli-run smoke: running locally..."
    HERMETIC_RUN_DIR="$RUN_DIR" "$CLI" run \
      --world "$SEALED_WORLD" \
      --task "$TASK_ID" \
      --agent-mode H || run_rc=$?
  fi

  [ "$run_rc" -eq 0 ] || [ "$run_rc" -eq 2 ] || {
    echo "cli-run smoke: run failed with unexpected exit code $run_rc" >&2
    exit "$run_rc"
  }

  # 6. Verify signed run record on host
  echo "cli-run smoke: verifying signed run record on host..."
  for f in record.json verdict.json submitted_work.patch probe_output.jsonl date_sentinel.json harness_summary.json boot_record.json; do
    if [ ! -f "$RUN_DIR/$f" ]; then
      echo "cli-run smoke: missing required run artifact $f" >&2
      exit 1
    fi
  done

  "$CLI" verify \
    --record "$RUN_DIR/record.json" \
    --key "$KEY_PUB" \
    --bundle "$SEALED_WORLD"

  # Assert the run status and the extracted patch digest
  /usr/bin/python3 -I - "$RUN_DIR/verdict.json" "$RUN_DIR/record.json" "$FIXTURE_SRC/../gold.patch" "$WORK/agent_volume_meta.json" "$RUN_DIR/probe_output.jsonl" "$RUN_DIR/date_sentinel.json" << 'PY'
import base64
import hashlib
import json
import sys
from pathlib import Path

verdict_path = Path(sys.argv[1])
record_path = Path(sys.argv[2])
patch_path = Path(sys.argv[3])
agent_meta_path = Path(sys.argv[4])
probe_path = Path(sys.argv[5])
date_sentinel_path = Path(sys.argv[6])

with open(verdict_path) as f:
    verdict = json.load(f)

with open(record_path) as f:
    envelope = json.load(f)

payload_bytes = base64.b64decode(envelope["payload"])
statement = json.loads(payload_bytes)
predicate = statement["predicate"]

# Assert run status matches
verdict_status = verdict.get("run_status") or verdict.get("status")
assert verdict_status is not None, "verdict missing run_status"
assert predicate["run_status"] == verdict_status, (
    f"run_status mismatch: {predicate['run_status']} vs {verdict_status}"
)

# Assert extracted patch digest matches gold patch
gold_bytes = patch_path.read_bytes()
expected_patch_digest = "sha256:" + hashlib.sha256(gold_bytes).hexdigest()
assert predicate["submitted_work_digest"] == expected_patch_digest, (
    f"patch digest mismatch: {predicate['submitted_work_digest']} vs {expected_patch_digest}"
)

# Assert agent volume digest matches fixture agent volume
with open(agent_meta_path) as f:
    agent_meta = json.load(f)
expected_agent_volume_digest = agent_meta["agent_volume_digest"]
assert predicate["agent_volume_digest"] == expected_agent_volume_digest, (
    f"agent volume digest mismatch: {predicate['agent_volume_digest']} vs {expected_agent_volume_digest}"
)

# Assert Mode H identity
assert predicate["agent_mode"] == "H", f"unexpected agent_mode: {predicate['agent_mode']}"

# Assert probe output exists and contains valid records
probe_lines = [json.loads(line) for line in probe_path.read_text().splitlines() if line.strip()]
assert len(probe_lines) > 0, "probe_output.jsonl is empty"

# Assert date sentinel output exists and was parsed
with open(date_sentinel_path) as f:
    date_sentinel = json.load(f)
assert "date_leak_observed" in date_sentinel, "malformed date_sentinel.json"

print(f"cli-run smoke: verified run status '{predicate['run_status']}' and patch digest '{expected_patch_digest}'")
PY

  echo "cli-run smoke: ok"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/cli-run-smoke.sh" "$@"
fi
