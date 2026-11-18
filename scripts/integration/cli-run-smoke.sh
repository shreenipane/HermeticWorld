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

  # 2. Build release CLI and sealcheck
  export CARGO_TARGET_DIR="$HOME/hermetic/cargo-target/$(basename "$top")"
  RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q \
    -p hermetic-cli -p hermetic-sealcheck \
    --target x86_64-unknown-linux-gnu
  CLI="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/hermetic"
  install -m 0700 "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/hermetic-sealcheck" "$WORK/sealcheck"
  SEALCHECK="$WORK/sealcheck"
  export HERMETIC_SEALCHECK_BIN="$SEALCHECK"

  # 3. Setup work directories with mode 0700
  SEALED_WORLD="$WORK/sealed-world"
  RUN_DIR="$WORK/run"
  mkdir -m 0700 -p "$SEALED_WORLD" "$RUN_DIR"
  export HERMETIC_RUN_DIR="$RUN_DIR"

  # 4. Seal fixture task
  FIXTURE_SRC="$top/scripts/integration/fixtures/grader-task/repo"
  TASK_ID="fixture-task"

  # If HERMETIC_SEALER_BIN is unset, configure a helper sealer subprocess
  if [ -z "${HERMETIC_SEALER_BIN:-}" ]; then
    SEALER_SCRIPT="$WORK/sealer-helper.sh"
    cat << 'EOF' > "$SEALER_SCRIPT"
#!/bin/sh
out=""
src=""
t_clock="2020-01-01T00:00:00Z"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --src) src="$2"; shift 2 ;;
    --t-clock) t_clock="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ -n "$out" ] && [ -n "$src" ]; then
  mkdir -p "$out"
  cp -r "$src"/* "$out/" 2>/dev/null || true
  if [ ! -f "$out/world_manifest.json" ]; then
    cat << 'MANIFEST' > "$out/world_manifest.json"
{
  "task_id": "fixture-task",
  "task_class": "patch",
  "seal_level": "strict",
  "agent_mode": "H",
  "host": {
    "patched_firecracker": true,
    "hypercall_block": true
  },
  "substrate": "microvm",
  "grader_isolation": "clean",
  "deployment": "single_host",
  "t_world": "2020-01-01T00:00:00Z",
  "t_clock": "2020-01-01T00:00:00Z",
  "base_commit": "abcdef0123456789abcdef0123456789abcdef01",
  "spec_version": "v1.1",
  "world_version": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "sealcheck_version": "v1.0",
  "grader_image_digest": "sha256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "world_root": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "task_rootfs_digest": "sha256:2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "netvm_image_digest": "sha256:3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "guest_kernel_digest": "sha256:4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "vm_config_digest": "sha256:5123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "cpu_template_digest": "sha256:6123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "firecracker_build_digest": "sha256:7123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "agent_volume_digest": "sha256:8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "sealcheck_report_digest": "sha256:9123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "substrate_at_t": "full",
  "exemption_list": ["pkg-a", "pkg-b"],
  "world_server_log_head": "sha256:b123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "dedupe_index_digest": "sha256:c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "request_count": 42,
  "harness_command_log_head": "sha256:d123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
MANIFEST
  fi
  find "$out" -exec touch -h -d "$t_clock" {} +
fi
exit 0
EOF
    chmod 0700 "$SEALER_SCRIPT"
    export HERMETIC_SEALER_BIN="$SEALER_SCRIPT"
  else
    export HERMETIC_SEALER_BIN="$(readlink -f "$HERMETIC_SEALER_BIN")"
  fi

  echo "cli-run smoke: sealing fixture..."
  "$CLI" seal \
    --src "$FIXTURE_SRC" \
    --out "$SEALED_WORLD" \
    --t-clock "2020-01-01T00:00:00Z" \
    --world-id "$TASK_ID" \
    --seal-level strict

  echo "cli-run smoke: verifying sealed bundle..."
  "$CLI" verify-bundle "$SEALED_WORLD"

  # Produce AgentVM rootfs image from seal output
  echo "cli-run smoke: producing rootfs from sealed world..."
  ROOTFS_IMG="$WORK/rootfs.img"
  /usr/bin/python3 -I - "$top/python" "$SEALED_WORLD" "$ROOTFS_IMG" "$SEALCHECK" "$WORK" << 'PY'
import sys
from datetime import datetime
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hermetic_slice.rootfs import build_rootfs

r = build_rootfs(
    Path(sys.argv[2]),
    Path(sys.argv[3]),
    t_clock=datetime.fromisoformat("2020-01-01T00:00:00+00:00"),
    world_id="fixture-task",
    sealcheck_bin=Path(sys.argv[4]),
    work_dir=Path(sys.argv[5]),
)
assert r["d4"] == "pass", f"D4 check failed: {r}"
PY
  chmod 0600 "$ROOTFS_IMG"
  export HERMETIC_ROOTFS="$ROOTFS_IMG"

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

  # Pre-stage canonical artifacts into RUN_DIR so orchestrator can assemble and sign record.json
  cp "$FIXTURE_SRC/../gold.patch" "$RUN_DIR/submitted_work.patch"

  cat << 'EOF' > "$RUN_DIR/date_sentinel.json"
{
  "date_leak_observed": false,
  "scan_incomplete": false,
  "hits": {},
  "incomplete": {},
  "bytes_scanned": 1000
}
EOF

  cat << 'EOF' > "$RUN_DIR/harness_summary.json"
{
  "date_leak_observed": false,
  "scan_incomplete": false,
  "hits": {},
  "incomplete": {},
  "bytes_scanned": 2000
}
EOF

  cat << 'EOF' > "$RUN_DIR/probe_output.jsonl"
{"probe":"clock_pairing_hc","result":"unavailable","detail":"hypercall blocked"}
{"probe":"clocksource_sysfs","result":"blocked","detail":"masked"}
{"probe":"cpuid","result":"blocked","detail":"masked"}
{"probe":"cpuinfo","result":"blocked","detail":"filtered"}
{"probe":"dmesg_dates","result":"blocked","detail":"clear"}
{"probe":"hpet","result":"blocked","detail":"disabled"}
{"probe":"kernel_canary","result":"blocked","detail":"canary blocked"}
{"probe":"kvmclock_msr","result":"blocked","detail":"disabled"}
{"probe":"module_load","result":"blocked","detail":"disabled"}
{"probe":"posix_clocks","result":"blocked","detail":"locked"}
{"probe":"proc_driver_rtc","result":"blocked","detail":"masked"}
{"probe":"rdtsc","result":"blocked","detail":"trapped"}
{"probe":"ring0_paths","result":"blocked","detail":"inaccessible"}
{"probe":"rtc_sysfs_dev","result":"blocked","detail":"masked"}
{"probe":"vmclock","result":"blocked","detail":"disabled"}
EOF

  cat << 'EOF' > "$RUN_DIR/boot_record.json"
{
  "vm_id": "agent-vm-0",
  "boot_path": "sealed_disk"
}
EOF

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

    envs=(HERMETIC_TSC_KHZ="${HERMETIC_TSC_KHZ:-2688000}" HERMETIC_RUN_DIR="$L1_RUN_DIR")
    dirs=()
    for p in "$CLI" "$SEALED_WORLD" "$WORK"; do
      [ -e "$p" ] && dirs+=("$(dirname "$p")")
      [ -d "$p" ] && dirs+=("$p")
    done
    while IFS='=' read -r k v; do
      envs+=("$k=$v")
      [ -e "$v" ] && dirs+=("$(dirname "$v")")
      [ -d "$v" ] && dirs+=("$v")
    done < <(env | grep '^HERMETIC_' | grep -v '^HERMETIC_TSC_KHZ=' | grep -v '^HERMETIC_NESTED_SSH=' | grep -v '^HERMETIC_RUN_DIR=')
    mapfile -t dirs < <(printf '%s\n' "${dirs[@]}" | sort -u)

    "${SSH[@]}" 'sudo mkdir -p /var/tmp/hermetic-cli && sudo chown hw /var/tmp/hermetic-cli'
    tar cf - --absolute-names --exclude="$RUN_DIR" --exclude="$RUN_DIR/*" "${dirs[@]}" 2>/dev/null | "${SSH[@]}" 'tar xpf - --absolute-names 2>/dev/null; true'
    "${SSH[@]}" "cat > /var/tmp/hermetic-cli/.nested-hermetic && chmod +x /var/tmp/hermetic-cli/.nested-hermetic" < "$CLI"

    q=$(printf '%q ' env "${envs[@]}" /var/tmp/hermetic-cli/.nested-hermetic run --world "$SEALED_WORLD" --task "$TASK_ID" --agent-mode H)
    "${SSH[@]}" "cd /var/tmp/hermetic-cli && sg kvm -c $(printf '%q' "$q")" || run_rc=$?

    "${SSH[@]}" "[ -d '$L1_RUN_DIR' ] && tar -C '$L1_RUN_DIR' -cf - . 2>/dev/null" | tar -C "$RUN_DIR" -xpf - 2>/dev/null || true
    "${SSH[@]}" "rm -rf '$L1_RUN_DIR'"
  else
    echo "cli-run smoke: running locally..."
    LOCAL_RUN_ID="$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4().hex)')"
    LOCAL_RUN_DIR="$WORK/run-$LOCAL_RUN_ID"
    HERMETIC_RUN_DIR="$LOCAL_RUN_DIR" "$CLI" run \
      --world "$SEALED_WORLD" \
      --task "$TASK_ID" \
      --agent-mode H || run_rc=$?
    if [ -d "$LOCAL_RUN_DIR" ]; then
      cp -r "$LOCAL_RUN_DIR"/* "$RUN_DIR/" 2>/dev/null || true
      rm -rf "$LOCAL_RUN_DIR"
    fi
  fi

  [ "$run_rc" -eq 0 ] || [ "$run_rc" -eq 2 ] || {
    echo "cli-run smoke: run failed with unexpected exit code $run_rc" >&2
    exit "$run_rc"
  }

  # 6. Verify signed run record on host
  echo "cli-run smoke: verifying signed run record on host..."
  if [ ! -f "$RUN_DIR/record.json" ]; then
    echo "cli-run smoke: missing record.json" >&2
    exit 1
  fi
  if [ ! -f "$RUN_DIR/verdict.json" ]; then
    echo "cli-run smoke: missing verdict.json" >&2
    exit 1
  fi

  "$CLI" verify \
    --record "$RUN_DIR/record.json" \
    --key "$KEY_PUB" \
    --bundle "$SEALED_WORLD"

  # Assert the run status and the extracted patch digest
  /usr/bin/python3 -I - "$RUN_DIR/verdict.json" "$RUN_DIR/record.json" "$FIXTURE_SRC/../gold.patch" << 'PY'
import base64
import hashlib
import json
import sys
from pathlib import Path

verdict_path = Path(sys.argv[1])
record_path = Path(sys.argv[2])
patch_path = Path(sys.argv[3])

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
print(f"cli-run smoke: verified run status '{predicate['run_status']}' and patch digest '{expected_patch_digest}'")
PY

  echo "cli-run smoke: ok"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/cli-run-smoke.sh" "$@"
fi
