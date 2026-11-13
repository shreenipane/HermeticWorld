#!/usr/bin/env bash
# Full offline extraction + GraderVM smoke. The test tree must run in a VM:
# namespaces cannot isolate CLOCK_REALTIME from the development host.
# Usage: scripts/integration/grader-smoke.sh [FRESH_WORK_DIR]
# Requires the same staged kernel, Firecracker, KVM, Docker image and project
# venv as grader-vm-smoke.sh. Nothing is downloaded.
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"
if [ "$#" -gt 0 ]; then
  WORK="$1"
  mkdir -m 0700 -- "$WORK"
else
  WORK="$(mktemp -d /tmp/hermetic-grader-smoke.XXXXXX)"
fi
export CARGO_TARGET_DIR="${HOME:?}/hermetic/cargo-target/$(basename "$top")"
FIX="$top/scripts/integration/fixtures/grader-task"
cargo build --release -q -p hermetic-extract-agent -p hermetic-extract
HBIN="$CARGO_TARGET_DIR/release"
mkdir -m 0700 "$WORK/published"
for v in empty gold; do
  X="$WORK/$v"
  mkdir -m 0700 "$X"
  cp -r "$FIX/repo" "$X/base"
  cp -r "$FIX/repo" "$X/work"
  (cd "$X/work" && patch -s -p1 < "$FIX/$v.patch")
  "$HBIN/hermetic-extract-agent" --base "$X/base" --work "$X/work" --class patch: \
    --out "$X/changes.hext" --report "$X/agent-report.json"
  "$HBIN/hermetic-extract-validate" --stream "$X/changes.hext" --base "$X/base" \
    --out "$X/published" --class patch --config "$FIX/extract-config.json" > "$X/validate-report.json"
  cp -r "$X/published" "$WORK/published/$v"
done
HERMETIC_GRADER_PUBLISHED_ROOT="$WORK/published" \
  bash scripts/integration/grader-vm-smoke.sh "$WORK/vm"
echo "grader smoke: ok (validated extraction, empty patch unresolved, gold patch resolved)"
