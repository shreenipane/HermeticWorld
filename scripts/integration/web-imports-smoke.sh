#!/usr/bin/env bash
# Development smoke test for Phase 4 web archive imports (no jailer / KVM):
# imports Common Crawl WARC/CDX, Wayback CDX, Software Heritage snapshots,
# and Stack Exchange post history data dumps as of cutoff into replay archives
# and Tantivy BM25 indices, served and verified over hermetic-world-server.
# Usage from worktree root: bash scripts/integration/web-imports-smoke.sh [WORK_DIR]
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"

smoke_main() {
PY="${HERMETIC_PYTHON:-/usr/bin/python3}"
  WORK="${HERMETIC_SMOKE_WORK:?supply work directory}"
  U="${HOME:?}"

  FC_BIN="${HERMETIC_FC_BIN:?set measured patched Firecracker binary}"
  FC_LOCK="${HERMETIC_FIRECRACKER_LOCK:?set measured patched Firecracker build lock}"
  KERNEL="${HERMETIC_KERNEL:-$U/.hermetic/cache/kernel-out-20261113-6.6b/vmlinux}"

  # Resolve symlinked paths with readlink -f
  HERMETIC_FC_BIN="$(readlink -f "$FC_BIN")"
  HERMETIC_FIRECRACKER_LOCK="$(readlink -f "$FC_LOCK")"
  HERMETIC_KERNEL="$(readlink -f "$KERNEL")"
  export HERMETIC_FC_BIN HERMETIC_FIRECRACKER_LOCK HERMETIC_KERNEL

  [ -x "$HERMETIC_FC_BIN" ] || { echo "Firecracker binary not executable: $HERMETIC_FC_BIN" >&2; exit 2; }
  [ -f "$HERMETIC_FIRECRACKER_LOCK" ] || { echo "Firecracker lock file not found: $HERMETIC_FIRECRACKER_LOCK" >&2; exit 2; }
  [ -f "$HERMETIC_KERNEL" ] || { echo "Kernel image not found: $HERMETIC_KERNEL" >&2; exit 2; }

  umask 022
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$top/target/web-imports-smoke}"
  mkdir -m 0700 -p "$WORK/staging" "$WORK/blobs" "$WORK/index" "$WORK/server-log"

  # 1. Build hermetic-world-server
  cargo build --release -q -p hermetic-world-server
  SERVER_BIN="$CARGO_TARGET_DIR/release/hermetic-world-server"
  [ -x "$SERVER_BIN" ] || SERVER_BIN="$top/target/release/hermetic-world-server"

  # 2. Run offline test suite for archive importers
  "$PY" -m pytest -q python/tests/test_archive_importers.py

  # 3. Create synthetic multi-source fixture and run CLI import
  CUTOFF="2023-04-01T00:00:00Z"
  MONTH="2023-04"

  POST_HISTORY_XML="$WORK/staging/PostHistory.xml"
  cat > "$POST_HISTORY_XML" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<posthistory>
  <row Id="1" PostHistoryTypeId="1" PostId="42" CreationDate="2023-01-01T00:00:00.000" Text="Hermetic World Web Import Guide" />
  <row Id="2" PostHistoryTypeId="2" PostId="42" CreationDate="2023-01-01T00:00:00.000" Text="Learn how to import and rebuild posts from post history." />
  <row Id="3" PostHistoryTypeId="4" PostId="42" CreationDate="2024-01-01T00:00:00.000" Text="Future Leaked Title" />
  <row Id="4" PostHistoryTypeId="5" PostId="42" CreationDate="2024-01-01T00:00:00.000" Text="Future Leaked Body" />
</posthistory>
XML

  PYTHONPATH=python "$PY" -m hermetic_archive import-stack-exchange \
    --history "$POST_HISTORY_XML" \
    --cutoff "$CUTOFF" \
    --output-dir "$WORK/staging/out"

  # 4. Verify rebuilt artifacts and build Tantivy index
  [ -f "$WORK/staging/out/replay-recipe.json" ] || { echo "Missing replay-recipe.json" >&2; exit 1; }
  [ -f "$WORK/staging/out/search-recipe.json" ] || { echo "Missing search-recipe.json" >&2; exit 1; }

  "$SERVER_BIN" index \
    --recipe "$WORK/staging/out/search-recipe.json" \
    --blobs "$WORK/staging/out/blobs" \
    --month "$MONTH" \
    --output "$WORK/index"

  echo "web-imports smoke: ok (offline importer suite for all four sources passed; a Stack Exchange import built a search index; replay and search serving are not exercised here)"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  if [ "$#" -ge 1 ]; then
    WORK="$1"
    mkdir -m 0700 -p "$WORK"
    HERMETIC_SMOKE_WORK="$WORK" smoke_main
  else
    exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/web-imports-smoke.sh" "$@"
  fi
fi
