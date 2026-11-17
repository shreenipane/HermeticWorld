#!/usr/bin/env bash
# Development ExtractorVM smoke test (offline, KVM, no jailer).
# Boots ExtractorVM through hermetic-vmm's dev-unjailed runner with
# init=/sbin/hermetic-extract-init (no vsock, no network), waits for the guest to power
# off, checks the validated result on the host:
#   - a modified file (calc.py)
#   - a new file (fresh.txt)
#   - a deletion (gone.txt)
#   - a symlink (rejected / skipped)
#   - a .git change (ignored)
#   - a conftest.py change (restored)
# Usage: scripts/integration/extract-vm-smoke.sh [WORK_DIR]   (run from the worktree root)
# Needs: /dev/kvm, mke2fs >= 1.47.1, Firecracker, the 6.6 kernel build.
set -euo pipefail
top="$(git rev-parse --show-toplevel)"
cd "$top"

smoke_main() {
WORK="${HERMETIC_SMOKE_WORK:?}"
U="${HOME:?}"
export CARGO_TARGET_DIR="$U/hermetic/cargo-target/$(basename "$top")"
hermetic_home="${HERMETIC_HOME:-$(readlink -f "$U/.hermetic")}"
if [ -z "${HERMETIC_FC_BIN:-}" ] && [ -x "$hermetic_home/fcbuild/out/patched/firecracker" ]; then
  FC="$hermetic_home/fcbuild/out/patched/firecracker"
else
  FC="${HERMETIC_FC_BIN:-$hermetic_home/tools/firecracker-1.18.0/firecracker}"
fi
if [ -z "${HERMETIC_FIRECRACKER_LOCK:-}" ] && [ -f "$hermetic_home/fcbuild/out/patched/firecracker.lock.json" ]; then
  export HERMETIC_FIRECRACKER_LOCK="$hermetic_home/fcbuild/out/patched/firecracker.lock.json"
fi
KERNEL="${HERMETIC_KERNEL:-$hermetic_home/cache/kernel-out-20261113-6.6b/vmlinux}"
T=1700000000
umask 022

# 0. Static guest binaries and host tools.
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -q \
  -p hermetic-extract-agent -p hermetic-sealcheck -p hermetic-extract \
  --bin hermetic-extract-init --bin hermetic-extract-agent \
  --bin hermetic-extract-validate --bin hermetic-sealcheck \
  --target x86_64-unknown-linux-gnu
BIN="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
install -m 0700 "$BIN/hermetic-sealcheck" "$WORK/sealcheck"

# Build the guest boot test binary once
cargo test -p hermetic-vmm --features dev-unjailed --test guest --no-run

# 1. Build clean ExtractorVM rootfs image with D4 guard.
EXTRACTOR_TREE="$WORK/extractor_tree"
EXTRACTOR_IMG="$WORK/extractor.img"
/usr/bin/python3 -I - "$top/python" "$EXTRACTOR_TREE" "$EXTRACTOR_IMG" "$BIN/hermetic-extract-init" "$BIN/hermetic-extract-agent" "$WORK/sealcheck" "$WORK" <<'PY'
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
    t_clock=datetime.fromtimestamp(1700000000, timezone.utc),
    world_id="extractor-smoke",
    sealcheck_bin=Path(sys.argv[6]),
    work_dir=Path(sys.argv[7]),
)
assert r["d4"] == "pass", r
PY
chmod 0400 "$EXTRACTOR_IMG"

# 2. Build base ext4 image and overlay ext4 image.
BASE_IMG="$WORK/base.img"
OVERLAY_IMG="$WORK/overlay.img"

/usr/bin/python3 -I - "$BASE_IMG" "$OVERLAY_IMG" "$WORK" <<'PY'
import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

base_img = Path(sys.argv[1])
overlay_img = Path(sys.argv[2])
work_dir = Path(sys.argv[3])
epoch = 1700000000

# Base tree tar:
# - calc.py (original)
# - gone.txt (file to be deleted)
# - conftest.py (base test infra)
# - .git (directory entry before .git/config)
# - .git/config (base git config)
base_tar_path = work_dir / "base.tar"
with tarfile.open(base_tar_path, "w") as tar:
    ti_git = tarfile.TarInfo(name=".git")
    ti_git.type = tarfile.DIRTYPE
    ti_git.mode = 0o755
    ti_git.mtime = epoch
    tar.addfile(ti_git)

    for name, content in [
        ("calc.py", b"def add(a, b):\n    return a + b\n"),
        ("gone.txt", b"this file will be deleted\n"),
        ("conftest.py", b"# base conftest\n"),
        (".git/config", b"[core]\n\trepositoryformatversion = 0\n"),
    ]:
        ti = tarfile.TarInfo(name=name)
        ti.size = len(content)
        ti.mtime = epoch
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(content))

# Extract base tree to work_dir / "base_tree" for host validator
base_tree_dir = work_dir / "base_tree"
base_tree_dir.mkdir(mode=0o700, exist_ok=True)
with tarfile.open(base_tar_path, "r") as tar:
    tar.extractall(base_tree_dir)

# Create base ext4 image (32 MiB)
base_img.write_bytes(b"\0" * (32 * 1024 * 1024))
subprocess.run([
    "/usr/sbin/mke2fs",
    "-q",
    "-t", "ext4",
    "-b", "4096",
    "-d", str(base_tar_path),
    str(base_img),
], check=True)

# Overlay tree tar:
# upper/:
# - calc.py (modified)
# - fresh.txt (new file)
# - gone.txt (whiteout character device major=0, minor=0)
# - link.txt (symlink -> calc.py, to be rejected)
# - conftest.py (modified by agent, to be restored)
# - .git/config (modified by agent, to be ignored)
# work/: (empty dir for overlayfs)
overlay_tar_path = work_dir / "overlay.tar"
with tarfile.open(overlay_tar_path, "w") as tar:
    # upper dir
    ti_upper = tarfile.TarInfo(name="upper")
    ti_upper.type = tarfile.DIRTYPE
    ti_upper.mode = 0o755
    ti_upper.mtime = epoch
    tar.addfile(ti_upper)

    # work dir
    ti_work = tarfile.TarInfo(name="work")
    ti_work.type = tarfile.DIRTYPE
    ti_work.mode = 0o755
    ti_work.mtime = epoch
    tar.addfile(ti_work)

    # upper/calc.py (modified)
    calc_mod = b"def add(a, b):\n    return a + b + 1\n"
    ti = tarfile.TarInfo(name="upper/calc.py")
    ti.size = len(calc_mod)
    ti.mtime = epoch
    ti.mode = 0o644
    tar.addfile(ti, io.BytesIO(calc_mod))

    # upper/fresh.txt (new file)
    fresh = b"hello fresh file\n"
    ti = tarfile.TarInfo(name="upper/fresh.txt")
    ti.size = len(fresh)
    ti.mtime = epoch
    ti.mode = 0o644
    tar.addfile(ti, io.BytesIO(fresh))

    # upper/gone.txt (whiteout: character device 0:0)
    ti_wh = tarfile.TarInfo(name="upper/gone.txt")
    ti_wh.type = tarfile.CHRTYPE
    ti_wh.devmajor = 0
    ti_wh.devminor = 0
    ti_wh.mode = 0o000
    ti_wh.mtime = epoch
    tar.addfile(ti_wh)

    # upper/link.txt (symlink)
    ti_sym = tarfile.TarInfo(name="upper/link.txt")
    ti_sym.type = tarfile.SYMTYPE
    ti_sym.linkname = "calc.py"
    ti_sym.mode = 0o777
    ti_sym.mtime = epoch
    tar.addfile(ti_sym)

    # upper/conftest.py (modified test infra)
    conftest_mod = b"# modified conftest by agent\n"
    ti = tarfile.TarInfo(name="upper/conftest.py")
    ti.size = len(conftest_mod)
    ti.mtime = epoch
    ti.mode = 0o644
    tar.addfile(ti, io.BytesIO(conftest_mod))

    # upper/.git/config (modified git config)
    git_mod = b"[core]\n\trepositoryformatversion = 0\n# hostile agent git\n"
    ti_git = tarfile.TarInfo(name="upper/.git")
    ti_git.type = tarfile.DIRTYPE
    ti_git.mode = 0o755
    ti_git.mtime = epoch
    tar.addfile(ti_git)

    ti = tarfile.TarInfo(name="upper/.git/config")
    ti.size = len(git_mod)
    ti.mtime = epoch
    ti.mode = 0o644
    tar.addfile(ti, io.BytesIO(git_mod))

# Create overlay ext4 image (32 MiB)
overlay_img.write_bytes(b"\0" * (32 * 1024 * 1024))
subprocess.run([
    "/usr/sbin/mke2fs",
    "-q",
    "-t", "ext4",
    "-b", "4096",
    "-d", str(overlay_tar_path),
    str(overlay_img),
], check=True)
PY

chmod 0400 "$BASE_IMG"

# 3. Create host CoW copy of overlay (host never mounts agent disk, TR-EXT-1).
OVERLAY_COW="$WORK/overlay_cow.img"
cp --reflink=auto "$OVERLAY_IMG" "$OVERLAY_COW"
chmod 0600 "$OVERLAY_COW"

OUTPUT_IMG="$WORK/output.img"
# Prepare initial output file (16 MiB)
truncate -s 16M "$OUTPUT_IMG"
chmod 0600 "$OUTPUT_IMG"

# 4. Boot ExtractorVM, wait for power-off, collect output drive.
HERMETIC_FC_BIN="$FC" HERMETIC_KERNEL="$KERNEL" \
HERMETIC_FIRECRACKER_LOCK="${HERMETIC_FIRECRACKER_LOCK:-}" \
HERMETIC_EXTRACT_ROOTFS="$EXTRACTOR_IMG" \
HERMETIC_EXTRACT_BASE="$BASE_IMG" \
HERMETIC_EXTRACT_BASE_DIR="$WORK/base_tree" \
HERMETIC_EXTRACT_OVERLAY_COW="$OVERLAY_COW" \
HERMETIC_EXTRACT_OUTPUT="$OUTPUT_IMG" \
HERMETIC_EXTRACT_TASK="patch:" \
  timeout 400 cargo test -q -p hermetic-vmm --features dev-unjailed --test guest \
  boots_extractor_and_collects_output_drive -- --ignored --nocapture --exact 2>&1 \
  | grep -E '^extractor serial:|^extractor stderr:|^extractor outcome:|test result:|panicked'

[ -s "$OUTPUT_IMG" ] || { echo "ExtractorVM smoke FAILED: output.img is missing or empty" >&2; exit 1; }

# 5. Check and validate output drive on host.
/usr/bin/python3 -I - "$OUTPUT_IMG" "$WORK" "$BIN/hermetic-extract-validate" <<'PY'
import json
import struct
import subprocess
import sys
import hashlib
from pathlib import Path

img_path = Path(sys.argv[1])
work_dir = Path(sys.argv[2])
validate_bin = Path(sys.argv[3])

data = img_path.read_bytes()
assert len(data) >= 80, "Output drive must be at least 80 bytes"

# Output drive header matching crates/hermetic-extract/src/disk.rs (ExtractDiskHeader)
# Header v2 (80 bytes, big-endian): magic(4), version(2), failure_code(2), length(8), nonce(32), sha256(32)
HEADER_SIZE = 80
assert len(data) >= HEADER_SIZE, f"Output drive must be at least {HEADER_SIZE} bytes"
magic, version, failure_code, length, nonce, sha256 = struct.unpack_from(">4sHHQ32s32s", data, 0)

assert magic == b"HEXD", f"Invalid magic: {magic}"
assert version == 2, f"Unsupported version: {version}"
assert failure_code == 0, f"Extraction failed with code {failure_code}"
assert length > 0, "Extraction failed: length is 0 (failure header)"
assert len(nonce) == 32, f"Invalid nonce length: {len(nonce)}"
assert len(sha256) == 32, f"Invalid sha256 length: {len(sha256)}"

payload = data[HEADER_SIZE:HEADER_SIZE + length]
assert len(payload) == length, f"Truncated payload: expected {length}, got {len(payload)}"
computed_sha256 = hashlib.sha256(payload).digest()
assert sha256 == computed_sha256, "Payload SHA-256 mismatch"

# Stream records matching crates/hermetic-extract-agent/src/stream.rs
# Stream header: magic b"HEXT" (4), version 1 (u32 little-endian)
smagic, sversion = struct.unpack_from("<4sI", payload, 0)
assert smagic == b"HEXT", f"Invalid stream magic: {smagic}"
assert sversion == 1, f"Invalid stream version: {sversion}"

# Record types matching crates/hermetic-extract-agent/src/stream.rs (and format.rs)
RECORD_TYPE_FILE = 1
RECORD_TYPE_DIR = 2
RECORD_TYPE_DELETE = 3
RECORD_TYPE_END = 4

# Record header layout matching RECORD_HEADER_SIZE (60 bytes, little-endian):
# type(1B), flags(1B), reserved(2B), path_len(4B), mode(4B), size(8B), record_count(8B), sha256(32B)
RECORD_HEADER_FORMAT = "<BB2sIIQQ32s"
RECORD_HEADER_SIZE = 60

# Records parse
records = []
offset = 8
while offset + RECORD_HEADER_SIZE <= len(payload):
    rtype, rflags, rreserved, path_len, rmode, data_len, rcount, rsha256 = struct.unpack_from(
        RECORD_HEADER_FORMAT, payload, offset
    )
    offset += RECORD_HEADER_SIZE
    path = payload[offset:offset + path_len].decode("utf-8") if path_len > 0 else ""
    offset += path_len

    if rtype == RECORD_TYPE_END:
        records.append((rtype, path, b""))
        break
    elif rtype == RECORD_TYPE_FILE:
        body = payload[offset:offset + data_len]
        offset += data_len
        assert hashlib.sha256(body).digest() == rsha256, f"File {path} SHA-256 mismatch"
        records.append((rtype, path, body))
    elif rtype in (RECORD_TYPE_DIR, RECORD_TYPE_DELETE):
        records.append((rtype, path, b""))
    else:
        raise AssertionError(f"Unknown record type: {rtype}")

paths = {r[1]: r for r in records}

# Assertions:
# 1. Modified file: calc.py
assert "calc.py" in paths, "calc.py missing from records"
assert paths["calc.py"][0] == RECORD_TYPE_FILE, f"calc.py should be regular file (type {RECORD_TYPE_FILE}), got {paths['calc.py'][0]}"
assert b"return a + b + 1" in paths["calc.py"][2], "calc.py content not modified"

# 2. New file: fresh.txt
assert "fresh.txt" in paths, "fresh.txt missing from records"
assert paths["fresh.txt"][0] == RECORD_TYPE_FILE, f"fresh.txt should be regular file (type {RECORD_TYPE_FILE}), got {paths['fresh.txt'][0]}"
assert b"hello fresh file" in paths["fresh.txt"][2], "fresh.txt content missing"

# 3. Deletion: gone.txt
assert "gone.txt" in paths, "gone.txt missing from records"
assert paths["gone.txt"][0] == RECORD_TYPE_DELETE, f"gone.txt should be deletion record (type {RECORD_TYPE_DELETE}), got {paths['gone.txt'][0]}"

# 4. Symlink: link.txt rejected/skipped
assert "link.txt" not in paths, "link.txt should NOT be emitted in stream"

# 5. .git change ignored
assert not any(".git" in p for p in paths), f".git change must be ignored, found: {list(paths.keys())}"

# 6. conftest.py restored from base:
# Write payload to changes.hext, run host validator, and check output tree and report.
changes_hext = work_dir / "changes.hext"
changes_hext.write_bytes(payload)

base_tree = work_dir / "base_tree"
published_tree = work_dir / "published"
published_tree.mkdir(mode=0o700, exist_ok=True)
config_path = work_dir / "extract-config.json"
config_path.write_text('{"repo_dir":""}\n')
report_path = work_dir / "validate-report.json"

proc = subprocess.run([
    str(validate_bin),
    "--stream", str(changes_hext),
    "--base", str(base_tree),
    "--out", str(published_tree),
    "--class", "patch",
    "--config", str(config_path),
], capture_output=True, text=True, check=True)
report_path.write_text(proc.stdout)

report = json.loads(proc.stdout)

# Check host validator's output tree has conftest.py byte-identical to base
base_conftest = (base_tree / "conftest.py").read_bytes()
published_conftest = (published_tree / "conftest.py").read_bytes()
assert published_conftest == base_conftest, (
    f"conftest.py in published output ({published_conftest!r}) must be byte-identical to base ({base_conftest!r})"
)

# Check that the report lists it as restored
restored_paths = [r["path"] for r in report.get("restored", [])]
assert "conftest.py" in restored_paths, (
    f"conftest.py must be listed as restored in validator report: {report.get('restored')}"
)

print("extractor smoke assertions passed successfully")
PY

echo "extractor VM smoke: ok (calc.py modified, fresh.txt added, gone.txt deleted, link.txt skipped, .git ignored, conftest.py restored)"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  exec /usr/bin/python3 -I "$top/scripts/integration/smoke_work.py" "$top/scripts/integration/extract-vm-smoke.sh" "$@"
fi
