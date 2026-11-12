#!/usr/bin/env bash
# Integration build script for the guest kernel.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <tarball-path> <output-directory>" >&2
  exit 1
fi

TARBALL="$1"
OUTPUT_DIR="$2"

if [ ! -f "$TARBALL" ]; then
  echo "Error: tarball does not exist: $TARBALL" >&2
  exit 1
fi

# Ensure output directory exists and is caller-owned and private.
mkdir -p "$OUTPUT_DIR"
chmod 0700 "$OUTPUT_DIR"

BASE_IMAGE="debian@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc"
BUILDER_TAG="hermetic/kernel-builder:6.1-v1"

# 1. Build the builder image from Dockerfile (network allowed only for this step).
docker build \
  --build-arg BASE_IMAGE="$BASE_IMAGE" \
  -t "$BUILDER_TAG" \
  -f images/kernel/Dockerfile \
  images/kernel

# Record image ID of the built builder image for lock resolution.
IMAGE_ID="$(docker inspect --format='{{.Id}}' "$BUILDER_TAG" | sed 's/^sha256://')"

# Prepare effective lock: if checked-in lock has placeholder, write resolved lock in output dir.
LOCK_FILE="images/kernel/kernel.lock.json"
if grep -q "TO-BE-FILLED-BY-OWNER" "$LOCK_FILE"; then
  TEMP_LOCK="$OUTPUT_DIR/kernel.lock.json"
  sed "s/TO-BE-FILLED-BY-OWNER/${IMAGE_ID}/g" "$LOCK_FILE" > "$TEMP_LOCK"
  LOCK_FILE="$TEMP_LOCK"
fi

# 2. Run the offline kernel build CLI (offline container, --network=none).
PYTHONBIN="$(command -v python3 || command -v python)"
PYTHONPATH=python "$PYTHONBIN" -m hermetic_slice kernel-build \
  --lock "$LOCK_FILE" \
  --tarball "$TARBALL" \
  --out "$OUTPUT_DIR"

# 3. Print the output directory's build record.
cat "$OUTPUT_DIR/build-record.json"
