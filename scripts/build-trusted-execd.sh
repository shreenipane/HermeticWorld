#!/usr/bin/env bash
# Build the static PID 1 inputs without host source paths in their bytes.
set -euo pipefail
refuse() { printf 'Trusted executable build refused\n' >&2; exit 2; }
top="$(git rev-parse --show-toplevel 2>/dev/null)" || refuse
cd "$top" 2>/dev/null || refuse
cargo_home="${CARGO_HOME:-}"
if [ -z "$cargo_home" ]; then
  [ -n "${HOME:-}" ] || refuse
  cargo_home="$HOME/.cargo"
fi
cargo_home="$(realpath -e -- "$cargo_home" 2>/dev/null)" || refuse
separator=$'\x1f'
# Cargo's encoded form preserves paths containing spaces as single arguments.
export CARGO_ENCODED_RUSTFLAGS="-C${separator}target-feature=+crt-static${separator}--remap-path-prefix=$top=/src${separator}--remap-path-prefix=$cargo_home=/cargo"
cargo build --offline --locked --release -p hermetic-execd --target x86_64-unknown-linux-gnu \
  >/dev/null 2>&1 || refuse
