#!/usr/bin/env bash
# Build, lint and test the Rust workspace inside WSL. The target dir lives on the Linux
# filesystem: building on /mnt/c is very slow.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/hermetic/cargo-target/$(basename "$(pwd)")}"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace "$@"
