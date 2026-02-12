#!/bin/bash
set -euo pipefail

# Only run in remote (Claude Code on the web) environments
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# Install the Rust toolchain specified in rust-toolchain.toml (1.93 with clippy + rustfmt)
rustup show

# Build the project to cache compiled dependencies
cargo build --features bin

# Build test dependencies so cargo test doesn't need to compile from scratch
cargo test --no-run
