#!/usr/bin/env bash
# Local CI gate for greentic-update. Mirrors the canonical host-crate checks.
set -euo pipefail

TOOLCHAIN=${TOOLCHAIN:-1.95.0}

run_cargo() {
  cargo +"$TOOLCHAIN" "$@"
}

echo ">> fmt"
run_cargo fmt --all -- --check

echo ">> clippy"
run_cargo clippy --workspace --all-targets --all-features -- -D warnings

echo ">> tests"
run_cargo test --workspace --all-features
