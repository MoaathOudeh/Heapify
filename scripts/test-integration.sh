#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "Skipping ptrace integration tests: requires Linux x86-64."
  exit 0
fi

cargo test --workspace -- --ignored
