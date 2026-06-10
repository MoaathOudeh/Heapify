#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

./scripts/build-examples.sh

cargo run -p heapify-cli -- trace-heap --allocator-views basic ./examples/simple_malloc
cargo run -p heapify-cli -- trace-heap --allocator-views basic --json-out /tmp/heapify-smoke.ndjson ./examples/simple_malloc
cargo run -p heapify-cli -- replay /tmp/heapify-smoke.ndjson
