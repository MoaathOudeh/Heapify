#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

flags=(-g -O0 -fno-omit-frame-pointer)

build_c_example() {
  local src="$1"
  local out="${src%.c}"
  echo "CC $out"
  gcc "${flags[@]}" -o "$out" "$src"
}

for src in examples/*.c examples/corruption/*.c; do
  build_c_example "$src"
done
