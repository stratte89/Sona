#!/usr/bin/env bash
# Regenerate src/hwenc/nvenc/abi_gen.rs from the vendored nvEncodeAPI.h.
#
# Run by hand after changing the vendored header; the build never runs it, because the
# build must keep working on a machine with no NVIDIA anything on it.
set -euo pipefail
cd "$(dirname "$0")"

out=../../src/hwenc/nvenc/abi_gen.rs
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

gcc -std=c11 -Wall -Wextra -I. -o "$tmp/abi_probe" abi_probe.c
"$tmp/abi_probe" > "$tmp/abi_gen.rs"
mv "$tmp/abi_gen.rs" "$out"
# CI checks `cargo fmt`, so the generated file has to already be formatted or every
# regeneration would show up as a diff the next fmt run undoes.
rustfmt --edition 2021 "$out"
echo "wrote $(cd "$(dirname "$out")" && pwd)/$(basename "$out")"
