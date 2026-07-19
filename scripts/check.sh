#!/usr/bin/env bash
# Full local gate — mirrors ci.yml exactly (incl. the clients feature flags).
set -euo pipefail
cd "$(dirname "$0")/.."

check_ws() { # dir, extra cargo flags
  echo "==> workspace: $1"
  (cd "$1" && cargo fmt --all --check)
  (cd "$1" && cargo test $2)
  (cd "$1" && cargo clippy --all-targets $2 -- -D warnings)
}
check_ws .       ""                          # backend
check_ws clients "--features os-keyring"     # clients (matches ci.yml matrix)

# Frontend: syntax + no duplicate top-level bindings (once js/ split exists)
if compgen -G "clients/desktop/src/js/*.js" > /dev/null; then
  command -v node >/dev/null || { echo "node required for JS checks"; exit 1; }
  for f in clients/desktop/src/js/*.js; do node --check "$f"; done
  dups=$(grep -hoE '^(let|const|var|function|async function) [A-Za-z_$][A-Za-z0-9_$]*' \
         clients/desktop/src/js/*.js | awk '{print $NF}' | sort | uniq -d)
  [ -z "$dups" ] || { echo "duplicate top-level bindings: $dups"; exit 1; }
fi
echo "ALL GREEN"
