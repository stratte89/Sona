#!/usr/bin/env bash
# Ratchet: keep source files from growing back into monoliths. Fails if any
# non-exempt production source file exceeds MAX_LINES. The exempt list only ever
# shrinks — never add to it to make a new monolith pass; split the file instead.
set -euo pipefail
cd "$(dirname "$0")/.."

MAX_LINES=900

# Exempt (path suffix match), decided during the 2026-07 modularization
# (`git log --grep 'p[0-9]'` on the major-refactoring merge). Rationale for each:
#   media.rs             — one cohesive media-pipeline domain.
#   history/mod.rs       — the History impl is deliberately kept whole.
#   multidevice/selfsync.rs — one cohesive fan-out + history-sync domain.
EXEMPT=(
  "clients/client-core/src/media.rs"
  "clients/client-core/src/history/mod.rs"
  "clients/client-core/src/multidevice/selfsync.rs"
)

is_exempt() {
  local f="$1"
  for e in "${EXEMPT[@]}"; do [ "$f" = "$e" ] && return 0; done
  return 1
}

fail=0
# Production source only: crate/app src trees + the desktop JS. Tests, vendored
# code, generated code, and non-source assets are out of scope.
while IFS= read -r f; do
  is_exempt "$f" && continue
  n=$(grep -c '' "$f")
  if [ "$n" -gt "$MAX_LINES" ]; then
    echo "MONOLITH: $f has $n lines (> $MAX_LINES)"
    fail=1
  fi
done < <(find crates/*/src clients/client-core/src clients/desktop/src-tauri/src \
              clients/desktop/src/js -type f \( -name '*.rs' -o -name '*.js' \) \
              ! -path '*/target/*' ! -path '*/vendor/*' 2>/dev/null)

[ "$fail" -eq 0 ] && echo "no-monolith: OK (all under $MAX_LINES lines)"
exit "$fail"
