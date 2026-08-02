#!/usr/bin/env bash
# There are now THREE cargo-deny policies — one per workspace — because the Tauri shell
# is a detached workspace and cargo-deny reads its config relative to the manifest it is
# pointed at. Three copies is three things that can drift, and a policy that silently
# applies to only one workspace is worse than no policy: it reads like coverage.
#
# The root file is authoritative. Each copy may differ ONLY by additions that are
# annotated in the file itself (the shell's extra advisory ignores and its IJG license
# allowance) — never by a *removed* ban, license restriction, or source rule. This checks
# exactly that: every `deny`, `allow`, `unknown-*`, and policy line present at the root
# must also be present in each copy.
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="deny.toml"
COPIES=("clients/deny.toml" "clients/desktop/src-tauri/deny.toml")

# The policy-bearing lines: everything that is not a comment or blank.
policy_lines() { grep -vE '^\s*(#|$)' "$1"; }

fail=0
while IFS= read -r line; do
  for copy in "${COPIES[@]}"; do
    if ! policy_lines "$copy" | grep -qxF "$line"; then
      echo "DENY-DRIFT: $copy is missing a policy line from $ROOT:"
      echo "    $line"
      fail=1
    fi
  done
done < <(policy_lines "$ROOT")

if [ "$fail" -eq 0 ]; then
  echo "deny.toml copies are in sync with $ROOT (additions allowed, removals are not)"
fi
exit "$fail"
