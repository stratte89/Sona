#!/usr/bin/env bash
# verify-reproducible.sh — prove (or disprove) that the relay binaries are reproducible.
#
# Builds the Docker image TWICE from scratch (no shared layer cache between the two
# builds), extracts the binaries from each, and compares their SHA-256 hashes. If they
# match, anyone can rebuild this commit and confirm the operator's running binary is
# the audited source — "trust the source, not the download".
#
#     ./deploy/verify-reproducible.sh          # run from the repo root
#
# Exit 0 = bit-identical. Exit 1 = mismatch (prints both hash sets).

set -euo pipefail

cd "$(dirname "$0")/.."
command -v docker >/dev/null || { echo "error: docker required" >&2; exit 1; }

hash_binaries() { # image-tag -> "hash  name" lines
    local tag="$1"
    docker run --rm --entrypoint sh "$tag" -c \
        'sha256sum /usr/local/bin/sona-relay /usr/local/bin/sona-auditor'
}

echo "== build #1 (clean) =="
docker build --no-cache -f deploy/Dockerfile -t sona-repro-a . >/dev/null
echo "== build #2 (clean) =="
docker build --no-cache -f deploy/Dockerfile -t sona-repro-b . >/dev/null

a="$(hash_binaries sona-repro-a)"
b="$(hash_binaries sona-repro-b)"

echo "build #1:"; echo "$a"
echo "build #2:"; echo "$b"

if [ "$a" = "$b" ]; then
    echo "REPRODUCIBLE: binaries are bit-identical across independent builds."
else
    echo "NOT REPRODUCIBLE: hashes differ." >&2
    exit 1
fi
