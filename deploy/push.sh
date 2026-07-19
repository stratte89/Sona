#!/usr/bin/env bash
# Manual deploy for the relay VPS. Runs ENTIRELY FROM YOUR LAPTOP — no CI, no SSH key
# ever stored in GitHub. It:
#
#   1. builds the relay + auditor in a pinned Debian-bookworm container (so the binary's
#      glibc matches the VPS; a binary built on your Mint host would fail there), then
#   2. ships the two binaries over your existing ssh alias (SONA_SSH_HOST), swaps them atomically,
#      and restarts the systemd services.
#
# Prereqs on the laptop: docker + a working ssh alias for the VPS (set SONA_SSH_HOST).
# Run the one-time server setup first: deploy/bootstrap-vps.sh (see deploy/RUNBOOK.md).
#
#   ./deploy/push.sh            # build + deploy
#   ./deploy/push.sh --build    # build only, don't touch the VPS
#   ./deploy/push.sh --clean    # drop the container build cache and exit
set -euo pipefail

REPO_EARLY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Operator config (gitignored): SONA_SSH_HOST / SONA_DOMAIN / SONA_UPDATE_BASE live in
# deploy/.env.publish so no deploy script needs them passed by hand (file wins, same
# as publish-updates.sh).
[ -f "$REPO_EARLY/deploy/.env.publish" ] && { set -a; . "$REPO_EARLY/deploy/.env.publish"; set +a; }
SSH_HOST="${SONA_SSH_HOST:?set SONA_SSH_HOST=your-vps-ssh-alias (deploy/.env.publish)}"
RUST_IMAGE="rust:1.96.0-slim-bookworm"   # bookworm == Debian 12 == the VPS glibc (2.36)
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_CACHE="${SONA_CARGO_CACHE:-$HOME/.cache/sona-vps-cargo}"
TARGET_DIR="$REPO/target/vps"            # kept out of the normal ./target (different ABI)

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

if [[ "${1:-}" == "--clean" ]]; then
	log "removing container build cache: $CARGO_CACHE and $TARGET_DIR"
	rm -rf "$CARGO_CACHE" "$TARGET_DIR"
	exit 0
fi

command -v docker >/dev/null || { echo "docker not found on this laptop" >&2; exit 1; }
mkdir -p "$CARGO_CACHE"

log "building relay + auditor in $RUST_IMAGE (glibc-matched to the VPS)"
# --user keeps the produced files owned by you (not root). CARGO_HOME points at a writable
# mounted cache so the image's root-owned /usr/local/cargo isn't touched. --locked forbids
# any Cargo.lock drift, matching the reproducible container build.
docker run --rm \
	-u "$(id -u):$(id -g)" \
	-v "$REPO":/src -w /src \
	-v "$CARGO_CACHE":/cargo \
	-e CARGO_HOME=/cargo \
	-e CARGO_TARGET_DIR=/src/target/vps \
	"$RUST_IMAGE" \
	cargo build --release --locked -p server -p auditor

RELAY_BIN="$TARGET_DIR/release/server"
AUDITOR_BIN="$TARGET_DIR/release/sona-auditor"
[[ -x "$RELAY_BIN" && -x "$AUDITOR_BIN" ]] || { echo "build did not produce the binaries" >&2; exit 1; }

log "built:"
sha256sum "$RELAY_BIN" "$AUDITOR_BIN"

if [[ "${1:-}" == "--build" ]]; then
	log "build-only; not touching $SSH_HOST"
	exit 0
fi

log "shipping to $SSH_HOST"
scp "$RELAY_BIN"   "$SSH_HOST:/tmp/sona-relay.new"
scp "$AUDITOR_BIN" "$SSH_HOST:/tmp/sona-auditor.new"

log "atomic swap + restart on $SSH_HOST"
# mv onto the same filesystem is atomic; the running process keeps its old inode until it
# restarts, so there's no torn-binary window. Then restart and report health.
ssh "$SSH_HOST" 'set -e
	chmod 0755 /tmp/sona-relay.new /tmp/sona-auditor.new
	mv -f /tmp/sona-relay.new   /usr/local/bin/sona-relay
	mv -f /tmp/sona-auditor.new /usr/local/bin/sona-auditor
	systemctl restart sona-relay
	systemctl restart sona-auditor || true
	sleep 1
	systemctl is-active sona-relay && echo "relay: up"
	systemctl is-active sona-auditor && echo "auditor: up" || echo "auditor: not active (ok if you run it elsewhere)"'

log "done. verify externally:  curl -sS https://YOUR-DOMAIN/v1/kt/pubkey"
