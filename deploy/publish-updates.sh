#!/usr/bin/env bash
# Publish a Sona release to the operator's update channel. Runs ENTIRELY on the
# operator's machine — signing keys never touch the server, so a compromised host can
# serve outages but never forged updates (clients verify minisign; apt verifies GPG).
#
# What it produces under $OUT (default ~/.cache/sona-publish), then rsyncs to the VPS:
#
#   apt/pool/main/s/sona/sona_<v>_amd64.deb          Linux channel: a real apt repo.
#   apt/dists/stable/{Release,InRelease,Release.gpg,  Installed debs enroll it (see
#                     main/binary-amd64/Packages{,.gz}}  build.sh) -> `apt upgrade`.
#   updates/manifest.json{,.minisig}                  In-app update feed (update.rs).
#   updates/Sona_<v>_x64-setup.exe{,.minisig}         Windows installer.
#   updates/Sona-<v>-arm64.apk{,.minisig}             Android package.
#
# Publish ORDER matters and is enforced below: artifacts first, signed indexes last —
# a client can never observe an index that points at a missing file.
#
#   ./deploy/publish-updates.sh              # publish whatever artifacts exist for the
#                                            # version in tauri.conf.json
#   ./deploy/publish-updates.sh --init       # first-time: generate keys, print .env.update
#   ./deploy/publish-updates.sh --no-upload  # build the tree locally, skip rsync + gh
#
# Config (env or deploy/.env.publish, gitignored):
#   SONA_UPDATE_BASE   channel base URL, e.g. https://relay.example.org
#   SONA_SSH_HOST      ssh alias of the VPS (same one deploy/push.sh uses)
#   SONA_WWW_DIR       server dir Caddy serves the channel from (default /srv/sona-www)
#   SONA_GH_MIRROR     "1" to also mirror artifacts to a GitHub release via `gh`
#
# Keys live in ~/.config/sona-release/ :
#   minisign.key/.pub  (rsign2)  — signs manifest + exe + apk; pubkey baked into builds
#   apt-archive.gpg / GPG keyring — signs the apt Release; pubkey shipped inside the deb
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DESKTOP="$REPO/clients/desktop"
KEYDIR="${SONA_KEYDIR:-$HOME/.config/sona-release}"
OUT="${SONA_PUBLISH_DIR:-$HOME/.cache/sona-publish}"
[ -f "$REPO/deploy/.env.publish" ] && { set -a; . "$REPO/deploy/.env.publish"; set +a; }
WWW_DIR="${SONA_WWW_DIR:-/srv/sona-www}"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }
die() { echo "error: $*" >&2; exit 1; }

command -v rsign >/dev/null || die "rsign not found — cargo install rsign2"
command -v gpg   >/dev/null || die "gpg not found"

GPG_UID="Sona apt archive"

# ---------------------------------------------------------------- --init: keygen
if [[ "${1:-}" == "--init" ]]; then
  mkdir -p "$KEYDIR"; chmod 700 "$KEYDIR"
  if [ -f "$KEYDIR/minisign.key" ]; then
    log "minisign key already exists — keeping it"
  else
    log "generating minisign keypair (pick a strong password — it protects the update channel)"
    rsign generate -s "$KEYDIR/minisign.key" -p "$KEYDIR/minisign.pub"
  fi
  if gpg --list-secret-keys "$GPG_UID" >/dev/null 2>&1; then
    log "apt GPG key already exists — keeping it"
  else
    log "generating apt archive GPG key (ed25519, no expiry, no passphrase)"
    # Explicit loopback + empty passphrase: without it gpg-agent pops pinentry and a
    # passphrase gets set by accident, breaking every headless publish afterwards.
    gpg --batch --pinentry-mode loopback --passphrase '' \
      --quick-generate-key "$GPG_UID" ed25519 sign never
  fi
  gpg --export "$GPG_UID" > "$KEYDIR/apt-archive.gpg"
  log "keys ready. Put these lines in clients/desktop/.env.update :"
  echo
  echo "SONA_UPDATE_BASE=${SONA_UPDATE_BASE:-https://YOUR-DOMAIN}"
  echo "SONA_UPDATE_PUBKEY=$(grep -v '^untrusted comment' "$KEYDIR/minisign.pub" | tr -d '\n')"
  echo "SONA_APT_KEYRING=$KEYDIR/apt-archive.gpg"
  echo
  echo "and set SONA_UPDATE_BASE + SONA_SSH_HOST in deploy/.env.publish"
  exit 0
fi

[ -n "${SONA_UPDATE_BASE:-}" ] || die "SONA_UPDATE_BASE not set (deploy/.env.publish; run --init first)"
[ -f "$KEYDIR/minisign.key" ] || die "no minisign key — run: $0 --init"
gpg --list-secret-keys "$GPG_UID" >/dev/null 2>&1 || die "no apt GPG key — run: $0 --init"

VERSION="$(grep -oE '"version": *"[0-9]+\.[0-9]+\.[0-9]+"' "$DESKTOP/src-tauri/tauri.conf.json" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
[ -n "$VERSION" ] || die "cannot read version from tauri.conf.json"
log "publishing version $VERSION"

DEB="$DESKTOP/src-tauri/target/release/bundle/deb/Sona_${VERSION}_amd64.deb"
EXE="$DESKTOP/src-tauri/target/x86_64-pc-windows-msvc/release/bundle/nsis/Sona_${VERSION}_x64-setup.exe"
APK="$DESKTOP/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk"
[ -f "$DEB" ] || { log "no deb for $VERSION — Linux channel skipped this round"; DEB=""; }
[ -f "$EXE" ] || { log "no exe for $VERSION — Windows entry skipped this round"; EXE=""; }
[ -f "$APK" ] || { log "no apk — Android entry skipped this round"; APK=""; }
[ -n "$DEB$EXE$APK" ] || die "nothing to publish — build first (build.sh)"

# Sign $1 → detached signature $2. rsign insists on a TTY for the key password; when
# ~/.config/sona-release/minisign.password exists (or $SONA_MINISIGN_PW_FILE points
# elsewhere) the password is fed through a throwaway pty NON-interactively. The pty
# echoes everything fed to it, so its entire output is discarded — never captured,
# never logged — and the produced signature is self-verified before being trusted.
sign() {
  local pwfile="${SONA_MINISIGN_PW_FILE:-$KEYDIR/minisign.password}"
  if [ -f "$pwfile" ]; then
    { cat "$pwfile"; echo; } | script -qec "rsign sign -s '$KEYDIR/minisign.key' -x '$2' '$1'" /dev/null >/dev/null 2>&1 || true
  else
    rsign sign -s "$KEYDIR/minisign.key" -x "$2" "$1"
  fi
  rsign verify -p "$KEYDIR/minisign.pub" -x "$2" "$1" >/dev/null 2>&1 \
    || die "signature self-check failed for $1"
}

rm -rf "$OUT"; mkdir -p "$OUT/updates"

# ------------------------------------------------------------------- apt repo tree
if [ -n "$DEB" ]; then
  log "assembling apt repo"
  mkdir -p "$OUT/apt/pool/main/s/sona" "$OUT/apt/dists/stable/main/binary-amd64"
  cp "$DEB" "$OUT/apt/pool/main/s/sona/"
  # Keep older debs already on the server in the index? No — the server tree is
  # replaced atomically per release; apt only ever needs the newest version, and
  # rollbacks are an operator action (re-publish an older build as a higher version).
  ( cd "$OUT/apt" && dpkg-scanpackages --multiversion pool /dev/null > dists/stable/main/binary-amd64/Packages )
  gzip -9 -kf "$OUT/apt/dists/stable/main/binary-amd64/Packages"
  ( cd "$OUT/apt/dists/stable" && apt-ftparchive \
      -o APT::FTPArchive::Release::Suite=stable \
      -o APT::FTPArchive::Release::Components=main \
      -o APT::FTPArchive::Release::Architectures=amd64 \
      release . > Release )
  # The archive key is generated passphrase-less (--batch quick-generate-key);
  # loopback + empty passphrase keeps gpg-agent from popping pinentry regardless.
  GPG_SIGN=(gpg --batch --yes --pinentry-mode loopback --passphrase '' --local-user "$GPG_UID")
  "${GPG_SIGN[@]}" --clearsign  -o "$OUT/apt/dists/stable/InRelease"   "$OUT/apt/dists/stable/Release"
  "${GPG_SIGN[@]}" --detach-sign --armor -o "$OUT/apt/dists/stable/Release.gpg" "$OUT/apt/dists/stable/Release"
fi

# ------------------------------------------------------------- updates/ + manifest
EXE_NAME="" APK_NAME=""
if [ -n "$EXE" ]; then
  EXE_NAME="$(basename "$EXE")"
  cp "$EXE" "$OUT/updates/"
  sign "$OUT/updates/$EXE_NAME" "$OUT/updates/$EXE_NAME.minisig"
fi
if [ -n "$APK" ]; then
  APK_NAME="Sona-${VERSION}-arm64.apk"
  cp "$APK" "$OUT/updates/$APK_NAME"
  sign "$OUT/updates/$APK_NAME" "$OUT/updates/$APK_NAME.minisig"
fi

log "writing manifest.json"
BASE="${SONA_UPDATE_BASE%/}"
python3 - "$OUT/updates/manifest.json" <<EOF
import hashlib, json, sys, pathlib
out = pathlib.Path(sys.argv[1])
plat = {}
def entry(path, url):
    p = pathlib.Path(path)
    return {
        "url": url,
        "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
        "minisig": pathlib.Path(str(p) + ".minisig").read_text(),
    }
if "$DEB":
    # Linux applies through apt (its own GPG chain); url is informational.
    plat["linux-deb"] = {"url": "$BASE/apt"}
if "$EXE_NAME":
    plat["windows-x86_64"] = entry("$OUT/updates/$EXE_NAME", "$BASE/updates/$EXE_NAME")
if "$APK_NAME":
    plat["android-arm64"] = entry("$OUT/updates/$APK_NAME", "$BASE/updates/$APK_NAME")
out.write_text(json.dumps({"version": "$VERSION", "pub_date": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(), "platforms": plat}, indent=2))
EOF
sign "$OUT/updates/manifest.json" "$OUT/updates/manifest.json.minisig"

if [[ "${1:-}" == "--no-upload" ]]; then
  log "built channel tree at $OUT — upload skipped"
  exit 0
fi

# ------------------------------------------------------------------------ upload
[ -n "${SONA_SSH_HOST:-}" ] || die "SONA_SSH_HOST not set (deploy/.env.publish)"
log "uploading to $SONA_SSH_HOST:$WWW_DIR (artifacts first, signed indexes last)"
ssh "$SONA_SSH_HOST" "mkdir -p '$WWW_DIR/apt' '$WWW_DIR/updates'"
if [ -n "$DEB" ]; then
  rsync -az "$OUT/apt/pool" "$SONA_SSH_HOST:$WWW_DIR/apt/"
fi
# Large artifacts before the manifest that references them.
rsync -az --exclude 'manifest.json*' "$OUT/updates/" "$SONA_SSH_HOST:$WWW_DIR/updates/"
if [ -n "$DEB" ]; then
  rsync -az "$OUT/apt/dists" "$SONA_SSH_HOST:$WWW_DIR/apt/"
fi
rsync -az "$OUT/updates/manifest.json" "$OUT/updates/manifest.json.minisig" "$SONA_SSH_HOST:$WWW_DIR/updates/"
log "channel live at $BASE/updates + $BASE/apt"

# Retention: the VPS keeps only the newest $SONA_VPS_KEEP versions per artifact family
# (older ones are dead weight — the apt index and manifest only ever reference the
# newest). The GitHub mirror is the unlimited archive.
KEEP="${SONA_VPS_KEEP:-3}"
log "pruning VPS channel to the $KEEP newest versions"
ssh "$SONA_SSH_HOST" "WWW='$WWW_DIR' KEEP='$KEEP' bash -s" <<'PRUNE'
set -eu
cd "$WWW"
prune() { ls -t $1 2>/dev/null | tail -n "+$((KEEP + 1))" | xargs -r rm -f; }
prune 'apt/pool/main/s/sona/sona_*.deb'
prune 'updates/Sona_*_x64-setup.exe'
prune 'updates/Sona-*-arm64.apk'
# Drop signature files whose artifact is gone (manifest's own sig always stays).
for f in updates/*.minisig; do
  [ "$f" = "updates/manifest.json.minisig" ] && continue
  [ -e "${f%.minisig}" ] || rm -f "$f"
done
PRUNE

# ------------------------------------------------------------------ GitHub mirror
if [[ "${SONA_GH_MIRROR:-0}" == "1" ]]; then
  log "mirroring to GitHub release v$VERSION"
  ( cd "$REPO" && {
      gh release view "v$VERSION" >/dev/null 2>&1 || gh release create "v$VERSION" --title "Sona v$VERSION" --notes "Signed release artifacts. Verify with minisign; the in-app updater does this automatically."
      files=()
      [ -n "$DEB" ] && files+=("$DEB")
      [ -n "$EXE_NAME" ] && files+=("$OUT/updates/$EXE_NAME" "$OUT/updates/$EXE_NAME.minisig")
      [ -n "$APK_NAME" ] && files+=("$OUT/updates/$APK_NAME" "$OUT/updates/$APK_NAME.minisig")
      files+=("$OUT/updates/manifest.json" "$OUT/updates/manifest.json.minisig")
      gh release upload "v$VERSION" "${files[@]}" --clobber
  } )
fi

log "publish complete: v$VERSION"
