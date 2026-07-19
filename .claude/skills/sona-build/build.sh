#!/usr/bin/env bash
# Sona release-build helper. Builds the desktop .deb and/or the Android .apk with all the
# host-environment workarounds baked in, so the build doesn't have to be re-derived.
#
#   ./build.sh deb      # desktop .deb only
#   ./build.sh apk      # Android .apk only (arm64, hardened)
#   ./build.sh exe      # Windows NSIS .exe installer (cross-compiled, no Windows box)
#   ./build.sh all      # deb + apk  (default; exe only when asked)
#   ./build.sh release  # deb + apk + exe under ONE version bump — the only correct way
#                       # to build a publishable release: publish-updates.sh matches
#                       # artifacts against tauri.conf's version, and separate runs
#                       # would bump past each other.
#
# Artifacts are copied to ~/Desktop/ at the end, and their in-tree paths printed.
#
# WHY the workarounds (each was a real build failure on this box, 2026-07-09):
#   * cmake: system cmake 3.28 can't detect NDK 30 on a fresh configure (Android-Determine
#     "Neither the NDK or a standalone toolchain was found"). The pip-installed cmake 3.27.7
#     does. Its `~/.local/bin/cmake` entrypoint shim is broken (missing module), but the
#     BUNDLED binary under site-packages works — point $CMAKE straight at it.
#   * NDK: cmake reads $ANDROID_NDK_ROOT / $ANDROID_NDK, NOT $NDK_HOME. Export them.
#   * JDK: JDK 25 breaks Gradle 8.14 / AGP 8.11 (":buildSrc > 25.0.2"). Use JDK 17 or 21.
#   * ABI: Opus's x86 asm emits non-PIC R_386_32 relocs -> i686/x86_64 shared-lib link
#     fails. Physical phones are arm64, so build --target aarch64 only. (x86 = emulator.)
#   * Hardening: run scripts/harden-android.sh before the apk build. The generated manifest
#     ships usesCleartextTraffic="${usesCleartextTraffic}" (a placeholder) which the harden
#     --check reads as "MISSING"; pin it to literal "false" so cleartext stays off + check passes.
set -euo pipefail

MODE="${1:-all}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DESKTOP="$REPO/clients/desktop"
DEST="${SONA_DIST_DIR:-$HOME/Desktop}"
TAURI_CONF="$DESKTOP/src-tauri/tauri.conf.json"

# stderr: build_deb/build_apk run in $(…) capture — stdout is their return value.
log() { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }
die() { echo "error: $*" >&2; exit 1; }

# ---- resolve a JDK 17 or 21 (NOT 25) -------------------------------------------------
pick_jdk() {
  for c in \
    "$HOME"/jdk/java-21-* "$HOME"/jdk/jdk-21* /usr/lib/jvm/java-21-* \
    "$HOME"/jdk/jdk-17* /usr/lib/jvm/java-17-* ; do
    [ -x "$c/bin/javac" ] && { echo "$c"; return; }
  done
  return 1
}

# ---- resolve a cmake that supports NDK 30 (bundled pip cmake preferred) ---------------
pick_cmake() {
  for c in "$HOME"/.local/lib/python3*/site-packages/cmake/data/bin/cmake ; do
    [ -x "$c" ] && { echo "$c"; return; }
  done
  # fall back to system cmake only if it configures NDK cleanly (>= 3.30 usually does)
  command -v cmake >/dev/null && { command -v cmake; return; }
  return 1
}

# ---- resolve the NDK -----------------------------------------------------------------
pick_ndk() {
  [ -n "${ANDROID_NDK_ROOT:-}" ] && { echo "$ANDROID_NDK_ROOT"; return; }
  [ -n "${NDK_HOME:-}" ] && { echo "$NDK_HOME"; return; }
  ls -d "${ANDROID_HOME:-$HOME/Android/Sdk}"/ndk/* 2>/dev/null | sort -V | tail -1
}

# ---- version bump: every build run gets a fresh, strictly increasing patch number ----
# Single source of truth is tauri.conf.json (Android's versionCode derives from it:
# major*1e6 + minor*1e3 + patch, so patch bumps keep upgrade installs working). The
# bump is committed immediately — two builds must never share a version number.
bump_version() {
  local cur next
  cur="$(grep -oE '"version": *"[0-9]+\.[0-9]+\.[0-9]+"' "$TAURI_CONF" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  [ -n "$cur" ] || die "cannot read version from tauri.conf.json"
  next="${cur%.*}.$(( ${cur##*.} + 1 ))"
  sed -i "s|\"version\": \"$cur\"|\"version\": \"$next\"|" "$TAURI_CONF"
  ( cd "$REPO" && git add "$TAURI_CONF" && git commit -q -m "chore(release): v$next" ) \
    || die "version bump commit failed (dirty tauri.conf.json?)"
  log "version: $cur -> $next (committed)"
  VERSION="$next"
}

# ---- update channel (in-app updates, src-tauri/src/update.rs) -------------------------
# clients/desktop/.env.update (gitignored) bakes the channel into the binaries:
#   SONA_UPDATE_BASE    e.g. https://relay.example.org   (serves /updates + /apt)
#   SONA_UPDATE_PUBKEY  minisign public key (the base64 line of the .pub file)
#   SONA_APT_KEYRING    path to the exported binary GPG archive key (for deb enrollment)
# Missing file = builds ship with in-app updates disabled. deploy/publish-updates.sh
# generates the keys and prints this file's contents on first run.
load_update_env() {
  if [ -f "$DESKTOP/.env.update" ]; then
    log "sourcing update-channel config from clients/desktop/.env.update"
    set -a; . "$DESKTOP/.env.update"; set +a
  else
    log "no clients/desktop/.env.update — building with in-app updates disabled"
  fi
}

# ---- Windows cross-build (x86_64-pc-windows-msvc via cargo-xwin, NSIS installer) ------
# No Windows box and no sudo needed. One-time prerequisites are auto-installed to the
# user's home. WHY each piece (all real failures on this box, 2026-07-19):
#   * clang-cl/lld-link: taken from the Android NDK's LLVM (no system clang here); a
#     tiny wrapper script gives NDK clang the `--driver-mode=cl` personality.
#   * makensis: Ubuntu package extracted with dpkg-deb into ~/.local/opt/nsis (no root).
#     The binary has /usr/share/nsis BAKED IN (no NSISDIR env support), so a wrapper
#     bind-mounts the extracted data dir over that path with bubblewrap (bwrap ships
#     with Ubuntu). tauri-bundler additionally reads $NSIS_PATH for Plugins/Stubs.
#   * TARGET_CFLAGS=-FIintrin.h: mozjpeg-sys uses MSVC intrinsics (_BitScanForward64)
#     without including <intrin.h>; real MSVC auto-declares them, clang-cl does not.
#   * cmake wrapper (cmake-sona): clang-cl defines _MSC_VER, so opus's "#ifdef _MSC_VER"
#     __builtin_ctz fallback redefines clang's builtin in silk/x86/NSQ_del_dec_avx2.c.
#     The wrapper appends -DOPUS_X86_MAY_HAVE_AVX2=OFF to opusic-sys configures only
#     (SSE4.1 paths remain). It also pins the working pip cmake (the shim is broken).
#   * ninja: cargo-xwin forces the Ninja generator; pip-installed, ~/.local/bin.
XWIN_TOOLS="$HOME/.local/opt/xwin-tools"
NSIS_PREFIX="$HOME/.local/opt/nsis"

ensure_exe_prereqs() {
  rustup target list --installed | grep -q x86_64-pc-windows-msvc || {
    log "installing rust target x86_64-pc-windows-msvc"
    rustup target add x86_64-pc-windows-msvc
  }
  command -v cargo-xwin >/dev/null || { log "installing cargo-xwin"; cargo install cargo-xwin; }
  [ -x "$HOME/.local/bin/ninja" ] || command -v ninja >/dev/null || {
    log "installing ninja (pip --user)"
    pip install --user --break-system-packages ninja
  }

  # NDK LLVM → clang-cl / lld-link / llvm-lib / llvm-rc
  local ndkbin
  ndkbin="$(ls -d "${ANDROID_HOME:-$HOME/Android/Sdk}"/ndk/*/toolchains/llvm/prebuilt/linux-x86_64/bin 2>/dev/null | sort -V | tail -1)"
  [ -n "$ndkbin" ] || die "no Android NDK LLVM found (source of clang-cl for the cross-build)"
  mkdir -p "$XWIN_TOOLS"
  printf '#!/bin/sh\nexec "%s/clang" --driver-mode=cl "$@"\n' "$ndkbin" > "$XWIN_TOOLS/clang-cl"
  chmod +x "$XWIN_TOOLS/clang-cl"
  ln -sf "$ndkbin/lld-link" "$XWIN_TOOLS/lld-link"
  ln -sf "$ndkbin/llvm-lib" "$XWIN_TOOLS/llvm-lib"
  ln -sf "$ndkbin/llvm-rc"  "$XWIN_TOOLS/llvm-rc"

  # NSIS without root: extract the Ubuntu debs into ~/.local/opt/nsis
  if [ ! -x "$NSIS_PREFIX/usr/bin/makensis" ]; then
    log "extracting NSIS debs into $NSIS_PREFIX (no root install)"
    local tmp; tmp="$(mktemp -d)"
    ( cd "$tmp" && apt-get download nsis nsis-common >/dev/null \
      && mkdir -p "$NSIS_PREFIX" \
      && for d in ./*.deb; do dpkg-deb -x "$d" "$NSIS_PREFIX"; done )
    rm -rf "$tmp"
    [ -x "$NSIS_PREFIX/usr/bin/makensis" ] || die "NSIS extraction failed"
  fi
  command -v bwrap >/dev/null || die "bubblewrap (bwrap) missing — needed to remap makensis's baked /usr/share/nsis"
  cat > "$XWIN_TOOLS/makensis" <<'WRAP'
#!/bin/sh
# Ubuntu's makensis has /usr/share/nsis baked in (no NSISDIR env support) and nsis
# isn't root-installed here: bind the extracted data dir over that path in a
# bubblewrap mount namespace.
exec bwrap --dev-bind / / --tmpfs /usr/share \
  --ro-bind "$HOME/.local/opt/nsis/usr/share/nsis" /usr/share/nsis \
  "$HOME/.local/opt/nsis/usr/bin/makensis" "$@"
WRAP
  chmod +x "$XWIN_TOOLS/makensis"

  # cmake wrapper (see header). Regenerated every run so the pinned path stays fresh.
  local realcmake; realcmake="$(pick_cmake)" || die "no usable cmake found"
  {
    printf '#!/bin/sh\nREAL="%s"\n' "$realcmake"
    printf 'case "$1" in --build) exec "$REAL" "$@" ;; esac\n'
    printf 'case "$*" in *opusic-sys*) exec "$REAL" "$@" -DOPUS_X86_MAY_HAVE_AVX2=OFF ;; *) exec "$REAL" "$@" ;; esac\n'
  } > "$XWIN_TOOLS/cmake-sona"
  chmod +x "$XWIN_TOOLS/cmake-sona"
}

build_exe() {
  ensure_exe_prereqs
  log "building Windows NSIS installer (cross, cargo-xwin)"
  ( cd "$DESKTOP" && \
    env PATH="$XWIN_TOOLS:$HOME/.local/bin:$PATH" \
        NSIS_PATH="$NSIS_PREFIX/usr/share/nsis" \
        TARGET_CFLAGS="-FIintrin.h" \
        CMAKE="$XWIN_TOOLS/cmake-sona" \
        cargo tauri build --runner cargo-xwin --target x86_64-pc-windows-msvc --bundles nsis ) 1>&2
  local exe
  exe="$(ls -t "$DESKTOP"/src-tauri/target/x86_64-pc-windows-msvc/release/bundle/nsis/*.exe | head -1)"
  [ -f "$exe" ] || die "no .exe produced"
  cp "$exe" "$DEST/"
  echo "$exe"
}

build_deb() {
  log "building desktop .deb"
  # Self-enrolling deb (Chrome/VS Code model): ship the apt source + archive keyring so
  # installed machines get every future version through plain `apt upgrade`. Generated
  # into tauri.linux.conf.json (gitignored, auto-merged by the tauri CLI on Linux
  # bundles only) so the public repo stays free of any operator-specific host.
  local lconf="$DESKTOP/src-tauri/tauri.linux.conf.json"
  rm -f "$lconf"
  if [ -n "${SONA_UPDATE_BASE:-}" ] && [ -n "${SONA_APT_KEYRING:-}" ] && [ -f "${SONA_APT_KEYRING:-}" ]; then
    local enroll="$DESKTOP/src-tauri/target/apt-enroll"
    mkdir -p "$enroll"
    printf 'deb [signed-by=/usr/share/keyrings/sona-archive.gpg] %s/apt stable main\n' \
      "${SONA_UPDATE_BASE%/}" > "$enroll/sona.list"
    cp "$SONA_APT_KEYRING" "$enroll/sona-archive.gpg"
    cat > "$lconf" <<EOF
{
  "bundle": {
    "linux": {
      "deb": {
        "files": {
          "/etc/apt/sources.list.d/sona.list": "$enroll/sona.list",
          "/usr/share/keyrings/sona-archive.gpg": "$enroll/sona-archive.gpg"
        }
      }
    }
  }
}
EOF
    log "deb self-enrolls apt repo: ${SONA_UPDATE_BASE%/}/apt"
  else
    log "no SONA_UPDATE_BASE/SONA_APT_KEYRING — plain deb (no apt enrollment)"
  fi
  ( cd "$DESKTOP" && cargo tauri build --bundles deb )
  local deb
  deb="$(ls -t "$DESKTOP"/src-tauri/target/release/bundle/deb/*.deb | head -1)"
  [ -f "$deb" ] || die "no .deb produced"
  cp "$deb" "$DEST/"
  echo "$deb"
}

build_apk() {
  local JDK CMAKE_BIN NDK
  JDK="$(pick_jdk)"   || die "no JDK 17/21 found (JDK 25 breaks Gradle/AGP)"
  CMAKE_BIN="$(pick_cmake)" || die "no usable cmake found"
  NDK="$(pick_ndk)"  || die "no Android NDK found"
  log "JDK=$JDK"
  log "CMAKE=$CMAKE_BIN ($("$CMAKE_BIN" --version | head -1))"
  log "NDK=$NDK"

  export JAVA_HOME="$JDK"
  export PATH="$JDK/bin:$PATH"
  export CMAKE="$CMAKE_BIN"
  export ANDROID_NDK_ROOT="$NDK" ANDROID_NDK="$NDK"

  # FCM identifiers (public, but kept out of the repo for reproducible builds).
  # Without them the APK builds fine — push modes P/C+P are simply unavailable.
  if [ -f "$DESKTOP/.env.fcm" ]; then
    log "sourcing FCM build fields from clients/desktop/.env.fcm"
    set -a; . "$DESKTOP/.env.fcm"; set +a
  else
    log "no clients/desktop/.env.fcm — building without FCM (push modes disabled)"
  fi

  log "applying Android hardening"
  ( cd "$DESKTOP" && bash scripts/harden-android.sh )
  # Pin the cleartext placeholder to literal false (generated manifest; regenerated on init).
  local manifest="$DESKTOP/src-tauri/gen/android/app/src/main/AndroidManifest.xml"
  [ -f "$manifest" ] && sed -i 's/android:usesCleartextTraffic="${usesCleartextTraffic}"/android:usesCleartextTraffic="false"/' "$manifest" || true
  ( cd "$DESKTOP" && bash scripts/harden-android.sh --check ) || die "hardening check failed"

  # Fresh opus dirs avoid a stale CMakeCache pinning a bad install prefix.
  rm -rf "$DESKTOP"/src-tauri/target/*-linux-android*/release/build/opusic-sys-* 2>/dev/null || true

  log "building arm64 .apk"
  ( cd "$DESKTOP" && cargo tauri android build --target aarch64 --apk )
  local apk
  apk="$(ls -t "$DESKTOP"/src-tauri/gen/android/app/build/outputs/apk/universal/release/*.apk | head -1)"
  [ -f "$apk" ] || die "no .apk produced"
  cp "$apk" "$DEST/Sona-arm64.apk"
  echo "$apk"
}

mkdir -p "$DEST"
load_update_env
bump_version
DEB_OUT="" APK_OUT="" EXE_OUT=""
case "$MODE" in
  deb) DEB_OUT="$(build_deb)" ;;
  apk) APK_OUT="$(build_apk)" ;;
  exe) EXE_OUT="$(build_exe)" ;;
  all) DEB_OUT="$(build_deb)"; APK_OUT="$(build_apk)" ;;
  release) DEB_OUT="$(build_deb)"; APK_OUT="$(build_apk)"; EXE_OUT="$(build_exe)" ;;
  *)   die "usage: build.sh [deb|apk|exe|all|release]" ;;
esac

echo
log "done. artifacts:"
[ -n "$DEB_OUT" ] && echo "  .deb: $DEB_OUT  (copied to $DEST/)"
[ -n "$APK_OUT" ] && echo "  .apk: $APK_OUT  (copied to $DEST/Sona-arm64.apk)"
[ -n "$EXE_OUT" ] && echo "  .exe: $EXE_OUT  (copied to $DEST/)"
exit 0
