---
name: sona-build
description: Build Sona release artifacts — the desktop .deb, the Android .apk, and/or the Windows .exe installer — on this host. Use whenever asked to "build the deb", "build the apk", "build the exe / Windows installer", "make a release build", "build for my phone/PC", or package Sona for install. Encodes the host-environment workarounds (JDK pin, cmake, NDK, arm64-only, hardening, cargo-xwin cross toolchain, no-root NSIS) so the build isn't re-derived each time.
---

# Sona release builds

Run the bundled helper from the repo root:

```sh
bash .claude/skills/sona-build/build.sh all   # .deb + .apk  (default)
bash .claude/skills/sona-build/build.sh deb   # desktop .deb only
bash .claude/skills/sona-build/build.sh apk   # Android .apk only
bash .claude/skills/sona-build/build.sh exe   # Windows NSIS .exe installer (cross-compiled)
bash .claude/skills/sona-build/build.sh release # deb + apk + exe under ONE version bump
```

Use `release` (never `all` + `exe` back-to-back) when the goal is publishing via
`deploy/publish-updates.sh` — each run bumps the version, and the publish script only
picks up artifacts matching tauri.conf.json's current version.

Artifacts land in the build tree and are copied to `~/Desktop/` (override with `SONA_DIST_DIR`).

**Every run bumps the patch version first** (tauri.conf.json is the single source of
truth; the bump is git-committed immediately so no two builds share a number — Android
upgrade installs depend on the derived versionCode strictly increasing). Publishing a
release afterwards = `./deploy/publish-updates.sh` (signs + assembles the apt repo and
the in-app update manifest, rsyncs to the VPS; `--init` on first use generates keys and
prints `clients/desktop/.env.update`, which build.sh bakes into the binaries as the
update channel — without that file, builds ship with in-app updates disabled).

- `.deb` → `clients/desktop/src-tauri/target/release/bundle/deb/Sona_*_amd64.deb`
- `.apk` → `clients/desktop/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk` (arm64-v8a, V2-signed, hardened)
- `.exe` → `clients/desktop/src-tauri/target/x86_64-pc-windows-msvc/release/bundle/nsis/Sona_*_x64-setup.exe` (unsigned; Windows hosts would be needed for Authenticode)

## What the script does (and why — each was a real failure on this box)

1. **Desktop .deb**: `cargo tauri build --bundles deb`. No special env needed.
2. **Android hardening**: runs `clients/desktop/scripts/harden-android.sh`, then pins
   `usesCleartextTraffic="false"` in the generated manifest (Tauri ships it as a
   `${usesCleartextTraffic}` placeholder that the harden `--check` misreads as MISSING),
   then re-checks (`--check` must exit 0).
3. **Android .apk**: `cargo tauri android build --target aarch64 --apk`, with:
   - **`JAVA_HOME` → JDK 17 or 21.** JDK 25 breaks Gradle 8.14 / AGP 8.11
     (`configuring project ':buildSrc' > 25.0.2`). Script auto-picks 21, else 17.
   - **`CMAKE` → bundled pip cmake 3.27.7** at
     `~/.local/lib/python3*/site-packages/cmake/data/bin/cmake`. System cmake 3.28 fails
     NDK-30 detection on a fresh configure (`Android-Determine … Neither the NDK or a
     standalone toolchain was found`). The pip `~/.local/bin/cmake` *shim* is broken
     (missing module) — use the bundled binary directly, not the shim.
   - **`ANDROID_NDK_ROOT` + `ANDROID_NDK`** exported (cmake ignores `NDK_HOME`).
   - **arm64 only.** Opus's x86 asm emits non-PIC `R_386_32` relocations → i686/x86_64
     shared-lib link fails. Physical phones are arm64; x86 ABIs are emulator-only. Also
     wipes stale `opusic-sys-*` build dirs first (a leftover CMakeCache can pin a bad
     install prefix → `/usr/local/lib … Permission denied`).
   - **FCM build fields**: auto-sources `clients/desktop/.env.fcm` (gitignored;
     `SONA_FCM_PROJECT/APP_ID/API_KEY/SENDER`) so push modes P/C+P are enabled in the
     APK. Missing file = clean build without FCM (modes hidden in the UI).

## Windows .exe cross-build (no Windows box, no root — worked out 2026-07-19)

`build.sh exe` self-installs everything it needs into the user's home:
`x86_64-pc-windows-msvc` rust target, `cargo-xwin` (downloads the MSVC CRT/SDK to
`~/.cache/cargo-xwin` on first run), pip `ninja`, `clang-cl`/`lld-link`/`llvm-lib`/
`llvm-rc` shimmed from the **Android NDK's LLVM** (`~/.local/opt/xwin-tools`), and
NSIS extracted from the Ubuntu debs into `~/.local/opt/nsis` (dpkg-deb, no root).

Failure modes it encodes (each was real):
- **mozjpeg-sys**: MSVC intrinsics without `<intrin.h>` → `TARGET_CFLAGS=-FIintrin.h`
  (TARGET_ so host build scripts keep gcc flags).
- **opusic-sys**: clang-cl defines `_MSC_VER`, so opus's `#ifdef _MSC_VER`
  `__builtin_ctz` fallback redefines a clang builtin in the AVX2 unit → the `cmake-sona`
  wrapper appends `-DOPUS_X86_MAY_HAVE_AVX2=OFF` to opusic-sys configures (SSE4.1 stays).
- **pip cmake shim broken + cargo-xwin forces Ninja** → wrapper pins the bundled pip
  cmake binary; ninja from pip.
- **makensis**: Ubuntu binary has `/usr/share/nsis` baked in (NSISDIR env ignored) →
  `makensis` wrapper bind-mounts the extracted data dir over that path with `bwrap`.
  tauri-bundler needs `NSIS_PATH` pointed at the extracted `share/nsis` too.

The installer is unsigned (Authenticode needs a Windows host or a `sign_command`);
SmartScreen will warn on first run — expected.

## Prerequisites (already set up on this host)
- `cargo-tauri` (2.11+), Android SDK at `~/Android/Sdk`, NDK 30, release keystore wired
  via `gen/android/keystore.properties` (the harden script's step 12).
- pip cmake package present (for the bundled 3.27.7 binary).
- A JDK 17 or 21 installed under `~/jdk` or `/usr/lib/jvm`.

## Extending
- **Need armv7 / older phones or emulator ABIs (x86):** the arm64-only limit is the Opus
  x86-PIC issue. Add `--target armv7` (arm, works) — but x86/x86_64 need the Opus asm PIC
  problem worked around separately before they'll link.
- Bundle formats other than deb: `cargo tauri build --bundles appimage,rpm` etc.
