# Sona clients

This is a **separate Cargo workspace** from the backend (`../Cargo.toml`), on purpose:
the Android/desktop builds must never try to cross-compile the server's native stack.
The shared crates (`crypto-core`, `kt-log`, `protocol-types`) are pulled in by relative
path.

```
clients/
  Cargo.toml          workspace: members = [client-core]; desktop is detached
  client-core/        headless client SDK — ALL client logic lives here, fully tested
    src/api/            command surface (account, chat, contacts, groups, files, calls, KT)
    src/history/        the E2E state machine: request gate, group epochs, quarantine, timers
    src/multidevice/    linking, rosters, revocation, self-sync
    src/wire/           ChatPayload — everything that travels inside the ratchet
    src/{call,groupcall,media,quicmedia,subscribe,attest,…}.rs
  desktop/            Tauri 2 app (Windows + Linux + Android); thin shell over client-core
    src-tauri/        Rust side (detached package, built with `cargo tauri`):
                        cmd/ (Tauri commands), call/, delivery engine + service,
                        Android bridges (audio, push, keystore, hw attestation)
    src/              web UI (static HTML/JS, no bundler): js/ ordered modules, vendor/
```

## client-core — the part that's tested

`client-core` is UI-agnostic: account lifecycle, KT-verified contact discovery,
sealed-sender messaging, groups, multi-device, calls, and the relay transport
(REST + WebSocket + QUIC media). It has no GUI dependency, so it builds and tests in
any plain-Rust environment.

```sh
cd clients
cargo test -p client-core        # end-to-end tests run the real relay in-process
```

The Tauri shells (`desktop/`) call into `client-core` and contain no security logic.

## Building the desktop / Android app (Tauri 2)

The app is **not** built by `cargo build` in this workspace — it needs the platform
webview and the Tauri CLI:

```sh
cargo install tauri-cli --version "^2"
```

### Linux / Windows desktop

Prerequisites:
* Linux: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, build tools.
* Windows: WebView2 runtime (preinstalled on Win10+), MSVC build tools.

```sh
cd clients/desktop/src-tauri
cargo tauri dev      # run
cargo tauri build    # produce installers
```

### Android

Prerequisites: Android SDK + NDK, JDK 17+, and the Rust Android targets:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
export ANDROID_HOME=... ; export NDK_HOME=...
cd clients/desktop/src-tauri
cargo tauri android init
cargo tauri android dev     # or: cargo tauri android build
```

Release APKs go through `desktop/scripts/harden-android.sh` (FLAG_SECURE, no backup,
StrongBox keystore, MTE, back-navigation routing — see `../docs/ANDROID_HARDENING.md`).

No iOS target — by design.

## Configuring a client against your relay

1. Run your relay (`cargo run -p server` from the backend workspace). It prints the
   **KT public key** to pin and the **seed** to persist (`KT_SIGNING_KEY`).
2. In the app: set the relay base URL and paste the pinned KT key (confirm it via a
   second channel — see `../docs/KEY_TRANSPARENCY.md`).
3. Create an account (username + password) and start messaging.
