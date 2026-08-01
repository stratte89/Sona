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
They have tests of their own — audio, pixel handling, notifications, the hardware
encoder — in their detached workspace:

```sh
cd clients/desktop/src-tauri
cargo test --lib                 # add `-- --ignored` for the tests that need real
                                 # hardware (a GPU encoder, a microphone, a screen)
```

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

Prerequisites: Android SDK + NDK, a **JDK Gradle actually supports** — use Android
Studio's bundled JBR (21); a bleeding-edge JDK fails with "Unsupported class file major
version" — and the Rust Android targets:

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

## Checking UI in the right engine

The shell is a Tauri webview, and that is **three different browsers**: WebKitGTK on
Linux, WebView2 (Chromium) on Windows, Android WebView (Chromium) on Android. Checking a
change in Chrome checks two of them and misses the one most desktop users run.

```sh
python3 clients/desktop/scripts/wk-screenshot.py clients/desktop/src/index.html out.png 1200 800
```

Renders offscreen in WebKitGTK and writes a PNG. Needs `gir1.2-webkit2-4.1` and
`python3-gi`, which a machine that can build the app already has.

Worth the habit: the call volume slider was a 4 px rail with a gradient fill, verified in
headless Chrome, and shipped. WebKitGTK ignores `height` on a range input and paints the
background across its full natural height, so it arrived as a fat green bar with the knob
floating inside it. The rule that came out of it — **do not style native form controls
and expect them to survive the engine change**; draw the parts you care about and keep
the native input as an invisible hit target, which is what `.volrail` does.

## Diagnostics

The desktop app keeps its own log, because on Windows a release build has no console
(`windows_subsystem = "windows"`) and asking someone to run a redirect incantation failed
twice in the field. It is **off unless asked for** — these lines name devices, sinks and
call state, and nobody should accumulate a file of them without opting in.

```sh
sona --debug            # or: SONA_DEBUG=1 sona
```

That turns on stderr *and* a `sona-diag.log` next to the vault, which a user can be asked
for by name and paste back. Without it, no file is created at all.

The lines worth knowing:

| Line | Says |
|---|---|
| `[media] call playout device: … @ … Hz` | which device the call plays into |
| `[media] share-audio capture source: …` | which device the share captures from — **these two must match**, or there is no echo to find |
| `[media] share-audio echo: locked at N ms, removed X dB (corr …, peak …, reseat aN/bN)` | the echo canceller found the delay and is cancelling |
| `[media] share-audio echo: NOT LOCKED …` | it did not, and the peer may hear themselves |
| `[media] audio frames lost in the last 5 s: …` | a frame path is shedding audio |

`removed X dB` is reduction of the *whole* captured mix, not ERLE. Most of that mix is the
audio being shared, which is supposed to survive, so it reads far below the real
cancellation — single digits at 35 dB of actual removal is normal. `locked at N ms` with a
high `corr` and `peak`, and `reseat a0/b0`, is the healthy signature.

### Measuring the call audio path locally

Six releases of echo-cancellation work were done by shipping a build to someone else and
reading their log — hours per round, one number per round. Don't. The whole path is
testable on any Linux desktop with a sound server, using production code end to end:

```sh
cd clients/desktop/src-tauri
SONA_AUDIO_LOOPBACK=1 SONA_DEBUG=1 \
  cargo test --release --lib -- --ignored --nocapture echo_loopback
```

**These tests play audible noise through the speakers.** That is why they need
`SONA_AUDIO_LOOPBACK=1` on top of `#[ignore]`: an earlier version ran at a third of full
scale and physically hurt someone wearing headphones. Take them off, and check nothing else
is playing — other audio makes the numbers meaningless.

| Test | Question |
|---|---|
| `echo_loopback_against_the_real_audio_stack` | does the canceller actually cancel? |
| `where_do_the_frames_go` | is any frame path losing audio? (prints every counter) |
| `where_does_each_captured_frame_come_from` | is the capture a faithful, in-order copy of the playout? |
| `measure_the_real_loopback_delay` | how long is the loopback, by clicks? |
| `capture_actually_contains_our_playout` | is our audio in the capture at all, by tone? |

The last three need `SONA_AEC_BYPASS=1` as well — they measure what the canceller is
*handed*, and without the bypass the echo has already been subtracted from it.

See [docs/CALL_AUDIO.md](../docs/CALL_AUDIO.md) for how the path fits together and the
traps that have already cost releases.
