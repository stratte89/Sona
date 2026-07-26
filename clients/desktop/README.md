# Sona desktop / Android (Tauri 2)

A thin Tauri 2 shell over the `client-core` SDK. One codebase targets **Windows, Linux,
and Android** (no iOS). All security logic lives in `client-core` / `crypto-core` /
`kt-log` — this crate only exposes Tauri commands and a minimal web UI.

```
desktop/
  src-tauri/          Rust side (detached package — own [workspace])
    src/lib.rs        Tauri commands → client-core
    src/main.rs       binary entry → lib::run()
    tauri.conf.json   Tauri 2 config (withGlobalTauri, CSP allowing ws/wss)
    build.rs
  src/                static web UI (index.html + main.js + styles.css, no bundler)
```

## Status

**Real messenger UI, runs on desktop and cross-compiles for Android.** The web UI is a
mobile-shaped, dependency-free (no npm) single-column messenger: onboarding (relay + KT
pin), account create/unlock, chat list (unread badges, per-contact avatar colors,
disappearing-timer badge), threads with message bubbles and send/delivered/seen ticks,
E2E-encrypted attachments (inline image previews, save-to-Downloads), groups, voice
notes with waveforms, an emoji/GIF composer, global search, and a per-chat
settings sheet (safety-number verification + disappearing-messages picker). Calls get a
Signal-style full-screen surface that collapses into a draggable bubble so the rest of
the app stays usable mid-call. The sealed
vault, encrypted history, and relay config persist to the app-data dir; inbound delivery
is a live authenticated WebSocket subscription (cancel-safe frame loop, acks after
persist), with a connection indicator in the UI. All security logic stays in
`client-core` / `crypto-core` / `kt-log`.

Delivery/locking discipline and why it must stay this way: see
`spawn_subscriber` in `src/lib.rs` — socket waits happen with **no** session lock,
decrypt/apply/re-seal under a short lock, network (acks/receipts) after release. Vault
re-seals use the **cached** seal key (`Account::reseal`, no per-message Argon2).

## Commands exposed to the UI

`app_status` · `configure(base_url, pinned_kt_key)` · `fetch_kt_pubkey(base_url)` ·
`password_strength(password)` · `create_account(username, password)` · `unlock(password)` ·
`lock` · `conversations` · `thread(peer)` (messages + timer) · `open_chat(username)`
(KT-verified) · `accept_key_change(username)` · `mark_verified(username, peer)` ·
`mark_seen(username, peer)` (once per message) · `send(username, text)` ·
`send_file(username, filename, data_b64)` · `fetch_attachment(peer, msg_id)` ·
`save_attachment(peer, msg_id)` (native Save-As) · `set_disappearing(username, peer, secs?)` ·
`set_pinned` / `set_muted` / `set_nickname` / `set_blocked` (local prefs, encrypted at rest) ·
`delete_chat(username, peer, for_both)` · `edit_message` (5-min window) · `delete_message` ·
`delete_message_everyone` · `create_group` / `add_to_group` / `group_thread` /
`send_group_msg` / `mark_group_seen` / `delete_group` / `set_group_muted` / `my_groups` ·
`audit_own_key` · `poll_now`. `send` takes an optional `reply_to` message id (quoted replies).

Voice calls: `call_start(username)` · `call_accept` / `call_decline` · `call_hangup` ·
`call_set_muted(muted)` · `call_status`. Signaling (offer with a random 128-bit room id
+ 32-byte call key, answer, end) rides the ratchet; media is native Rust
(`client-core::call`): 48 kHz mono Opus **CBR**, 20 ms frames padded to a constant size,
XChaCha20-Poly1305 per-direction keys, sequence-checked, relayed through the server's
blind call rooms (`/v1/call/{id}` — capability-token join, no identities). No P2P: peers
never learn each other's IPs. Mute sends encoded silence, so the wire cadence (and the
relay's view) never changes. Audio devices via cpal (`src/audio.rs`); ring timeout 45 s
both sides; busy/blocked callers are auto-declined. UI events: `call`
(`incoming/outgoing/connected/declined/no_answer/missed/ended`).

Video, screen share and devices (media v2 — `docs/PROTOCOL.md`):
`call_set_camera(on)` · `call_set_screen(on, source?)` · `call_set_screen_audio(on)` ·
`screen_sources` (one small PNG preview per screen/window, inlined as a data URL, so the
picker can say exactly what it is about to share) · `call_media_devices` /
`call_set_media_device` (pin a microphone, speaker or camera; the pin survives the call)
· `call_set_noise_suppression` · `call_audio_routes` / `call_set_route` /
`call_set_speaker` (Android earpiece/speaker/Bluetooth) · `call_media_channel` (the IPC
channel decoded peer frames stream over — `track(1) || w(2 BE) || h(2 BE) || I420`,
`w=h=0` meaning the track went off). Decoded frames are painted by a small WebGL
YUV→RGB shader in the UI, so a 1080p share costs the webview almost nothing.

Encoding is software H.264 by default and **hardware** where the machine has a GPU
encoder that passes a probe — Media Foundation on Windows, NVENC on Linux/NVIDIA
(`src/hwenc/`). Neither library is linked; both are loaded at runtime, so a machine
without them is unaffected. `call_status` reports which one is live as `hw_encode`, and
the call-settings gear shows it as "Video encoding: hardware (GPU)" or "software".
The GPU tests are `#[ignore]`d — run them on a machine that has one:

```sh
cd src-tauri && cargo test --lib -- --ignored nvenc
```

Voice messages: `send_voice(username, data_b64, mime, duration_secs)` — records in the
webview (MediaRecorder/opus where available, 16 kHz WAV fallback for WebKitGTK builds
without it, 3-minute cap) and ships over the **same E2E attachment pipeline** as any
file: client-side encryption, padded blob, key inside the ratchet. The relay cannot tell
a voice note from a PDF; only the `voice` flag + duration travel inside the ciphertext
so the recipient renders a player. Playback via `fetch_attachment` (decrypted in memory,
cached per session, dropped on lock). Mic access: Android's generated WebChromeClient
prompts at first use (RECORD_AUDIO added by `harden-android.sh`); on Linux the shell
enables WebKitGTK media streams and allows **audio-only** capture requests (camera stays
denied — nothing in the app may ask for it).

Security/quick-unlock commands: `security_status` · `pin_strength(pin)` ·
`verify_password(password)` · `set_pin(password, pin)` / `disable_pin` /
`unlock_pin(pin)` / `verify_pin(pin)` (5 wrong attempts wipe the PIN blob) ·
`set_auto_unlock(password?, enable)` / `try_auto_unlock` ·
`set_bio_unlock(password?, enable)` / `unlock_bio` (Android fingerprint, Keystore-gated) ·
`os_presence_check` (ceremony step 2; auto-passes on desktop / factor-less devices) ·
`change_password(current_password, pin, new_password)` ·
`change_username(current_password, pin, new_username)` (KT re-claim + E2E rename notices
+ old-mailbox drain) · `set_lock_after(secs?)` · `set_pin_reminder(every?)` ·
`note_app_open`. The change ceremony (password → OS check → PIN) is re-verified
atomically in Rust — the UI order is UX, not the security boundary. Design rationale:
`crypto-core/src/quick.rs` and `docs/THREAT_MODEL.md` ("Quick unlock").

Backend → UI events (require `capabilities/default.json` granting `core:default` —
without it Tauri v2 silently rejects `listen()` and the UI never repaints):
`sync` (inbound state changed, repaint) · `conn` (relay link up/down).

## Known limitations

* Calls are relay-routed by design — latency is one relay hop (~150–250 ms typical);
  the trade buys IP privacy and no ICE/STUN surface.
* Call echo/noise: Android captures via the platform `VOICE_COMMUNICATION` path with
  hardware AEC/NS/AGC (cpal's generic AAudio input bypasses the echo canceller — the
  source of the speaker→mic feedback static); desktop runs its own canceller
  (`src/aec/`) which re-estimates the capture↔playout delay as the two clocks drift
  apart, plus always-on RNNoise. It is good enough for loudspeakers, but a headset is
  still the better answer.
* Capture is hardware-dependent and cannot be covered by CI: microphones, cameras,
  screens and GPU encoders all need a real machine. Those tests are `#[ignore]`d and are
  meant to be run by hand on hardware that has the thing. Android call audio needs the
  RECORD_AUDIO runtime grant — the app prompts before opening the mic.
* Screen share is X11-only on Linux. Wayland needs the PipeWire portal, which is not
  wired yet.
* Background delivery on Android runs a `specialUse` foreground service (persistent
  low-importance notification) and asks for the Doze exemption once; some OEM battery
  managers (Xiaomi/Huawei/Samsung "sleeping apps") still kill exempted apps and need a
  manual whitelist. Desktop keeps delivering from the tray after window close — Quit
  lives in the tray menu.
* Attachment previews are decrypted per session (in-memory cache only, nothing written
  to disk until the user explicitly saves).
* The PIN attempt counter (`prefs.json`) is plaintext and resettable by root — it stops
  casual on-device guessing, not a compromised OS. Offline it's irrelevant: the PIN blob
  is useless without the OS-keyring/Keystore device key.
* After a username change the old name stays in the public append-only KT log forever
  (inherent to KT), its mailbox keeps being drained (up to 5 former names), and a contact
  who missed the E2E rename notice may briefly show two entries (same key) until their
  next message converges them.
* Biometric unlock must be re-enabled after a password change (its Keystore wrap covers
  the rotated seal key); PIN and auto-unlock re-wrap automatically in the ceremony.
* Fingerprint unlock is compile-verified (Rust JNI + Kotlin both build) but not yet
  exercised on a physical device/emulator.

## Build

See `../README.md` for full prerequisites. Quick start (desktop):

```sh
cargo install tauri-cli --version "^2"
# Linux: install libwebkit2gtk-4.1-dev, libgtk-3-dev, libayatana-appindicator3-dev, librsvg2-dev
cd src-tauri
cargo tauri dev
```

### Android

Prereqs: Android SDK + **NDK** (Studio → SDK Manager → SDK Tools → "NDK (Side by
side)"), the Rust Android targets (`rustup target add aarch64-linux-android ...`), and
a **JDK Gradle supports — use Android Studio's bundled JBR**, not a bleeding-edge JDK
(JDK 25 fails with "Unsupported class file major version 69"):

```sh
export ANDROID_HOME=~/Android/Sdk
export NDK_HOME=$ANDROID_HOME/ndk/<version>
export JAVA_HOME=~/android-studio/jbr          # Gradle-compatible JDK 21

cargo tauri android init
../scripts/harden-android.sh          # idempotent; re-run after any re-generation
../scripts/harden-android.sh --check  # exit 0 = hardened
cargo tauri android build --debug --target aarch64
# → gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```

The hardening script is applied to the generated project (FLAG_SECURE, backups
disabled, accessibility warning — see `../../docs/ANDROID_HARDENING.md`). On Android
the vault device key is wrapped by a non-exportable **Android Keystore** key
(`client-core::devicekey::AndroidKeystore`); desktop uses the OS keyring.

## TODO before this is a real app

* ~~Fix per-message Argon2id re-seal latency~~ — done (`Account::reseal` with the seal
  key cached at unlock; the password itself is no longer kept in memory).
* ~~Attachments UI~~ — done (send/preview/save, E2E, padded blobs).
* ~~Group chat UI~~ — done (creation, admin-signed membership epochs, per-group settings;
  `../../docs/GROUPS.md`).
* ~~Calls~~ — done (voice, video, screen share with system audio, mesh group calls;
  see the call commands above and `../../docs/PROTOCOL.md`).
* ~~Persist the sealed vault to disk~~ — done (`vault.bin` / `history.bin` / `config.json`
  in the app-data dir; history encrypted under the account `data_key`).
* ~~Long-lived inbox streaming (push) instead of `fetch_inbox` polling~~ — done (live
  `subscribe` WebSocket in the shell; cancel-safe loop, poison-message acks).
* ~~Bind the vault wrapping key to the OS keystore~~ — done on desktop (Secret
  Service / Credential Manager via `client-core`'s `os-keyring` feature; vault v2) and
  Android (`client-core::devicekey::AndroidKeystore`).
* ~~Quick unlock (PIN / fingerprint / auto), idle auto-lock, PIN reminders, and
  username/password change ceremony~~ — done (see the security commands above).
* App icons under `src-tauri/icons/`.
