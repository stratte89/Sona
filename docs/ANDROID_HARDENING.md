# Android Hardening

How Sona defends the *client* on Android, what each measure actually stops, and where the
honest limits are. Companion to `THREAT_MODEL.md` ("Endpoint compromise" and "Device
thief" sections).

## The two attacker classes

**1. Non-root spyware (stalkerware, malicious apps).** By far the most common real-world
Android spyware. It runs as an ordinary app and *cannot* read another app's files or
memory — Android already sandboxes every app in its own UID + SELinux domain with private
storage. So it spies through side channels the OS hands out as permissions:

| Channel | How it's abused | Sona's answer |
|---|---|---|
| Screen capture (MediaProjection) | records the screen while you chat | **`FLAG_SECURE`** — the OS refuses to capture the window; recents preview is blanked too |
| Accessibility services | "reads" the UI tree as a fake screen reader | **detect + warn** on every resume (see below) |
| ADB / cloud backup | extracts app data, including the vault blob | **`allowBackup="false"`** + `fullBackupContent="false"` + `dataExtractionRules` excluding everything |
| Notification listener | reads message previews from the shade | **policy: notifications are content-free** ("New message" — no text, no sender). Binding requirement for the GUI phase. |
| Malicious keyboard (IME) | logs everything typed | can't be blocked by an app; user-side (below). The OS already suppresses IME learning in `FLAG_SECURE`-adjacent password fields, not chat text. |

**2. Root / kernel-level compromise (Pegasus class).** The attacker owns the kernel:
screen, RAM, input, our sandbox — everything. **No app-level defense exists**, for Sona,
Signal, or anyone, and we do not pretend otherwise (`THREAT_MODEL.md` scopes this out).
What still matters under that model:

* **Post-compromise security** — once the implant is removed, the Double Ratchet heals;
  future messages are safe again.
* **Disappearing messages** — less history resident on the device to steal.
* **Device-bound vault key (Android Keystore, StrongBox-preferred)** — the identity key's
  wrapping key lives in the secure element and is *non-exportable*: a root attacker can
  use it while resident but cannot copy it off-device. Removal ends the compromise
  instead of it persisting via stolen keys.

## What `harden-android.sh` applies

Tauri generates the Android project (`src-tauri/gen/android`) locally with
`cargo tauri android init`; that directory is gitignored, so the hardening ships as an
idempotent patch script:

```sh
cd clients/desktop
cargo tauri android init          # needs the Android SDK/NDK toolchain
./scripts/harden-android.sh       # apply
./scripts/harden-android.sh --check   # verify (exit 0 = hardened)
```

1. **`MainActivity.kt`**
   * `FLAG_SECURE` on the window, set *before* `super.onCreate` so no frame is ever
     capturable.
   * On every `onResume`: if any accessibility service is enabled, a toast warns
     *"An accessibility service is enabled — it may be able to read this screen."*
     Warning, not blocking: blocking would also break screen readers for blind users,
     and the user — not us — knows whether the service is one they installed.
2. **`AndroidManifest.xml`** — `allowBackup="false"`, `fullBackupContent="false"`,
   `dataExtractionRules="@xml/data_extraction_rules"`.
3. **`res/xml/data_extraction_rules.xml`** — excludes every domain from cloud backup and
   device-to-device transfer, in case a manifest merge ever re-enables backups.
3b. **`android:memtagMode="sync"`** — ARM Memory Tagging Extension opt-in (API 31+
   attribute, ignored elsewhere). On MTE hardware (Pixel 8+, hence current GrapheneOS
   devices) every heap allocation is tagged and use-after-free / out-of-bounds in
   native code faults precisely — covering the Rust unsafe/JNI surface and the C deps.
   Sync mode for precise fault addresses; a messenger's load makes the overhead moot.
4. **`BiometricGate.kt` + `USE_BIOMETRIC`** — the fingerprint-unlock / presence-check
   helper (framework `BiometricPrompt`, no extra Gradle dependencies). The vault seal key
   is wrapped by a Keystore AES-GCM key with `setUserAuthenticationRequired(true)` +
   BIOMETRIC_STRONG per use, `setInvalidatedByBiometricEnrollment(true)`. Driven from
   Rust over JNI (`src-tauri/src/bio.rs`). Fingerprint-only in practice: BIOMETRIC_STRONG
   is class 3, which camera-based face unlock does not meet.
5. **`RECORD_AUDIO` + `MODIFY_AUDIO_SETTINGS`** — voice messages. wry's WebChromeClient
   answers the webview's AUDIO_CAPTURE request by runtime-requesting *both* permissions;
   a permission missing from the manifest is auto-denied with no dialog, which fails the
   whole grant (getUserMedia then reports "Permission denied" even after a manual grant
   in system settings — found on-device). Both entries are required.
6. **`proguard-sona.pro`** — R8 keep rules for `MediaBridge`, `BiometricGate`,
   `MediaProjectionService` and `DeliveryService`. Release builds minify, and these
   classes are driven from Rust over JNI reflection with no Kotlin call sites, so R8
   strips them without the rules (found on-device: camera/screen-share controls dead,
   fingerprint unlock option missing — while the `native` JNI exports survived via the
   default keep rules, which made the breakage look partial). The generated Gradle
   config includes every `*.pro` under `app/`, so the dropped file is picked up
   automatically.
7. **`MediaBridge.kt` voice-call audio (both directions)** — calls capture through a
   `VOICE_COMMUNICATION` `AudioRecord` with the platform `AcousticEchoCanceler` /
   `NoiseSuppressor` / `AutomaticGainControl` attached and `MODE_IN_COMMUNICATION`
   routing (earpiece-first), instead of cpal's generic AAudio input, which bypasses the
   OEM echo canceller — loudspeaker→mic feedback built into static within seconds of a
   phone↔phone call (found on-device). Playout equally bypasses cpal: the far end
   plays through a `USAGE_VOICE_COMMUNICATION` `AudioTrack` — a MEDIA-usage stream in
   `MODE_IN_COMMUNICATION` is muted/heavily ducked by many OEM ROMs (found on-device:
   completely silent calls), ignores the earpiece↔speaker communication routing, and
   never feeds the AEC its far-end reference. The `NoiseSuppressor` follows the
   in-call noise-suppression toggle (default on). Rust side:
   `src-tauri/src/android_media.rs` (`nativeVoiceAudio`, `nativeVoicePlayoutFrame`,
   `set_voice_capture`, `set_voice_playout`, speakerphone routing).
8. **Bulletproof background delivery** (`SonaApp.kt`, `NotificationBridge.kt`,
   `DeliveryService.kt` v2, `BootReceiver.kt`, `SonaFirebaseService.kt`, plus
   `RECEIVE_BOOT_COMPLETED` / `USE_FULL_SCREEN_INTENT` / `FOREGROUND_SERVICE_SPECIAL_USE`
   / `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` / `POST_NOTIFICATIONS`). The full design is
   NOTIFICATIONS.md; the shape:
   * **Headless delivery engine** — delivery, decryption, and notification decisions
     run on a process-global Rust engine (`src-tauri/src/engine.rs`) with its own
     runtime, started by ANY entry point: the Tauri activity, the sticky-restarted
     `DeliveryService` (which now calls `nativeStartHeadless` — a restart actually
     boots Rust, auto-unlocks, and reconnects instead of posting a "Connected" lie
     over a dead runtime), the boot receiver, or a push wake. `SonaApp` loads the
     native library and hands ndk-context the APPLICATION context; the activity lives
     in a separate slot used only by prompt-needing flows (BiometricPrompt,
     projection consent).
   * **Native notifications** — everything posts through `NotificationBridge`
     (app-context, never the activity): MessagingStyle messages per chat,
     CallStyle + full-screen-intent + insistent-ringtone call rings with working
     Answer/Decline from the lock screen, truthful foreground-service status
     ("Connected" / "Reconnecting…" / "Delivery paused — unlock Sona"), and honest
     locked-vault generics. The disappearing-messages reaper also pulls expired
     content out of the shade.
   * **Delivery modes** — **Connection** (the `specialUse` foreground service +
     hardened socket: read watchdog, client keepalive pings, jittered backoff,
     connectivity-callback reconnect; Google-free, the default), **Push only**
     (no persistent service; the relay sends a content-free FCM wake and the app
     drains the mailbox in a shortService burst), or **Connection + push fallback**
     (the relay wakes only when it sees no live subscriber — self-healing when an
     OEM kills the service). Wake metadata is documented in `docs/THREAT_MODEL.md`;
     the default remains no-third-party.

Re-run the script whenever the project is regenerated; it detects an already-hardened
tree and does nothing. If `MainActivity.kt` has drifted from the pristine template the
script refuses to guess and asks for a manual merge.

On **desktop**, the same screen-capture protection is on via `contentProtected: true` in
`tauri.conf.json` (effective on Windows/macOS; Linux has no compositor-level equivalent).

## What we deliberately do not do

* **Root detection / attestation theater.** Trivially bypassed by the attacker it claims
  to detect, and it punishes power users. A warning-based posture is honest; fake
  assurance is worse than none.
* **Blocking accessibility.** See above — it breaks assistive tech, and a determined
  service can often evade view-level opt-outs anyway. We warn instead.
* **Hiding from the app list, panic wipes, etc.** Out of scope; tools like that belong
  to a different product with a different threat model.

## User-side hardening (for high-risk users)

The app cannot see outside its own sandbox; these steps raise the wall around it:

* **Run Sona in a separate Android user profile** (Settings → System → Multiple users)
  or a **work profile** (e.g. via Shelter). Apps in the main profile cannot see or touch
  it, and the profile has its own encryption keys.
* **GrapheneOS** if the hardware allows it — hardened kernel, per-profile isolation,
  storage scopes.
* **Use a trusted keyboard** (e.g. an open-source offline IME). The keyboard sees every
  word you type before Sona does; no app can protect you from a hostile IME.
* **Audit accessibility services** (Settings → Accessibility): anything you didn't
  knowingly enable should be removed — it can read your screen in any app.
* **Keep notifications content-free** (Sona's default) and lock-screen notifications
  hidden (Settings → Notifications).

## Implemented follow-ups

* **Android Keystore vault binding** — done. The vault device key is wrapped by a
  non-exportable AES-GCM key inside the Android Keystore (TEE-backed where the
  hardware provides one); the wrapped blob lives in the app's private files dir
  (`client-core::devicekey::AndroidKeystore`). A root attacker can use the wrapping
  key only while resident on the device — it cannot be extracted, so disk images and
  backups cannot open the vault. New wrapping keys prefer **StrongBox** (the discrete
  secure element — present on every Pixel, hence every GrapheneOS device) and fall
  back to the TEE where absent; the biometric seal-wrapping key (`BiometricGate.kt`)
  does the same. Existing TEE-backed keys are kept — regenerating would orphan the
  wrapped material they protect.
* **Content-free push** — done end-to-end: relay wake classes + FCM adapter, client
  registration/drain, delivery-mode settings UI with a health panel (battery
  exemption, notification permission, full-screen intent, Play services) — see
  `ARCHITECTURE.md` §5 and item 8 above. UnifiedPush distributor glue remains (the
  relay webhook path already speaks the UP shape).

* **Biometric (fingerprint) unlock + quick unlock** — done. See item 4 above and
  `docs/THREAT_MODEL.md` ("Quick unlock"): PIN and auto-unlock wrap the vault seal key
  with the Keystore device key (PIN adds an Argon2id-stretched factor and a 5-attempt
  wipe); nothing weakens the password path.
* **Auto-lock** — done in the GUI shell (idle timer, off by default; keys leave memory
  on lock). Runtime Keystore/BiometricPrompt round-trip on a real device is still on the
  verification checklist.

## Planned follow-ups

* **UnifiedPush distributor glue** (obtaining the endpoint URL from a distributor app
  and passing it to `register_push`) — GUI phase.
