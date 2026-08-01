# Notifications, delivery & the native ring — as built

> Status: **implemented and shipping** (2026-07-12). This document describes the
> system as it exists in the tree: how a message or call reaches the device in every
> app state, how notifications are produced, what each delivery mode does, and how
> the system degrades when the vault is locked. It replaces the original build plan
> (`PLAN.md`, now deleted); code comments that cite a `§` refer to the sections
> below, which keep the plan's numbering. Remaining follow-ups are in §10; the
> on-device acceptance protocol is `docs/NOTIFICATIONS_TESTING.md`.

**The promise:** a message arriving in *any* app state — foreground, backgrounded,
task swiped away, process killed, after reboot — produces a local notification:
sub-second in connection mode, within seconds in push mode. An incoming call
**rings** — audible, full-screen over the lock screen — in any of those states, and
Answer/Decline on the notification actually answer/decline. No plaintext, sender,
or recipient identity ever leaves the device or reaches a push broker.

---

## 1. Architecture — three pillars

```
                   ┌────────────────────────────── Android process ───────────────────────────────┐
                   │                                                                               │
 relay ──WS/HTTP──▶│  RUST DELIVERY ENGINE (singleton, own tokio runtime, activity-independent)    │
   │               │   Session · vault · delivery loops · watchdog · notif decisions · call state  │
   │               │        │ JNI (NotificationBridge)                 ▲ JNI entry points          │
   │               │        ▼                                         │                           │
   │               │  Kotlin: channels, MessagingStyle msgs,   MainActivity/Tauri (attach/detach)  │
   │               │  CallStyle+FSI ring, FGS status text      DeliveryService (sticky/boot start) │
   │               │                                           FCM / UnifiedPush receivers (wake)  │
   └──"wake" POST──▶ push broker (FCM / UP-shaped webhook) ── content-free, fires only when no live WS
                   └───────────────────────────────────────────────────────────────────────────────┘
```

**Pillar A — headless delivery engine (Rust).** Delivery, decryption, and every
notification *decision* live in a process-global engine
(`clients/desktop/src-tauri/src/engine.rs`) with its own tokio runtime, startable by
any entry point: Tauri setup (normal launch), `DeliveryService` (sticky restart,
boot), or a push receiver — FCM or UnifiedPush (wake-drain). The UI *attaches* to a running engine — it
never owns delivery. On desktop the same engine runs under the tray model.

**Pillar B — native notification pipeline (Kotlin).** All OS notifications post
through `NotificationBridge` (source of record `clients/desktop/scripts/`, injected
by `harden-android.sh`) using the **application context** — never the activity, never
the Tauri notification plugin. This is what keeps notifications working after the
activity (or the whole task) is gone. Desktop posts through the Tauri plugin via the
engine's attached UI handle.

**Pillar C — wake transports.** Three user-selectable delivery modes (§2) built on
the relay's content-free wake system: a persistent WebSocket, push wakes (FCM or any
UnifiedPush-shaped webhook), or both.

Historic root causes these pillars fixed (still cited as `RC-n` in code comments):
**RC-1** sticky service restart brought back a Kotlin shell with no Rust runtime —
the "Connected" notification lied; **RC-2** notifications posted through an
Activity-bound plugin died with the activity; **RC-3** zombie sockets were never
detected (no client watchdog/pings); **RC-4** there was no native ring path at all;
**RC-5** `focused` defaulted to true, which would have suppressed every notification
on a headless start.

## 2. Delivery modes (user-facing)

Persisted in `Prefs.delivery_mode` (`"c"` | `"cp"` | `"p"`), applied live by the
engine. Transitions are crash-safe ordered: register-before-stop /
start-before-unregister — never a gap with neither transport live.

| Mode | What runs | Latency | Battery | Third parties |
|---|---|---|---|---|
| **Connection** | foreground service + persistent WebSocket | sub-second | highest | none |
| **Connection + push fallback** (default) | both: socket while alive, push when the OS kills it | sub-second, self-healing | medium | broker sees wakes only when the socket is dead |
| **Push only** | no persistent service; relay wakes the device per message | seconds (deep Doze: tens) | ≈ idle | broker sees every wake |

The relay only fires a wake when it has **no live subscriber** for the mailbox, so in
C+P pushes fire exactly when the socket is dead (OEM kill, Doze park, crash) — the
system self-heals without double delivery.

**The default is resolved, not fixed** (`push.rs::auto_delivery_target`). Until the
user picks a mode in settings (`Prefs.delivery_mode_set`), the stored value is a
default re-resolved after every unlock and whenever a push transport appears or
disappears: **C+P** where a wake transport is actually usable — a transport on the
phone *and* a relay that can drive it — and **C** everywhere else. Never P: push-only
is an explicit choice, because a best-effort wake is not something an incoming call
can be relied on to survive. Both targets keep the connection, so
a push token appearing never takes a healthy connection down, and a distributor being
uninstalled leaves the connection carrying everything. With no usable wake path the
health panel says **"Push fallback not configured"** rather than implying coverage
that does not exist.

**Transport policy (capability-adaptive UI).** Two audiences, one backend:

- **Stock devices (Play Services present)** keep the familiar surface: push modes
  gate on the relay's `push-fcm-v1` and ride FCM, exactly as before. The UnifiedPush
  row stays hidden unless a distributor is already in use.
- **De-Googled devices (GrapheneOS, CalyxOS…)** get the same modes powered by
  **UnifiedPush** (§6.7): a "Push wake-ups" row lists installed distributors (with a
  pointer to ntfy when none is installed), and push modes gate on a chosen
  distributor plus the relay's wake support.

Endpoint precedence in the client is UnifiedPush first, FCM token second — a user
who explicitly picked a distributor is never silently routed through Google; a stock
user who never touches UnifiedPush never sees it.

## 3. Message notifications

- Engine-side `notif_for_event` privacy-levels the content (`notif_level` pref:
  `sender` default / `sender_message` / `generic`) **before** anything crosses JNI —
  the bridge never sees more than the leveled strings.
- Per-chat `MessagingStyle` notification (stable id = 31-bit hash of the chat key),
  engine-buffered last ≤ 8 lines replayed on each post, `sona_msgs` group + summary
  when more than one chat is active, monochrome `ic_stat_sona` small icon,
  lock-screen visibility PRIVATE.
- Tap → activity PendingIntent carrying `open_chat=<chatKey>` →
  `MainActivity.onNewIntent` → JNI → engine → `navigate` event → the webview opens
  the chat after unlock (cold starts read the pending intent via
  `take_pending_intent`).
- Disappearing messages: the engine reaper **cancels** an affected chat's
  notification when content expires — expired content never outlives its timer in
  the shade; messages already expired on arrival are never shown.
- Opening a chat cancels its notification; a bounded per-chat msg-id ring dedups the
  drain-vs-socket handoff window.
- **Shade actions — Mark read and inline Reply** — ride *only* on these real,
  decrypted notifications; the locked-state generics (§7.4) never carry them, because
  acting on an unknown message is meaningless. Mark read runs the exact same
  receipt path as opening the chat (honoring the read-receipts privacy pref; groups
  mark locally). Reply sends through the exact same fan-out path as the composer and
  confirms by appending "You: …" to the notification — that repost is also what
  clears the RemoteInput spinner. Both re-check the vault at tap time: locked (it can
  lock between post and tap) → mark-read no-ops and a reply reposts with "Unlock Sona
  to send — reply not sent" instead of silently eating the text.

## 4. The delivery engine

### 4.1 Shape

Engine singleton in the app crate (it orchestrates `Session`, prefs, vault paths;
`client-core` stays transport+crypto): own tokio runtime, the session `Arc` (Tauri's
`AppState` borrows it), an attachable UI sink (event emits no-op headless; the UI
re-syncs on attach), `focused` (starts **false** — RC-5), open-chat tracking,
connection state, notification line buffers, ring state, push token, drain counter,
and the background auto-lock backstop (§7.3). `notifier.rs` is a cfg-split module:
Android → JNI bridge, desktop → Tauri plugin.

### 4.2 Entry points

| Entry | Caller | Effect |
|---|---|---|
| Tauri `setup` | normal launch | ensure engine, attach UI |
| `nativeStartHeadless` | sticky restart, `BootReceiver` | ensure engine; try auto-unlock (§4.4); full loops or truthful `Locked` status (§4.5) |
| `nativeWake(class)` | FCM / UnifiedPush receiver | ensure engine; live subscriber → ignore; else drain (§6.4) |
| `nativeSetUpEndpoint` | UnifiedPush receiver | store/clear the distributor endpoint; reconcile relay registration |
| `nativeNetworkChanged` | `ConnectivityManager` callback | all loops reconnect immediately (skip backoff) |
| `nativeActivityState(resumed)` | `MainActivity` lifecycle | authoritative `focused` on Android |
| `nativeNotifAction(json)` | notification actions | `decline_call{call_id}` validated against live state |
| `nativeOpenIntent(json)` | notification taps | stored as pending intent + `navigate` event |
| `nativeSetPushToken` | `onNewToken` / engine-kicked fetch | re-register endpoint on rotation |

### 4.3 Android context split

`ndk_context` holds the **application** context (installed once by `SonaApp`);
the activity lives in a separate slot (`MainActivity.nativeSetActivity`) consumed
only by flows that genuinely need one: BiometricPrompt (`bio.rs`), MediaProjection
consent, camera permission. Keystore, service control, and notification posting all
run on the app context — which is why headless starts work.

### 4.4 Headless unlock

The delivery socket cannot authenticate without account keys (subscribe signs a
challenge), so after process death:

- **Quick auto-unlock enabled** (`prefs.auto_unlock`, Keystore-wrapped device key):
  the engine unlocks the vault headlessly and resumes full delivery — Signal's
  at-rest model, covered in `THREAT_MODEL.md`.
- **Password/PIN/biometric-only**: headless decrypt is impossible *by design*; the
  UX degrades honestly (§4.5, §7.4) instead of pretending.
- Before the first device unlock after boot, Keystore keys are unavailable
  (`isUserUnlocked` checked by boot/push receivers) — generic notifications are the
  only possible output.

### 4.5 Truthful service status

The foreground-service notification text is engine-driven (`setServiceStatus`) and
can never lie:

| Engine state | FGS text |
|---|---|
| Connected | "Connected — receiving messages" |
| Reconnecting | "Reconnecting…" |
| Locked (no auto-unlock) | "Delivery paused — unlock Sona to receive messages" |
| Mode P / logged out | *(no persistent notification)* |

### 4.6 Socket hardening & boot

- **Read watchdog**: 75 s of transport silence (server pings every 30 s) tears the
  socket down and reconnects — applied at the frame-wait level only, never around
  decrypt+ack (preserves the cancel-safety invariant).
- **Client keepalive pings** every 55 s of send-idle (NAT-proven interval).
- **Reconnect**: exponential backoff 1→60 s with ±30 % jitter; reset to immediate on
  network change and unlock.
- **Boot receiver**: mode C/CP + `isUserUnlocked` → `startForegroundService`
  (`specialUse` FGS type — not boot-restricted, no `dataSync` 6 h cap).
- `onTaskRemoved` is a no-op; Doze-exemption status is surfaced live in the health
  panel instead of fire-and-forgotten.

## 5. Calls — Core-Telecom and the native ring

**Core-Telecom owns the call.** Sona registers with `CallsManager` in
`Application.onCreate` (before any component can ring) and adds every incoming and
outgoing call to the platform, so ringing, answered, active, held and disconnected are
system states rather than a private state machine. That is what makes a call visible to
a watch, a headset, and a car head unit, what survives an Activity or WebView being
destroyed, and what owns the audio route (§5.1). Hold and streaming are deliberately
**not** advertised: a capability Sona cannot honor is how a car ends up holding a call
that never comes back. Every ring carries an opaque single-use `ring_handle` that keys
the system call, the notification, and every cancellation — never the media room id,
which is a capability and must not reach the platform call log.

The notification below is Core-Telecom's *presentation*, not a second lifecycle.

`showCall` (bridge): API 31+ `Notification.CallStyle.forIncomingCall`; API 26–30
equivalent high-priority actions. Both: `CATEGORY_CALL`, ongoing, full-screen intent
over the lock screen, **`FLAG_INSISTENT`** (the system loops the `calls` channel
ringtone until the notification is cancelled — no MediaPlayer to babysit),
`setTimeoutAfter(45 s)` aligned with the Rust ring window. Display name honors
`notif_level` (generic level rings as "Sona — Incoming call"). Group calls take the
identical path with the group name.

**Answer** — the notification's Answer action goes to Rust, which is the single answer
path Core-Telecom, a headset, a watch and the lock screen all share. Rust decides
whether this device may answer now or must open the vault first;
when it must, it brings the app forward itself and holds the answer against the exact
`call_instance_id` + `ring_handle` until the unlock completes, bounded at 45 s
(§8). The superseded design — a 60-second WebView flag redeemed by whatever rang next
— is gone: it answered later calls as readily as the right one, and answered before
anything checked who was holding the phone.

**Decline** — `NotifActionReceiver` (exported=false) cancels the notification and
sends `decline_call{call_id}` through the engine, validated against the live offer —
works without ever opening the UI. Declining the *generic* locked ring (below) just
dismisses it: there is no decryptable offer to decline yet.

**Cancel paths** (engine-driven): caller hung up → cancel + "Missed call" (status
channel); answered or declined on another device (a `CallTerminalV2` naming
`answered_elsewhere` / `declined_elsewhere`, plus its capsule copy for a locked or
sleeping phone — ring-all is live) → silent cancel; ring timeout → cancel + missed. In-app accept/decline cancels the
native ring for that call id. **Every successful unlock also clears the locked-state
generics** (`clearGenerics`): the generic ring is superseded the moment real,
decrypted call state exists — it must never keep "ringing" beside the real call UI.

Foreground suppression: when the activity is resumed *and* unlocked, the engine
skips the native ring — the in-app ring UI handles it (no double audio). Any other
state rings natively.

**Headset / watch / car answer.** Core-Telecom delivers these directly: a registered
call receives the real HFP call button and every remote surface's answer and hangup.
The ring-window `MediaSession` that used to approximate this — it claimed media-button
KeyEvents because an unregistered app never receives the HFP button — is deleted along
with the parallel accept path it fed. Platform callbacks report to Rust and return
immediately; nothing waits inside one for a relay round trip or a human unlock.
The accept runs the exact same path as the UI button (`call_accept_inner`), fully
native audio, so answering with the app closed still produces a working call.

**In-call audio routing (Android).** One route model: earpiece / loudspeaker /
Bluetooth headset. A connected SCO headset is the automatic default (someone who
answers on their earbuds expects to hear the call there); an `AudioDeviceCallback`
keeps it live — headset appears mid-call → auto-switch to it, disappears → fall
back to the earpiece, both pushed to the UI as an `audio_route` event. The in-call
button adapts: headset present → Bluetooth icon opening a chooser (Bluetooth by
name / Loudspeaker / Phone earpiece — an explicit pick wins over automatic for the
rest of the call); no headset → the classic loudspeaker toggle. Legacy (< API 31)
devices ride `startBluetoothSco`; API 31+ uses `setCommunicationDevice`.

Full-screen-intent permission (Android 14+) is surfaced in the health panel with a
fix-it deep link; if revoked, the ring still works as heads-up + insistent sound.

## 6. Push transports

### 6.1 Wake classes (protocol)

`Envelope.wake` (`protocol-types`): `None | Normal | Call`, `#[serde(default)]` —
absent (old clients) = `Normal`. Tagged in **one place**
(`client-core::seal_payload_to` via `wake_class_for`): chat/attachment/group sends →
`Normal`; call + group-call offers → `Call` (reconnect offers = `Normal`, never
`Call`); receipts, typing, self-sync, call signaling → `None`. The relay reads it
only to decide whether/how to fire a content-free wake. Metadata cost (wake-class
distribution visible to relay, and to Google in FCM mode) is documented in
`THREAT_MODEL.md` — strictly less than Signal's per-envelope urgent flag + push
payload.

### 6.2 Relay wake policy

Per registered push endpoint, when an envelope arrives for a mailbox with **no live
subscriber** (`http/msg.rs::claim_wake`): `None` → never; `Normal` → debounced
(`WAKE_DEBOUNCE_SECS`, 30 s); `Call` → bypasses the debounce with its own 2 s
per-recipient min-interval (`CALL_WAKE_MIN_SECS`) — anti-battery-DoS, on top of the
sender envelope rate limits. Payloads are constant per class: webhook body
`"wake"`/`"wake-call"`, FCM data `{"t":"m"}`/`{"t":"c"}`. Two classes exist so a
locked-vault device can ring generically without decrypting (§7.4).

### 6.3 FCM adapter (relay-side, optional)

`crates/server/src/push.rs`: FCM HTTP v1, OAuth2 service-account JWT (RS256 via
`ring`; no Google SDK), token cached ~55 min. Messages are **data-only** (never
`notification:`), high priority, TTL 60 s (call) / 24 h (message), constant collapse
key. `UNREGISTERED`/`INVALID_ARGUMENT` deletes the push row (self-heals via
`onNewToken`); 429/5xx are dropped (the next envelope re-fires). `fcm:<token>`
registrations are accepted only when the relay is configured
(`FCM_SERVICE_ACCOUNT_JSON(_FILE)`) — setup in `DEPLOYMENT.md`; the webhook path
(which *is* the UnifiedPush transport shape) works regardless and the SSRF posture
is untouched (`fcm:` never hits the URL fetcher). Endpoints are stored encrypted at
rest.

### 6.4 Client receive — the drain

High-priority FCM grants ~10 s of network in Doze plus a background-FGS exemption:
`SonaFirebaseService` → shortService ("Checking for new messages…", 3-min cap) →
`nativeWake(class)`. If a live subscriber exists → done (rare race; the relay only
wakes when it saw none). With auto-unlock → **drain mode**: the normal delivery loop
(`drain=true`) — same decrypt, poison-ack, notification and ring code as mode C —
with no reconnect retries and a 15 s idle disconnect; a `DrainGuard` always releases
the shortService. Without auto-unlock → skip the socket (it cannot auth), post the
generic for the wake class (§7.4), stop.

### 6.5 Client FCM init

No `google-services.json`, no Google Gradle plugin (reproducible-builds constraint):
only the `firebase-messaging` dependency plus manual `FirebaseOptions` init in
`SonaApp` from `BuildConfig` fields injected at build time (`SONA_FCM_*` env vars —
see `DEPLOYMENT.md`; the build script auto-sources `clients/desktop/.env.fcm` if
present). Missing values or missing Play Services → init skipped → FCM mode gated
off in the UI with an explanation; the webhook path remains.

### 6.6 Multi-device

Push registration is **per mailbox** (`register_push_as`, same auth path as
`subscribe_as`): a linked device registers its device mailbox, the primary the
account mailbox; unlink/revoke unregisters. Ring-all-devices already fans call
offers per device mailbox — each offline device gets its own `Call`-class wake, and the
`answered_elsewhere` terminal (urgent-silent `CallControl` wake, so a sleeping phone
wakes to stop ringing) cancels the losers' rings after their drains. Former-username
mailboxes are not push-registered (their backlog surfaces on next open).

### 6.7 UnifiedPush — the Google-free push transport

The user installs a **distributor** app of their choice (ntfy — F-Droid or Play,
self-hostable server —, NextPush, Sunup, …), which keeps one battery-cheap connection
for every UnifiedPush app on the phone. Sona's settings list the installed
distributors; picking one sends it a `REGISTER` broadcast, the distributor answers
with an endpoint **URL**, and the client registers that URL with the relay through
the ordinary webhook push path — which was UnifiedPush-shaped from day one
(challenge-signed registration, SSRF-filtered, constant body `"wake"`/`"wake-call"`).
**The relay needs zero configuration for this** — unlike FCM; any relay that
advertises `push-webhook-v1` serves UnifiedPush wakes.

Client mechanics (`UnifiedPush.kt`, implemented against the raw broadcast spec — no
connector library, keeping the reproducible build dependency-free):

- `UnifiedPushReceiver` is **exported** (the distributor is another app); every
  broadcast is validated against an app-private random registration token — a spoofed
  `MESSAGE` is a no-op without it, and even with it could only trigger a drain of an
  empty mailbox.
- `MESSAGE` (`"wake"`/`"wake-call"`) → the same shortService + `nativeWake(class)`
  drain pipeline as FCM (§6.4). One pipeline, two wake transports.
- `NEW_ENDPOINT` → endpoint stored + handed to Rust, which re-registers with the
  relay (UnifiedPush outranks any FCM token). `UNREGISTERED`/`REGISTRATION_FAILED` →
  endpoint cleared, Rust falls back to the system token or unregisters — a wake must
  never be aimed at a dead URL.
- Distributors expect re-registration after boot/app update: `SonaApp.onCreate`
  re-broadcasts `REGISTER` when a distributor was chosen (idempotent upsert).
- Discovery needs a manifest `<queries>` element declaring the
  `org.unifiedpush.android.distributor.REGISTER` intent (harden step 15c2): Android
  11+ package-visibility filtering otherwise hides distributors' receivers from
  `queryBroadcastReceivers`, so the picker would claim none are installed even with
  ntfy present.

Metadata: the distributor (and its server) sees wake class + timing for this device —
the same single bit FCM would see, but the user *chooses and can self-host* the party
that sees it. Locked-vault behavior, debounce/flood caps, and multi-device fan-out
are identical to the FCM path (§6.2, §7.4).

## 7. Settings & UX

### 7.1 Notifications settings + health panel

Delivery-mode radio (C / C+P / P; push options unlock per the §2 transport policy),
a **"Push wake-ups" row** — shown on de-Googled devices (and wherever a distributor
is already active) — that lists installed UnifiedPush distributors and lets the user
pick/drop one (no distributor → a pointer to ntfy), the existing `notif_level`
content control, "Test notification" and "Test ring" buttons, and a **live health
panel**: a plain-language status hero plus one row per check — notification
permission, battery exemption, full-screen-intent grant (A14+), channel mute state,
the active push transport (UnifiedPush / system push / none) — each with a fix-it
button where one exists. The panel **re-polls every 2 s while open**, so a switch
flipped in system settings turns its row green on return, no reopen needed. On
makers with aggressive background killers (Samsung, Xiaomi, OnePlus, … — keyed off
`Build.MANUFACTURER`) an extra row deep-links the maker's page on
**dontkillmyapp.com** (sub-brands map to their parent page, unknown makers to
/general) — those killers have no API, only user-flippable switches.
`POST_NOTIFICATIONS` denial surfaces as a banner with a settings deep link instead
of posting into the void.

Device-offline is reported honestly, not as a fault: when the OS presents no default
network (airplane mode, or the app's per-app **Network permission revoked on
GrapheneOS** — which the app simply sees as "no network"), the health hero and the
delivery foreground notification say "No network" instead of an eternal
"Reconnecting…", and suggest no action. `NetworkMonitor` tracks default-network
presence (`health.network`); reconnect attempts fail instantly without a route and
back off to the 60 s cap, so an offline device costs no meaningful battery, and the
existing `onAvailable` nudge reconnects the moment a network returns.

### 7.3 Auto-lock interplay

The auto-lock idle timer runs **in the engine** (webview timers freeze in the
background — a UI-side timer is a correctness bug for a security feature). Locking
wipes keys and stops delivery — that is its contract; the FGS then reads "Delivery
paused", and in push modes locked wakes produce generics (§7.4). The push
registration deliberately survives `lock()`.

### 7.4 Locked-vault degradation matrix

| State | Mode C | Mode P / C+P |
|---|---|---|
| Unlocked / auto-unlock | full notifications + ring | full notifications + ring (after drain) |
| Locked, PIN/password-only | FGS "Delivery paused — unlock Sona"; nothing else is *possible* (no keys → no socket auth → the app cannot even know a message exists) | `"t":"m"` → generic "You may have new messages" (status channel); `"t":"c"` → generic insistent ring "Sona — Incoming call" whose Answer lands on the lock screen → unlock → drain → real call UI |
| Before first unlock after boot | as locked | as locked |

On every successful unlock the generics are cleared (§5) and the real
subscriber/drain takes over. Settings states the trade plainly and links quick
auto-unlock; it is never enabled silently.

## 8. Security properties

- Notifications are built **after** local decrypt and privacy-leveled before
  crossing JNI; wake payloads are constant strings; lock-screen visibility PRIVATE.
- New metadata (wake class → relay; class + timing → broker; FCM token ↔ mailbox
  hash in the relay's encrypted DB) is documented in `THREAT_MODEL.md`; each item is
  ≤ Signal's equivalent.
- Wake-flood/battery-DoS: per-recipient per-class relay caps + sender rate limits;
  one drain serves any number of queued wakes; a replayed wake drains an empty
  mailbox (nothing to amplify).
- Notification intents: activity PendingIntents only (Android 12+ trampoline rules),
  `FLAG_IMMUTABLE`, extras limited to routing keys; the decline receiver is
  exported=false and validated against the live call id in Rust.
- Headless auto-unlock reuses the existing opt-in Keystore quick-unlock blob —
  PIN/password postures are not weakened, they simply don't get background decrypt
  (and the UI says so). The truthful FGS text doubles as security UX.
- Reproducible builds: no Google build plugin, no bundled Firebase JSON.

## 9. Failure-mode matrix

| # | Scenario | Behavior |
|---|---|---|
| 1 | Backgrounded, other app focused | C: socket live → instant. P: wake → drain |
| 2 | Task swiped, process survives | engine + bridge are activity-independent → works |
| 3 | Task swiped, OEM kills process | C: sticky restart → headless start → auto-unlock → reconnected in seconds; no auto-unlock → truthful "paused". C+P: next message wakes via push regardless |
| 4 | Deep Doze, exemption granted | network stays; watchdog covers hiccups |
| 5 | Deep Doze, exemption revoked | C alone: delayed to maintenance windows (health panel shows it); C+P: dead socket → high-prio FCM punches Doze → drain |
| 6 | NAT/carrier silently drops TCP | 75 s watchdog + 55 s client pings → reconnect |
| 7 | Network flap / VPN toggle | connectivity callback → immediate reconnect |
| 8 | Reboot | boot receiver (C, after first unlock); FCM works from boot (P); before first unlock → generics only (OS design) |
| 9 | Force-stop from app settings | Android contract: nothing runs until the user opens the app (unfixable, Signal included); health panel reports it |
| 10 | Call, screen locked | CallStyle + FSI + insistent ringtone over the lock screen |
| 11 | Call while vault locked (P/C+P) | call-control capsule decides: live ring → generic insistent ring; terminal → the ring is cancelled. Answer → unlock → the held claim is submitted for that exact call |
| 12 | Caller hangs up pre-answer | ring cancelled + "Missed call"; FCM TTL 60 s kills stale call wakes in transit |
| 13 | Answered on another device | silent cancel (ring-all preserved) |
| 14 | Offer expires (45 s) | notification timeout + engine timer both cancel; missed-call posted |
| 15 | FCM token rotates / reinstall | `onNewToken` re-registers; relay purges dead tokens |
| 16 | Play Services absent | no Firebase class is loaded at all (`SonaApp` gates init on the `com.google.android.gms` package being installed); FCM modes hidden; webhook/UnifiedPush shape remains; the default resolves to C |
| 17 | Relay restart | jittered backoff reconnects; wakes fire for envelopes queued while down |
| 18 | Poison envelope in a drain | poison-ack invariant keeps the loop alive; later messages still notify |
| 19 | Disappearing message expires in the shade | reaper cancels the chat notification |
| 20 | Push + live socket race (C+P) | relay wakes only with no live subscriber; engine singleton + msg-id ring dedup the residue |
| 21 | Notification permission denied | banner + deep link; the FGS channel is exempt and still runs |
| 22 | FSI permission revoked (A14+) | heads-up + insistent sound still ring; health-panel fix-it |
| 23 | User silences a channel | respected; health panel states it |
| 24 | OEM revokes battery exemption | health panel re-checks each open; C+P self-heals via push |
| 25 | Hostile peer spams call offers | relay wake caps + sender rate limits; `used_call_ids` blocks replays |
| 26 | Malicious broker replays wakes | drains an empty mailbox; constant body, nothing to amplify |
| 27 | Desktop | tray keeps the process; plugin notifier path; no FGS/push semantics |

## 10. Future work

- Server ping-interval battery tuning (server config, `http/`).
- On-device certification of the Core-Telecom lifecycle, the locked call-control layer
  and the resolved delivery default: they build and are covered host-side, but nothing
  runtime is proven until the `NOTIFICATIONS_TESTING.md` matrix runs on real phones.

(UnifiedPush (§6.7), the mark-read / inline-reply shade actions (§3), and the live
health panel with OEM dontkillmyapp guidance (§7.1) shipped 2026-07-12. Core-Telecom —
which was this section's open item, listed as "in-car UI and the true HFP call button" —
landed with the call-reliability work and is now §5. A metrics debug screen was
considered and dropped — not needed.)

## 11. Testing

On-device acceptance protocol, adb crib (`deviceidle force-idle`, `am kill` vs the
documented-broken `force-stop`, notification-shade dumps) and the state × mode
matrix live in `docs/NOTIFICATIONS_TESTING.md`. Automated coverage: server tests for
wake classes × debounce × flood caps × live-subscriber suppression and the FCM
adapter; client-core tests for wake tagging and `register_push_as` signing; engine
watchdog/backoff tests (tokio time-paused); the `Envelope.wake` field rides the
existing fuzz harness.
