# Background delivery & call-ring test protocol (Android)

The on-device acceptance matrix for NOTIFICATIONS.md (bulletproof notifications & calls).
Run after any change to the delivery engine, the Kotlin pipeline, or the wake
transports. Every cell: send a **message** and place a **call** from a second
account, expect a notification / audible ring and note the latency.

## Device matrix

| State ↓ / Config → | C (auto-unlock) | C (PIN-only) | P (auto-unlock) | P (PIN-only) | C+P |
|---|---|---|---|---|---|
| Foreground, other chat open | | | | | |
| Backgrounded (other app) | | | | | |
| Task swiped from recents | | | | | |
| Process killed (`am kill`) | | | | | |
| Force-idle Doze 30 min | | | | | |
| After reboot, unlocked once | | | | | |
| Screen locked (calls ring over lock screen) | | | | | |

Expected: C = sub-second with a live socket, reconnect ≤ 10 s after a kill
(auto-unlock) or a truthful "Delivery paused — unlock" (PIN-only). P/C+P = seconds
via wake (tens of seconds in deep Doze); PIN-only degrades to the generic
notification / generic ring (§7.4 of NOTIFICATIONS.md) — never silence.

Calls additionally: Answer and Decline work from the lock screen; answering on a
second own device cancels the ring here; a caller hang-up pre-answer yields
"Missed call"; an unanswered ring stops at 45 s with a missed-call entry; no double
audio when the app is foregrounded.

## Calls: Core-Telecom, arbitration, and the locked path

The call-reliability work (`internal/CALL_PLAN.md`, which the `§` refs below cite) added
surfaces the matrix above cannot
reach. These need real hardware and, for several rows, a second and third device.

**Telecom lifecycle and audio route** (§12.4). Voice and video, incoming and outgoing:

| Case | Expect |
|---|---|
| Answer/hang up from a **Bluetooth headset**, a watch, or a car head unit | works — the call is a system call, not a notification action |
| Route switch earpiece ↔ speaker ↔ Bluetooth ↔ wired | Telecom's endpoint changes; the in-call UI shows the endpoint Telecom actually selected, not the one requested |
| Bluetooth connects/disconnects mid-ring and mid-call | route follows; no dead audio |
| **Cellular call arrives** during a Sona ring, and during an active Sona call | the Sona call goes inactive (muted, not torn down) and comes back when the cellular call ends |
| Mic/camera permission granted **during** connect | capture restarts; the call does not silently continue with no audio |
| Audio fails to start | the call fails visibly — never a connected call with no sound |
| Process killed mid-ring (`am kill`), then reopened | reconciliation restores a still-valid ring and disconnects one that ended; **no duplicate missed-call entry**, and no ring raised merely because a stored row exists |

**Unlock-to-answer** (§8), with the vault locked, once per lock method (fingerprint,
PIN-only, password-only):

- Answer from the lock screen → the ringtone stops at once and the call shows
  *connecting*, then Sona's unlock appears. Media starts only after the unlock.
- Other devices **keep ringing** while this phone waits — it has won nothing yet.
- Cancel or fail the unlock → only this device disconnects; a sibling can still answer.
- Let the unlock time out (45 s) → no permanently "connecting" system call is left.
- Unlock *after* the call already ended → the tombstone disconnects it; no late answer.
- With the setting **off** and auto-unlock on, the answer completes without a prompt.

**Multi-device arbitration** (§12.2). Run with Android as primary and as linked,
paired with Windows and with Linux, and once with two Android devices:

- every device rings within a second or so of the others (this is what the concurrent
  fan fixed — a 10–15 s linked-device lag is a regression);
- the first device to answer wins; **every** other device stops ringing, with the right
  wording (*answered elsewhere* vs *declined elsewhere* vs *cancelled*);
- answer on two devices at nearly the same instant → exactly one connects;
- a busy device reports busy **without** ending the ring on its siblings;
- caller cancels → every device stops, including one that is locked, Dozing, or was
  process-killed after posting its ring;
- no device rings after a prior terminal, and no duplicate missed-call chip appears.

**GrapheneOS** (§10.4). Both configurations — no Play services with a UnifiedPush
distributor, and sandboxed Play with FCM:

- delivery mode resolves to **C+P** by itself where a wake transport exists, and to
  **C** where none does (never P), with the health panel saying so honestly;
- revoke Sona's **Network** permission → the panel says no network and names the
  permission, rather than blaming delivery;
- with a SOCKS/Tor proxy set, calls use the relay WebSocket media path — verify no UDP
  leaves the device for a call;
- hardware attestation `SelfSigned` with a locked bootloader must not gate calls;
- force-stop and a paused profile: nothing arrives until the user reopens Sona — expected,
  and the docs must not claim otherwise.

## adb crib

```sh
# Deep Doze on demand (screen off first), and back:
adb shell dumpsys deviceidle force-idle
adb shell dumpsys deviceidle unforce

# Kill the process the way Android does (NOT force-stop):
adb shell am kill app.sona.messenger

# Force-stop = the user said stop: no service, no FCM until the next manual open.
# Documented-broken case (#9 in NOTIFICATIONS.md's failure matrix) — Signal included:
adb shell am force-stop app.sona.messenger

# Simulate an OEM background-killer:
adb shell cmd appops set app.sona.messenger RUN_ANY_IN_BACKGROUND ignore

# Battery-exemption state:
adb shell dumpsys deviceidle whitelist | grep sona

# Network flaps (watchdog + connectivity-callback test):
adb shell svc wifi disable && sleep 20 && adb shell svc wifi enable
adb shell svc data disable && sleep 20 && adb shell svc data enable

# What's in the shade (content check — verify the privacy level!):
adb shell dumpsys notification --noredact | grep -A4 sona

# Watch the engine:
adb logcat -s SonaRust SonaDelivery SonaDrain
```

## What must never appear

- The persistent notification saying "Connected" while `SonaRust` logs show no live
  socket (RC-1's lie — the status text is engine-driven now).
- Message *content* above the user's chosen notification level in
  `dumpsys notification --noredact`.
- An expired disappearing message still readable in the shade after its timer.
- A wake payload with anything beyond `{"t":"m"}` / `{"t":"c"}` / `{"t":"x"}` (check FCM
  diagnostics / the relay logs), or a UnifiedPush body beyond the constant
  `wake` / `wake-call` / `wake-call-control`.
- A second ring for one call — a capsule ring and an encrypted-offer ring must converge
  on one system call, one notification, and one ringtone.
- A ring that outlives its call: after answer-elsewhere, decline, or caller cancel, the
  phone must go quiet even if it is locked and was asleep.
- A media room id (`call_id`) in the platform call log, a notification, or any push
  payload — it is a capability, and the ring handle exists so it never leaks.
