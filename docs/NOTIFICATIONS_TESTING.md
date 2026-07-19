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
- A wake payload with anything beyond `{"t":"m"}` / `{"t":"c"}` (check FCM
  diagnostics / the relay logs).
