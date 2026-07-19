# Sona Threat Model

What we defend against, what we don't, and how. The guiding assumption is that **the
server is untrusted** — even though you self-host it. If security depended on trusting the
operator, none of the cryptography would be necessary.

## Assets

* Message **content** (highest value).
* The **social graph** (who talks to whom, when).
* Long-term **identity keys** (at rest on a device).
* Account **availability**.

## Adversaries & defenses

### Honest-but-curious server
*Can:* read everything it stores; observe timing and recipient hashes.
*Defended:* messages are end-to-end encrypted (Olm Double Ratchet); the server holds only
ciphertext, public keys, and hashes. It never sees plaintext or usernames.

### Malicious / compromised / coerced server
*Can:* forge a key on lookup; drop, reorder, or withhold messages; try to rewrite history;
try to show different people different logs.
*Defended:*
* **Key forgery → Key Transparency.** Bindings are self-signed and logged append-only; the
  server can't forge an entry or hijack a username. Clients verify inclusion against a
  **pinned** tree-head key before trusting any key. (See `KEY_TRANSPARENCY.md`.)
* **Rogue key under your name → self-audit.** A client periodically audits its own log
  entry (`Client::audit_own_key`); a different key published for its username is detected.
* **Silent key swap → key-change detection.** `Client::add_contact_checked` compares the
  offered key against the pinned one and refuses to auto-start a session on a change —
  the user must compare the new safety number and accept first.
* **One-time-key-drain DoS → fallback key.** An attacker fetching a victim's bundle
  repeatedly can exhaust one-time keys; a reusable, signed **fallback key** is then served
  so sessions still start. (Clients also replenish one-time keys.)
* **History rewrite → consistency proofs.** A pinned client detects any non-append-only
  change.
* **Equivocation (split view) → gossip + independent auditors.** Clients witness the log
  over time and compare the heads they were shown (`Client::advance_witness` /
  `compare_foreign_head`); additionally, anyone can run the standalone **`sona-auditor`**
  daemon (`crates/auditor`) against a relay — it pins the KT key, demands an append-only
  consistency proof for every head change, and on violation writes an evidence file with
  both signed heads. A server that signed two conflicting histories is caught with
  non-repudiable proof.
* **Withholding/DoS → partial.** A server *can* refuse to deliver; that is recoverable
  (transient) and detectable, unlike silent reading. Availability is explicitly weaker
  than confidentiality in our model.

### Network attacker (passive or active)
*Can:* read/modify traffic.
*Defended:* TLS (terminated by the reverse proxy) for confidentiality of metadata; the
auth scheme additionally needs no TLS to stay unforgeable — login is a signature over a
single-use server nonce, so a captured frame can't be replayed. Message integrity comes
from the ratchet regardless of TLS.

### Server disk / backup theft (seizure, leaked backup)
*Can:* read the relay's database at rest.
*Defended:* message bodies are stored as an AEAD blob (XChaCha20-Poly1305) under a key
held **off the data disk** (env/secrets manager), so a stolen DB is undecryptable; and the
content was end-to-end encrypted before it ever reached the server anyway. What remains
readable is the irreducible routing metadata a store-and-forward relay must keep:
recipient **hashes** (one-way, not usernames), timing, and counts. The directory and KT
log are stored as plaintext because they are public by design. This is "inability, not
good faith": the operator cannot hand over message content or sender identities because
the server never had them in a readable form.

### Device thief (offline access to a *client* disk)
*Can:* read the on-disk vault and try to brute-force it.
*Defended:* the vault is Argon2id (memory-hard) → XChaCha20-Poly1305; a weak password is
refused at creation. Keys are zeroized in memory on lock. Where an OS keyring is
available the vault is additionally **device-bound** (format v2): the wrapping key mixes
in a random 32-byte device key held in the keyring (Linux Secret Service / Windows
Credential Manager; Android Keystore on Android), so the stolen blob alone cannot be
brute-forced on the password at all — the attacker needs the keyring secret too. See
`crypto-core::vault` and `client-core::devicekey`.

**Quick unlock (PIN / fingerprint / auto-unlock)** does not change any of the above: the
vault format and its password derivation are untouched. Each method stores a *wrapped
copy of the vault seal key* (`crypto_core::quick`) next to the vault:

* *PIN (4–8 chars):* wrapped under `HKDF(Argon2id(PIN) || device key)`. The device key is
  **mandatory**, so the low-entropy PIN can never be brute-forced offline — an attacker
  must guess on-device, where 5 wrong entries wipe the PIN blob (leaving the password
  path). The attempt counter lives in plaintext `prefs.json`; a root attacker can reset
  it, but a root attacker on an unlocked device is out of scope anyway, and *offline* the
  counter is irrelevant (the device key is unavailable).
* *Fingerprint (Android):* wrapped by a non-exportable Keystore AES key requiring a
  BIOMETRIC_STRONG (class 3 — fingerprint; camera face unlock doesn't qualify) auth per
  use, invalidated by new fingerprint enrollment.
* *Auto-unlock (opt-in, default off):* wrapped under the device key alone — possession of
  the unlocked OS session becomes the gate. Useless off-device; the user is warned.

A password change rotates the seal key, instantly invalidating every quick-unlock blob
(PIN/auto are re-wrapped inside the ceremony; biometric must be re-enabled). Username and
password changes are gated by a three-factor ceremony re-verified atomically in Rust:
current password → OS presence check (fingerprint, else device credential, skipped only
when the device has neither; Android only) → the app PIN (6+ chars required).
`prefs.json` is plaintext by necessity (the lock screen reads it before unlock); it
reveals *that* a PIN/biometric is configured, never anything that helps open the vault.

### Metadata adversary
*Can:* try to learn who talks to whom.
*Defended:* **sealed sender** (envelopes name only the recipient hash; the sender is
recovered cryptographically by the recipient, never exposed to the server) + hash-only
addressing + **message-length padding** (payloads are bucketed before encryption, so the
ciphertext length no longer reveals the message length; attachment blobs are padded too).
Residual leak: the server still sees recipient hashes and timing. **Content-free push**
is implemented end-to-end: an offline recipient's registered endpoint gets a constant
wake — no content, no sender, no identity — and the client pulls ciphertext over the
authenticated channel. Registration requires a signed single-use challenge per mailbox
(nobody can subscribe to another user's message *timing*; a linked device registers its
own device mailbox), wakes are debounced, endpoints are stored AEAD-encrypted at rest,
and in production only public HTTPS endpoints are accepted (SSRF hardening); `fcm:`
endpoints never touch the URL fetcher.

**Push-wake metadata (deliberate, bounded).** Making messages/calls arrive with the
app closed adds exactly three metadata facts, each chosen over a worse alternative:

1. *Wake class → relay.* Every envelope carries one sender-declared coarse bit
   (`none` / `normal` / `call`) the relay reads ONLY to decide whether/how to fire a
   wake. It carries no identifier and is strictly less than Signal's per-envelope
   `urgent` flag. Without it, either every receipt would burn a battery wake or calls
   could not ring through Doze.
2. *Wake class + timing → push broker.* The FCM payload is a constant `{"t":"m"}` or
   `{"t":"c"}`, data-only, high priority; TTL 60 s for calls / 24 h for messages.
   Google learns "this device was poked (message|call) at time T" — compare Signal,
   which ships the sealed envelope bytes *through* FCM. The `"t":"c"` bit exists so a
   locked-vault (PIN/password-only) device can still ring generically without
   decrypting anything; users who reject even that stay on connection mode, which
   involves no third party at all and remains the default.
3. *FCM token ↔ mailbox hash → relay DB.* Stored AEAD-encrypted at rest, deleted on
   unregister/revocation, self-purged when FCM reports the token dead. Google already
   knows the device; the relay already knows the mailbox — the link is the only new
   fact, and it never leaves the relay.

Wake-flood/battery-DoS: per-recipient min-intervals per class on the relay (messages
debounced 30 s; calls 2 s) on top of the sender envelope rate limits; the client
coalesces any number of queued wakes into one drain. A malicious push broker replaying
wakes only makes the client drain an empty mailbox — the constant body carries nothing
to amplify.

### Voice calls
*Can:* an observer/relay try to learn who calls whom, when, and what is said.
*Defended:* call signaling (offer/answer/hangup) travels **inside the Double Ratchet** —
the relay never sees it. Media is end-to-end encrypted (XChaCha20-Poly1305, per-call
random key from the offer, HKDF per-direction keys, AEAD-bound strictly-increasing
sequence numbers), **relay-routed, never peer-to-peer** — the parties never learn each
other's IP addresses and there is no STUN/ICE surface. The media room is joined by a
random 128-bit capability id (from inside the ratchet), *deliberately unauthenticated*:
the relay cannot link a call to the identities in it, only "two sockets shared a room".
Frames are constant-size (CBR Opus + padding) at a constant 20 ms cadence in both
directions — silence and mute included — so traffic analysis of the stream yields
nothing beyond the call's existence and duration, which the relay necessarily observes.
Call keys live only in memory and die at hangup (per-call forward secrecy).

### Video calls & screen share
*Can:* an observer/relay try to learn who shares what with whom; a hostile relay try to
inject/replay media; the share itself leak the app's own screen.
*Defended:* the same properties as voice — signaling and the per-call key inside the
ratchet, relay-routed (no IP exposure), unauthenticated capability rooms, per-track ×
per-direction AEAD keys with strictly-increasing AEAD-bound sequences (replay, reorder,
forgery, and cross-track splices are all dropped), keys die at hangup. Video/screen
tracks are enabled only when both peers advertise `media2` *inside the ratchet* and the
relay allows it — a downgrade only ever yields a voice call, never a weaker video path.
On Android the app's own window is FLAG_SECURE, so a screen share shows Sona itself as
black: sharing your screen cannot leak your chats.
*Accepted (and documented):* the QUIC media path is visible as QUIC-on-UDP to an
on-path observer (vs. WebSocket blending into HTTPS TCP) — same endpoints, same
"a call is happening" information, so nothing new is learned; networks that block UDP
simply get the WebSocket path. The QUIC certificate is pinned by exact hash fetched
over the trusted HTTPS channel, and media stays end-to-end encrypted above the
transport either way. Video is bursty. Cells are padded to coarse (1 KiB)
buckets and encoders are bitrate-capped with periodic-IDR-only keyframes, but the relay
can still distinguish "voice call" from "call with video-class bandwidth" and can see
track on/off transitions as bandwidth changes. Hiding that would cost constant
multi-hundred-kb/s cover traffic for every voice call; we choose to state the leak
instead. Voice frames remain perfectly uniform even during video.

### Endpoint compromise (malware on a logged-in device)
*Can:* read live plaintext and keys while unlocked.
*Out of scope to prevent* — no messenger can. Blast radius is bounded by the ratchet's
**post-compromise security**: once the attacker loses access, future messages heal as new
ratchet steps run. Forward secrecy protects past messages.

### Multi-device (Signal-style linking)

*Can:* an account runs on several devices; each has its **own** Olm identity and prekeys
(no shared long-term key, no shared ratchet state — one device's compromise never exposes
another's history). A device roster is published in the **same append-only KT log** as the
key bindings, signed by the account key, with a per-device proof-of-possession.
*Defended:*
* **Rogue device injection → account-signed roster in KT.** The relay cannot add a device:
  it lacks the account key to sign a roster, and a device record without a valid
  proof-of-possession (bound to the account username hash) is rejected. Any device the
  account *did* sign is permanent, public, auditable evidence (`Client::audit_own_roster`).
* **Roster rollback / downgrade → monotonic epoch pinning.** Each client pins the highest
  roster epoch it has seen per contact; a relay that later serves a **lower** epoch (to
  resurrect a revoked device) or **deletes** a roster (append-only rosters never vanish, to
  downgrade a multi-device account to primary-only) is caught and the send **fails closed**
  (`RosterRollback`). This is the tree-head monotonic-witness principle applied per-roster.
* **Device revocation.** Removing a device is a new signed epoch; the relay drops the
  device's mailbox record on publish, so its socket auth and any new inbound sessions stop
  at once, and peers drop its session on the next roster resolve. Per-device fan-out means a
  revoked device simply stops receiving.
* **History sync is gated, and the relay can't brute-force the gate.** History moves between
  a user's devices as an opaque blob sealed under `HKDF(Argon2id(account password/PIN) ||
  256-bit link secret)`. The link secret travels only over the QR/link channel, never to the
  relay, so the relay — which holds the blob — cannot brute-force the password *or* the PIN.
  A device-bound *vault* copied to another device still opens nowhere; history arrives only
  through this explicit, user-authenticated channel.
*New metadata exposure (accepted, documented):* the public KT log now reveals, per account
hash, device **count**, device public keys, and link/revoke **times** (never device names or
models). The relay can group an account's device mailboxes (it must, to route) and learns
per-device delivery timing. **Self-fan-out** (a send also copies to the sender's own other
devices) would produce a correlatable burst; own-device copies are therefore delayed by a
random 0–25 s **jitter** so the relay cannot reliably tie the burst back to who is talking to
whom. An account with one device is unaffected; a user who declines the trade simply does not
link a second device. See `docs/MULTI_DEVICE.md` §9 for the full delta.

### Relay discoverability (scrapers, scanners, unwanted users)

*Can:* fingerprint a host as a Sona relay (the endpoint shapes are public with the
source), enumerate relays at internet scale, probe them for vulnerabilities, or simply
freeload on someone's private infrastructure.
*Defended (opt-in, `ACCESS_MODE`):*
* **token** — every request, including WebSocket upgrades and the QUIC call-media join,
  must carry a shared access token; it is enforced as the *outermost* middleware, so a
  rejected request never reaches routing, body parsing, or the KT log. The point is
  containment as much as privacy: a future bug in any handler is unreachable without
  the token.
* **stealth** — additionally answers every rejected request with a bare, empty `404`,
  byte-identical to the server's unknown-path answer, and disables the QUIC endpoint
  (a QUIC handshake would answer probes before any token check). A scanner cannot
  distinguish the relay from a web server with nothing on it.
* **One shared token, never per-user credentials — deliberately.** Message submission
  is unauthenticated *by design* (sealed sender); a per-user credential on every
  request would attribute every send and destroy the anonymity set. All members present
  the same token and stay mutually indistinguishable. Eviction/re-key = token rotation
  (clients detect the gate's refusal and walk the user through reconnecting); the env
  var takes a list so old and new tokens can overlap during migration.
* **Registration invite codes** (`REGISTRATION_CODES`, independent of the mode) gate
  who may *join*: each brand-new account claim — a permanent, anonymous append to the
  KT log — consumes a single-use code. Rotations, renames, and device linking are never
  gated, so existing users cannot be locked out. Codes are single-use and their
  consumption survives restarts.
* **Anti-DoS floor** (all modes): per-address request rate limits and byte budgets,
  per-address WebSocket caps with a pre-auth deadline, a global storage ceiling, and
  global concurrency/timeout backstops — so even a relay that *wants* to be public
  degrades to refusals, not resource exhaustion.
*Residual:* the TLS certificate (and so the hostname) is public in Certificate
Transparency logs the moment it is issued — stealth hides *what* the host is, not
*that* it exists. Volumetric (network-layer) DDoS is out of app-layer scope. The
strongest posture is not an HTTP feature at all: bind the relay to a WireGuard
interface and the port doesn't exist publicly (`IP_ALLOWLIST` complements that setup).

## Explicit non-goals (v1)

* Anonymous network-layer routing (we minimize metadata, we don't hide your IP). The
  client *supports* the Tor route rather than providing it: a SOCKS5 proxy setting
  (Settings → Tor/SOCKS proxy; Orbot on Android) carries every relay connection —
  HTTP and WebSocket, hostnames resolved at the proxy so DNS never leaks — and while
  set, the QUIC call-media path is disabled (UDP would bypass the proxy) in favor of
  relay-bridged WebSocket media. Running/choosing the proxy remains the user's job.
* Defending a rooted/compromised endpoint.
* Federation across multiple trust domains.
* Protecting *availability* against a hostile server.

## Comparison to Signal

* **More private:** no phone number (anonymous usernames); self-hosted (no central
  servers); KT built in from day one.
* **At parity:** Double Ratchet (FS + PCS), sealed sender, safety-number verification;
  security-audited with all findings remediated; reproducible builds and a standalone KT
  auditor in place.
* **Behind only in reach:** adoption and third-party client ecosystem, not architecture.
