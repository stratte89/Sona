# Sona Protocol

The concrete wire protocol as implemented. Reflects the code in `crates/` and `clients/`.

## Identifiers

* **Username** — a chosen handle (≤64 chars). The account id.
* **Identity hash** — `SHA-256(username)`, hex (64 chars). The *only* way the server
  addresses a user. The server never learns the username.
* **Identity key** — Curve25519 public key (base64). The user's long-term Olm identity;
  what peers encrypt to and what Key Transparency binds the username to.
* **Signing key** — Ed25519 public key (base64). Signs KT entries and login challenges.

All base64 is standard alphabet, **no padding** (matches vodozemac).

## Cryptographic building blocks

| Purpose | Primitive |
|---|---|
| Vault at rest | Argon2id (m=64MiB, t=3, p=1) → XChaCha20-Poly1305 |
| Messaging | Olm Double Ratchet (vodozemac) — triple-DH handshake, forward secrecy, PCS |
| Identity / signatures | Curve25519 (identity), Ed25519 (signing) |
| Key Transparency log | SHA-256 RFC 6962 Merkle tree (ct-merkle); Ed25519-signed tree heads |

## REST endpoints (`/v1`)

| Method | Path | Body / Query | Purpose |
|---|---|---|---|
| POST | `/register` | `{ entry: KtEntry, one_time_keys: [b64], fallback_key: b64 }` | Publish a KT binding + seed one-time keys + a reusable fallback key |
| GET | `/bundle/{hash}` | — | Fetch + consume one of a peer's one-time keys → `PreKeyBundle` |
| POST | `/onetimekeys` | `{ identity_hash, one_time_keys, signature }` | Replenish your own one-time keys (signed by your identity key) |
| GET | `/keys/count/{hash}` | — | How many one-time keys an identity has left (so its client knows when to top up) |
| POST | `/messages` | `Envelope` | Relay an opaque message (sealed sender) |
| GET | `/challenge?hash=` | — | Get a single-use login nonce |
| POST | `/account/delete` | `{ hash, alias_hashes, nonce, signature }` | Delete the account from the relay: directory records, device mailboxes, queued messages, push subscriptions; live sockets get a terminal `revoked` frame. Alias (former-username) mailboxes are honored only if their record carries the **same signing key** — the signature can never widen deletion to someone else's mailbox. The KT log is deliberately untouched (append-only, public); the client unbinds the username separately with a signed release entry |
| POST | `/push/register` | signed registration | Register a content-free push endpoint for a mailbox (HTTPS webhook / UnifiedPush, or `fcm:<token>`); challenge-signed so nobody can subscribe to another user's message timing. See `NOTIFICATIONS.md` |
| POST | `/push/unregister` | signed request | Remove a push registration |
| POST | `/blobs` | raw ciphertext bytes | Store an opaque attachment blob → `{ blob_id }` (≤10 MiB) |
| GET | `/blobs/{id}` | — | Fetch an attachment blob (opaque ciphertext) |
| GET | `/kt/pubkey` | — | Bootstrap: the log's Ed25519 pin (confirm out-of-band!) |
| GET | `/kt/sth` | — | Current `SignedTreeHead` |
| GET | `/kt/proof/{hash}` | — | `{ entry, index, proof_b64, sth }` — latest binding + inclusion proof |
| GET | `/kt/consistency?from=` | — | `{ proof_b64, sth }` — append-only proof from an earlier size |
| GET | `/capabilities` | — | Optional surfaces this relay supports (`multi-device-v1`, `history-sync-v1`, `push-webhook-v1`, plus `gif-search-v1` / `push-fcm-v1` / `invite-register-v1` when configured); old relays 404 |
| GET | `/gif/search?q=&pos=` | — | GIF search via the relay privacy proxy (`GIPHY_API_KEY` set): `{ results: [{url, preview, width, height}], next }`. The provider sees only the relay, never the client |
| GET | `/gif/trending?pos=` | — | Trending GIFs through the same proxy (relay-side cached) |
| GET | `/gif/proxy?url=` | — | Fetch GIF bytes through the relay (strict `*.giphy.com` https allowlist, ≤10 MiB). The client re-sends the GIF as a normal E2E attachment, so the recipient never contacts the provider |
| POST | `/kt/roster` | `KtRosterEntry` | Append a device-roster epoch to the KT log (account-signed, validated fail-closed; see `MULTI_DEVICE.md`) |
| GET | `/kt/roster/{hash}` | — | `{ roster, index, proof_b64, sth }` — latest device roster + inclusion proof; 404 = single-device account |
| POST | `/sync` | raw ciphertext bytes | Store an opaque history-sync blob (≤32 MiB, 7-day TTL) → `{ sync_id }` (capability id; see `MULTI_DEVICE.md`) |
| PUT | `/sync/{id}` | raw ciphertext bytes | Store a provisioning/history blob at a caller-chosen 32-hex id (device linking); first-writer-wins |
| GET | `/sync/{id}` | — | Fetch a history-sync/provisioning blob (opaque ciphertext) |

Request bodies are capped at 64 KiB. `/messages` is rate-limited fail-closed.

Every route sits behind the **access gate** (`ACCESS_MODE`: `open` / `token` / `stealth`,
plus an optional IP allowlist) as the *outermost* layer — in token/stealth mode a request
without the shared token is rejected before routing, body parsing, or any handler runs.
Access tokens are shared per relay, never per user (per-user credentials would break
sealed sender by re-identifying senders). See `DEPLOYMENT.md`.

## WebSocket (`/v1/ws`)

1. Client connects.
2. **First frame must be auth**: `{ "type":"auth", "hash", "nonce", "signature" }` where
   `signature` is Ed25519 over the base64-decoded `nonce` bytes, by the hash's signing
   key. The server consumes the nonce (single-use) and verifies against the registered
   key. On a bad nonce/signature it sends `{ "type":"auth_failed" }` (retryable — get a
   fresh nonce) and closes. If the nonce was live but the hash has **no directory
   record** — the device was revoked from its account's roster, or the account is
   gone — it sends `{ "type":"revoked" }` and closes: **terminal**, the client must
   unlink locally (lock the UI, offer relink) and never retry.
3. On success the server flushes queued messages as `{ "type":"message", "envelope": … }`,
   then `{ "type":"ready" }`, then streams live messages as they arrive.
4. Client acks delivery with `{ "type":"ack", "msg_id": … }`; the server then drops it.
5. When a roster removal revokes a device that is **currently connected**, the server
   pushes `{ "type":"revoked" }` on its socket and closes it — the zombie device is
   kicked immediately, not at its next reconnect.

No password or bearer token is ever sent — auth is a signature over a fresh nonce, so a
captured frame cannot be replayed.

## Core types

```jsonc
// Envelope — the unit the relay stores/forwards. Sealed sender: no sender field.
{ "to": "<identity_hash>", "ciphertext": "<json CiphertextMessage>",
  "kind": "message", "msg_id": "<hex>", "expires_at": null }

// CiphertextMessage — rides (JSON-encoded) inside Envelope.ciphertext.
{ "message_type": 0, "body": "<base64 Olm message>" }   // 0 = pre-key, 1 = normal

// PreKeyBundle — what a sender fetches to start a session.
{ "identity_key": "<b64>", "signing_key": "<b64>", "one_time_key": "<b64>" }

// ChatPayload — the plaintext INSIDE the ratchet ciphertext (server never sees it).
// A conversation carries messages and control messages over the same E2E channel.
{ "t": "text",  "body": "hello", "ts": 1735689600, "from": "alice",
  "reply": null, "expire_secs": null, "fwd": false }     // a chat message
{ "t": "timer", "secs": 3600 }                          // disappearing-msgs timer (null = off)
{ "t": "file",  "attachment": { "blob_id": "...", "key": "<b64>", "filename": "cat.png",
                                "size": 1234, "content_hash": "<b64 sha256(ciphertext)>",
                                "ts": 1735689600 },
  "from": "alice" }                                      // attachment reference
{ "t": "edit",  "msg_id": "...", "body": "fixed typo" }  // edit own earlier message
{ "t": "delete_msg", "msg_id": "..." }                    // delete own message everywhere
{ "t": "delete_chat" }                                    // wipe the whole chat on both sides
{ "t": "knock", "from": "alice" }                         // explicit chat request, no content
{ "t": "receipt", "ids": ["..."], "seen": true }          // delivered/read receipts (E2E)
{ "t": "reaction", "target_msg_id": "...", "emoji": "👍",
  "add": true, "ts": 1735689600 }                          // toggle an emoji reaction
{ "t": "pin_msg", "msg_id": "...", "pin": true }          // pin/unpin
{ "t": "typing", "typing": true }                         // typing indicator (E2E)
{ "t": "rename", "new_username": "..." }                  // sender changed username
{ "t": "profile", "avatar": "data:image/..." }            // E2E profile picture (null clears)
{ "t": "gossip", "head": { ...SignedTreeHead... } }      // KT head shared for gossip
// Groups — membership travels as a SIGNED epoch (see GROUPS.md); content is fanned out
// pairwise. Each 1:1 arm has a group twin: group_text / group_file / group_edit /
// group_delete_msg / group_timer / group_reaction / group_pin_msg / group_typing /
// group_rename / group_avatar / group_leave.
{ "t": "group_roster", "epoch": { ...GroupEpoch... }, "name": "trip",
  "disappearing_secs": null, "avatar": null }             // signed membership epoch
{ "t": "group_text", "group_id": "...", "body": "hi all", "ts": 1735689600 }  // group msg
// Multi-device self-sync (a copy sent to the sender's OWN other devices; honored only from
// a verified own device — see MULTI_DEVICE.md). msg_id is shared with the recipient copies.
// The family mirrors the content arms: self_text / self_file / self_seen / self_reaction /
// self_timer / self_profile / self_pin_msg / self_call_handled.
{ "t": "self_text", "peer_key": "<b64>", "peer_username": "bob", "msg_id": "...",
  "body": "hi", "ts": 1735689600 }                        // record as outgoing on my other device
{ "t": "self_seen", "peer_key": "<b64>", "ids": ["..."] } // read marker self-sync
// Primary→linked forwarding of a legacy sender's message (recorded as incoming from from_key)
{ "t": "forward_incoming", "from_key": "<b64>", "from_username": "bob", "msg_id": "...",
  "body": "hi", "ts": 1735689600, "attachment": null }
// Primary transfer: hand the primary role to another linked device (see MULTI_DEVICE.md)
{ "t": "primary_transfer", ... }
// History re-export request: a linked device whose synced blob expired asks its primary to
// re-seal history. Carries a fresh capability id + link secret (E2E, so the relay never
// sees the link secret). Honored only from a verified own device.
{ "t": "sync_request", "provisioning_id": "<32hex>", "link_secret_b64": "<b64>" }

// KtEntry — one signed username→key binding (see KEY_TRANSPARENCY.md).
{ "seq": 0, "username_hash": "<hex>", "identity_key": "<b64>", "signing_key": "<b64>",
  "prev_signing_key": null, "timestamp": 0, "signature": "<b64>" }

// SignedTreeHead — the server's signed commitment to the whole log.
{ "tree_size": 0, "root_b64": "<b64>", "timestamp": 0, "signature_b64": "<b64>" }
```

## Message flow (1:1)

1. Both parties `register` (append KT entry, upload one-time keys).
2. **Sender → discover:** `GET /bundle/{hash}` + `GET /kt/proof/{hash}`, then verify the
   bundle's `identity_key` equals the KT-proven key (else abort). Establish an outbound
   Olm session.
3. **Sender → send:** ratchet-encrypt → `CiphertextMessage` → wrap in `Envelope` → `POST /messages`.
4. **Recipient → receive:** authenticate over WS, receive the `Envelope`, parse the
   `CiphertextMessage`, and decrypt *unattributed*: a pre-key message reveals the sender's
   identity key (Olm), a normal message is attributed by trial over known sessions. Ack.

## Storage at rest

The relay persists to SQLite (env `DB_PATH`; in-memory if unset). Message envelopes are
stored as an AEAD blob (XChaCha20-Poly1305) keyed by `STORAGE_KEY` — kept **off the data
disk**. Plaintext columns are only what delivery/pruning require: `target_hash` (one-way),
`msg_id`, `expires_at`. The directory and KT log are stored plaintext (public by design).
On boot, the KT log is rebuilt by replaying entries in append order (re-validated), and
the message queue + directory are reloaded. The KT signing key persists via
`KT_SIGNING_KEY` so the pinned public key is stable across restarts.

## Local history & disappearing messages

Message history lives **only on the client**, encrypted at rest with the account's
`data_key` (a stable 32-byte key sealed in the vault) via XChaCha20-Poly1305. The server
never stores content.

**Attachments** are encrypted client-side with a fresh random key (XChaCha20-Poly1305);
only the ciphertext is uploaded to `/v1/blobs` (opaque to the server), and the key +
reference travel inside the ratchet. The recipient downloads the blob, checks its SHA-256
against the reference, then decrypts. The server never sees the file or the key.

**Edits/deletes are sender-scoped:** a recipient applies `edit` / `delete_msg` /
`delete_chat` only to messages *from that authenticated sender* — no one can edit or
delete your copy of your own messages. `text` may carry `reply: {msg_id, preview}` for
quoted replies (the preview travels along so the quote renders even if the original is
gone). All cooperative: both ends hold plaintext, so deletion is hygiene, not security.

**Sender naming (`from`):** `text` and `file` carry the sender's username *inside* the
ciphertext (sealed sender keeps it from the server). The ratchet authenticates the sending
*key*; the claimed `from` is display/reply routing only and is KT re-checked on first reply.

**Length padding:** before encryption, every `ChatPayload` is padded to a size bucket
(starts at 256 bytes, grows ~1.25×) with its real length prefixed. So all short messages
are identical on the wire and longer ones reveal only a coarse bucket — the ciphertext
length no longer leaks the message length. Attachment blobs are padded the same way.

**Disappearing messages** are per-conversation and end-to-end synced. Turning the timer
on/changing it sends a `{"t":"timer","secs":N}` control message inside the ratchet; the
peer's client adopts it, so both sides share the same duration — and the server never
learns the timer exists or its value. Each stored message gets `delete_at = ts + timer`
(the sender's `ts` travels in the payload, so both sides compute the same instant), and a
reaper deletes expired messages on both devices together. `secs: null` turns it off.

**Groups** are pairwise fan-out: a group message is encrypted separately to each member
over the existing KT-verified 1:1 Double Ratchet sessions and sent as N envelopes — no
shared group key. Membership is an **admin-signed, append-only epoch chain** carried in
`group_roster` payloads; recipients validate every epoch against their pinned chain
before adopting a change, and content from non-members is quarantined (held, never
rendered) until an epoch admits the sender. The server sees only individual opaque
envelopes. Full design: [`GROUPS.md`](GROUPS.md).

**Message requests:** a first message (or an explicit `knock`) from a stranger lands as a
pending request on the recipient — content is held behind the gate until the user
accepts, and receipts/typing/timer changes from a pending requester are not honored (no
read-state leak, no settings tampering before acceptance). Replying or accepting clears
the request everywhere (self-synced across the recipient's devices). Turning the request
gate off accepts all pending requests — open mode never leaves invisible held content.

## Sealed sender

The `Envelope` carries no sender. The server routes only by recipient hash, so it cannot
build a social graph. The recipient recovers the sender cryptographically from the
decrypted ratchet message — never from anything the server can read.

## Voice calls (`/v1/call/{id}`)

Signaling is three `ChatPayload` variants inside the normal ratchet channel — the relay
never sees them:

* `CallOffer { call_id, key_b64, ts, from }` — `call_id` is 128 random bits (hex), the
  capability to join the relay room; `key_b64` is a random 32-byte call key.
* `CallAnswer { call_id, accept }` — accept/decline (busy and blocked auto-decline).
* `CallEnd { call_id }` — hangup/cancel (also sent on 45 s ring timeout).

**Silent resume after a drop.** `CallOffer` also carries `reconnect_of` (`serde
default`, empty = normal ring). A connected call whose media leg dies without a
`CallEnd` (a deliberate hangup's `CallEnd` lands within a 2 s grace) is a network
drop: the pair's owner (lexicographically smaller identity key) mints a **fresh** room
+ key — a call key is never reused — and sends the offer with `reconnect_of` naming
the dropped call. The peer's in-call device auto-accepts silently; every other
recipient ignores it (a reconnect never rings and is never declined, so it leaks
nothing). Both sides give the resume 15 s, then end the call visibly. Old clients
ignore the unknown field and simply ring — degraded, not broken.

Media: each side opens `GET /v1/call/{call_id}` (WebSocket, **no authentication** — the
random id is the capability, so the relay cannot link the room to identities). The room
holds at most two members; the relay forwards opaque binary frames between them, stores
nothing, and dissolves the room when either leaves (`{"type":"peer_joined"}` /
`{"type":"peer_left"}` / `{"type":"joined","peers":N}` are the only control frames).

Frame format (constant size, constant 20 ms cadence, both directions, silence included):

```
wire  = seq(8, BE) || XChaCha20-Poly1305(key = HKDF(call_key, direction-label),
                                         nonce = 0^16 || seq, aad = seq,
                                         plaintext = len(2, BE) || opus || zero-pad)
```

`plaintext` is padded to 256 bytes (Opus is CBR 24 kbps, so ~60 bytes of codec output);
`seq` must strictly increase — anything else (replay, reorder, forgery) is dropped.
Direction labels: `sona-call-v1 caller->callee` / `callee->caller`. Keys exist only in
call memory; a new call mints a new id and key.

## Group calls (mesh of pair rooms)

A group call is a **full mesh of the 1:1 rooms above** — nothing new exists on the
relay, which cannot distinguish a group-call leg from an ordinary voice call. Voice-only
(a mesh participant uploads one constant-rate stream per other member; clients cap
groups at 8 for calls).

Signaling, inside each pair's ratchet session:

* `GroupCallOffer { group_id, call_instance, call_id, key_b64, ts, from }` — one **pair
  leg's** ticket. `call_instance` (128 random bits, hex) names the call across all
  participants; `call_id`/`key_b64` are a fresh 1:1-style room capability + key for this
  pair only. Receiving any offer for an instance also means *the sender is in that call*.
* `GroupCallEnd { group_id, call_instance }` — decline / leave / cancel, indistinguishable
  on the wire by design.

Joining (starter and accepter run the same procedure): mint one fresh ticket per other
roster member and send each member their offer (multi-device: fan copies of the same
ticket to every device in the member's verified roster — one of them answers the pair
room, as in a 1:1 ring-all). **Glare rule:** for each pair, the room minted by the
lexicographically smaller identity key wins; both sides compute this locally, the loser's
ticket is ignored and its lonely room is reaped by the relay GC (§ voice calls). So every
pair converges on exactly one two-member room with zero extra round trips.

Security is the 1:1 call's, inherited per pair: per-direction HKDF keys, AEAD-bound
strictly-increasing sequence numbers, constant-size CBR frames. There is **no shared
group key** — a member removed from (or declining) a call simply never receives new pair
tickets, and each leg's keys die with the call. Recipients honor a `GroupCallOffer` only
from a ratchet-authenticated sender on the (locally stored) group roster; anyone else's
offer is discarded unanswered. Latency is one relay hop, identical to a 1:1 call; audio
is Opus-encoded once per 20 ms and sealed per leg; inbound legs are decoded per sender
and mixed client-side (i32 sum, saturating).

**Key hygiene / drop recovery.** A pair-room key is used **once, ever**: clients track
every joined room id per call and refuse to re-derive a consumed key (re-deriving would
restart the seal counter — nonce reuse — and a malicious relay could trigger it by
replaying an old offer). A leg that dies *without* a `GroupCallEnd` is a network drop,
not a leave: after a short grace period (2 s, so a genuine leave's `GroupCallEnd` can
land) the pair's **owner** mints a fresh ticket, re-offers, and both sides converge on
the new room — at most 3 automatic re-offers per member, reset when a leg connects.
Deliberate leavers are never re-offered; a leaver's own fresh offer marks a rejoin.

## Video calls & screen share (media v2)

Camera video, screen sharing, and screen audio multiplex extra **tracks** over the same
blind call room — no second room, no new endpoints, and voice keeps the exact v1 wire
format above.

**Negotiation (three-way, degrade-to-voice):**
* `CallOffer`/`CallAnswer` gain `caps: ["media2", …]` (`serde(default)` — absent from
  old clients, ignored by them as an unknown field).
* The relay's `joined` message gains `"media": 2`. Old relays close connections on
  video-sized frames, so clients enable video tracks only when **both** the peer's caps
  and the relay's media level say v2. Anything less runs a plain voice call.

**Track wire format.** A v1 voice frame's first byte is the high byte of a 64-bit
sequence counter — zero for any realistic call — so v2 cells are distinguished by a
nonzero first byte, with no handshake on the media socket:

```
cell  = track(1) || seq(8, BE) || XChaCha20-Poly1305(
            key   = HKDF(call_key, "sona-call-v2 <direction> track <id>"),
            nonce = track || 0^15 || seq, aad = track || seq,
            plaintext = more(1) || chunk_len(4, BE) || chunk || zero-pad)
```

Tracks: `1` camera video, `2` screen video, `3` screen audio, `15` control. Each
track×direction has its own HKDF-derived key and its own strictly-increasing sequence
(replay/regression ⇒ drop). Video cells pad to a 1 KiB grid, cap at 16 KiB plaintext,
and fragment larger encoded frames (`more = 1` on all but the last cell; reassembly is
bounded at 256 KiB). Control and screen-audio cells are constant-size (128 B / 256 B
plaintext).

**Codecs.** Video is H.264 (OpenH264, built from source) in realtime mode — camera and
screen-content tunings, zero frame lag, no B-frames, periodic IDR every 300 frames.
Screen audio is Opus stereo 64 kb/s CBR at the same 20 ms cadence as voice. Control
cells carry `track_on` / `track_off` / `keyframe_req` (a decoder that lost sync asks
the sender to force an IDR, rate-limited to 1/s/track).

**Hardware encoding (desktop, optional, invisible on the wire).** A full-resolution
software encode can cost more per frame than the frame interval it is aiming for, and
the casualty is not the video — it is the 20 ms voice tick, which then has to fight the
encoder for a core. Where the machine has a GPU encoder the shell supplies one:
**Media Foundation** on Windows (one path for NVIDIA/AMD/Intel — `MFTEnumEx` returns
whatever the driver registered) and **NVENC** on Linux/NVIDIA. Both are loaded at
runtime and never linked, so a machine without them starts and runs exactly as before.

Three properties keep this from being a risk:
* *It changes nothing above the encoder.* The trait hands back an Annex-B access unit
  and everything downstream — sealing, cells, padding, the wire — is byte-identical to
  the software path. A peer cannot tell which encoded a frame, and old clients need no
  changes.
* *It has to prove itself.* Before a call depends on it, a backend encodes a synthetic
  frame and must hand back something **our own decoder** accepts as a keyframe of the
  right size. One failure and hardware encode is off for the life of the process.
  The fallback is not a degraded mode — it is the software encoder that was always there.
* *It never sees a key.* Encoding happens **before** sealing: the encoder turns pixels
  into an access unit and the media layer seals that with the per-call, per-track key.
  No key, no plaintext frame and no ciphertext ever reaches a driver.

Transient failures are separated from permanent ones: NVENC caps concurrent sessions per
driver and other applications spend from the same budget, so one track failing to get a
session falls back for that track alone and leaves a track that is encoding happily
untouched.

**Relay changes.** The per-frame cap rises to the largest v2 cell (16 409 bytes +
headers) and each member gets a token-bucket byte budget (1 MiB/s sustained, 4 MiB
burst) so the blind relay cannot be repurposed as a bulk pipe. The relay still stores
nothing and still cannot read or forge any frame.

## QUIC media path (`/v1/call/quic` + UDP)

WebSocket media rides TCP: one lost packet stalls every frame behind it. Calls prefer
a QUIC mapping when both the relay and the network allow it; the fallback to
WebSocket is silent and per-leg (the relay bridges transports inside one room, so a
QUIC caller and a WS callee interoperate).

**Discovery.** `GET /v1/call/quic` → `{"enabled":bool,"port":u16,"cert_sha256":b64}`.
The relay mints a fresh self-signed certificate at every boot; the client pins the
exact DER hash it fetched over the HTTPS channel it already trusts (no certificate
management for operators, no CA involved). ALPN `sona-media-v1`. The QUIC TLS layer
is transport armor only — media above it is end-to-end encrypted regardless.

**Mapping.**
* *Join*: the client opens one bidirectional stream and writes the 32-hex call id;
  the server answers with the same newline-framed JSON lines the WebSocket path uses
  (`joined` / `peer_joined` / `peer_left`) for the life of the call. A room dissolved
  by hangup may instead arrive as the connection-close reason `peer_left` (close
  frames deliver their reason atomically; a control line could still be unflushed).
* *Loss-tolerant frames* — voice (first wire byte `0`) and screen-audio cells (first
  byte `3`) — ride **unreliable datagrams**: a lost frame plays as 20 ms of silence
  and never stalls the stream. Receivers already tolerate gaps (sequence numbers must
  only increase, not be contiguous); a late/reordered frame is dropped as a replay.
* *Loss-intolerant cells* — video (`1`/`2`) and control (`15`) — travel in groups on
  **one short unidirectional stream per encoded frame**, each cell prefixed
  `u16 BE len`. Reliable within a frame, independent between frames: a retransmit
  delays only its own frame and the H.264 reference chain never breaks.
* *Bridging*: toward a WS member each cell becomes its own binary frame; toward a
  QUIC member the relay applies the same datagram/stream policy by first wire byte.

Abuse bounds match the WS leg: same per-frame cap, same per-connection byte budget,
join must arrive within 5 s, stream groups are capped at 300 KiB.

**What v2 deliberately does *not* hide** (unlike voice): video bitrate varies with
motion and keyframes, and turning a track on/off is visible to the relay as a bandwidth
change. Cells are padded to coarse buckets and the encoder is bitrate-capped, but the
honest claim is: the relay learns *"this call has video-class bandwidth"*, never
content, identities, or IPs. Voice frames keep their perfectly constant size + cadence
even during a video call.
