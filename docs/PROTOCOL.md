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

## Signing domains

One Ed25519 identity key signs many different things, so **every signed payload carries a
distinct byte prefix**. The property that has to hold is *prefix-freeness*: no context's
message may ever be a valid message in another context, or a signature harvested in one
place is a forgery in another. That is not a style rule — it is what stops a hostile relay
from turning any signing surface into an oracle for the rest (see the WebSocket section).

| Prefix | Signs |
|---|---|
| `sona-register-v1\|` | registration: hash + identity key + signing key |
| `sona-kt-entry-v1` | `KtEntry` — a username↔key binding, and its rotation chain |
| `sona-kt-roster-v1` | `KtRosterEntry` — an account's device roster epoch |
| `sona-kt-device-v1` | `DeviceRecord` proof-of-possession |
| `sona-kt-sth-v1` | signed tree heads (the relay's KT key, not an account's) |
| `sona-kt-leaves-v1\|` | owner-gated leaf enumeration: hash + nonce |
| `sona-ws-auth-v1\|` | WebSocket/mailbox login: mailbox hash + nonce |
| `sona-otk-upload-v1\|` | one-time-key upload: hash + keys |
| `sona-push-register-v1\|` / `sona-push-unregister-v1\|` | push endpoint (de)registration |
| `sona-account-delete-v1\|` | account deletion: hash + alias hashes + nonce |
| `sona-call-key-publish-v1\|` | publishing a device's call-control key binding |
| `sona-call-key-v1` | `CallKeyBinding` — the binding itself, by the device's roster key |
| `sona-call-capsule-v1` | `CallCapsule` — offer/terminal, by the call-control key |
| `sona-group-epoch-v1` | `GroupEpoch` — membership, by the admin key |
| `sona-kt-leaf-roster-v1\|` | not a signature — the **Merkle leaf** prefix for roster leaves, so a roster leaf can never be read as a binding leaf in the tree |

`crates/crypto-core/tests/signing_domain_separation.rs` holds the registry and proves
pairwise disjointness. **A new signing context must be added there**, or the proof
silently stops covering the tree — the failure mode is that nobody notices until a
collision is found by someone else.

## REST endpoints (`/v1`)

| Method | Path | Body / Query | Purpose |
|---|---|---|---|
| POST | `/register` | `{ entry: KtEntry, one_time_keys: [b64], fallback_key: b64 }` | Publish a KT binding + seed one-time keys + a reusable fallback key |
| GET | `/bundle/{hash}` | — | Fetch + consume one of a peer's one-time keys → `PreKeyBundle`. Rate-limited per client, and per **recipient mailbox** once that mailbox's stock is low: over that floor the reusable fallback key is served instead of consuming a fresh one, so a drain spread over many addresses cannot empty a stock |
| POST | `/onetimekeys` | `{ identity_hash, one_time_keys, signature }` | Replenish your own one-time keys (signed by your identity key) |
| GET | `/keys/count/{hash}` | — | Whether an identity still has fresh one-time keys, as a coarse bucket (`{ level: plenty\|low\|none, low_watermark }`) — **never an exact count**, which would be a first-contact activity oracle |
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
| POST | `/kt/leaves` | `{ hash, nonce, signature }` | **Owner-gated**: every leaf published under one username — bindings *and* device rosters — each with an inclusion proof against one head. Challenge-signed with the account's own key, deliberately not public: "all leaves for this username" served to anyone would be an activity-enumeration oracle (who registered, when, how often they rotate, how many devices). Feeds `Client::audit_own_leaves` — see `KEY_TRANSPARENCY.md` |
| GET | `/capabilities` | — | Optional surfaces this relay supports (`multi-device-v1`, `history-sync-v1`, `push-webhook-v1`, plus `gif-search-v1` / `push-fcm-v1` / `invite-register-v1` when configured); old relays 404 |
| GET | `/gif/search?q=&pos=` | — | GIF search via the relay privacy proxy (`GIPHY_API_KEY` set): `{ results: [{url, preview, width, height}], next }`. The provider sees only the relay, never the client |
| GET | `/gif/trending?pos=` | — | Trending GIFs through the same proxy (relay-side cached) |
| GET | `/gif/proxy?url=` | — | Fetch GIF bytes through the relay (strict `*.giphy.com` https allowlist, ≤10 MiB). The client re-sends the GIF as a normal E2E attachment, so the recipient never contacts the provider |
| POST | `/callkey` | signed publication | Publish this device's **call-control key** (§ Locked call delivery): challenge-signed by the same device key the directory holds for that mailbox, refuses a future-dated or non-superseding binding, and gives the device's call-control mailbox its own directory record |
| GET | `/callkey/{mailbox}` | — | Fetch a device's published call-control key binding — public and self-authenticating, like a prekey bundle |
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
   `signature` is Ed25519, by the hash's signing key, over the **domain-separated**
   message — never over the raw nonce:

   ```
   "sona-ws-auth-v1|" || mailbox_hash || "|" || nonce_b64
   ```

   The decoded nonce must be exactly 32 bytes (`WS_AUTH_NONCE_LEN`); both sides reject
   any other length. The server consumes the nonce (single-use) and verifies against the
   registered key. On a bad nonce/signature it sends `{ "type":"auth_failed" }`
   (retryable — get a fresh nonce) and closes. If the nonce was live but the hash has
   **no directory record** — the device was revoked from its account's roster, or the
   account is gone — it sends `{ "type":"revoked" }` and closes: **terminal**, the client
   must unlink locally (lock the UI, offer relink) and never retry.

   > **Why the prefix is not optional.** The relay chooses the challenge bytes, and the
   > key signing them is the account's long-term identity key — the same key that signs
   > KT bindings, device rosters, device proofs-of-possession, group epochs, and every
   > `*_signing_message` below. Signing the *raw* nonce made the login a blind signing
   > oracle: a hostile relay could serve another context's signing payload as the "nonce"
   > and harvest a genuine signature over it, one per reconnect. Binding the mailbox hash
   > in matters too — with `prefix || nonce` alone, one victim's signature would
   > authenticate a different mailbox. The same message covers the call-key socket, which
   > signs with the device's call-control key.
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

The relay persists to SQLite (env `DB_PATH`; in-memory if unset). Message envelopes, push
endpoints, directory records and call-key bindings are stored as AEAD blobs
(XChaCha20-Poly1305) keyed by `STORAGE_KEY` — kept **off the data disk**.

Mailbox hashes are never stored as such. The relay has to *look up* by hash on every
route, so those columns hold a **keyed blind index** instead — `HMAC-SHA256(index_key,
table_tag | hash)`, `index_key` derived from the same `STORAGE_KEY`. Equality queries work
unchanged; the mapping is a PRF to anyone without the key. `messages.msg_id` is keyed
jointly with the target hash for the same reason: it is chosen by the *sender*, so a
plaintext copy would let anyone who ever messaged a user find that user's row and
re-identify every other row they own. `expires_at` stays in the clear (the pruner needs
it).

This matters because `target_hash` is an *unsalted* `SHA-256(username)` and is deliberately
sender-computable, so it is **not** secret against an offline dictionary. The blind index
does not hide who has an account — the KT log does that for the attacker — it makes the
stored rows unattributable to one. See the disk-theft section of `THREAT_MODEL.md` for
exactly what that does and does not buy.

The **KT log stays plaintext** (`kt_entries`): an independent auditor must be able to read
it, and that identity leak is inherent to Key Transparency. Attachment and history-sync
blobs are opaque client ciphertext under random capability ids, addressed by no mailbox.

On boot, the KT log is rebuilt by replaying entries in append order (re-validated), and
the message queue + directory are reloaded. The KT signing key persists via
`KT_SIGNING_KEY` so the pinned public key is stable across restarts. A database written
before the blind index is migrated in place on first open (one transaction, then a
`VACUUM` so the freed pages stop holding the old plaintext).

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

Signaling is a family of `ChatPayload` variants inside the normal ratchet channel — the
relay never sees them. There is **no v1 compatibility branch**; the old
`CallOffer`/`CallAnswer`/`CallEnd`/`SelfCallHandled` names are deleted and explicitly
rejected.

Four identifiers, none of which may double as another's capability:

| Id | Names | Lifetime |
|---|---|---|
| `call_instance_id` | one logical call, across every recipient device and retry | the call |
| `offer_id` | one encrypted offer (a group ring uses its `ring_id` instead) | the offer |
| `claim_nonce` | one device's answer attempt | the attempt |
| `call_id` | the relay media room — a capability, never a correlation id | one room |

* `CallOfferV2 { call_instance_id, offer_id, call_id, key_b64, created_at,
  ring_expires_at, expires_at, from, caller_device_id, reply_to_mailbox, caps,
  resume_of }` — `call_id` is 128 random bits (hex), the capability to join the relay
  room; `key_b64` is a random 32-byte call key. `reply_to_mailbox` is the caller's exact
  device mailbox, validated against the sender's KT-verified roster entry, so replies go
  to the device that rang rather than to the account.
* `CallAnswerClaimV2 { …, claim_nonce, answering_device_id, reply_to_mailbox, caps }` —
  an *attempt*, not an answer. Sending it starts no media.
* `CallWinnerV2 { …, claim_nonce, winner_device_id }` — the caller is the authority: the
  first valid claim wins, and only the named device+nonce may join the room. Every other
  device gets a terminal control instead.
* `CallBusyV2 { …, device_id }` — one occupied device, reported without cancelling its
  siblings' rings.
* `CallTerminalV2 { …, reason, from, actor_device_id }` — the final outcome, named:
  `answered_here`, `answered_elsewhere`, `declined_here`, `declined_elsewhere`,
  `caller_cancelled`, `expired`, `busy`, `transport_error`.

**Ordering is not assumed.** A terminal control that arrives *before* the offer it ends
writes a bounded tombstone; the late offer is then acknowledged and never rings. State is
monotonic and every transition idempotent, so duplicates, retries and reordering
converge instead of producing a second ring or extending a deadline.

**Expiry is explicit at every layer.** Offers, claims, winners and terminals all carry an
absolute deadline, and the envelope carries a call-scale TTL rather than the relay's
generic 30-day default (45 s ring, 60 s signal TTL, one shared constant). A duplicate
never extends the original deadline, and a peer cannot ring longer by claiming a
far-future one.

**Wake classes.** Fresh offers are a ring wake; winners, cancellations and every terminal
control are an **urgent silent** wake — a sleeping phone must wake to *stop* ringing, not
only to start. Resume offers and stale controls never ring.

**Silent resume after a drop.** `CallOfferV2` carries `resume_of` (empty = normal ring).
A connected call whose media leg dies without a terminal (a deliberate hangup's terminal
lands within a 2 s grace) is a network drop: the pair's owner (lexicographically smaller
identity key) mints a **fresh** room + key — a call key is never reused — and sends the
offer with `resume_of` naming the dropped call. The peer's in-call device resumes
silently; every other recipient ignores it (a reconnect never rings and is never
declined, so it leaks nothing). Both sides give the resume 15 s, then end the call
visibly.

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

## Locked call delivery (the call-control layer)

A phone whose Sona vault is locked cannot decrypt a `CallOfferV2` — the ratchet lives in
the vault — so on Android an incoming call is delivered on **two concurrent layers**. The
encrypted offer above carries the media capability and is the only layer that can produce
an answerable ring. Beside it rides a minimal **capsule**, and it exists so a locked or
sleeping phone can ring, stop ringing, and decline.

* **Call-control identity.** Each device mints an X25519 half (opens capsules) and an
  Ed25519 half (signs the relay's mailbox challenge, so a locked device can authenticate
  a subscription at all). The secret is sealed under a key derived from the **device
  key** — not the vault seal key — which is exactly what lets it open while the vault is
  shut, and it is useless off-device (the device key is OS-keyring/Keystore-held). It is
  not a ratchet identity and signs nothing else.
* **Binding.** `CallKeyBinding` is signed by the device's own roster Ed25519 key over
  (username hash, device id, call key, created_at) and verified against the KT-verified
  roster, so no new authority exists and revocation is free: a device off the roster has
  no verifiable binding. `supersedes` makes publication monotonic.
* **Mailbox.** `call_mailbox_hash(username_hash, device_id)` is deliberately distinct
  from every message mailbox, **including the primary's** — the mailbox a call-only key
  can drain must never be the one carrying chat ciphertext.
* **Capsule.** `PayloadKind::CallCapsule`, sealed to that key (ephemeral-sender X25519 +
  HKDF + XChaCha20-Poly1305, sender-anonymous on the wire). It carries version and kind
  (offer/terminal), the `call_instance_id`, the id its ring is keyed under (`offer_id`,
  or a group's `ring_id`), a random single-use `ring_handle`, the caller's verification
  material, the destination device id, audio/video/group flags, absolute
  created/ring/expiry values, the exact reply mailbox, a terminal reason, an anti-replay
  nonce, and the caller device's signature over every one of those fields.
  It carries **no** room id, media key, message content, or reusable capability — a
  capsule cannot answer a call, only present or cancel one.
* **Screening.** While locked, signing keys come from a keyed-hash approved-caller index
  (HKDF over the call-only store key) rather than from the vault. Absent = refused, so a
  blocked or unknown caller cannot ring a locked phone; it still rings normally after
  unlock, which is the safe direction.
* **Convergence.** Both layers name the same registry record, so a device that receives
  both rings **once** — the encrypted offer adopts the capsule's presentation handle. A
  terminal capsule writes the tombstone that stops a late offer from ringing.

## Group calls (mesh of pair rooms)

A group call is a **full mesh of the 1:1 rooms above** — nothing new exists on the
relay, which cannot distinguish a group-call leg from an ordinary voice call. Voice-only
(a mesh participant uploads one constant-rate stream per other member; clients cap
groups at 8 for calls).

Signaling, inside each pair's ratchet session:

* `GroupCallOfferV2 { group_id, call_instance_id, ring_id, offer_id, call_id, key_b64,
  created_at, ring_expires_at, expires_at, from, caller_device_id, coordinator_*,
  resume }` — one **pair leg's** ticket. `call_instance_id` names the call across all
  participants; `ring_id` names one logical *ring* (every participant's offer for the
  same ring carries it, which is what makes one ring out of many offers);
  `call_id`/`key_b64` are a fresh 1:1-style room capability + key for this pair only.
  Receiving any offer for an instance also means *the sender is in that call*.
* `GroupCallAnswerClaimV2` / `GroupCallWinnerV2` — the same arbitration as 1:1, with the
  **originating device as the stable coordinator**: each recipient account's devices
  claim, the coordinator names one winner per account, and only that device may emit or
  join pair legs. An answer on one phone therefore cannot leave a sibling in the mesh.
* `GroupCallTerminalV2 { …, reason, actor_device_id, coordinator_* }` — decline / leave /
  cancel. A **coordinator** terminal ends the logical call for everyone; anyone else's
  removes only their own pair leg.

Deadlines, tombstones, idempotency, wake classes and TTLs are the 1:1 rules verbatim —
initial offers from every participant reuse the starter's absolute deadline, so a slow
member cannot extend the ring, and a `resume` offer for an already-active member is an
urgent silent control that never rings.

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
tickets, and each leg's keys die with the call. Recipients honor a `GroupCallOfferV2` only
from a ratchet-authenticated sender on the (locally stored) group roster; anyone else's
offer is discarded unanswered. Latency is one relay hop, identical to a 1:1 call; audio
is Opus-encoded once per 20 ms and sealed per leg; inbound legs are decoded per sender
and mixed client-side (i32 sum, saturating).

**Key hygiene / drop recovery.** A pair-room key is used **once, ever**: clients track
every joined room id per call and refuse to re-derive a consumed key (re-deriving would
restart the seal counter — nonce reuse — and a malicious relay could trigger it by
replaying an old offer). A leg that dies *without* a `GroupCallTerminalV2` is a network
drop, not a leave: after a short grace period (2 s, so a genuine leave's terminal can
land) the pair's **owner** mints a fresh ticket, re-offers, and both sides converge on
the new room — at most 3 automatic re-offers per member, reset when a leg connects.
Deliberate leavers are never re-offered; a leaver's own fresh offer marks a rejoin.

## Video calls & screen share (media v2)

Camera video, screen sharing, and screen audio multiplex extra **tracks** over the same
blind call room — no second room, no new endpoints, and voice keeps the exact v1 wire
format above.

**Negotiation (three-way, degrade-to-voice):**
* `CallOfferV2`/`CallAnswerClaimV2` carry `caps: ["media2", …]`.
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

**Isolation is part of the mapping, not an implementation detail.** Splitting the two
classes across datagrams and streams buys nothing unless every party — sender, relay,
receiver — also *drains* them independently. A reliable group is only complete when its
last byte lands, which on a lossy or congested link is a retransmit away; any place that
waits for that in the same task as voice has re-created head-of-line blocking above the
transport that was chosen to avoid it. Both ends had exactly that bug, and the symptom was
not "video is slow" but "the whole call breaks up while someone shares": voice stopped
being captured, sent, forwarded and decoded for as long as one video frame took to arrive.
Two rules follow, and both are load-bearing:

* **Never await a reliable send or read on the voice path.** Outbound video belongs to its
  own task; a relay must read datagrams in a task that no stream read can park.
* **Drain stream groups in order, one at a time.** Frames must reach a decoder in encode
  order — a small P-frame overtaking a large keyframe breaks the reference chain, and the
  recovery (another keyframe) is larger still. Order costs nothing here, because a stream
  read can only ever delay *later video*, never voice.

Abuse bounds match the WS leg: same per-frame cap, same per-connection byte budget,
join must arrive within 5 s, stream groups are capped at 300 KiB.

**What v2 deliberately does *not* hide** (unlike voice): video bitrate varies with
motion and keyframes, and turning a track on/off is visible to the relay as a bandwidth
change. Cells are padded to coarse buckets and the encoder is bitrate-capped, but the
honest claim is: the relay learns *"this call has video-class bandwidth"*, never
content, identities, or IPs. Voice frames keep their perfectly constant size + cadence
even during a video call.
