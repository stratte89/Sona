# Multi-Device (Signal-style) — Design & Status

> Status: **Phases 1–3 implemented** end to end in `client-core` (headless, tested
> against the real relay) and wired into the Tauri desktop shell:
> * Phase 1 — per-device key model, KT device rosters, relay endpoints, password/PIN +
>   link-secret history-sync sealing.
> * Phase 2 — roster-aware **fan-out** + **self-fan-out** with jitter, device→account
>   **attribution**, **anti-rollback epoch pinning** (the deferred security gate),
>   **own-roster self-audit**, linked-device **fallback/one-time-key** upload, **device
>   revocation**.
> * Phase 3 — **QR device-linking** (`create_link_request` / `authorize_link` /
>   `complete_link`), password/PIN-gated **history export/import**, **primary→linked
>   forwarding** of legacy-sender traffic, multi-device **receipts** and **groups**.
>
> The **desktop GUI** now drives the whole flow: a Settings → Devices section (list /
> revoke / self-audit warning / link / **primary transfer**), a "Link this as a new
> device" entry on the unlock and create screens, the new-device link screen (**QR code**
> by default, copyable text code behind a toggle, device-key fingerprint), the primary's
> authorize-a-device modal (**camera QR scan** + paste), group send over fan-out, and the
> history re-export prompt.
>
> Everything client-facing is **capability-gated per relay** (`/v1/capabilities`) and
> **per-peer** (a contact with no published roster is delivered to single-device): a
> client on an old relay, or an account that never links a second device, runs the exact
> single-device path that ships today. What remains stubbed/partial is listed in §10.

---

## 0. Goals and non-negotiables

1. One account on several devices, each a **first-class endpoint**: messages to the
   account reach every device; a user's own sends sync to their other devices.
2. **Per-device Olm identities.** One device's compromise must not expose another's
   ratchet state or history. No identity private key is ever copied between devices;
   no Double Ratchet session is ever shared (the ratchet is single-owner — shared
   state corrupts and destroys its security properties).
3. **The relay stays blind.** No plaintext, no usernames, no sender identity, no new
   linkable identifiers beyond what §9 explicitly documents.
4. **The device list is transparency-logged and account-signed.** Neither the relay
   nor a network attacker can silently add a device that receives your messages.
5. **History sync is gated by the account password (or PIN)** and the relay can never
   read the history or brute-force the gate (§6).
6. **Backward compatible with zero user action.** Existing accounts, old clients, and
   the currently deployed production relay all keep working unchanged.

## 1. Identity model

| Concept | Today (single-device) | With multi-device |
|---|---|---|
| Account identity | one Olm account: Curve25519 identity key + Ed25519 signing key | unchanged — these become the **account keys**, held only by the **primary device** |
| KT binding | `KtEntry`: username_hash → (identity_key, signing_key) | unchanged (same leaf type, same chain rules) |
| Device identity | — (account == device) | every device runs its **own** Olm account (own Curve25519 + Ed25519 + prekeys) |
| Mailbox | `SHA-256(username)` | primary keeps it; each linked device gets a derived mailbox (§4) |
| Sessions | per peer | per **(peer account, peer device)** — a contact with 3 devices means 3 independent Olm sessions |

The **primary device** is the device holding the account keys — for every existing
account, the device it already runs on. The account signing key is what signs KT
entries, rosters (§2), and login challenges for the legacy mailbox. Rotating the
account keys remains exactly today's `KtEntry` rotation (signed by the previous key).

Implemented in: `crates/kt-log/src/roster.rs` (`DeviceRecord`, `KtRosterEntry`,
`PRIMARY_DEVICE_ID`, `MAX_DEVICES = 8`), `crates/crypto-core/src/kt.rs`
(`Account::device_record`, `Account::kt_roster_entry`).

## 2. The device roster in Key Transparency

The roster is the account's complete, ordered device list, recorded as **its own leaf
type in the same append-only KT log** (distinct domain-separated leaf bytes:
`sona-kt-leaf-roster-v1|…` vs the binding leaves' `sona-kt-entry-v1…`). One tree, one
signed head, one consistency proof covers both bindings and rosters — the auditor
(`crates/auditor`) and all existing gossip/witness machinery apply unchanged, because
they operate on heads and consistency proofs, never on leaf contents.

```jsonc
// KtRosterEntry — one roster epoch, appended to the KT log.
{
  "seq": 0,                      // epoch: 0,1,2,… strictly contiguous per account
  "username_hash": "<hex>",
  "devices": [
    { "device_id": "0",          // "0" = primary (reserved); else 32-hex random
      "identity_key": "<b64>", "signing_key": "<b64>",
      "added_at": 1751846400,
      "signature": "<b64>" },    // proof-of-possession by the DEVICE key (see below)
    ...
  ],
  "timestamp": 1751846400,
  "signature": "<b64>"           // by the ACCOUNT signing key currently bound in KT
}
```

**Cross-signing, both directions:**

* The **account key signs the roster** (over every device record including their
  signatures, length-prefixed and domain-separated: `sona-kt-roster-v1`). The relay
  cannot mint, extend, shrink, or reorder a roster — it lacks the private key. A rogue
  device can only appear if the account key signed it, and then it is *public,
  permanent, append-only evidence* the account's own self-audit
  (`Client::audit_own_key`-style roster audit, Phase 2) and any third party will see.
* Each **device record carries a proof-of-possession**: the device's own Ed25519 key
  signs `sona-kt-device-v1 | username_hash | device_id | identity_key | signing_key |
  added_at`. An account cannot be tricked into enrolling a key whose private half the
  enrollee doesn't control, and a record cannot be transplanted between accounts
  (username_hash is bound in).

**Validation (fail-closed), enforced by `KtLog::append_roster` on the server and by
`KtRosterEntry::validate_against` on every client:** roster is for an existing
username; signed by that username's **current** KT-bound key; epochs strictly
contiguous; 1..=8 devices; unique, well-formed ids; **exactly one primary whose keys
equal the KT entry's keys**; every proof-of-possession verifies.

**Add / remove / revoke = append a new epoch.** Removal is not deletion — epoch N+1
without the device is appended, permanently recording when the device existed. After
an account-key **rotation**, the previous roster no longer validates (its primary keys
mismatch the new binding); the account must publish a fresh epoch, and until it does,
peers **fall back to single-device delivery to the KT-bound key** — never to a stale
roster.

**Client rule (implemented, `Client::resolve_account_devices`):** the sender verifies STH
signature (pinned key) → roster Merkle inclusion (`verify_roster_inclusion_b64`) →
`validate_against` the independently KT-verified `KtEntry`. Outcomes:
* verified roster → resolve to its device list, and **pin its epoch monotonically**
  (`History::pin_roster`);
* roster that fails semantic validation (stale, e.g. pre-rotation) → **ignore it, fall
  back to single-device delivery** on the current KT-bound key — never an unverified list;
* **served epoch < pinned epoch, or a 404 after we pinned a roster** (append-only rosters
  are never deleted) → `RosterRollback` error → **the send fails closed**. This is how a
  relay replaying an old roster to resurrect a revoked device, or deleting a roster to
  downgrade a multi-device account, is caught. It is the same monotonic-witness principle
  the KT tree heads already use, applied per-contact per-roster.

Implemented in: `crates/kt-log/src/roster.rs`, `crates/kt-log/src/log.rs`
(`KtRecord`, `append_roster`, `latest_roster_for`, `roster_inclusion`),
`crates/kt-log/src/verify.rs` (`verify_roster_inclusion[_b64]`).

## 3. Linking a new device (authorization flow — implemented)

Implemented as three `client-core` calls + three Tauri commands
(`link_start` → `authorize_device` → `complete_link_cmd`). The user types their **username**
on the new device (resolving the "device doesn't know the account yet" bootstrap while
keeping the username-bound proof-of-possession), and enters the **account password** on
both devices. Concretely:

1. **New device** (`create_link_request`): mints a fresh Olm identity + random `device_id`,
   a signed `DeviceRecord` (PoP over the account username hash), a 256-bit **link secret**,
   and a random **provisioning id**. These form the QR/short-code `LinkRequest`.
2. **Primary** (`authorize_link`, after the account password re-opens the vault): validates
   the record, fetches its current full roster, appends the new device, publishes roster
   epoch N+1, seals the current history under `sync::seal_history(password, link_secret)`
   and uploads it (`POST /v1/sync`), then PUTs a link-secret-sealed provisioning pointer
   (`{username, history_sync_id, primary_key}`) at the new device's chosen id
   (`PUT /v1/sync/{provisioning_id}`).
3. **New device** (`complete_link`): downloads the provisioning pointer, downloads + decrypts
   the history with `sync::open_history(password, link_secret)`, imports it, adopts its
   device identity, uploads its one-time keys on its device mailbox, pins its own roster,
   and sends a no-op **hello** to the primary so the primary gains a session for legacy
   forwarding (§8). "Primary offline / not done yet" surfaces as a plain 404 the UI retries;
   "history blob expired past TTL" is a 404 the caller can turn into a re-export request.

The rest of this section is the original design rationale, unchanged:

Adding a device is authorized **by the primary device, never by the server**:

1. **New device** generates its own Olm account and a random 128-bit `device_id`, and
   displays a QR (or short code) containing: `device_id`, its two public keys, a
   random 256-bit **link secret** (§6), and a random provisioning mailbox id.
2. **Primary device** scans the QR. The user confirms the action and enters the
   **account password (or ceremony-grade PIN)** — this both gates the UI action and is
   required anyway to use the vault-held account signing key. The primary shows the
   new device's key fingerprint for visual confirmation (the QR channel is the
   out-of-band trust anchor; anything tampering with it changes the fingerprint).
3. Primary signs **roster epoch N+1** including the new device's proof-of-possession
   record and publishes it (`POST /v1/kt/roster`). The relay mirrors a directory
   record for the device's mailbox (§4).
4. Primary sends a **provisioning envelope** to the new device's provisioning mailbox
   (a normal sealed envelope, `PayloadKind::DeviceSync`, encrypted to the new device's
   identity key): the account username, the pinned KT key, current roster seq, contact
   list pins, and the history-sync capability id (§6).
5. New device fetches + verifies the roster it now appears in, uploads its one-time
   keys (existing `/v1/onetimekeys`, signed by its device key), authenticates its
   delivery socket (existing challenge flow — the directory record for its mailbox
   holds its device signing key), and prompts for the **account password/PIN** to
   decrypt history (§6).

The QR never contains private keys. The link secret and provisioning mailbox id are
capabilities that die when linking completes. If either side aborts, nothing was
published (steps 1–2), or the roster is corrected by appending epoch N+2 (step 3+).

**Hardware attestation (advisory).** An Android linker additionally mints an
*ephemeral* Keystore key (StrongBox preferred, TEE fallback — `HwAttest.kt`) whose
attestation challenge is `SHA-256("sona-link-attest-v1" ‖ device_id ‖ identity_key)`,
uploads the hardware-signed certificate chain sealed under the link secret to a fresh
capability id (`/v1/sync/{attest_id}` — a chain is several KB, far too big for the QR,
which carries only the id), and deletes the key. Before the primary's user confirms,
the authorize dialog fetches and verifies the chain (`client-core attest.rs`):
signatures up to a **pinned Google hardware-attestation root**, **our exact
challenge** (so a chain proves this request, not a replayed one), and TEE/StrongBox
**security level** (a software keymaster or emulator can't produce it). The verdict —
"hardware-verified (+ boot state: stock verified / locked-bootloader custom OS such as
GrapheneOS / unlocked)" or a failure — is shown next to the key fingerprint. It is
**advisory only**: desktop linkers have no attestation (silence, not a warning), a
malicious-but-real phone still attests fine, and no CRL is fetched (that would leak
the ceremony to Google and defeat Tor routing). What it stops: linking an emulator or
a scripted client that replays extracted key material while claiming to be a phone.

**Removal/revocation:** any device with the account key (the primary) appends an
epoch without the device. The relay immediately drops the revoked device's directory
record — killing its socket authentication and any new inbound sessions — **and kicks
its live sockets**: connected sockets get a terminal `{"type":"revoked"}` frame and are
closed, and any later auth against the dead mailbox answers `revoked` instead of the
retryable `auth_failed` (implemented, `publish_roster` / `authenticate` in
`crates/server/src/http/kt.rs`). The diff is by identity **key**, not device id: a device
whose id moved but whose key is still in the new roster (a primary transfer re-ids the
two devices involved) has its dead mailbox cleaned up but is *not* told `revoked` — it
moved, it wasn't removed.

The client never takes the relay's word for it. A `revoked` frame (or an auth landing
on a missing directory record) is a **server-asserted, unauthenticated claim**; the
client verifies it against the KT log (`Client::verify_device_revocation`): if its
identity key is still the account binding or in the verified roster it merely moved
mailboxes — device state is fixed up and delivery re-subscribes on the current mailbox.
Only a KT-confirmed absence persists the lockout (`History::revoked`); the client then
refuses to send (recipients would silently discard its messages
anyway — it is off the roster), and pins the UI on a relink-or-new-account screen.
Verification errors are transient (retry), never a lockout — a hostile relay cannot
lock a healthy device out of its account.
Peers drop its sessions when they next refresh the roster (Phase 2). **Loss of the
primary** = loss of the account key: recovery is today's KT rotation via the vault
backup, or a new account — unchanged.

## 4. Mailboxes and message fan-out

* Primary mailbox: `SHA-256(username)` — **unchanged**, which is the whole
  backward-compatibility story: old clients and never-upgraded senders keep working.
* Linked-device mailbox: `SHA-256("sona-device-mailbox-v1|" + username_hash + "|" +
  device_id)` (`protocol_types::device_mailbox_hash`). Any sender holding the
  KT-verified roster derives every mailbox; the relay still routes on opaque hashes.

**Sending (implemented, `Client::prepare_text_fanout` / `prepare_*_fanout`):** to send to
a contact, encrypt the same `ChatPayload` separately under the Olm session for **each
device in their verified roster** (immediate), and a **self-sync** copy under the session
for **each of your own other devices** (deferred). All copies share **one message id** so
every device dedups. Sessions to a device are established on demand from that device's
bundle (`GET /v1/bundle/{device_mailbox}`), with the bundle's identity key checked against
the roster record (`ensure_device_session`). The own-device copies are latency-tolerant, so
the caller posts them after a random **0–25 s jitter** (`self_sync_jitter_secs`) — this
blunts the burst-correlation the relay could otherwise use to link sender↔recipient (see
§9.3). Own-device self-sync uses dedicated payloads (`SelfText` / `SelfFile` / `SelfSeen`)
so the receiving device files them correctly (outgoing message / read marker). Groups and
read receipts flow through the same fan-out.

**Durable outbox:** the jittered self-sync copies (and a primary's forwards of
legacy-sender traffic) are persisted in the sealed history (`History::outbox`, capped,
oldest-first eviction) *before* anything hits the network, and drained on unlock, every
30 s while unlocked, and once right after the jitter elapses. An in-memory jitter timer
alone silently lost the copy whenever the app closed or Android killed the process
inside the jitter window — which is exactly how linked devices' histories drifted apart.

**Ephemeral typing** never rides the full fan-out: `prepare_typing_fanout` /
`prepare_group_typing_fanout` seal one copy per device we **already** share a session
with (from the pinned roster) — network-free (no bundle fetches, no roster refresh, no
one-time keys burned, no self-sync), because typing fires every few seconds and is
worthless a minute later.

**Receiving (implemented):** `decrypt_unattributed` attributes by session; a peer-device
session is just another session keyed by that device's identity key. `client-core` then
does **device→account attribution** in `History` (`attribute_device`): a verified roster
teaches `device_key → account primary_key`, so every one of a contact's devices files
into the **one** conversation keyed by the account's stable primary key, and a self-sync
from one of *our own* devices (`is_own_device`) is recorded as our outgoing message. A
device whose owning roster we have not yet fetched is attributed to itself (unchanged
single-device behavior) until we resolve the roster.

## 5. Session management

* Sessions are per-(peer device); stored exactly as today in the vault ratchet state
  (`crypto-core/src/ratchet.rs` needs no change — sessions are keyed by identity key,
  and every device has a distinct one).
* **Roster refresh:** on each send (the client already KT-re-verifies per send), the
  sender re-fetches the roster (cheap proof, no OTK consumed), compares against the
  pinned epoch: new device → warn-and-verify UX (same posture as a key change: show
  it, let the user block), removed device → drop its session and stop encrypting to
  it. Epoch regression → treat as equivocation evidence.
* A revoked device that kept its last ratchet keys can decrypt nothing new once
  senders stop encrypting to it (per-device fan-out is what makes revocation *work*).

## 6. Password/PIN-gated history sync

Implemented primitive: `crates/crypto-core/src/sync.rs`; relay store:
`POST/GET /v1/sync` (`crates/server/src/http/sync.rs`, `db.rs`).

```
sync_key = HKDF-SHA256( salt,
                        Argon2id(password-or-PIN, salt) || link_secret,
                        "sona-history-sync-v1" )
blob     = "SHS1" || 1 || salt(16) || nonce(24)
           || XChaCha20-Poly1305(sync_key, pad64KiB(history), aad = header)
```

* **Why the 256-bit link secret is mandatory:** the blob rests on the relay, so the
  relay is the offline brute-force adversary. A key from the password alone is only as
  strong as the password; from a 4–8 char **PIN** alone it would be trivial. The link
  secret travels only inside the QR/short code between the two devices — the relay
  never sees it — so the relay can brute-force neither. This mirrors the vault-v2
  device-key mix-in. Only vetted primitives (argon2, hkdf, chacha20poly1305), no new
  dependencies.
* **The user experience is Signal-adjacent:** after linking, the new device asks for
  the account password (or PIN, if set); only then does history decrypt. Wrong
  password, wrong link secret, and tampering are one indistinguishable AEAD failure.
* **Flow:** primary seals its `history.bin` export → `POST /v1/sync` → capability id
  (random 128-bit, **unauthenticated by design** like `/blobs` and call rooms, so the
  relay cannot link blob↔account) → id travels in the provisioning envelope → new
  device downloads (any time within the 7-day TTL — this covers "no other device
  online": the primary can be off; the blob waits) → user enters password/PIN →
  decrypt → import. If the blob expired before the new device fetched it, the new
  device requests a re-export over the E2E device-sync channel next time the primary
  is online (Phase 3); history sync is eventually-consistent, never a gate on linking.
* The plaintext is bucket-padded (64 KiB) before sealing so the relay learns only a
  coarse size class.
* The vault's **device binding is untouched**: history arrives via this explicit
  re-encryption channel; a *copied vault* still opens nowhere else. Ongoing sync of
  new messages is the self-fan-out channel (§4), not this blob.

## 7. Server (blind relay) surface — implemented

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/capabilities` | `{"capabilities":["multi-device-v1","history-sync-v1"]}`; old relays 404 → client stays single-device |
| POST | `/v1/kt/roster` | Append a roster epoch (self-authenticating; validated fail-closed by the KT log; rate-limited on the strict `auth_rate` budget). Mirrors linked-device directory records; revokes dropped ones (directory + push) |
| GET | `/v1/kt/roster/{hash}` | Latest roster + index + inclusion proof + STH; 404 = single-device account |
| POST | `/v1/sync` | Store an opaque history blob (≤32 MiB, 7-day TTL, rate-limited) → random capability id |
| PUT | `/v1/sync/{id}` | Store a provisioning/history blob at a **caller-chosen** id (new device picks it, primary PUTs); first-writer-wins, hex id, rate-limited |
| GET | `/v1/sync/{id}` | Fetch the opaque blob |

Persistence: roster leaves share the ordered `kt_entries` table (tagged rows) so the
boot replay rebuilds the Merkle tree in identical leaf order, re-validating every
record; `sync_blobs` table with TTL, swept by the existing reaper. The deployed
production relay needs **no redeploy** for existing apps to keep working — every new
surface is additive, and clients discover it via `/v1/capabilities`.

Client SDK (`clients/client-core/src/lib.rs`): `server_capabilities`,
`publish_roster`, `fetch_verified_roster` (STH + inclusion + `validate_against`, with
mandatory single-device fallback semantics), `upload_sync_blob`, `download_sync_blob`.
Nothing in the default flow calls any of them.

## 8. Backward compatibility & migration

* **Old client ↔ old relay:** untouched code paths.
* **Old client ↔ new relay:** every existing endpoint byte-identical; new routes are
  additive. Old senders deliver to the primary mailbox only — a multi-device
  recipient's linked devices miss those messages until Phase 3 adds primary→linked
  re-encryption (an E2E `DeviceSync` forward by the primary; the relay stays blind).
  Documented degradation, not breakage.
* **New client ↔ old relay:** `/v1/capabilities` 404 → single-device path.
* **Migration:** an existing account needs *nothing* — no roster means single-device,
  forever if the user never links. The first link publishes roster epoch 0 (primary =
  existing keys, id `"0"`, mailbox unchanged) + the new device. There is no flag day
  and no KT chain break: the binding chain is untouched by roster leaves.

## 9. THREAT_MODEL delta — new exposure, honestly stated

New metadata / attack surface, with mitigations:

1. **Public device roster.** The KT log now publicly records, per account hash:
   device count, device public keys, add/remove times, epoch history. *Accepted:*
   this is the price of auditable device lists (Signal exposes device ids to the
   server and senders too; we make them verifiable instead of trusted). Device
   *names/models are never published* — records carry keys and timestamps only.
2. **Relay links device mailboxes to accounts.** Derivation from the public roster is
   deterministic, so the relay learns account↔device-mailbox groupings and per-device
   online/delivery timing (it must, to route). *Mitigation:* nothing new is learnable
   beyond the public roster + existing timing channel; hashes stay one-way for
   accounts with no roster.
3. **Self-fan-out weakens sealed-sender timing.** A send produces near-simultaneous
   envelopes to the recipient's devices *and the sender's own other devices*; the
   relay can correlate the burst and guess sender-account ↔ recipient-account with
   good probability. *Mitigation (Phase 2, required):* randomized per-envelope jitter
   (0–30 s) on own-device sync copies, which are latency-tolerant; recipient-device
   copies stay immediate. *Residual:* an account with one device is unaffected;
   correlation remains probabilistic, and the envelopes themselves still name no
   sender. Stated plainly: multi-device trades some sealed-sender timing resistance
   for device sync — users who refuse the trade simply don't link a second device.
4. **History blob on the relay.** The relay sees upload/download timing, coarse
   (64 KiB-bucketed) size, and holds ciphertext for ≤7 days. *Mitigation:* capability
   addressing (relay can't tie blob→account by content), mandatory link-secret mix-in
   (relay cannot brute-force password *or* PIN, §6), TTL deletion.
5. **Roster publish = link event.** The relay (and the public log, via timestamps)
   learns *when* an account linked/removed a device. *Accepted:* inherent to any
   transparency-logged roster; the alternative (server-trusted device lists) is the
   attack we're preventing.
6. **New unauthenticated write surface (`/v1/sync`).** Abuse bounded like `/blobs`:
   size cap, per-client fail-closed rate limit, TTL, random ids (no enumeration, no
   overwrite). A flood costs the attacker rate-limit budget and buys ≤7-day storage.
7. **Rogue-device injection (the key new *attack* to beat):** requires forging the
   account signature (relay can't), or compromising the primary device (out of scope —
   endpoint compromise already loses everything), or a stale-roster replay (blocked
   client-side by epoch pinning + the same gossip that guards tree heads; a *withheld*
   roster only yields fewer devices, never an attacker device).
8. **PIN brute-force positioning unchanged:** the PIN never protects anything
   relay-resident by itself; on-device it remains counter-limited (5 attempts), and in
   sync keys it is always fortified by the 256-bit link secret.

Unchanged invariants (verified by existing + new tests): KT append-only with signed
heads and auditor split-view detection (one tree, consistency proofs span mixed
leaves); blind-relay properties (no plaintext, no sender, hash-only routing, ZK-clean
envelopes); cached-seal-key / cancel-safe subscriber loop / poison-ack delivery
behavior; WS `Origin` policy (absent Origin = native client, still permitted).

**Rename × multi-device (current constraint):** changing the username is a
**single-device ceremony** — refused on a non-primary device, and on a primary with
linked devices it first **unlinks them all** behind an explicit, count-aware "are you
sure" dialog (each revoked device lands on the relink screen; QR relink afterwards).
Device rosters and device mailboxes are derived from the username hash; a rename would
need every linked device to re-sign its roster record (a proof-of-possession only that
device can mint) for the new hash and migrate mailboxes, which is a re-enrollment
protocol we have not built. Renames are capped at **5 per rolling week** (client-enforced
in `History`, relay-backstopped per signing key on the release side). Renaming also **releases** the old name into the KT log's grace-period
takeover flow (see `docs/KEY_TRANSPARENCY.md`); a released name accepts no roster
epochs, and a taken-over name's roster chain restarts at 0 for the new owner (clients
require an advanced KT binding to accept the restart — the combined binding+roster view
can never be rolled back to the old owner's era).

## 10. Implementation status

**Fully working + tested (headless `client-core` e2e against the real relay, plus unit
tests; wired into the Tauri desktop shell, which compiles):**
* Roster types + validation + KT integration (`kt-log`); device-record/roster minting
  (`crypto-core::kt`); history-sync + provisioning sealing (`crypto-core::sync`).
* Relay endpoints + directory mirroring/revocation + persistence + reaper (`server`),
  incl. `PUT /v1/sync/{id}`.
* `client-core::multidevice`: `resolve_account_devices` (anti-rollback pin — the deferred
  security gate), `prepare_text_fanout` / `prepare_attachment_fanout` /
  `prepare_receipt_fanout` (fan-out + self-fan-out with jitter), device→account
  attribution + self-sync recording in `History`, `create_link_request` /
  `authorize_link` / `complete_link`, `revoke_device`, `audit_own_roster` (compares
  identity *keys* against the pinned view — device ids legitimately move in a primary
  transfer; `audit_own_key` is likewise device-aware: a linked device checks the
  binding against its pinned primary key, not its own device key),
  `verify_device_revocation` (KT-verifies a relay `revoked` claim before any lockout;
  fixes up device identity when the roster moved us),
  `export_history` / `import_history`, `forward_inbound_to_devices` /
  `forward_inbound_sync` (legacy-sender forwarding), linked-device mailbox subscribe +
  one-time-key replenish.
* `client-core::multidevice` also has `send_group_multi` (group fan-out to every member's
  devices + own devices), and the history re-export triad `request_history_resync` /
  `fulfill_resync` / `poll_resync` over an E2E `SyncRequest` (the relay never sees the
  re-sync link secret).
* Tauri desktop shell: capability probe; fan-out `send` + `mark_seen` + `send_group_msg`;
  linked-device delivery loop (device mailbox); primary legacy-forwarding in the loop;
  `SyncRequested` surfaced to the UI; commands `link_start`, `authorize_device`,
  `complete_link_cmd`, `request_resync`, `poll_resync_cmd`, `fulfill_resync_cmd`,
  `list_devices`, `revoke_device`, `audit_devices`.
* **Desktop GUI** (`clients/desktop/src`): Settings → **Devices** (list, per-device
  Revoke, a visible rogue-device warning from `audit_devices`, "Link a device"); a **Link
  this device** screen reachable from the unlock and create screens (username + account
  password → copyable link code → finish); the primary's **authorize** modal (paste code +
  password); group messages sent via fan-out with cross-device "mine" attribution; a
  **re-sync** row on a linked device whose history didn't transfer, and a password prompt
  on the primary when a device requests re-export. Loaded + driven headlessly (stubbed
  Tauri bridge) with zero console errors; screenshots of the Devices and Link screens
  captured.

**Also shipped (QR + primary transfer):**
* **QR device-linking UI**: the new device renders its link code as a QR (inline SVG,
  vendored `qrcode-generator` — MIT, no CDN/remote assets; the strict CSP stays intact),
  with the copyable text code one toggle away. The primary's authorize modal gains
  **Scan with camera** (`getUserMedia` + vendored `jsQR` (`vendor/jsQR.js`), Apache-2.0, lazy-loaded);
  manual paste remains everywhere. Android needs no native bridge: wry's generated
  `RustWebChromeClient` runtime-requests CAMERA for the webview's VIDEO_CAPTURE request,
  and the manifest permission is already applied by `scripts/harden-android.sh` (§5/§10
  of that script). On Linux the shell's WebKit permission handler now allows user-media
  video (it previously allowed audio only). Both sides display a short **device-key
  fingerprint** (first 8 bytes of a domain-separated SHA-256), so a swapped/tampered
  code is visible before the password is ever entered. Scanned input is accepted only if
  it parses as an exact `LinkRequest` shape (bounded length, hex ids, string keys).
* **Primary-ownership transfer** (`offer_primary_transfer` / `accept_primary_transfer` /
  `finish_primary_demotion`, Tauri commands `transfer_primary` / `accept_primary_cmd` /
  `check_transfer_cmd`): the primary role moves to a linked device with **no private key
  ever leaving a device**. The primary signs a KT **rotation entry** (binding the account
  to the target's already-enrolled, PoP-verified keys) plus its own **demoted device
  record** (same keys, fresh linked id) and sends both E2E to the target only. The
  *target* publishes the rotation (its fresh one-time keys seed the account-mailbox
  directory) and a roster epoch naming itself device `"0"`; the old primary cannot be
  notified (the account mailbox changes hands), so it **polls the KT log** and demotes
  itself when it observes the completed transfer — surviving restarts via a persisted
  `PendingDemotion`. Both steps are password-gated on their respective devices. Peers see
  an ordinary account-key rotation (key-change UX) and the standard roster fallback rules
  cover every intermediate state; sessions keyed to either device's identity key survive,
  since neither key changes — only the roster/binding roles do. The Devices UI hides
  **Link a device** / **Revoke** / **Make primary…** on non-primary devices (the server
  refuses a roster not signed by the KT-bound key regardless). In-flight messages posted
  to a mailbox that moves during the transfer can be lost (same window as any rotation);
  senders re-verify KT per send, so the window is one round-trip.

* **Calls ring all devices** (first answer wins), with no added ring latency and no new
  metadata class:
  * The caller signals the KT-bound key first over the existing 1:1 path (first-ring
    latency byte-identical to single-device), then posts *extra* copies of the same
    `CallOffer` (same call id + key) to the rest of the contact's verified roster
    (`extra_call_offer_envelopes`). Any roster problem — stale epoch, rollback, offline —
    yields **no extra copies**: the per-call key is never sealed to a device outside the
    current verified roster, and the primary keeps ringing regardless.
  * `CallAnswer` gains a `busy` flag (serde-default, so old clients are unaffected): an
    *automatic* decline (device already in a call / already ringing) no longer ends the
    ring while the callee's other devices can still answer — the caller counts busy
    declines against the number of devices rung (`ring_fanout`) and ends the ring only at
    zero. An explicit decline (and every old-client decline) still ends it at once, and a
    decline can never tear down a call that already connected (accept race).
  * The answering/declining device sends `SelfCallHandled { call_id }` to its own other
    devices so they stop ringing ("Answered on another device"); honored only from a
    roster-verified own device, never enters history, carries no key material. It is sent
    *after* the media join, so answering adds no latency to the connect path, and it is
    **not** jittered — a ring is already a simultaneous, relay-visible event (the
    answering device's call-room join happens at the same instant), so this adds no new
    correlation signal beyond THREAT §9.3's accepted fan-out shape.
  * Hangup/cancel and the caller-side ring timeout fan `CallEnd` to every rung device, so
    nothing rings into the 45 s timeout. Old-client callers still ring the primary only
    (documented degradation, unchanged).
  * **Answer routing for linked-device callers:** the direct 1:1 answer travels to the
    caller's *account* mailbox, which only the primary drains — so accepts/declines are
    also fanned to the caller's other roster devices (`extra_call_answer_envelopes`),
    and the fan skip rule exempts only the primary *when it is also the
    directly-addressed key*. Without this, a call placed from a linked device could
    never learn it was answered.

**Hardening pass (post-ship bug sweep):**
* **Multi-session ratchet** (`crypto-core::ratchet`): each peer identity key now holds up
  to 5 live Olm sessions (MRU-ordered; decrypt tries all, encrypt uses the front). This
  is what makes simultaneous session establishment — the linking hello still queued while
  the peer opens its own session — converge instead of ping-ponging one session slot and
  silently destroying messages (undecryptable envelopes are acked out of the mailbox, so
  every such drop was permanent). **Replay containment:** a pre-key message whose
  `session_id` matches a held session must decrypt with that state or is rejected —
  without this, replaying a captured *fallback-key* pre-key message (the fallback secret
  is reusable and long-lived) would let the relay rewind a live session at will. Vaults
  written before the change import losslessly (single-pickle layout still deserializes);
  note the reverse is not true — a *downgraded* app cannot read a multi-session vault.
* **Primary transfer is crash-safe on both ends, with the KT log as the only truth.**
  The target persists the received offer in (sealed) history — the accept publishes the
  rotation *then* the roster, and a crash between the two would otherwise wedge the
  account, since the old primary can no longer re-send the offer once the binding moved;
  the persisted offer re-prompts at unlock and the accept is idempotent across partial
  completion. The old primary's demotion no longer requires its local pending marker or
  a specific device id: any multi-device primary reconciles against the verified binding
  (via the demotion check at unlock / in the watch), and roster membership is matched by
  identity key alone (sound — the record PoP binds the id and only the key holder can
  sign one). A pending offer whose target was since revoked is dropped. The demotion
  watch never gives up while an offer is out (it slows to once a minute).
* A late `CallAnswer` (another callee device losing the accept race) can no longer flip
  the media caps of a call already connected.

**Partial / stubbed (documented, safe defaults):**
1. **Proactive roster-change banner**: `audit_devices` surfaces an unknown/rogue device in
   Settings → Devices, but there is no push banner the instant a roster changes (the user
   sees it next time they open Devices).
2. **Auditor** semantic roster validation (defense-in-depth) — the append-only + STH
   guarantees already cover roster leaves; a dedicated roster check in `crates/auditor` is
   optional future work.
3. **Fan-out cost**: every multi-device send re-resolves the contact's and our own roster
   (a KT proof + a roster GET each). Correct but not yet cached per-contact with a TTL — a
   latency optimization.
