# Groups — pairwise fan-out + signed membership epochs

How Sona does group chat **without the relay ever learning a group exists**, and without
inventing group cryptography.

## The two design pillars

1. **No shared group key.** A group message is ratchet-encrypted separately to every
   member over the existing KT-verified 1:1 Olm sessions and sent as N sealed-sender
   envelopes. The relay sees individual opaque envelopes, indistinguishable from 1:1
   traffic — no group id, no roster, no fan-out pattern it can attribute.
2. **Membership is a signed, append-only epoch chain** (`kt-log/src/group.rs`), not a
   mutable list anyone can rewrite. Same signing/rotation pattern as the public Key
   Transparency log — but exchanged **peer-to-peer inside the E2E sessions**, never
   published to the tree, because group membership is private.

## Membership epochs (`GroupEpoch`)

Each epoch carries the **complete member list** at a point in time plus the admin who
authorized it:

* `seq` — 0 for genesis (group creation), then strictly +1. Rollback = rejected.
* `admin_key` — the admin's **account Ed25519 signing key**, the same key bound to their
  username in the public KT log. Any member can independently verify "this admin key
  really belongs to that account" against KT. Because that key lives on the primary
  device, admin actions are primary-device-only (like a username rename).
* `prev_admin_key` — the continuity chain: genesis is self-signed; every later epoch must
  be signed by the admin named in the epoch *before* it. Only the current admin can
  extend the chain; admin transfer is just an epoch whose `admin_key` names the successor.
* The signature covers a domain-separated, length-prefixed payload — no field or member
  can be swapped, added, dropped, or reordered without breaking it.

Recipients validate every epoch against their pinned chain (`History::adopt_group_epoch`)
before adopting any membership change: bad signature, broken continuity, or a rollback in
`seq` is discarded. A relay (or a kicked member) can replay or reorder epochs; it cannot
forge one.

**What is admin-gated:** adding a member, removing (kicking) a member, admin transfer.
**What stays egalitarian:** rename, disappearing timer, avatar, pins, messages, and
leaving — gated on *current membership*, not on the admin.

## Membership-gating content — the quarantine

Group content (text, files, reactions, timer changes, …) is honored only from a
ratchet-authenticated sender **currently on the group roster**. But epochs and content
race: an add epoch can land *after* the new member's first message. So content from a
non-member is **quarantined, not dropped**: held encrypted-at-rest per group, never
rendered, and replayed losslessly if a signed epoch that admits the sender arrives within
the TTL (10 minutes for known groups; 7 days for a group we've never seen — the invite
race). Caps bound what a spammer can park; oldest entries evict first.

The same holds for the whole-group race: content for an unknown `group_id` waits for its
genesis epoch (the invite) and replays on adoption. A removed member's messages stop
rendering the moment the removal epoch is adopted — the kick applies to the *validated
epoch*, not to whoever relayed it.

## Everything else groups can do

Feature parity with 1:1 chats, all over the same pairwise channels: edits and
delete-for-everyone (sender-scoped), quoted replies, @mentions, reactions, pinned
messages, forwarding, per-group disappearing timers, group avatars (E2E, size- and
format-checked), drafts, and attachments — one shared ciphertext blob per file, whose key
travels only inside each pair's ratchet.

**Group calls** are a full mesh of the 1:1 blind call rooms — the relay cannot tell a
group-call leg from an ordinary voice call. See the "Group calls" section of
[`PROTOCOL.md`](PROTOCOL.md) for the glare rule, key hygiene, and drop recovery.

## Honest limits

* Fan-out costs N envelopes per message; `MAX_GROUP_MEMBERS = 256` bounds the signed
  epoch (group *calls* cap at 8, voice-only).
* A member removed by epoch keeps the history they already decrypted — deletion of the
  past is impossible in any E2E system; the epoch chain controls the *future*.
* The relay still sees per-envelope timing and recipient hashes, the same irreducible
  floor as 1:1 traffic ([`THREAT_MODEL.md`](THREAT_MODEL.md)).
