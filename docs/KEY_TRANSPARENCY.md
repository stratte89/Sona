# Key Transparency

Key Transparency (KT) is what lets Sona claim to be **as safe as Signal on key
verification, with an untrusted server**. It closes the first-contact MITM hole that
end-to-end encryption alone leaves open.

## The hole it closes

Two people exchange *usernames*, not keys. Something maps username → public key — the
server's directory. A malicious, compromised, or coerced server can answer that lookup
with **its own** key and silently relay-and-read everything. The ciphertext is perfectly
encrypted… to the attacker. E2EE does not help; the trust problem is in *key discovery*.

## The mechanism

Every `username → identity_key` binding is published into an **append-only, signed,
publicly verifiable log** — an RFC 6962 Merkle tree (the same construction as Certificate
Transparency), implemented with the vetted `ct-merkle` crate. Three properties stack up:

### 1. Entries are self-authenticating (`kt-log/src/entry.rs`)

A `KtEntry` is signed:

* **First claim** (`prev_signing_key = null`): signed by its own signing key. Establishes
  the username's initial key. First-come-first-served — and *immutable* once logged.
* **Rotation** (`prev_signing_key = Some`): signed by the **previous** signing key. Only
  the current key-holder can authorize a successor, forming a continuity chain back to
  the first claim.
* **Release** (`released = true` on a rotation): the owner signs away the name, typically
  on a rename. The name stays theirs (and reclaimable with a plain rotation) for a grace
  period — [`RELEASE_GRACE_SECS`](../crates/kt-log/src/log.rs), 7 days — after which
  anyone may append a self-signed **takeover claim** (`prev_signing_key = null` at
  `seq > 0`, `KtEntry::new_reclaim`). The takeover is authorized by the release entry
  plus the elapsed grace (measured between *signed* timestamps; the server refuses
  future-dated entries so the window cannot be gamed), not by the old owner — and it is
  an explicit, auditable event in the name's public history. Contacts of the old owner
  are protected the same way as on any key change: their pinned key no longer matches,
  so the client surfaces a KeyChanged warning instead of silently trusting the new
  holder. Device-roster epochs restart at 0 for the new owner (clients accept the
  restart only together with a KT binding that *advanced* the chain — a relay cannot
  roll the combined binding+roster view back to the previous owner's era).

The server validates this on every append (`kt-log/src/log.rs::append`) and **cannot
forge an entry** — it has no user's private key. It cannot hijack an existing username
(a second first-claim is refused), cannot rotate a key it doesn't control, and cannot
fake a release (only the owner's signature creates one) or shorten its grace. Releases
are additionally rate-limited per **signing** key (5 per rolling week — the relay-side
backstop of the client's username-change limit), with the budget keyed by the key that
actually signed the entry so forged releases naming someone else cannot burn their
allowance.

**Account deletion** does not (cannot, by design) rewrite the log: the log is append-only
and public. Deleting an account is a primary-device ceremony that signs a **release**
entry for the username (starting the normal grace-then-claimable clock above) and
separately tells the relay (`POST /v1/account/delete`, challenge-signed) to drop the
directory records, mailboxes, queued messages, and push subscriptions — including
former-username alias mailboxes, but only those whose record carries the *same signing
key*, so the signature can never widen deletion to someone else's mailbox.

### 2. The log cannot be rewritten

* **Inclusion proof** (`/kt/proof/{hash}`): proves a binding really is in the tree.
* **Consistency proof** (`/kt/consistency?from=`): proves the tree at a newer size is an
  *append-only extension* of an earlier one — nothing was altered or removed.

A client that pinned an earlier tree head can demand a consistency proof and detect any
rewrite of history.

### 3. The log cannot equivocate

Tree heads are **signed** by the server's KT key (`SignedTreeHead`, Ed25519), and clients
**gossip** them (`kt_log::check_heads`, `Client::advance_witness` / `compare_foreign_head`):

* **Over time (self-witness):** each client remembers the last head it accepted and
  requires every new head to be a consistent, append-only continuation. A server that
  rolls back or forks the log *against one client* is caught.
* **Across clients:** two people compare the heads they were each shown. If the server
  signed two conflicting histories (a split view), the heads collide — same size, different
  root, or a consistency proof that fails to verify — which is non-repudiable proof of
  equivocation.

## What the client enforces (`crypto-core/src/kt.rs`)

Before starting a session with a contact, `verify_contact_binding`:

1. checks the `SignedTreeHead` is signed by the **pinned** KT key (shipped out-of-band),
2. verifies the inclusion proof for the contact's entry,
3. checks the entry is for the expected username, and
4. checks the entry's `identity_key` equals the key in the fetched bundle.

Any failure returns a specific `KtCheck` (`BadTreeHead` / `NotInLog` / `WrongUsername` /
`KeyMismatch`) and the client refuses to start the session.

## The pinned key

Trust is rooted in one value: the server's KT **public key**, distributed out-of-band
(baked into the client build / shipped through a second channel). `/kt/pubkey` exists only
for first-run bootstrap — trusting it blindly would defeat the point, so it must be
confirmed independently. For a self-hosted instance you pin your own server's key.

## Safety numbers (the last line)

Even if everything above failed, two people can compare a **60-digit safety number**
derived from both identity keys (`crypto-core::kt::safety_number`) over any trusted
channel (in person, a voice call). It is symmetric (both compute the same value) and
changes if either key changes. This is the zero-server-trust verification of last resort,
exactly like Signal's safety numbers.

## Threats not yet covered

* **Gossip transport** — heads are now carried in-band (`Client::send_head` →
  `InboundEvent::PeerHead` → `compare_foreign_head`). What remains is *policy*: how often
  clients gossip and how an alarm is surfaced to the user.
* **First *inbound* contact** — verification is enforced on the outbound path (you look up
  a username and verify its key). A message from a brand-new sender is attributed by key,
  not name; confirm via safety number before trusting it as a particular person.
