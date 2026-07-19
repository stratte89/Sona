<div align="center">

<img src="assets/sona-icon.png" alt="Sona" width="140" height="140" />

# Sona

### The messenger where the guards are locked outside.

*End-to-end encrypted. Anonymous. Self-hosted. Built so the server **can't** betray you —
not because it promises not to, but because it has no way in.*

</div>

---

## The name

In *Prison Break*, **Sona** is the prison the government gave up on. They pulled every
guard out, sealed the walls, and let the inmates run everything inside. The guards still
ringed the perimeter — but they had **no eyes, no reach, no power** within.

That's the architecture. **The server is the guard outside the wall.** It moves opaque
ciphertext across the perimeter and nothing more: it can't read what crosses, can't see
who's talking to whom, and can't forge its way in without leaving public, provable
evidence. Its ignorance isn't a policy you have to trust. It's the structure.

**Security by inability, not by good faith.**

## What the guard cannot do

| The server **cannot…** | …because |
|---|---|
| read messages | E2E encryption (audited Olm Double Ratchet); it only ever holds ciphertext |
| learn who talks to whom | **sealed sender** — envelopes name only a one-way hash of the recipient |
| hand out a fake key | **Key Transparency** — every key lives in a public, append-only, signed Merkle log; forgery is loud and provable |
| see who's in a group — or that a group exists | groups are pairwise fan-out with admin-**signed** membership epochs, indistinguishable from 1:1 traffic |
| identify you | anonymous accounts — username + password; no phone number, no email |
| betray you under subpoena or breach | nothing readable to give: no plaintext, no social graph, no passwords; storage encrypted under an off-disk key |
| learn your IP, if you choose | built-in SOCKS5 routing through Tor/Orbot |

The honest floor — what a store-and-forward relay irreducibly learns — is stated
plainly in the [threat model](docs/THREAT_MODEL.md). We don't pretend otherwise.

## What's inside the walls

Everything a modern messenger does, all end-to-end encrypted, on **Windows, Linux, and
Android** from one Rust codebase:

**Chats** — groups with cryptographic admin control, disappearing messages, message
requests (strangers knock first), edits, reactions, pins, replies, @mentions,
forwarding, voice notes, media galleries, GIFs via a privacy proxy, global search.
**Calls** — voice, video, and screen share over blind relay rooms (WebSocket + QUIC);
group calls as a mesh the relay can't tell from 1:1 calls.
**Multi-device** — Signal-style linking with QR + hardware attestation, KT-published
device rosters, primary transfer, encrypted history sync.
**Delivery** — headless engine, native call ring, content-free push (UnifiedPush or
FCM) that wakes the device without telling Google anything but timing.
**Hardening** — StrongBox keystore, ARM MTE, screen-capture blocking, reproducible
builds, fuzzed parsers, relay access tiers up to a stealth mode that plays dead
without a token.

## Built on things already broken by experts

Sona writes almost no crypto — it glues **audited, published** components and verifies
the seams: [vodozemac](https://github.com/matrix-org/vodozemac) (Matrix's audited Olm
Double Ratchet), [ct-merkle](https://github.com/rozbb/ct-merkle) (RFC 6962, the
construction behind Certificate Transparency), Argon2id + XChaCha20-Poly1305, Ed25519.
One Rust crypto core, compiled directly into every client.

**1,108 tests green** (175 backend + 933 client), clippy-clean, fmt-gated, fuzzed,
security-audited with every finding remediated.

## The docs

| Doc | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | the design contract — every locked decision and why |
| [PROTOCOL.md](docs/PROTOCOL.md) | the wire, as implemented: endpoints, payloads, calls, padding |
| [KEY_TRANSPARENCY.md](docs/KEY_TRANSPARENCY.md) | how a lying server gets caught: the Merkle log, proofs, safety numbers |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | adversaries, defenses, and the honest limits |
| [GROUPS.md](docs/GROUPS.md) | invisible groups: signed membership epochs + content quarantine |
| [MULTI_DEVICE.md](docs/MULTI_DEVICE.md) | linking, device rosters in KT, revocation, history sync |
| [NOTIFICATIONS.md](docs/NOTIFICATIONS.md) | the delivery engine, native ring, and content-free push |
| [NOTIFICATIONS_TESTING.md](docs/NOTIFICATIONS_TESTING.md) | the on-device Doze/OEM-killer test protocol |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | self-hosting: Docker/systemd, the three secrets, access tiers, auditing |
| [ANDROID_HARDENING.md](docs/ANDROID_HARDENING.md) | the mobile attack surface and what's done about it |
| [REPRODUCIBLE_BUILDS.md](docs/REPRODUCIBLE_BUILDS.md) | proving the binary matches the source |
| [clients/README.md](clients/README.md) | building the desktop and Android apps |

## Quickstart

```sh
# Run the relay (prints the Key-Transparency key to pin + the storage seed to persist)
DB_PATH=sona.sqlite cargo run -p server

# Run the whole test suite
cargo test                       # backend
cd clients && cargo test         # client SDK (spins the real relay up in-process)
```

Self-hosting for real: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
Building the apps: [clients/README.md](clients/README.md).

## Versus Signal

**More private** — no phone number, self-hosted, Key Transparency from day one, groups
the server can't even see, optional Tor routing. **At parity** — Double Ratchet,
sealed sender, safety numbers, multi-device, disappearing messages, calls, audited.
**Behind only in reach** — adoption, not architecture.

---

<div align="center">

**The guards are outside. You're inside. Welcome to Sona.**

</div>
