# Sona — Architecture & Design

> Status: **shipped end-to-end** — backend, client SDK, and the full Tauri app
> (Windows/Linux/Android): chats, groups (admin-model epochs), voice/video/group calls,
> multi-device, message requests, disappearing messages, push delivery, Tor routing.
> Decisions below are locked (see §14). This doc is the design contract; the live,
> code-accurate detail lives in `docs/` (PROTOCOL, KEY_TRANSPARENCY, THREAT_MODEL,
> GROUPS, MULTI_DEVICE, NOTIFICATIONS, …).
> Guiding rule: **author as little crypto as possible.** Every primitive we write
> ourselves is a liability. We glue vetted components and get the result audited.

---

## 0. Goals & non-goals

**Goals**
- End-to-end encrypted 1:1 and groups (groups shipped as pairwise fan-out over
  admin-signed membership epochs — see `docs/GROUPS.md`).
- Multi-platform: **Android, Windows, Linux** (no iOS). (Web deferred — see §9.)
- Self-hosted; anonymous accounts (username + password, no phone number).
- Maximally secure under an **untrusted-server** threat model.
- Forward secrecy + post-compromise security.
- **Authenticated key distribution** — close the first-contact MITM gap that TOFU leaves open.
- Metadata minimization (server learns as little as possible about who talks to whom).
- One audited crypto core shared by every platform.

**Non-goals (v1)**
- Tor-grade sender anonymity as a *built-in* (we minimize metadata; network identity can
  be hidden by routing the client through Tor/Orbot via the shipped SOCKS5 proxy support,
  but we don't run our own mixnet).
- Defending a fully compromised endpoint (we limit blast radius via PCS; we don't pretend a rooted phone is safe).
- Federation / multiple servers (single trust domain v1).
- Web client as a primary surface (weakest E2EE surface — see §9).

---

## 1. Core decisions (the short version)

| Concern | Decision | Why |
|---|---|---|
| Messaging protocol | **Double Ratchet via vodozemac (Olm)** | Audited (Least Authority 2022), published on crates.io, maintained. Same guarantees as Signal's ratchet (forward secrecy + post-compromise security). Chosen over the two candidates we evaluated: official **libsignal** is "unsupported outside Signal" + unstable API + not on crates.io; **MLS/OpenMLS** was the other option but vodozemac is the proven, cleanly embeddable pick for 1:1. Groups shipped as pairwise fan-out over these same sessions (`docs/GROUPS.md`) — no shared group key, nothing new for the relay to see. |
| Directory trust | **Key Transparency** (append-only RFC 6962 Merkle log via `ct-merkle`) + **out-of-band safety numbers** | The SOTA fix for "untrusted server hands you a fake key." See §4. |
| Crypto core | **Rust**, one crate (`crypto-core`), embedded directly in every client | Write the hard part once, audit once. `zeroize` + `subtle` for hygiene. |
| Client stack | **Tauri 2** — one Rust + web codebase → **Windows, Linux, Android** | No iOS. The crypto core is embedded directly (no FFI hop). Replaces the earlier native+UniFFI plan, which only existed for iOS's Secure Enclave; with iOS dropped, one Tauri codebase covers all targets. All client logic lives in a headless `client-core` crate that the Tauri shell wraps (and that is unit-tested without a GUI). |
| Server / relay | **Rust** (Axum) | Blind relay. **No Go anywhere.** |
| At-rest vault | Argon2id KDF + XChaCha20-Poly1305 AEAD | Standard AEAD, memory-hard KDF. |
| Durable storage | SQLite; message blobs AEAD-encrypted under a key held **off the data disk** | Survives restart without weakening the zero-knowledge stance — see §5 / `docs/PROTOCOL.md`. |

---

## 2. System overview

```
        ┌─────────────┐        ┌─────────────┐        ┌─────────────┐
        │   Client A  │        │   Client B  │        │   Client C  │
        │  (Android/  │        │  (desktop)  │        │   (...)     │
        │   desktop)  │        │             │        │             │
        │ ┌─────────┐ │        │ ┌─────────┐ │        │             │
        │ │crypto-  │ │        │ │crypto-  │ │        │             │
        │ │ core    │ │        │ │ core    │ │        │             │
        │ └─────────┘ │        │ └─────────┘ │        │             │
        └──────┬──────┘        └──────┬──────┘        └──────┬──────┘
               │  opaque ciphertext, hash-addressed only     │
               ▼                      ▼                      ▼
   ┌───────────────────────────────────────────────────────────────┐
   │                      SERVER (untrusted)                        │
   │  ┌───────────┐  ┌──────────────┐  ┌───────────┐  ┌──────────┐  │
   │  │ WS gateway│  │ KeyPackage / │  │ Offline   │  │ Push     │  │
   │  │ (relay)   │  │ bundle store │  │ queue     │  │ fan-out  │  │
   │  └───────────┘  └──────────────┘  └───────────┘  └──────────┘  │
   └───────────────────────────────┬───────────────────────────────┘
                                    │ append + audit
                                    ▼
                       ┌────────────────────────┐
                       │  Key Transparency log   │
                       │  (append-only Merkle)   │
                       └────────────────────────┘
```

The server is a **blind delivery service**. It never sees plaintext, and with sealed
sender (§5) it doesn't reliably learn the sender of a message either. It cannot
forge a key binding without being **caught** by the KT log.

---

## 3. Components in detail

### 3.1 `crypto-core` (Rust)
The only place secrets live. Everything else is a dumb shell around it.

Responsibilities:
- **Vault** — identity key material at rest. Argon2id(password) → wrapping key →
  XChaCha20-Poly1305 over the identity blob. Where an OS keyring is available the vault
  is **device-bound** (format v2, implemented): HKDF mixes a keyring-held random device
  key into the wrapping key (`client-core::devicekey`, Linux Secret Service / Windows
  Credential Manager; Android Keystore on Android — implemented), so the on-disk blob is useless
  off-device — no offline password brute force from the blob alone. The Argon2id run
  happens **once per unlock**: the derived wrapping key is cached in the unlocked
  `Account` (`Account::reseal`), so the per-message vault re-seal is cheap and the
  password never stays in memory.
- **Ratchet engine** — wraps vodozemac (Olm). Identity keys, one-time keys, session
  establishment, encrypt/decrypt (including sealed-sender *unattributed* decrypt), state export/import.
- **Pre-key bundle management** — generate, publish, consume one-time keys.
- **Key Transparency client** — mint our entry; verify inclusion/consistency proofs before trusting any key.
- **Safety numbers** — out-of-band identity confirmation (60-digit, symmetric).
- **Local encrypted state** — the ratchet/identity state, sealed in the vault.

Hygiene baked in: `zeroize` on secret buffers, `subtle` for constant-time comparisons.

### 3.2 `client-core` (Rust, in the clients workspace)
The headless client SDK — account lifecycle, KT-verified contact discovery, sealed-sender
messaging, and the relay transport (REST + WebSocket). UI-agnostic, so it is unit-tested
without a GUI and shared by every client shell. (Replaces the old FFI/WASM binding crates:
since clients are Tauri/Rust, `crypto-core` is linked directly — no language boundary.)

### 3.3 Clients
- **Desktop (Windows/Linux)** and **Android** — one **Tauri 2** app. `crypto-core` +
  `client-core` compiled into the Rust backend directly; a thin web UI on top.
- Hardening: Android ships via `clients/desktop/scripts/harden-android.sh` —
  `FLAG_SECURE` (blocks screen capture), `allowBackup=false` + extraction rules,
  accessibility-service warning, StrongBox-preferred Keystore, ARM MTE
  (`memtagMode=sync`); desktop windows set `contentProtected`. See
  `docs/ANDROID_HARDENING.md`. Vault device-binding is live on both: OS keyring on
  desktop, Android Keystore on Android. App auto-lock with a PIN-or-password
  quick-unlock gate is shipped; SOCKS5 proxy support routes the client through
  Tor/Orbot.
- No iOS.

### 3.4 Server (Rust / Axum)
Blind relay. Persists to encrypted SQLite (or in-memory if no `DB_PATH`):
- Pre-key bundles (public key material), addressed by identity hash.
- Offline queue: opaque envelopes, **AEAD-encrypted at rest under an off-disk key**,
  TTL-bounded, deleted on delivery.
- The KT log (public entries, plaintext — auditable by design).

Stores **no passwords** (auth is a signed challenge, not a credential) and **no login
records**. Never stores plaintext, the social graph (sealed sender), or message history
(that lives only on clients).

WS gateway: frame-size limited, rate-limited (fail-**closed**), origin-checked in prod,
hash-addressed delivery. A device revoked from its account's roster is kicked live
(terminal `revoked` frame) and refused at auth thereafter — but a device whose id merely
*moved* in the roster (primary transfer) is not treated as revoked, and clients verify
any `revoked` claim against the KT log before locking out (the frame is unauthenticated;
a hostile relay must not be able to lock a healthy device out).

Optional GIF privacy proxy (`GIPHY_API_KEY`): the relay forwards GIF search and media
so client IPs and queries never reach the provider; a picked GIF is re-sent as a normal
E2E-encrypted attachment (recipients never touch the provider). Strict https host
allowlist + size cap — same SSRF posture as the push-wake endpoint.

### 3.5 Key Transparency service
Append-only Merkle log mapping `identity → current public key(s)`. Clients fetch a
key **plus** a cryptographic proof that (a) it's really in the log (inclusion) and
(b) the log hasn't been rewritten (consistency). Independent auditors gossip log
heads to detect a server that shows different logs to different people (equivocation).
This is what turns "trust the server's directory" into "the server cannot lie about
a key without leaving permanent, detectable evidence." See §4.

---

## 4. The first-contact problem — and the real fix

**Recap of the gap (Bob's question).** A and B exchange *identifiers* (uuid / #tag),
never public keys directly. The server's directory maps identifier → public key. A
malicious server answers the lookup with an **attacker's** key. Both sides TOFU-trust
it. No key ever "changes," so change-detection never fires. The server sits in the
middle decrypting and re-encrypting. The #tag doesn't help — it's a *discovery handle*,
not a commitment to a specific public key.

**Three layers of defense, strongest first:**

1. **Key Transparency (primary, automatic).**
   Every identity→key binding is published into an append-only verifiable log. When A
   fetches B's key, A also gets a proof of inclusion + consistency. A malicious server
   *can* still hand A a fake key — but to do so it must enter that fake key into the
   public log, where B's own client (and auditors) will see "there's a key for B that
   B never published." Equivocation (showing A a different log than B) is caught by
   auditor gossip. Result: silent MITM becomes **loud and provable**. This is what
   Apple Contact Key Verification, Google/WhatsApp Key Transparency, and CONIKS all do.

2. **Out-of-band verification (gold standard, user-driven).**
   QR scan in person or safety-number read-aloud over a trusted channel. Confirms the
   key with zero trust in the server. We **surface and encourage** it (not bury it like
   Bob's silent auto-trust), and mark conversations "verified" vs "not yet verified."

3. **Change alerts that keep the human in the loop (replaces auto-unfriend).**
   When a peer's key changes mid-relationship: **warn, pause, ask to re-verify** — do
   *not* silently unfriend-and-re-handshake. As established: auto-unfriend + auto-re-add
   walks the user straight back into the attacker's swapped key. A warning stops them.

**On Bob's auto-unfriend, resolved:** keep it *only* as a user-chosen action on the
warning screen, reversible by re-verifying. New-account / lost-password cases (genuine
new identity) flow through the same warning and a one-tap "re-add." Reinstall-with-vault
changes no key, so nothing fires. Active MITM gets caught by KT and/or the warning.

---

## 5. Metadata minimization

- **Sealed sender** — the sender's identity is encrypted to the recipient, not exposed
  to the server. Server routes on the recipient hash only; it can't build the social graph.
- **Hash-only addressing** — server holds `H(identity)`, never the raw identity. Fail-closed
  integrity check rejects any frame carrying a raw identifier (keep Bob's ZK check, both edge + app).
- **Decoupled push** *(implemented end-to-end)* — a registered push endpoint gets a
  constant content-free wake when the offline mailbox receives a message; the client
  pulls the ciphertext over the authenticated channel. Push providers learn nothing
  but timing plus ONE sender-declared coarse bit, the **wake class**
  (`none`/`normal`/`call` on the envelope): `none` never wakes (receipts, typing,
  self-sync), `normal` is debounced (chat messages), `call` wakes immediately under
  its own tiny anti-flood interval so calls ring through Doze. That single bit is
  strictly less than Signal's per-envelope `urgent` flag + push payload (Signal ships
  the sealed envelope bytes *through* FCM; Sona ships a constant). Two transports:
  any HTTPS webhook (the UnifiedPush shape, SSRF-filtered), or `fcm:<token>` when the
  relay is configured with a Firebase service account (data-only `{"t":"m"|"c"}`,
  never a `notification:` payload — display happens locally, post-decrypt).
  Registration is challenge-signed per mailbox (a linked device registers its device
  mailbox; nobody can subscribe to another user's message *timing*), endpoints stored
  encrypted at rest, dead FCM tokens self-purge. On Android the user picks the mode:
  **Connection** (persistent socket, Google-free, default), **Push only**, or
  **Connection + push fallback** (the relay wakes only when it sees no live
  subscriber, so pushes fire exactly when the socket is dead — self-healing).
- **Padding** — pad ciphertext to fixed buckets to blunt length-based traffic analysis.
- **Per-device leaves, not a shared key** — see §6: one device's compromise doesn't expose others.

---

## 6. Multi-device — *built* (`docs/MULTI_DEVICE.md`)

Signal-style linking, shipped. The founding principle held: **no long-term key is shared
across devices** — each device has its own identity and runs its own Olm sessions with
each contact; one device's compromise never exposes another's history. Adding a device is
authorized by an existing device (QR link with hardware-key attestation on Android), not
the server; the account's device roster is a signed, append-only epoch chain published in
the KT log, so a relay cannot invent or hide a device. History sync is an explicit,
E2E-encrypted, password-gated channel; primary transfer and revocation are first-class
(revocation claims are verified against KT — a hostile relay's unauthenticated `revoked`
frame can't lock a healthy device out). Calls ring on all devices; first answer wins.

---

## 7. Threat model (summary — full version in `docs/THREAT_MODEL.md`)

| Adversary | Capability | Our defense |
|---|---|---|
| Honest-but-curious server | reads everything it stores | E2EE; server holds only ciphertext + hashes |
| Malicious server | forges keys, drops/reorders, equivocates | Key Transparency + OOB verification + sealed sender |
| Network attacker | intercepts/modifies traffic | TLS; ratchet integrity under that; non-replayable signed auth |
| Server disk / backup theft | reads the relay DB at rest | message blobs AEAD-encrypted under an off-disk key; content was E2E anyway; only recipient hashes + timing remain |
| Client device thief | offline access to a client's disk | Argon2id vault + secure-element wrap + backup exclusion + auto-lock |
| Metadata adversary | watches who-talks-to-whom | sealed sender, hash routing, content-free push, length padding, optional Tor routing |
| Endpoint compromise | reads live secrets | out of scope to *prevent*; PCS bounds the damage window |

---

## 8. Security properties we commit to

- **Confidentiality + integrity** — Olm AEAD (vodozemac).
- **Forward secrecy** — past messages safe after a key compromise (the ratchet).
- **Post-compromise security** — future messages recover after a compromise heals.
- **Authenticated key distribution** — KT + out-of-band safety numbers. *The headline upgrade over plain TOFU.*
- **At-rest protection** — Argon2id + AEAD vault (client); AEAD-encrypted, off-disk-keyed storage (server).
- **Metadata minimization** — sealed sender + hash routing + content-free push + length padding.
- **No self-authored primitives** — vodozemac / ct-merkle / ed25519-dalek / RustCrypto only.

---

## 9. Web client — why deferred

Web is the weakest E2EE surface and it's worth saying why out loud:
- No OS-backed secure key storage (IndexedDB is readable).
- The **server ships the code on every load** — it can serve malicious JS at any time,
  defeating E2EE silently. (Native apps are signed + reviewed; the binary is fixed.)
- Larger XSS / supply-chain surface.

If we ever do web: WASM core, **subresource integrity + reproducible builds**, and a
loud "linked device, lower assurance" label. Not a v1 surface.

---

## 10. Repo layout (monorepo)

**Two Cargo workspaces** in one repo, so an Android build never tries to cross-compile the
server's native stack. Shared crates are pulled into the client workspace by relative path.

```
sona/                   # backend workspace (Cargo.toml: members = crates/*, exclude = clients)
├── crates/
│   ├── protocol-types/       # shared wire types (serde): IdentityHash, Envelope, PreKeyBundle, …
│   ├── crypto-core/          # vault, vodozemac ratchet, KT client, safety numbers
│   ├── kt-log/               # Key Transparency: RFC 6962 Merkle log, entries, STHs, proofs,
│   │                         #   device-roster epochs, group-membership epochs (group.rs)
│   ├── auditor/              # standalone KT witness daemon (sona-auditor): third parties
│   │                         #   poll a relay, verify append-only growth, dump evidence on violation
│   └── server/               # Axum blind relay: http/ (per-surface handlers), ws + call rooms,
│                             #   QUIC media, access gate (tiers), push fan-out, encrypted SQLite
├── clients/                  # SEPARATE workspace (clients/Cargo.toml)
│   ├── client-core/          # headless client SDK — api/ (commands), history/ (E2E state
│   │                         #   machine), multidevice/, wire/ (payloads), calls, media
│   └── desktop/              # Tauri 2 app (Windows/Linux/Android); thin shell over client-core
│       ├── src-tauri/        # Rust shell: cmd/ (Tauri commands), call/, delivery engine,
│       │                     #   Android bridges (audio, push, keystore, attestation)
│       └── src/              # static web UI: js/ (ordered modules, no bundler), vendor/
├── docs/                     # PROTOCOL · KEY_TRANSPARENCY · THREAT_MODEL · GROUPS ·
│                             #   MULTI_DEVICE · NOTIFICATIONS(+TESTING) · DEPLOYMENT ·
│                             #   ANDROID_HARDENING · REPRODUCIBLE_BUILDS
├── deploy/                   # Dockerfile · compose + Caddy · systemd units · repro verify
├── fuzz/                     # libFuzzer targets on every attacker-reachable parser
├── scripts/                  # check.sh (local CI mirror) · no-monolith.sh (file-size ratchet)
└── README.md                 # (ARCHITECTURE.md — this file — sits at the repo root)
```

---

## 11. Build & supply-chain pipeline

- `crypto-core` is compiled directly into each client (Tauri embeds it; no FFI/WASM step).
- CI (`.github/workflows/ci.yml`): `cargo test`, `clippy -D warnings`, `cargo fmt --check`,
  **`cargo audit`** (known CVEs), **`cargo deny`** (license + dependency policy, see
  `deny.toml`) — across both workspaces on every push/PR — plus a **smoke-fuzz** job.
- **Fuzzing** (`fuzz/`): libFuzzer targets on every parser that touches attacker bytes —
  the wire envelope + identity hash (`envelope`), KT proof/head decoders a malicious
  server controls (`kt_proofs`), KT entries POSTed to /register (`kt_entry`), and the
  at-rest vault/localbox blobs (`vault_open`). `cargo +nightly fuzz run <target>`.
  First session found a real one: a malformed inclusion proof from the server could
  panic (crash) a verifying client via `ct-merkle::from_bytes` — now fails closed.
- **Reproducible builds** (server + auditor: done; clients: with the GUI phase) — exact
  toolchain pin, `--locked` deps, fixed-path container build with path remapping;
  `deploy/verify-reproducible.sh` double-builds and diffs binary hashes. See
  `docs/REPRODUCIBLE_BUILDS.md`.
- Dependency policy: vetted crypto only (vodozemac, ct-merkle, ed25519-dalek, RustCrypto).
  New crypto deps require explicit review.

---

## 12. Roadmap (phased — each phase shippable/testable)

- **Phase 1 — crypto-core.** ✅ Vault (Argon2id + AEAD) + Double Ratchet (vodozemac Olm) 1:1, with persistence round-trip.
- **Phase 2 — Server.** ✅ Axum relay, bundle store, offline queue, hash routing, Ed25519 challenge auth, sealed sender, fail-closed limits.
- **Phase 3 — Key Transparency.** ✅ `kt-log` (Merkle log, entries, STHs, inclusion + consistency proofs); server endpoints; client verification + safety numbers.
- **Phase 4 — Client SDK.** ✅ `client-core`: account lifecycle, KT-verified discovery, sealed-sender send, authenticated inbox — end-to-end tested against the real relay.
- **Phase 5 — Durable storage.** ✅ Encrypted-at-rest SQLite (off-disk key); survives restart (tested).
- **Phase 6 — GUI.** ✅ Tauri 2 app (Windows/Linux/Android) over `client-core`: full UI — chats, voice/video calls, groups, settings, vault unlock.
- **Phase 7 — Hardening.** ✅ Security audit completed and findings remediated; message padding; OTK replenishment; KT gossip/auditor; OS-keystore vault binding; reproducible builds.
- **Beyond the plan (all shipped):** groups with admin-signed membership epochs + content
  quarantine (`docs/GROUPS.md`); Signal-style multi-device with KT device rosters,
  QR linking, hardware attestation, primary transfer (`docs/MULTI_DEVICE.md`); voice,
  video, screen-share, and mesh group calls over blind relay rooms (WS + QUIC);
  headless delivery engine, native ring, UnifiedPush/FCM wake-class push
  (`docs/NOTIFICATIONS.md`); message requests; disappearing messages; username rename +
  release/takeover; account deletion; relay access tiers (open/token/stealth);
  SOCKS5/Tor routing; GrapheneOS-grade Android hardening (StrongBox, MTE —
  `docs/ANDROID_HARDENING.md`).

Test status: **1,108 tests green** (175 backend + 933 client), clippy clean across both
workspaces, fmt-gated CI, plus a no-monolith file-size ratchet.

---

## 13. Kept-from-Bob / changed-from-Bob

**Kept (he got these right):**
Argon2id vault · at-rest AEAD · blind hash routing · fail-closed integrity checks ·
forward secrecy on the offline queue · native backup exclusion · memory zeroization ·
auto-lock · safety numbers as a concept.

**Changed (the upgrades):**
audited vodozemac ratchet instead of hand-wired Olm/Signal glue · **Key Transparency** to
fix first-contact TOFU · enforced/encouraged verification instead of silent auto-trust ·
warn-and-verify instead of silent auto-unfriend · per-device identities instead of a
shared vault key (planned, §6) · sealed sender for metadata · fail-**closed** rate
limiting · encrypted-at-rest storage with an off-disk key · no self-authored crypto.

---

## 14. Decisions (resolved)

These were the open questions; all are now locked.

1. **Client stack** — one **Tauri 2** codebase for Windows/Linux/Android. No iOS, no
   React Native. (Killed the native+UniFFI plan, which existed only for iOS.)
2. **Ratchet library** — **vodozemac** (audited Olm). Not libsignal (unsupported for
   external use), not MLS (vodozemac is the cleaner embeddable pick for 1:1).
3. **1:1 first**, groups later — since shipped, as pairwise fan-out with admin-signed
   membership epochs (`docs/GROUPS.md`).
4. **Key Transparency — build our own** (`kt-log`), on top of the vetted `ct-merkle`
   Merkle-log crate.
5. **Account model — anonymous**: username + password only, no email/phone. Usernames are
   first-come, claimed permanently in the KT log.
```
