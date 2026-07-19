# Deploying a Sona relay

How to self-host the relay, keep its keys where they belong, and let others audit you.
Everything here follows from one stance: **the server is untrusted by design** — so
operating it well is mostly about not leaking metadata and not losing keys, because the
relay holds nothing readable to begin with.

## What you are running

* **`sona-relay`** — the blind relay (Axum, port 5002, plain HTTP/WS). It stores:
  pre-key bundles (public material), the public KT log, and AEAD-encrypted queued
  messages addressed by recipient hash. No plaintext, no usernames, no passwords, no
  social graph.
* **`sona-auditor`** *(optional but encouraged, on a different machine)* — witnesses
  your KT log so your users don't have to take your honesty on faith.
* **A reverse proxy** (Caddy here) — terminates TLS/`wss://`. The relay itself never
  speaks TLS.

## The three secrets

Generate each with `head -c 32 /dev/urandom | base64 | tr -d '='`:

| Variable | Role | If lost | If leaked |
|---|---|---|---|
| `KT_SIGNING_KEY` | signs the Key Transparency log | every client's pinned key breaks — effectively a new server identity | attacker can sign forged tree heads (auditors + client gossip will still catch equivocation, but don't) |
| `STORAGE_KEY` | encrypts queued message blobs at rest | undelivered queued messages are unreadable and dropped; nothing else | a stolen *database* becomes readable as ciphertext+metadata (content is still E2EE) |
| `RATE_SALT` | pseudonymizes rate-limit bookkeeping | nothing — rotate freely | mild: rate-limit keys become linkable |

**The rule that matters: `STORAGE_KEY` lives OFF the data disk.** The env file / secrets
manager satisfies this; storing it inside the database volume defeats the design.
Back up `KT_SIGNING_KEY` offline (printed copy, password manager) — it is the one
thing you cannot regenerate.

Optional: `GIPHY_API_KEY` enables GIF search. The relay proxies both the search and
the GIF bytes (strict host allowlist, size-capped), so client IPs and queries never
reach Giphy; the chosen GIF travels on as an ordinary E2E-encrypted attachment. Unset
= endpoints off, clients hide the GIF UI. On a systemd install this goes in
`/etc/sona/relay.env` (the unit's `EnvironmentFile`), then `systemctl restart
sona-relay`.

## FCM push wakes (optional)

Enables the Android "Push only" / "Connection + push fallback" delivery modes: when a
message is queued for an offline mailbox with a registered `fcm:<token>` endpoint, the
relay sends a **content-free, data-only** FCM message (`{"t":"m"}` or `{"t":"c"}` —
wake class only; see `docs/THREAT_MODEL.md` for the exact metadata cost). Without this
config the relay refuses `fcm:` registrations, does not advertise `push-fcm-v1`, and
the client UI hides the modes; webhook (UnifiedPush-shaped) push works regardless.

1. Create a Firebase project (Messaging only — no analytics, no google-services.json
   ever enters the repo or the APK).
2. Project settings → Service accounts → generate a private-key JSON.
3. On the relay:

```
FCM_SERVICE_ACCOUNT_JSON_FILE=/etc/sona/fcm-service-account.json   # chmod 600
# or inline: FCM_SERVICE_ACCOUNT_JSON='{"type":"service_account",...}'
# optional override (defaults to the JSON's project_id): FCM_PROJECT_ID=my-project
```

4. Build the APK with the client-side Firebase identifiers (Project settings →
   General → your Android app), injected as env vars at build time — they are public
   identifiers, not secrets, but keeping them out of the repo keeps builds
   reproducible byte-for-byte without them:

```
SONA_FCM_PROJECT=my-project SONA_FCM_APP_ID=1:1234567890:android:abcdef SONA_FCM_API_KEY=AIza... SONA_FCM_SENDER=1234567890 cargo tauri android build ...
```

Wake pacing knobs (defaults are fine): `WAKE_DEBOUNCE_SECS` (message-class, 30) and
`CALL_WAKE_MIN_SECS` (call-class, 2).

## Docker (recommended)

```sh
cd deploy
cp sona.env.example sona.env   # fill in the three generated secrets
chmod 600 sona.env
DOMAIN=relay.example.org docker compose up -d
```

That starts the relay (durable SQLite in a named volume, `PROD=1`, origin-checked),
Caddy (automatic Let's Encrypt for `$DOMAIN`, proxies HTTP + WebSocket), and a
same-host auditor. Point clients at `https://relay.example.org` and give them the KT
public key printed on first boot (`docker compose logs relay | grep 'KT'`).

The container build is **reproducible**: publish your commit hash and
`sha256sum /usr/local/bin/sona-relay`, and anyone can rebuild and confirm you run the
audited source — see `REPRODUCIBLE_BUILDS.md` and `deploy/verify-reproducible.sh`.

## Bare metal (systemd)

```sh
cargo build --release -p server -p auditor
install -m 755 target/release/server /usr/local/bin/sona-relay
mkdir -p /etc/sona && install -m 600 deploy/sona.env /etc/sona/relay.env
install -m 644 deploy/sona-relay.service /etc/systemd/system/
systemctl enable --now sona-relay
```

The unit runs with `DynamicUser` + a locked-down sandbox (`ProtectSystem=strict`,
syscall filter, no home access); state lives in `/var/lib/sona`. Put Caddy or nginx in
front of `127.0.0.1:5002` for TLS — for nginx remember WebSocket headers (`Upgrade`,
`Connection`) on `/v1/ws`.

Set `ALLOWED_ORIGINS=https://your-domain` in the env file: with `PROD=1` the relay
enforces WebSocket `Origin` checks against it.

**QUIC media (lower call latency):** the relay also binds `udp/4443` (override with
`QUIC_PORT`, disable with `QUIC_PORT=0`). Open that UDP port in your firewall and
forward it **directly to the relay** — do *not* route it through the proxy (Caddy and
nginx proxy TCP/HTTP; this is a bespoke QUIC endpoint, and its TLS is a boot-time
self-signed certificate that clients pin via `GET /v1/call/quic`). If the port is
unreachable, calls silently use the WebSocket path — video/voice still work, just
with TCP's head-of-line blocking on lossy links.

## Private relays (ACCESS_MODE)

By default anyone who finds your relay can use it. If you run it for a closed circle,
`ACCESS_MODE` changes the posture:

* **`open`** (default) — public relay, today's behavior.
* **`token`** — every request (REST *and* WebSocket upgrade) must carry a shared access
  token in the `x-sona-access` header; anything else gets `401`. Set the token(s) in
  `RELAY_ACCESS_TOKENS` and hand them to members with the relay URL — the client's
  connect screen has an "Access token" field under **Advanced**.
* **`stealth`** — like `token`, but every rejected request is answered with a bare,
  empty `404`, byte-identical to the relay's answer for any unknown path. A scanner
  (or a scraper sweeping the internet for Sona's now-public endpoint shapes) cannot
  distinguish your host from a web server with nothing on it. Stealth also disables
  the QUIC media port — a QUIC handshake would answer probes before any token check —
  so calls use the (token-gated) WebSocket media path.

The gate is the outermost layer in the relay: a rejected request never reaches routing,
JSON parsing, or the KT log. If a vulnerability is ever found in any of those, a private
relay is unreachable for whoever doesn't hold the token — that containment, not the
secrecy itself, is the main value.

**Why one shared token instead of per-user credentials:** sealed sender. Message
submission is deliberately unauthenticated so the relay cannot learn who talks to whom;
a per-user credential on every request would attribute every send and quietly destroy
that property. One shared token keeps members mutually indistinguishable. The trade-off:
evicting someone means rotating the token — `RELAY_ACCESS_TOKENS` takes a comma-separated
list so the old and new token can overlap while members migrate.

**Inviting members.** The desktop/mobile app generates an invite QR (Settings → the QR
button next to the relay address — it appears only when the relay is private): one scan
on the new member's connect screen fills the relay address, the access token, and the
pinned KT key. The same invite works as pasteable text.

**Invite-gated registration (`REGISTRATION_CODES`).** Independent of the access mode:
a comma-separated list of single-use codes, each admitting exactly one brand-new
account (the client asks for the code at account creation). Rotations, renames, and
linked devices are never gated. Use it when members may reach the relay but you still
want to control who *joins* — every new account grows the permanent KT log. Consumed
codes persist in the database; add fresh ones and restart to invite more people.

**Auditing a private relay** still works — give the auditor the token:
`SONA_ACCESS_TOKEN=<token>` in the `sona-auditor` unit's environment.

Two honest caveats:

* **Certificate Transparency.** Your TLS certificate (and so your hostname) is in the
  public CT logs the moment Let's Encrypt issues it. Stealth hides *what* the host is,
  not *that* it exists. If even the hostname must be unlinkable to Sona, use a name that
  doesn't say "sona", or a wildcard certificate on the parent domain.
* **The strongest tier is not an HTTP feature.** Bind the relay to a WireGuard
  interface (`BIND=<wg-ip>:5002`, no public proxy) and put every member on the VPN:
  the port simply doesn't exist on the public internet. `IP_ALLOWLIST` (comma-separated
  CIDRs, off by default, checked against the proxy's `X-Real-IP`, fail-closed) pairs
  well with that setup; for roaming phones without a VPN it is impractical — addresses
  change constantly.

## Being auditable (do not skip)

Your users' protection against *you* (or whoever coerces you) is the KT log — but only
if someone independent watches it. Ask a friend, or run it yourself on an unrelated
machine/provider:

```sh
install -m 755 target/release/sona-auditor /usr/local/bin/
install -m 644 deploy/sona-auditor.service /etc/systemd/system/
systemctl edit sona-auditor   # set SONA_RELAY_URL + (ideally) SONA_KT_PUBKEY
systemctl enable --now sona-auditor
```

Every ~5 minutes it verifies your log only ever grew. If your relay ever serves a
rewritten, rolled-back, or forked log, the auditor writes an evidence file containing
two conflicting heads signed by your key — proof anyone can check. Publish your KT
public key so third parties can run auditors you don't control; that is a feature.

**Operator warning about restores:** restoring the relay database from a backup rolls
the KT log back — auditors and clients will (correctly) treat that as misbehavior.
Back up continuously (see below) and treat KT-log restore as an incident, not routine.

## Backups

* **Back up**: the SQLite file (`DB_PATH`, snapshot while stopped or via `.backup`) and
  `KT_SIGNING_KEY` (separately, offline).
* **Keep apart**: `STORAGE_KEY` never goes in the same backup as the database — that
  pairing is exactly what the at-rest encryption exists to prevent.
* A lost database loses queued (undelivered) messages and the KT log history; message
  history was never on the server to lose.

## What the logs show

The relay itself logs no usernames, no message content, and **no IP addresses** — the
only place a client identifier is even touched is the in-memory rate limiter, which
keys on a salted hash and forgets everything on restart. Nothing IP-shaped is ever
written to the database or to stdout.

**But your reverse proxy logs IPs by default.** nginx's default `access_log` and
Caddy's default JSON logs record every client IP with a timestamp — including every
call-room join (`/v1/call/{id}`), which turns "the relay cannot link calls to people"
into "the proxy wrote who talked to it and when" sitting in a plaintext file. Turn it
off:

```nginx
# nginx — inside the server/location block that proxies Sona
access_log off;
```

```caddyfile
# Caddy — inside your site block (Caddy logs only what you enable, but be explicit)
log {
    output discard
}
```

The bundled `deploy/` Caddy config ships with access logging disabled. IP + timing at
the wire is the residual metadata this design can't remove (see `THREAT_MODEL.md`) —
the point is to not *retain* it. Logging less is a gift to your users.

## Client updates (the operator's update channel)

Clients update from a channel *you* serve — static, pre-signed files under `/apt`
(a real apt repository for the Linux deb; GPG-signed `InRelease`) and `/updates`
(a minisign-signed `manifest.json` plus the Windows installer and Android APK). The
signing keys live only on the operator's machine (`~/.config/sona-release/`): the
server can go down or rogue and clients still refuse anything that doesn't verify.
Manifests at or below the installed version are ignored (downgrade/replay-proof), and
Android additionally gets the platform's same-signer + rising-versionCode rules.

Setup and the per-release flow (`build.sh release` → `deploy/publish-updates.sh`) are
in `deploy/RUNBOOK.md`. The channel URL and public key are baked into the client
binaries at build time from `clients/desktop/.env.update`; builds without that file
simply have in-app updates disabled. Back up `~/.config/sona-release/` offline — a
lost key means shipped clients will reject every future update.
