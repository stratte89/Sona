# Runbook — deploying the relay to a VPS

Concrete companion to the generic `docs/DEPLOYMENT.md`. Placeholders used throughout:
`YOUR-VPS` = your ssh alias (key-only root), `your.relay.domain` = the public DNS name,
`YOUR.VPS.IP` = the box's address. Public URL: **`https://your.relay.domain`**.

## Design in one picture

```
clients ── https://your.relay.domain ─▶ YOUR.VPS.IP   (DNS-only / grey cloud if Cloudflare)
                                        Caddy :443  ──TLS ends HERE──▶ relay 127.0.0.1:5002
                                        :4443/udp   ───────────────▶ relay (QUIC calls)
                                        /apt /updates ─▶ static update channel (pre-signed)
```

* **No Docker on the VPS.** Relay + auditor run as sandboxed systemd services.
* **TLS terminates on the box** (Caddy + Let's Encrypt). If DNS is on Cloudflare, the
  record MUST stay grey-cloud (Proxied OFF) or ACME breaks and Cloudflare re-enters the wire.
* **Deploys are manual, from your laptop** (`push.sh`, `SONA_SSH_HOST=YOUR-VPS`). No SSH
  key lives in GitHub; CI stays a pure quality gate. A compromised GitHub account cannot
  reach the VPS.
* **Binaries are built in a Debian-bookworm container** so their glibc matches the VPS.
* **The update channel is static files** (`/srv/sona-www`), signed on your laptop by
  `deploy/publish-updates.sh` — the VPS never holds a signing key.

## Prerequisites

* Laptop: `docker` + a working `ssh YOUR-VPS` alias.
* DNS: `A  your.relay.domain → YOUR.VPS.IP`, grey cloud if Cloudflare.

## One-time setup

0. **Write your operator config** (gitignored; every deploy script reads it):

   ```sh
   cat > deploy/.env.publish <<EOF
   SONA_SSH_HOST=YOUR-VPS
   SONA_DOMAIN=your.relay.domain
   SONA_UPDATE_BASE=https://your.relay.domain
   EOF
   ```

1. **Prepare the server** (opens 2 ports, installs Caddy, generates secrets, installs units):

   ```sh
   . deploy/.env.publish && ssh "$SONA_SSH_HOST" "SONA_DOMAIN=$SONA_DOMAIN bash -s" < deploy/bootstrap-vps.sh
   ```

   Re-runnable and non-destructive — it never overwrites an existing `/etc/sona/relay.env`.

2. **Ship the binaries and start it** (from the repo root on your laptop):

   ```sh
   ./deploy/push.sh
   ```

3. **Grab the KT public key** (the pin you distribute to users out-of-band):

   ```sh
   ssh YOUR-VPS 'journalctl -u sona-relay --no-pager | grep -i "KT"'
   # or: curl -sS https://your.relay.domain/v1/kt/pubkey
   ```

4. **Back up `KT_SIGNING_KEY` offline** (password manager / printout). It is the relay's
   identity and the one secret you cannot regenerate:

   ```sh
   ssh YOUR-VPS 'grep KT_SIGNING_KEY /etc/sona/relay.env'
   ```

5. **Point a client at it:** `base_url = https://your.relay.domain`, and pin the KT pubkey
   from step 3.

6. **(Optional) set up the update channel** — generates the two signing keys and prints
   the `.env.update` lines that build.sh bakes into clients:

   ```sh
   ./deploy/publish-updates.sh --init
   ```

## Every subsequent deploy

```sh
./deploy/push.sh                          # build (bookworm container) → scp → atomic swap → restart
```

`--build` builds without touching the VPS; `--clean` drops the container build cache.

## Publishing a client release

```sh
bash .claude/skills/sona-build/build.sh release   # one version bump, builds deb + apk + exe
./deploy/publish-updates.sh                   # sign + assemble apt repo & manifest, rsync
```

Clients then update via Settings → "Check for updates" (Windows/Android) or
`apt upgrade` (Linux, self-enrolled by the deb).

## Verifying it's up

```sh
curl -sS https://your.relay.domain/v1/kt/pubkey        # JSON with the KT key = healthy
ssh YOUR-VPS 'systemctl status sona-relay --no-pager'
ssh YOUR-VPS 'journalctl -u sona-relay -n 50 --no-pager'
```

## Firewall state after setup

`ufw` allows only: `22/tcp` (SSH, unchanged), `443/tcp` (Caddy/TLS), `4443/udp` (QUIC).
Everything else stays default-deny. The relay's HTTP port `5002` is loopback-only.

## Important caveats

* **Grey cloud is load-bearing.** If a Cloudflare record is ever switched to Proxied
  (orange), Let's Encrypt's TLS-ALPN challenge fails AND Cloudflare re-enters the wire and
  starts seeing client IPs. Keep it DNS-only.
* **Independent auditing.** The co-located auditor is a smoke check only. For real
  split-view detection, run `sona-auditor` on a *different* machine with `SONA_KT_PUBKEY`
  set to the pinned key from step 3. See `docs/DEPLOYMENT.md` → "Being auditable".
* **QUIC is best-effort.** If `4443/udp` is blocked anywhere on the path, calls silently
  fall back to WebSocket through Caddy — still E2EE, just higher latency on lossy links.
* **Restores are incidents, not routine.** Restoring the SQLite DB rolls the KT log back;
  auditors and clients treat that as misbehavior. Back up continuously; see DEPLOYMENT.md.
* **Reproducible-build note.** The published `deploy/Dockerfile` builds on Debian *trixie*;
  this bare-metal path builds on *bookworm*, so the shipped binary's `sha256` won't match a
  trixie rebuild. If you want to publish a verifiable hash, either align the Dockerfile to
  bookworm or run the relay under the trixie Docker image instead.

## Rollback

Nothing here is destructive, but to undo:

```sh
ssh YOUR-VPS 'systemctl disable --now sona-relay sona-auditor caddy
              ufw delete allow 443/tcp; ufw delete allow 4443/udp'
# secrets in /etc/sona and the systemd unit files remain until you remove them by hand.
```
