#!/usr/bin/env bash
# One-time server setup for the relay VPS. Self-contained: run it ON the VPS as root.
#
#   SONA_DOMAIN=your.relay.domain ssh YOUR-VPS "SONA_DOMAIN=$SONA_DOMAIN bash -s" < deploy/bootstrap-vps.sh
#   # or, in one shot:
#   SONA_DOMAIN=your.relay.domain ssh YOUR-VPS "SONA_DOMAIN=your.relay.domain bash -s" < deploy/bootstrap-vps.sh
#
# What it does (and does NOT do):
#   * opens ufw 443/tcp + 4443/udp  (leaves 22 and everything else untouched)
#   * installs Caddy from its official apt repo (systemd service) if missing
#   * writes /etc/caddy/Caddyfile for $SONA_DOMAIN  (backs up any existing one)
#   * creates /etc/sona/relay.env with freshly generated secrets, mode 600
#     - NEVER overwrites an existing relay.env (your KT identity is irreplaceable)
#   * installs the sona-relay + sona-auditor systemd units and enables them
#
# It does NOT place the binaries — those come from your laptop via deploy/push.sh. Services
# will sit in "failed/activating" until the first push.sh, which is expected.
#
# Idempotent: safe to re-run. Nothing here deletes data or rotates existing secrets.
set -euo pipefail

DOMAIN="${SONA_DOMAIN:?set SONA_DOMAIN=your.relay.domain when running this script}"
[[ $EUID -eq 0 ]] || { echo "run as root on the VPS" >&2; exit 1; }

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }

# ── 1. firewall ──────────────────────────────────────────────────────────────────────
say "opening ufw 443/tcp (Caddy/TLS) and 4443/udp (QUIC calls); 22 stays as-is"
ufw allow 443/tcp   >/dev/null
ufw allow 4443/udp  >/dev/null
ufw status verbose | sed 's/^/    /'

# ── 2. Caddy ─────────────────────────────────────────────────────────────────────────
if ! command -v caddy >/dev/null; then
	say "installing Caddy from its official apt repo"
	apt-get update -qq
	apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl gnupg
	curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
		| gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
	curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
		> /etc/apt/sources.list.d/caddy-stable.list
	apt-get update -qq
	apt-get install -y -qq caddy
else
	say "Caddy already installed: $(caddy version | head -1)"
fi

say "writing /etc/caddy/Caddyfile for $DOMAIN"
if [[ -f /etc/caddy/Caddyfile ]] && ! grep -q "$DOMAIN" /etc/caddy/Caddyfile; then
	cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%s)"
	say "  backed up the existing Caddyfile"
fi
# Update channel dir (deploy/publish-updates.sh rsyncs here; static pre-signed files).
mkdir -p /srv/sona-www/apt /srv/sona-www/updates
chown -R caddy:caddy /srv/sona-www 2>/dev/null || true
cat > /etc/caddy/Caddyfile <<CADDY
# Managed by deploy/bootstrap-vps.sh — mirrors deploy/Caddyfile.baremetal.
$DOMAIN {
	log {
		output discard
	}
	handle /apt/* {
		root * /srv/sona-www
		file_server
	}
	handle /updates/* {
		root * /srv/sona-www
		file_server
	}
	reverse_proxy 127.0.0.1:5002 {
		header_up X-Real-IP {remote_host}
	}
}
CADDY
systemctl reload caddy 2>/dev/null || systemctl restart caddy
systemctl enable caddy >/dev/null 2>&1 || true

# ── 3. secrets ───────────────────────────────────────────────────────────────────────
mkdir -p /etc/sona
if [[ -f /etc/sona/relay.env ]]; then
	say "/etc/sona/relay.env already exists — leaving it untouched (KT identity is irreplaceable)"
else
	say "generating /etc/sona/relay.env (mode 600) with fresh secrets"
	gen() { head -c 32 /dev/urandom | base64 | tr -d '='; }
	umask 077
	cat > /etc/sona/relay.env <<ENV
# Sona relay secrets — generated $(date -u +%FT%TZ) by bootstrap-vps.sh. Mode 600, root.
# BACK UP KT_SIGNING_KEY OFFLINE: it is this relay's identity; losing it breaks every
# client's pinned key. STORAGE_KEY and RATE_SALT can be rotated (see docs/DEPLOYMENT.md).
KT_SIGNING_KEY=$(gen)
STORAGE_KEY=$(gen)
RATE_SALT=$(gen)
# Enforced WebSocket Origin check (PROD=1). Must match the client's base_url exactly.
ALLOWED_ORIGINS=https://$DOMAIN
ENV
	chmod 600 /etc/sona/relay.env
fi

# ── 4. systemd units ─────────────────────────────────────────────────────────────────
say "installing sona-relay.service"
cat > /etc/systemd/system/sona-relay.service <<'UNIT'
[Unit]
Description=Sona relay (blind E2EE message relay)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sona-relay
EnvironmentFile=/etc/sona/relay.env
Environment=BIND=127.0.0.1:5002
Environment=DB_PATH=/var/lib/sona/relay.sqlite
Environment=PROD=1
# QUIC media binds 0.0.0.0:4443 by default (set QUIC_PORT=0 to disable).

DynamicUser=yes
StateDirectory=sona
WorkingDirectory=/var/lib/sona
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

say "installing sona-auditor.service (co-located smoke witness → 127.0.0.1:5002)"
cat > /etc/systemd/system/sona-auditor.service <<'UNIT'
[Unit]
Description=Sona Key Transparency auditor (co-located smoke witness)
After=network-online.target sona-relay.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sona-auditor
# Co-located witness talks to the relay directly over loopback (no TLS round-trip). This
# catches local accidents (bad restore, disk corruption); it is NOT independent witnessing.
# Run a SECOND auditor on another machine with SONA_KT_PUBKEY pinned — see RUNBOOK.
Environment=SONA_RELAY_URL=http://127.0.0.1:5002
Environment=AUDITOR_STATE=/var/lib/sona-auditor/sona-auditor.json
Environment=AUDITOR_INTERVAL_SECS=300

DynamicUser=yes
StateDirectory=sona-auditor
WorkingDirectory=/var/lib/sona-auditor
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable sona-relay sona-auditor >/dev/null 2>&1 || true

say "DONE. Server is prepared. Next, from your laptop:"
echo "    ./deploy/push.sh                      # build + ship the binaries, start the services"
echo "    ssh YOUR-VPS 'journalctl -u sona-relay -n 20 --no-pager'   # grab the printed KT pubkey"
