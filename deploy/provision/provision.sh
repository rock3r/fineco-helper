#!/usr/bin/env bash
# Provision a fineco-helper host — run as root INSIDE the target (e.g. the LXC).
#
# Creates the three least-privileged users + four IPC groups + their memberships,
# installs the binary, systemd units (+ the gateway drop-in), the tmpfiles setgid
# socket dirs, the egress helper, and the firewall template, then daemon-reloads.
#
# It deliberately does NOT:
#   - install your /etc/fineco/* secrets/config (do that from deploy/config/*.example),
#   - APPLY the firewall (`nft -f`) — that denies inbound SSH by default; apply it
#     yourself once you've set your management rule,
#   - start any service.
# Idempotent — safe to re-run. Review it before running. Full walkthrough:
# docs/SELF-HOSTING.md.
#
# Usage:  sudo deploy/provision/provision.sh /path/to/built/fineco-helper
set -euo pipefail

BIN="${1:?usage: provision.sh /path/to/built/fineco-helper}"
[ -f "$BIN" ] || { echo "binary not found: $BIN" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
DEPLOY="$(cd "$(dirname "$0")/.." && pwd)"   # the repo's deploy/ directory

echo "== users =="
for u in fineco-store fineco-gateway fineco-worker; do
    id -u "$u" >/dev/null 2>&1 ||
        useradd --system --no-create-home --shell /usr/sbin/nologin "$u"
done

echo "== groups =="
for g in fineco-ipc-store fineco-ipc-refresh fineco-ipc-live fineco-policy; do
    getent group "$g" >/dev/null || groupadd --system "$g"
done

echo "== memberships =="
# Gateway: cached reads + (live) refresh, NEVER the live socket.
usermod -aG fineco-ipc-store,fineco-ipc-refresh fineco-gateway
# Store-server/controller: clients the worker's live socket.
usermod -aG fineco-ipc-live fineco-store
# The capability policy (0640 root:fineco-policy) is read by gateway + store-server.
# One LOGIN per usermod (the comma-list is the GROUP list, not a user list):
usermod -aG fineco-policy fineco-gateway
usermod -aG fineco-policy fineco-store
# fineco-worker needs no extra group (it OWNS the live-socket dir).

echo "== /etc/fineco =="
install -d -m0755 -o root -g root /etc/fineco

echo "== binary =="
install -m0755 -o root -g root "$BIN" /usr/local/bin/fineco-helper.new
mv -f /usr/local/bin/fineco-helper.new /usr/local/bin/fineco-helper

echo "== systemd units + gateway drop-in =="
install -m0644 "$DEPLOY"/systemd/*.service "$DEPLOY"/systemd/*.timer /etc/systemd/system/
install -d -m0755 /etc/systemd/system/fineco-gateway.service.d
install -m0644 "$DEPLOY"/systemd/fineco-gateway.service.d/override.conf \
    /etc/systemd/system/fineco-gateway.service.d/override.conf

echo "== tmpfiles (setgid socket dirs) =="
install -m0644 "$DEPLOY"/tmpfiles.d/fineco-helper.conf /etc/tmpfiles.d/fineco-helper.conf
systemd-tmpfiles --create /etc/tmpfiles.d/fineco-helper.conf

echo "== libexec helpers (egress set + backup/restore + alerting) =="
install -d -m0755 /usr/local/libexec
install -m0755 "$DEPLOY"/firewall/fineco-refresh-egress-set.sh \
    /usr/local/libexec/fineco-refresh-egress-set
# The backup unit's ExecStart is /usr/local/libexec/fineco-backup; the restore
# drill uses /usr/local/libexec/fineco-restore.
install -m0755 "$DEPLOY"/backup/fineco-backup.sh  /usr/local/libexec/fineco-backup
install -m0755 "$DEPLOY"/backup/fineco-restore.sh /usr/local/libexec/fineco-restore
# The alert unit's ExecStart is /usr/local/libexec/fineco-alert.
install -m0755 "$DEPLOY"/alerting/fineco-alert.sh /usr/local/libexec/fineco-alert

echo "== backup output dir (owned by the backup user; default FINECO_BACKUP_DIR) =="
# The backup unit runs as fineco-store and writes here; /var/backups is root-owned,
# so pre-create this owned by fineco-store or the first backup fails. 0700
# (owner-only) — the backup user is the only principal that needs it; matches the
# DEPLOYMENT.md runbook.
install -d -m0700 -o fineco-store -g fineco-store /var/backups/fineco-helper

echo "== firewall template (installed + syntax-checked, NOT applied) =="
install -m0644 "$DEPLOY"/firewall/fineco-egress.nft /etc/nftables.conf
nft -c -f /etc/nftables.conf

systemctl daemon-reload

cat <<'NEXT'

Provisioned. cloudflared is NOT installed by this script — install the
`cloudflared` package separately if you use the bundled unit.

NEXT (see docs/SELF-HOSTING.md):
  1. Fill in /etc/fineco/* from deploy/config/*.env.example (+ deploy/policy.json
     -> /etc/fineco/policy.json) and set the owners/modes in deploy/config/README.md.
  2. Set up your Cloudflare Tunnel (Host header -> 127.0.0.1:8799) + Access app.
  3. Apply the firewall (review the management-SSH rule first):
       nft -f /etc/nftables.conf
       systemctl enable --now nftables.service fineco-refresh-egress-set.timer
  4. Start:
       systemctl enable --now fineco-store-server fineco-gateway fineco-private-worker cloudflared
  5. Enable the periodic jobs (backup + live-refresh alerting):
       systemctl enable --now fineco-backup.timer fineco-alert.timer
     (alerting runs with journald defaults until you write /etc/fineco/alert.env.)
  6. ONLY once live refresh is wired (worker + Fineco credential in place): enable
     the scheduled Mon-Sat portfolio refresh (a real login in the 06:00-08:00
     Europe/Rome window):
       systemctl enable --now fineco-refresh-portfolio.timer
       systemctl list-timers fineco-refresh-portfolio.timer   # confirm the next run
NEXT
