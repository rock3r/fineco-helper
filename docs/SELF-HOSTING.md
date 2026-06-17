# Self-hosting fineco-helper

A from-scratch runbook for standing up your **own** `fineco-helper` instance — an
owner-only remote MCP server exposing read-only Fineco portfolio / market / tax /
order data, a local SQLite history, and optional third-party stock enrichment.

There are two deployment paths:

- **Path A — Proxmox LXC (recommended, hardened).** The reference deployment: a
  single binary split into three least-privileged users behind systemd sandboxing
  + per-uid nftables egress pinning. This is what the security model is built for.
- **Path B — Docker (best-effort).** Convenient, but Docker cannot reproduce the
  LXC's systemd seccomp/namespace hardening or per-uid egress pinning. Treat it as
  a lower-isolation option (see the caveats in that section).

This doc is the **ordered how-to**; for the *why* (process topology, hardening
rationale, threat model) see [`ARCHITECTURE.md`](ARCHITECTURE.md) and
[`DEPLOYMENT.md`](DEPLOYMENT.md). Deployment artifacts live in
[`../deploy/`](../deploy/); per-host config templates in
[`../deploy/config/`](../deploy/config/).

> **Secrets never enter the repo, image, or git history.** Your Fineco credential,
> Cloudflare tunnel token, Access config, the enrichment host, and the backup age
> recipient all live only in `/etc/fineco/*` on the host.

## What you'll need

- A **Fineco** account — your numeric *codice utente* (login user code) and web password.
- A **Cloudflare** account with a domain on it (free Zero Trust tier is enough):
  you'll create a **Tunnel** and an **Access** application.
- A host: a **Proxmox** host (Path A) **or** a Docker host (Path B).
- An **MCP client** that can send Cloudflare Access credentials (e.g. a service
  token) — that's how you'll actually call the tools.
- *(Optional)* a third-party **stock-enrichment host** of your choosing, to enable
  the market enrichment tools, and *(optionally)* a separate **ETF-enrichment host**
  for ISIN-keyed ETF reference data. Both are config-only.
- *(Optional)* **age** for encrypted backups.

## Security model in one paragraph

Three secrets stay **separate**: the Cloudflare Access JWT (client → gateway), the
Fineco credential (worker → Fineco), and (later) a 1Password token. The
internet-facing **gateway** never holds the Fineco credential, never opens the DB
or backups, and never reaches the worker's live socket — it only speaks the
cached-read and refresh-control sockets. The credential-holding **worker** has no
DB key (orders cross un-hashed and are hashed by the store-server). Everything is
**read-only**: no trading, ever. This is enforced by three OS users + IPC groups,
systemd sandboxing, and an nftables egress allowlist.

---

## Path A — Proxmox LXC (hardened)

### 1. Build the binary

The LXC carries no toolchain; build locally and ship the binary. From a checkout
(any arch — it cross-builds to x86_64/glibc via buildx):

    deploy/build/build.sh        # → deploy/build/dist/fineco-helper

### 2. Create the LXC

An **unprivileged Debian 12** container with **nesting on** (required so the
systemd sandboxing below works unprivileged):

    pct create <ctid> <template> --unprivileged 1 --features nesting=1 \
      --hostname fineco-helper --net0 name=eth0,bridge=vmbr0,ip=dhcp
    pct start <ctid>

### 3. Provision users, groups, sockets, and units

Inside the container (`pct exec <ctid> -- …` or `pct enter <ctid>`):

- **Users** (system, no login): `fineco-store`, `fineco-gateway`, `fineco-worker`.
- **Groups** + memberships and the **setgid socket dirs** (tmpfiles.d): follow the
  table and commands in [`DEPLOYMENT.md`](DEPLOYMENT.md) → *Process topology* (it
  lists every group, who joins it, and why — the gateway joins
  `fineco-ipc-store`/`-refresh` but **never** `fineco-ipc-live`).
- **Binary** → `/usr/local/bin/fineco-helper` (atomic `mv`; it's `ETXTBSY` to
  overwrite a running one — push to a temp path then `mv`).
- **Units** → `/etc/systemd/system/`: everything in
  [`../deploy/systemd/`](../deploy/systemd/) (store-server, gateway + its drop-in,
  private-worker, the egress-set service+timer, backup service+timer, cloudflared),
  plus [`../deploy/tmpfiles.d/fineco-helper.conf`](../deploy/tmpfiles.d/fineco-helper.conf).

A helper script automates all of this —
[`../deploy/provision/provision.sh`](../deploy/provision/provision.sh), run as root
inside the container:

    sudo deploy/provision/provision.sh /path/to/built/fineco-helper

It creates the users/groups/memberships, installs the binary + units + tmpfiles +
egress helper + firewall template, and `daemon-reload`s — it does **not** install
your secrets or start services. The unit comments + the topology table above remain
the source of truth for what it does.

### 4. Configure (`/etc/fineco/*`)

Copy each template, fill it in, and set the owner/mode from
[`../deploy/config/README.md`](../deploy/config/README.md):

    install -m0640 -o root -g fineco-worker  private-worker.env /etc/fineco/private-worker.env
    install -m0640 -o root -g fineco-gateway access.env         /etc/fineco/access.env
    install -m0640 -o root -g fineco-gateway enrichment.env     /etc/fineco/enrichment.env   # optional
    install -m0600 -o root -g root           cloudflared.env    /etc/fineco/cloudflared.env
    install -m0640 -o root -g fineco-store   backup.env         /etc/fineco/backup.env       # optional

Then the **capability policy** — copy [`../deploy/policy.json`](../deploy/policy.json)
to `/etc/fineco/policy.json` (`0640 root:fineco-policy`) and grant your auth id the
capabilities you want (start with cached reads; add `*.live.refresh` only when
you're ready, ideally one area first; add `market.authenticated.read` only after
the market live-session gate has been reviewed clean and you intentionally want
on-demand Fineco-backed instrument search).

### 5. Cloudflare Tunnel + Access

**Tunnel** (Zero Trust → Networks → Tunnels): create a named tunnel; add a public
hostname routed to the gateway's loopback service `http://127.0.0.1:8799`; under
*Origin request → HTTP Host Header* set **`127.0.0.1:8799`** (required — the
gateway keeps rmcp's loopback-only `Host` validation as DNS-rebinding defense and
rejects the public host otherwise). Put the connector token in
`/etc/fineco/cloudflared.env`.

**Access** (Zero Trust → Access → Applications): add a *self-hosted* application
for that hostname. Add a policy. **You must pin at least one identity — the gateway
fails closed (refuses to start) if Access is enabled with neither pin set**, since
without a pin any token the Access policy admits would map to `owner`:
- interactive: an *Allow* policy matching your email (→ `FINECO_OWNER_EMAIL`);
- programmatic: create a **Service Token** and a *Service Auth* policy including it,
  then pin its Client ID via `FINECO_ACCESS_OWNER_COMMON_NAME`. Your MCP client
  sends the `CF-Access-Client-Id` / `CF-Access-Client-Secret` headers.

**Both pins may be set together (dual-pin):** a token matching **either** maps to
`owner`. This is how ChatGPT / Claude connectors (OAuth → `email`) and CLI clients
(service token → `common_name`) share one deployment — see
[CONNECTORS.md](CONNECTORS.md).

Fill `FINECO_ACCESS_ISSUER` / `_AUDIENCE` / `_JWKS_URL` in `/etc/fineco/access.env`
from the application's settings (the JWKS URL is on the issuer's own origin).

### 6. Firewall

Apply the egress/inbound policy and the egress-set helper:

    install -m0644 deploy/firewall/fineco-egress.nft /etc/nftables.conf
    install -m0755 deploy/firewall/fineco-refresh-egress-set.sh /usr/local/libexec/fineco-refresh-egress-set
    nft -c -f /etc/nftables.conf && nft -f /etc/nftables.conf   # syntax-check, then apply
    systemctl enable --now nftables.service fineco-refresh-egress-set.timer

Inbound SSH is denied by default (manage via the Proxmox console / `pct exec`); to
allow it from your admin subnet, uncomment the rule in `fineco-egress.nft`. The
worker's egress is pinned to the resolved Fineco IPs by the egress-set timer.

### 7. Start + verify

The bundled `cloudflared` unit runs `/usr/bin/cloudflared` — install the
**cloudflared package** first (it is NOT bundled here; follow Cloudflare's
"Install cloudflared" instructions for Debian, which add their apt repo). Then:

    systemctl daemon-reload
    systemctl enable --now fineco-store-server fineco-gateway fineco-private-worker cloudflared

Verify: all units `active`; the gateway boots (it fails closed without a valid
Access config); `cloudflared` registers; an authenticated MCP `initialize` to your
public hostname returns HTTP 200; a cached read works. Live refresh works once the
worker credential + a `*.live.refresh` capability are in place. Fineco-backed
market reads also need the worker credential, but keep them dark until the full
market live-session gate is green.

### 8. Backups (strongly recommended)

Once the store holds real captured history, that data is **irreplaceable** without
a re-fetch (and live refresh is rate-limited), so treat backups as required, not
optional. Generate an age keypair **offline** (keep the private key off the host),
put the public recipient in `/etc/fineco/backup.env`, and enable the timer:

    systemctl enable --now fineco-backup.timer

The DB is `VACUUM INTO`-copied, gzipped, and age-encrypted; only your offline
private key can decrypt it.

### 9. Alerting (strongly recommended)

This is how you find out about a worker egress deny, a stuck credential, or a
silently-failing scheduled refresh — so treat it as required for any unattended
deployment, not optional. Enable the live-refresh alert scan (budget exhausted,
repeated auth failures, circuit opened, refresh spike, worker egress deny, gateway
egress deny, worker restart loop, scheduled-refresh failure). It runs on boot +
every ~3 min and pipes
payload-free one-liners to a notifier command; the default sink is journald, so it
works with no config:

    systemctl enable --now fineco-alert.timer

To deliver off-box, set `FINECO_ALERT_COMMAND` in `/etc/fineco/alert.env`
(`0640 root:root`) — see "Alerting notifications" below.

### Alerting notifications

`fineco-alert.sh` delivers a fired alert by piping **one payload-free line**
(`fineco-alert: <type> (<count>) at <UTC>` — type + count + timestamp, never a
value) on stdin to `sh -c "$FINECO_ALERT_COMMAND"`. The **hook contract**: exit 0 =
delivered; a non-zero exit re-fires the alert next scan (at-least-once, so a flaky
channel never drops an alert — always make HTTP notifiers fail closed with
`curl -f`). The command runs as root but **capability-less**, and any **secret must
live in a `0600 root:root` file the notifier reads, never in `FINECO_ALERT_COMMAND`**
(the command string is visible in `ps`/`/proc`). Ready-to-adapt configs are in
[`deploy/alerting/examples/`](../deploy/alerting/examples/).

**Telegram** (the easy default):

1. In Telegram, message **@BotFather** → `/newbot` → it gives a **bot token**
   (`123456:ABC-…`). Then message your new bot once and open
   `https://api.telegram.org/bot<TOKEN>/getUpdates` to read your numeric **chat id**
   (or message **@userinfobot**).
2. Install the curl config (token stays out of argv):

        install -m0600 -o root -g root deploy/alerting/examples/telegram.curl.example /etc/fineco/telegram.curl
        # then edit /etc/fineco/telegram.curl: replace <BOT_TOKEN> and <CHAT_ID>

3. Point the alert command at it and verify:

        # in /etc/fineco/alert.env:
        FINECO_ALERT_COMMAND='curl -fsS -o /dev/null --config /etc/fineco/telegram.curl --data-urlencode text@-'
        # then source the file (it isn't in your shell yet) and smoke-test delivery:
        ( set -a; . /etc/fineco/alert.env; set +a
          printf 'fineco-alert: test at %s\n' "$(date -u +%FT%TZ)" | sh -c "$FINECO_ALERT_COMMAND" )   # → a Telegram message

**ntfy** and **email (SMTP via msmtp)** follow the same pattern — see
[`deploy/alerting/examples/README.md`](../deploy/alerting/examples/README.md). The
per-alert source map is in [`docs/LIVE-REFRESH-GATES.md`](LIVE-REFRESH-GATES.md).

### 10. Scheduled refresh (optional, needs live refresh)

Keep the cached portfolio fresh without a manual trigger. The
`fineco-refresh-portfolio.timer` runs the binary's `refresh portfolio`
subcommand on **Mon–Sat** at a **random time in 06:00–08:00 Europe/Rome** — well
after the ~22:00-Rome US close (so the prior day's US prices land), at a
human-plausible hour so the unattended login doesn't trip the bank's fraud
heuristics. The subcommand is a refresh-control *client* (runs as an ephemeral
`DynamicUser` in only the refresh group, holds no credentials); the controller
does the login/fetch behind its existing gates. Enable it **only once live refresh
is wired** (worker + Fineco credential in place):

    systemctl enable --now fineco-refresh-portfolio.timer
    systemctl list-timers fineco-refresh-portfolio.timer   # confirm the next run

It's **best-effort**: if Fineco demands SCA or the login times out, that run
exits non-zero — which the alert scanner (step 9, *if you enabled it*) surfaces as
`scheduled portfolio refresh failed` — and the cached data simply holds at the
last good refresh. Only `portfolio` is scheduled — orders and tax take parameters
and stay on-demand through the gated MCP tools. To watch a run live:
`journalctl -u fineco-refresh-portfolio.service -f`, or trigger one now with
`systemctl start fineco-refresh-portfolio.service`.

---

## Path B — Docker (best-effort)

> **Caveat.** Docker cannot reproduce the LXC path's systemd sandboxing
> (`SystemCallFilter`, the protect-*/restrict-* directives) or the per-uid
> nftables egress pinning. The compose below runs the same three-process topology
> with Docker's nearest equivalents — `cap_drop: [ALL]`, `read_only` rootfs,
> `no-new-privileges`, user namespaces, tmpfs socket dirs, and a constrained
> network — but the **LXC path is the hardened reference**. Use Docker for
> convenience/testing; prefer the LXC for a real exposure.

A best-effort `docker compose` topology lives under
[`../deploy/docker/`](../deploy/docker/) (gateway + store-server + worker + a
sidecar `cloudflared`, sharing socket volumes). The per-host config is the same
`/etc/fineco/*` set, supplied as env files / Docker secrets. See that directory's
README for the compose, the security options applied, and what is *not* equivalent
to the LXC. The Cloudflare Tunnel + Access setup (step 5) and the capability policy
(step 4) are identical.

---

## Updating

Rebuild (step 1) and atomic-replace the binary, then restart — see
[`DEPLOYMENT.md`](DEPLOYMENT.md) → *Build & ship*. Re-run `nft -c -f` before
re-applying the firewall if you changed it.
