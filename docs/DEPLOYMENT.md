# Deployment (LXC)

How the binary is deployed as the hardened two-process topology. The *why*
(threat model, egress reasoning, gates) lives in the project's private design
spec; this doc records the as-built deployment shape, not the rationale.

Artifacts live under [`deploy/`](../deploy/): a reproducible build kit in
`deploy/build/`, systemd units in `deploy/systemd/`, the applied egress/inbound
firewall in `deploy/firewall/`, and the capability policy `deploy/policy.json`.

> The real LXC apply is owner-supervised. Validate every unit on the target host
> with `systemd-analyze security <unit>` and adjust paths/users to the host.

**As built (M7):** deployed to an **unprivileged Debian 12 LXC** (Proxmox,
`features: nesting=1` — required so the systemd sandboxing below works in an
unprivileged container) reached only through a local `cloudflared` tunnel +
Cloudflare Access. The gateway binds `127.0.0.1:8799` (the deploy drop-in
overrides the documented `8765` default to match the tunnel route's HTTP Host
Header). Per-host config and secrets live in `/etc/fineco/` (below) and are
never committed.

## Build & ship

The binary is **built locally and shipped** (the LXC has no toolchain). The kit
in [`deploy/build/`](../deploy/build/) produces a reproducible x86_64/glibc
binary regardless of the build host's arch:

```
deploy/build/build.sh        # docker buildx --platform linux/amd64, exports deploy/build/dist/fineco-helper
```

Ship it to the LXC via Proxmox (the binary is pushed onto the container's
filesystem, not over the network):

```
scp deploy/build/dist/fineco-helper root@<proxmox>:/tmp/fineco-helper
ssh root@<proxmox> 'pct push <ctid> /tmp/fineco-helper /tmp/fineco-helper.new --perms 0755'
ssh root@<proxmox> 'pct exec <ctid> -- mv -f /tmp/fineco-helper.new /usr/local/bin/fineco-helper'
ssh root@<proxmox> 'pct exec <ctid> -- systemctl restart fineco-store-server fineco-gateway'
```

> Push to a temp path and **atomic `mv`** over the live binary — overwriting the
> running executable in place fails with `ETXTBSY` ("Text file busy").

## Process topology

The cached-read deployment is **two processes / two users / one socket**; **M8+
live refresh + authenticated market reads** add a third process, two
live-refresh sockets, and an optional authenticated market-control socket,
splitting into the plan's
**three users / three IPC groups** (the controller runs inside the store-server,
so the plan's `fineco-store` + `fineco-refresh` collapse to one process/user):

| Process | Unit | User | Network | Reaches |
| --- | --- | --- | --- | --- |
| store-server (DB + query + **controller**) | `fineco-store-server.service` | `fineco-store` | none (`AF_UNIX`) | owns the SQLite store; serves `snapshot-query.sock` + `refresh-control.sock` + optional `market-control.sock`; clients `fineco-live.sock` |
| owner MCP gateway | `fineco-gateway.service` | `fineco-gateway` | yes | the sockets only (no DB, no credentials, **no live socket**); binds `127.0.0.1` only |
| private Fineco worker (M8) | `fineco-private-worker.service` | `fineco-worker` | yes (Fineco) | holds the Fineco credentials; serves `fineco-live.sock`; **no DB** |

A local `cloudflared` ([`deploy/systemd/cloudflared.service`](../deploy/systemd/cloudflared.service))
is the only client of the gateway's loopback bind; Cloudflare Access verification
is **live** (M6, below).

**IPC groups** (one per socket — so reachability is separable):

| Socket | Runtime dir (setgid 2750) | Owner:group | Connected by |
| --- | --- | --- | --- |
| `snapshot-query.sock` | `/run/fineco-helper` | `fineco-store:fineco-ipc-store` | gateway |
| `refresh-control.sock` | `/run/fineco-helper-refresh` | `fineco-store:fineco-ipc-refresh` | gateway (live refresh) |
| `market-control.sock` | `/run/fineco-helper-refresh` | `fineco-store:fineco-ipc-refresh` | gateway (authenticated market reads) |
| `fineco-live.sock` | `/run/fineco-worker` | `fineco-worker:fineco-ipc-live` | store-server (controller) |

The internet-facing gateway joins `fineco-ipc-store` + `fineco-ipc-refresh` but
**NEVER `fineco-ipc-live`** — it has no path to the credential worker's socket
(also a build-time barrier: `fineco-gateway` cannot depend on `fineco-live`). The
credential worker holds **no** DB handle (the DB is `0700 fineco-store`) and is
the only reader of the credentials file.

## Users, groups, and the sockets

The M8 deployment provisions three users + three IPC groups (the LXC has **no
important data** — the live path was dark — so this is a clean provision, not an
in-place migration):

```
useradd --system --no-create-home --shell /usr/sbin/nologin fineco-store
useradd --system --no-create-home --shell /usr/sbin/nologin fineco-gateway
useradd --system --no-create-home --shell /usr/sbin/nologin fineco-worker
groupadd --system fineco-ipc-store
groupadd --system fineco-ipc-refresh
groupadd --system fineco-ipc-live
# The gateway reaches cached reads + (live) refresh, never the live socket:
usermod -aG fineco-ipc-store,fineco-ipc-refresh fineco-gateway
# The store-server/controller clients the worker's live socket:
usermod -aG fineco-ipc-live fineco-store
# fineco-worker needs no extra group (it OWNS the live-socket dir).
# The (non-secret) capability policy is read by the gateway + store-server, not
# the worker (the worker validates command/params + socket isolation, not policy):
groupadd --system fineco-policy
# One LOGIN per usermod (the comma-list is the GROUP list, not a user list):
usermod -aG fineco-policy fineco-gateway
usermod -aG fineco-policy fineco-store
```

> **Re-provisioning from the M7 layout** (where `fineco-worker` ran the store):
> stop the services first; create `fineco-store`; **`chown -R fineco-store:fineco-store /var/lib/fineco-helper`**
> (and any backups) so the repurposed `fineco-worker` retains **no** DB access —
> this is the one isolation-critical step; remove `fineco-worker` from
> `fineco-ipc-store`; set the memberships above; install the updated units. Group
> changes don't affect already-running processes, so restart everything.
> **Only if this instance has no SQLite history to preserve** (a fresh or test
> deployment) you may instead drop `/var/lib/fineco-helper` and let the store-server
> recreate it fresh as `fineco-store` — simpler, but **destructive**. On any instance
> with data to keep, use the `chown` step above; never drop the directory.

Each socket sits in its own **setgid (`2750`) runtime dir** so the socket inherits
the dir's IPC group; the binary then chmods the socket to `0660`. The dir is
owner-write only (no group write), so only the serving process can create/unlink the
socket — group members merely connect. Connecting to a
Unix socket needs write access to the socket inode, so only the owner + that one
group may connect. The dirs are created by `systemd-tmpfiles`
([`deploy/tmpfiles.d/fineco-helper.conf`](../deploy/tmpfiles.d/fineco-helper.conf))
— **not** `RuntimeDirectory=`, which can't give the store-server's two sockets two
different groups. (The default socket mode is `0600` for same-user/Docker-E2E;
the multi-user LXC uses `0660`. The mode is validated fail-closed: owner rw, no
"other" access.)

## Install

```
install -Dm0755 fineco-helper                /usr/local/bin/fineco-helper
install -Dm0644 deploy/systemd/fineco-store-server.service   /etc/systemd/system/fineco-store-server.service
install -Dm0644 deploy/systemd/fineco-gateway.service        /etc/systemd/system/fineco-gateway.service
install -Dm0644 deploy/systemd/fineco-private-worker.service /etc/systemd/system/fineco-private-worker.service  # M8 live refresh
# The gateway drop-in (the loopback-bind override + EnvironmentFiles) and the
# cloudflared unit are REQUIRED for the remote deployment — without the drop-in
# the gateway keeps the base 127.0.0.1:8765 bind and never loads access.env, so it
# fails closed and will not start.
install -Dm0644 deploy/systemd/fineco-gateway.service.d/override.conf /etc/systemd/system/fineco-gateway.service.d/override.conf
install -Dm0644 deploy/systemd/cloudflared.service          /etc/systemd/system/cloudflared.service
# The per-socket setgid runtime dirs (snapshot-query / refresh+market-control / live):
install -Dm0644 deploy/tmpfiles.d/fineco-helper.conf /etc/tmpfiles.d/fineco-helper.conf
systemd-tmpfiles --create /etc/tmpfiles.d/fineco-helper.conf                    # needs the users/groups above to exist
install -d -m0700 -o fineco-store -g fineco-store /var/lib/fineco-helper        # DB dir (owner fineco-store; the worker has NO access)
install -Dm0640 -o root -g fineco-policy deploy/policy.json /etc/fineco/policy.json # capability policy (required; non-secret)
# Install the firewall ruleset, then validate it BEFORE enabling — `nftables.service`
# loads /etc/nftables.conf, so without this it would come up with the image's
# default (empty) ruleset and the deny-by-default policy would NOT be applied.
install -Dm0644 deploy/firewall/fineco-egress.nft /etc/nftables.conf
nft -c -f /etc/nftables.conf                                                    # syntax-check; fix before enabling
# Worker + gateway egress: the allow-set populator + its timer/service (re-run after
# any nft reload — `flush ruleset` empties the sets). It reads the gateway's JWKS +
# enrichment hosts from access.env/enrichment.env, so install those (below) first.
install -Dm0755 deploy/firewall/fineco-refresh-egress-set.sh /usr/local/libexec/fineco-refresh-egress-set
install -Dm0644 deploy/systemd/fineco-refresh-egress-set.service /etc/systemd/system/fineco-refresh-egress-set.service
install -Dm0644 deploy/systemd/fineco-refresh-egress-set.timer   /etc/systemd/system/fineco-refresh-egress-set.timer
# Write /etc/fineco/ config/secrets (access.env, enrichment.env, cloudflared.env,
# and — M8 — private-worker.env; see "Per-host config" + "Live refresh") BEFORE
# enabling: the gateway fails closed without access.env, cloudflared needs its
# TUNNEL_TOKEN, and the worker needs its Fineco credentials.
systemctl daemon-reload
systemctl enable --now nftables.service fineco-refresh-egress-set.timer         # the firewall + the worker/gateway egress sets
systemctl enable --now fineco-store-server.service fineco-gateway.service cloudflared.service
systemctl enable --now fineco-private-worker.service                            # M8 live refresh (after private-worker.env exists)
```

Post-deploy verification must check **boot persistence**, not only the current
process state:

```
systemctl is-enabled fineco-store-server fineco-gateway fineco-private-worker cloudflared
systemctl is-active  fineco-store-server fineco-gateway fineco-private-worker cloudflared
test -S /run/fineco-worker/fineco-live.sock
```

`fineco-private-worker` is easy to miss because cached tools still work when it is
down: the gateway and store-server remain healthy, but authenticated market tools
fail immediately with `live_transport_failure`. Always include the worker in both
`enable --now` and the post-reboot `is-enabled`/socket checks.

The capability policy (`/etc/fineco/policy.json`) is **required** — both roles
fail closed without it. Grant `owner` only the capabilities for the tools you
expose (`market.read`, `portfolio.cached.full_read`, `portfolio.shareable.read`,
`orders.cached.read`, `tax.cached.read`). Keep `market.authenticated.read`
ungranted until the market live-session gate has been reviewed clean and the
owner intentionally wants on-demand authenticated Fineco market reads.
`*.live.refresh` stays grant-only-if-needed.

> Order matters: the gateway and cloudflared each need their `/etc/fineco/`
> EnvironmentFiles present before `enable --now` — the gateway refuses to start
> without `access.env` (fail closed), and the tunnel won't connect without
> `cloudflared.env`. Populate `/etc/fineco/` (next section) first.

### Per-host config (`/etc/fineco/`)

The units carry no deployment values; they pull config/secrets from
`EnvironmentFile=`s so the committed units stay generic. None of these files are
committed.

| File | Mode | Consumed by | Holds |
| --- | --- | --- | --- |
| `policy.json` | `0640 root:fineco-policy` | gateway + store-server | capability policy (required; non-secret) |
| `access.env` | `0640 root:fineco-gateway` | gateway drop-in | Cloudflare Access issuer/audience/JWKS (required — fail-closed) + the service-token `FINECO_ACCESS_OWNER_COMMON_NAME` pin |
| `enrichment.env` | `0640 root:fineco-gateway` | gateway drop-in | two **independent** config-only host pairs: stock enrichment (`FINECO_ENRICHMENT_BASE` + `FINECO_ENRICHMENT_HOST_HASHES`) and ISIN-keyed ETF enrichment (`FINECO_ETF_ENRICHMENT_BASE` + `FINECO_ETF_ENRICHMENT_HOST_HASHES`). Each pair: both present → that route on, one alone → fail closed. **Either** pair enables the market tools; neither → off. Both hosts are **config-only** (never in source). |
| `cloudflared.env` | `0600 root:root` | `cloudflared` unit | `TUNNEL_TOKEN` (the tunnel credential) |
| `private-worker.env` | `0640 root:fineco-worker` | private-worker unit (M8) | `FINECO_USER_ID` + `FINECO_PASSWORD` (the Fineco credential — **only `fineco-worker` can read it**) |
| `backup.env` | `0640 root:fineco-store` | backup unit (M8) | `FINECO_BACKUP_AGE_RECIPIENT` (the age **public** key; the private identity stays offline) + optional `FINECO_BACKUP_DIR` |

The gateway drop-in
([`deploy/systemd/fineco-gateway.service.d/override.conf`](../deploy/systemd/fineco-gateway.service.d/override.conf))
sets the loopback bind (`127.0.0.1:8799`) and wires `access.env` (required) +
`enrichment.env` (optional, `-` prefix).

`FINECO_MARKET_CONTROL_SOCKET` is optional and explicit-only. Leave it unset in
normal deployments until the market live-session gate has been reviewed clean
and the owner intentionally enables authenticated market reads. When
enabled, set it on both gateway and store-server to a
controller-owned socket such as `/run/fineco-helper-refresh/market-control.sock`;
it uses the same `fineco-ipc-refresh` group and socket mode. In the current
controller topology it is valid only when `FINECO_REFRESH_SOCKET` and
`FINECO_LIVE_SOCKET` are also configured; market-control is served by the same
controller block as refresh-control.

> **Do not set `FINECO_ETF_URL` in production.** The zero-commission ETF list
> defaults to its fixed public Fineco endpoint, baked into the binary. The
> override exists only to point the e2e suite at a loopback mock; unlike the
> enrichment host it is **not** SHA-256-pinned (only HTTPS-or-loopback transport
> is enforced), so a production override would turn the gateway into an arbitrary
> HTTPS JSON fetcher. It is not client-supplied (root-owned `enrichment.env`
> only), but leave it unset so the pinned default is the sole ETF source.

## Enabling authenticated market tools

On-demand authenticated Fineco market reads (`market_search_asset`,
`market_get_asset_details`, `market_get_indices`) are **dark by default**: the
committed `policy.json` does not grant `market.authenticated.read`, the
market-control socket is left unset, and the three tools are excluded from the
default connector allowlist. Turn them on deliberately, host-side, only after the
market live-session gate has been reviewed clean ([LIVE-REFRESH-GATES.md](LIVE-REFRESH-GATES.md)).
Each step is reversible; the rollback below is the exact inverse.

1. **Grant the capability.** In `/etc/fineco/policy.json`, add
   `market.authenticated.read` to `owner`'s capabilities. This is the live-host
   policy, not the committed fail-safe baseline.
2. **Bind the controller socket.** Uncomment the
   `FINECO_MARKET_CONTROL_SOCKET=/run/fineco-helper-refresh/market-control.sock`
   line in **both** `fineco-store-server.service` (the controller binds it) and
   `fineco-gateway.service` (the gateway connects to it) — same path on both. It
   lives in the `fineco-ipc-refresh` group the gateway already joins, so no group
   change is needed; the store-server only accepts it when `FINECO_REFRESH_SOCKET`
   and `FINECO_LIVE_SOCKET` are already set (it fails closed otherwise).
3. **Expose to connectors (optional).** To let ChatGPT/Claude connectors call the
   three tools, set in `/etc/fineco/access.env`:

       FINECO_CONNECTOR_TOOLS=+market_search_asset,market_get_asset_details,market_get_indices

   The leading `+` means "the fail-safe default connector set **plus** these", so
   every default tool stays exposed and only the three market tools are added — no
   need to re-list the whole default set, and no risk of accidentally narrowing it.
   (Leaving `FINECO_CONNECTOR_TOOLS` unset keeps the tools reachable on the CLI /
   service-token channel but hidden from connectors; granting the capability is
   still required either way.) See [CONNECTORS.md](CONNECTORS.md).
4. **Reload and restart.** `systemctl daemon-reload`, then restart both units:
   `systemctl restart fineco-store-server.service fineco-gateway.service`.
5. **Smoke-test.** Call `market_get_indices` once and confirm a `200` with index
   data. Then call `market_search_asset` for a basket of instruments back-to-back
   and confirm the response session facts show `session_reused: true` after the
   first read (one login amortized across the basket), with
   `reused_session_401_recovered` staying at/near zero — a spike there means the
   reuse TTL (`MARKET_SESSION_REUSE_TTL_SECS`, 180 s) is longer than the live
   server session and should come down.

**Rollback** (any time): re-comment `FINECO_MARKET_CONTROL_SOCKET` on both units,
remove `market.authenticated.read` from `policy.json`, unset
`FINECO_CONNECTOR_TOOLS` (or drop the `+market_*` additions), `daemon-reload`, and
restart both units. The tools go dark again with no other change.

## Hardening

Both units apply the plan's hardening (`NoNewPrivileges`, `PrivateTmp`,
`ProtectSystem=strict`, `ProtectHome`, the `Protect*`/`Restrict*` set, a
`@system-service` syscall filter, `UMask=0077`, minimal `ReadWritePaths`).
Process-specific:

- **store-server** has **no network**: `PrivateNetwork=true` +
  `RestrictAddressFamilies=AF_UNIX`. It only speaks the local sockets (including
  clienting the worker's live socket — a pathname `AF_UNIX` connect works under
  the private netns).
- **gateway** allows `AF_INET`/`AF_INET6` (the loopback bind) + `AF_UNIX` (the
  socket); its real egress is **pinned by the firewall** to its resolved targets
  (CF JWKS + stock & ETF enrichment hosts + ETF list) via `meta skuid "fineco-gateway"`, so a compromised
  gateway can't exfiltrate cached private data to an arbitrary host — see *Live
  refresh* for the egress-set + the loopback-first ordering and the host check.
- **private-worker** (M8) keeps the network for Fineco (`AF_UNIX AF_INET
  AF_INET6`, no `PrivateNetwork`) — its egress is pinned to the resolved Fineco
  IPs by the nftables `meta skuid "fineco-worker"` rules, **not** systemd
  `IPAddress*` (cgroup-BPF, unreliable in an unprivileged LXC). It holds no DB.

## Live refresh (M8)

Live refresh adds the credential worker and the controller (see *Process
topology*). It is **gated**: enable it only after the egress allowlist is applied
and the negative checks below pass.

**Credentials.** The Fineco credential goes only into `/etc/fineco/private-worker.env`
(`0640 root:fineco-worker`), readable by the worker alone. Do **not** type or echo
it; pipe it straight from 1Password into the file on the CT, e.g.:

```
op read 'op://<vault>/Fineco Bank/username' | ...   # build the env file content
# then install it 0640 root:fineco-worker, e.g. via:
ssh root@<proxmox> "pct exec <ctid> -- install -m0640 -o root -g fineco-worker /dev/stdin /etc/fineco/private-worker.env" < private-worker.env
```

(The password flows 1Password → ssh → file; it never lands in a shell history or a
log. The worker reads `FINECO_USER_ID`/`FINECO_PASSWORD` via `EnvCredentialSource`;
leaving them unset surfaces as `auth_required`, never a crash. The Fineco **session
cookie is memory-only** — minted per fetch, held on the stack, and discarded; it is
never written to disk, as the plan's §"Credential Storage" requires.)

**Egress (the hard gate — apply BEFORE the first real login).** The worker's
egress is allowlisted to the resolved Fineco IPs + pinned DNS by the nftables
`meta skuid "fineco-worker"` rules ([`deploy/firewall/fineco-egress.nft`](../deploy/firewall/fineco-egress.nft)),
populated by the `fineco-refresh-egress-set.timer`
([script](../deploy/firewall/fineco-refresh-egress-set.sh)). First verify nft/kernel
support on the LXC (`nft --version`, `uname -r` — the CT runs the *host* kernel),
then apply, run the egress-set service once, and confirm the sets are populated
(`nft list set inet fineco fineco_worker_v4`).

**Negative checks (run after every deploy).** Confirm the boundary holds. The CT
has no `sudo` — use `runuser -u <user> -- …` (util-linux; it applies the user's
supplementary groups). Each line should print `ok`:

```
# the gateway must NOT reach the live socket:
runuser -u fineco-gateway -- test -w /run/fineco-worker/fineco-live.sock && echo FAIL || echo ok
# the credential worker must NOT read the DB:
runuser -u fineco-worker  -- test -r /var/lib/fineco-helper/fineco-history.sqlite && echo FAIL || echo ok
# neither the store nor the gateway may read the Fineco credential:
runuser -u fineco-store   -- test -r /etc/fineco/private-worker.env && echo FAIL || echo ok
runuser -u fineco-gateway -- test -r /etc/fineco/private-worker.env && echo FAIL || echo ok
# positive: the gateway reaches the query+refresh sockets, the controller the live one:
runuser -u fineco-gateway -- test -w /run/fineco-helper/snapshot-query.sock && echo ok || echo FAIL
runuser -u fineco-store   -- test -w /run/fineco-worker/fineco-live.sock && echo ok || echo FAIL
# arbitrary worker egress must be DENIED (a non-Fineco IP), a Fineco IP allowed:
runuser -u fineco-worker -- timeout 4 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' && echo "FAIL reached non-Fineco" || echo "ok egress denied"
# and the deny is observable via the nft COUNTER (NOT the log line — it does not
# surface in the unprivileged LXC's journald/dmesg; the counter is the alert source):
nft list chain inet fineco output | grep 'fineco-egress-deny'   # … counter packets N … drop
```

**First real login.** Owner present; start with one data area; the controller does
**not** retry a `4xx` (`auth_required`) — watch for SCA/2FA prompts; tail the audit
(`journalctl -u fineco-gateway -f -o cat`) before enabling all three refresh tools.

**Gateway egress (apply + verify carefully — it can brick the gateway).** The
`meta skuid "fineco-gateway"` block pins the gateway to its resolved targets so a
compromised gateway can't exfiltrate cached private data. Apply the new ruleset
(`nft -f /etc/nftables.conf`) and run the egress-set once, THEN restart the gateway
(its startup JWKS fetch is fail-closed). Confirm the gateway set is populated
(`nft list set inet fineco fineco_gateway_v4`), the gateway still works (a remote MCP
call through the tunnel succeeds — so JWKS + the tunnel loopback path are intact), and
that a non-allowlisted connect is denied:

```
runuser -u fineco-gateway -- timeout 4 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' && echo "FAIL reached non-allowlisted" || echo "ok gateway egress denied"
nft list chain inet fineco output | grep 'fineco-egress-deny gateway'   # … counter packets N … drop
```

If the gateway breaks (no JWKS / tunnel dead), revert via the Proxmox host
(`pct exec <ctid> -- nft flush ruleset` or re-apply the previous ruleset) — direct CT
SSH is denied by the input chain, but `pct exec` from the host is unaffected.

**Scheduled refresh.** Once live refresh is wired, `fineco-refresh-portfolio.timer`
keeps the cached portfolio fresh unattended: it runs `fineco-helper refresh portfolio`
**Mon–Sat** at a random time in **06:00–08:00 Europe/Rome** (after the ~22:00-Rome US
close; a human-plausible hour so the login doesn't trip fraud heuristics). The
subcommand is a refresh-control *client* run as an ephemeral `DynamicUser` joined to
only `fineco-ipc-refresh` (the plan's "local admin" caller) — no credentials, no DB,
no live socket, and none of the gateway account's other groups; the controller
authorizes by socket access + policy (OWNER_AUTH_ID), not by uid.
It's **best-effort**: an SCA/timeout/gate-denial makes the run exit non-zero — the
alert scanner reads `fineco-refresh-portfolio.service`'s journal on the same cursor
as the gateway's, so a failure surfaces as `scheduled portfolio refresh failed` (if
`fineco-alert.timer` is enabled) — and the cached data holds at the last good
refresh. Only `portfolio` is scheduled (orders/tax take params → on-demand via the
MCP tools).
Enable with `systemctl enable --now fineco-refresh-portfolio.timer`; watch a run via
`journalctl -u fineco-refresh-portfolio.service -f` or trigger one with
`systemctl start fineco-refresh-portfolio.service`.

## Cloudflare Access (remote authentication, M6 — live)

A local `cloudflared` (Cloudflare Tunnel) is the only client of the gateway's
loopback bind; the internet never reaches the LXC directly. When Access is
configured, the gateway **verifies the `Cf-Access-Jwt-Assertion` JWT on every
request** — issuer, audience, expiry, and RS256 signature against the team JWKS —
and maps the verified owner to `auth_id: owner`. A missing/spoofed/invalid token
is rejected with `401` before reaching the MCP service; the team JWKS is
re-fetched periodically to track key rotations.

> **Required tunnel setting — rewrite the origin Host header.** The gateway keeps
> rmcp's loopback-only `Host` validation (DNS-rebinding defense), so it rejects the
> *public* `Host` that cloudflared forwards by default
> (`Forbidden: Host header is not allowed`). On the tunnel's public-hostname
> route set **HTTP Host Header → the gateway's loopback bind** (the deploy uses
> `127.0.0.1:8799`) so cloudflared presents a loopback Host; the Access JWT stays
> the real auth gate. Verified end-to-end in the Cloudflare Access spike and again
> on the live deployment — see `e2e/spike/README.md`.

Configure on the gateway host (**required for the remote deployment**; absent →
loopback-only with no auth):

- `FINECO_ACCESS_ISSUER` — `https://<team>.cloudflareaccess.com`
- `FINECO_ACCESS_AUDIENCE` — the Access application's AUD tag
- `FINECO_ACCESS_JWKS_URL` — `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`
  (must be on the **issuer's own origin** — the key source is bound to the issuer;
  a JWKS URL on a different origin is rejected fail-closed, so foreign keys can't
  be trusted to verify tokens that merely *claim* this issuer/audience)
- **At least one identity pin is REQUIRED when Access is enabled** — set one or
  both of the next two (the gateway refuses to start with neither: without a pin
  every admitted token maps to `owner`, so a later Access-policy widening would
  grant ownership):
- `FINECO_OWNER_EMAIL` — pin the owner identity by the JWT `email`
  claim (for interactive/SSO tokens)
- `FINECO_ACCESS_OWNER_COMMON_NAME` — pin the **service-token** Client
  ID by the JWT `common_name` claim. For service-token deployments this is the
  gateway-side binding to one specific token: even if the Access app is later
  widened to admit another token, only this `common_name` maps to `owner` (a
  token lacking the claim fails closed)
- `FINECO_CONNECTOR_TOOLS` (optional, **requires an email/OAuth pin** —
  `FINECO_OWNER_EMAIL`) — the connector (email/OAuth) channel's tool allowlist; the
  CLI (service-token) channel is always full. Unset = the default (every tool except
  the four detailed-portfolio absolute-€ tools plus `market_search_asset`,
  `market_get_asset_details`, and `market_get_indices`);
  `*`/`all` = no restriction; a comma
  list = exactly those tools. Unknown names fail closed; setting it without an email
  pin errors. Applies to any email-pinned deployment (incl. single-email-pin), not
  only dual-pin. See [CONNECTORS.md](CONNECTORS.md).
- `FINECO_ALLOWED_ORIGINS` (optional, comma-separated) — Origin allowlist for
  DNS-rebinding protection (the gateway already validates `Host` to loopback)

These are config-only (the team domain / AUD tag are not hard-coded). If neither
the Access vars nor `FINECO_ACCESS_DISABLED=true` is set, the gateway **refuses to
start** — a missing config can never silently run it without authentication.

Notes:
- A request with **no `Origin` header still passes** even with
  `FINECO_ALLOWED_ORIGINS` set — origin-less native MCP clients must connect, and
  the JWT (not Origin) is the real auth gate; Origin validation is only
  defence-in-depth against browser-context DNS-rebinding. Accepted residual.
- `FINECO_OWNER_EMAIL` pins the owner by the JWT `email` claim (interactive
  SSO/OAuth tokens — including ChatGPT/Claude connectors).
  `FINECO_ACCESS_OWNER_COMMON_NAME` pins the **service-token** Client ID by the
  `common_name` claim (CLI clients; service-token JWTs carry no `email`).
- **Dual-pin:** set one or both. With both set, the verifier maps a token matching
  **either** pin to `owner` (OR-semantics) — this is how the connectors (`email`)
  and the CLI (`common_name`) coexist on one deployment. With a single pin, a token
  must match that pin (one lacking the claim fails closed). Both are blank-is-no-pin
  (whitespace counts as unset); with neither set the gateway **refuses to start**
  (fail closed). See [CONNECTORS.md](CONNECTORS.md).

The **Cloudflare Access spike** (real Tunnel + Access + the target MCP client; whether it
uses interactive SSO or a service token; revocation; direct-origin-unreachable)
was run against the real Cloudflare account; the live deploy uses a **service
token**, so `FINECO_ACCESS_OWNER_COMMON_NAME` pins the token's Client ID — see the
plan §"Cloudflare Access". To add ChatGPT/Claude connectors, **also** set
`FINECO_OWNER_EMAIL` (dual-pin) and configure Cloudflare Access managed OAuth —
see [CONNECTORS.md](CONNECTORS.md).

## Egress/inbound firewall

The applied policy is [`deploy/firewall/fineco-egress.nft`](../deploy/firewall/fineco-egress.nft),
deployed to the LXC as `/etc/nftables.conf` and loaded at boot by
`nftables.service` (`systemctl enable --now nftables`). Posture (plan
§"LXC Hardening"):

- **Inbound deny-by-default** — no public port is open (the gateway binds
  loopback only; verify with `ss -ltnp | grep -v 127.0.0.1` returning nothing
  for the gateway). The input chain allows loopback, established/related,
  ICMP/ICMPv6 (PMTUD + IPv6 ND), and the DHCP reply; LAN-only management SSH is a
  **commented-out** opt-in template (off by default — uncomment + set your admin
  subnet to enable).
- **Egress deny-by-default** — the output chain pins each privileged uid to its
  own targets: the **worker** (`fineco-worker`) and the **gateway**
  (`fineco-gateway`) each reach only the pinned DNS resolver + their own resolved
  IP set (`fineco_worker` / `fineco_gateway`) over **TCP 443**, then a
  deny+log+counter. Everything else falls through to the broad allowances —
  cloudflared's **443** + **7844 TCP/UDP** to the Cloudflare edge, DHCP, system
  DNS. The store-server has no network at all (`PrivateNetwork=true`).

**Host-pinned gateway egress (M8):** the `fineco-gateway` uid — which can read
cached private data over the snapshot-query socket — is pinned to a resolved
`fineco_gateway` IP set (the Access JWKS host + the enrichment host + the ETF CDN),
kept fresh by `fineco-refresh-egress-set` on a 5-min timer (last-known-good on a
resolve miss). That re-resolution is how the CDN-rotating-IP problem is solved
(the same mechanism as the worker), so a compromised gateway can no longer
exfiltrate to an arbitrary host. The DHCP allowances matter: the LXC leases its
address (`ip=dhcp`), so blocking 67/68 would silently kill its network at lease
renewal.

> Apply/recover out-of-band via Proxmox `pct exec <ctid> -- nft …` (works
> regardless of the in-container firewall), so a bad ruleset can always be
> flushed without LAN access. The previous ruleset is backed up at
> `/etc/nftables.conf.orig`.

**Residual (egress, owner-ratified).** The gateway egress pin is **IP-level, not
SNI/host-level**: the JWKS + ETF targets are CDN-fronted, so the allowlisted edge
IPs may also serve other hostnames — a hijacked gateway could in principle
exfiltrate to a different site sharing those IPs. Airtight host-level egress would
need an L7 hostname-policy proxy; the plan weighed that against the timer-refreshed
nftables address set and chose the IP-set (a real reduction — arbitrary non-CDN
exfil is blocked — without an L7 proxy in the credentialed path). Outbound market
fetches are also globally timed out (`MARKET_FETCH_TIMEOUT`) so a stalled upstream
can't pin a worker.

**Management SSH (off by default).** Inbound SSH is denied by default — primary
management is Proxmox `pct exec` (out-of-band). To allow SSH from a trusted admin
subnet, uncomment the management rule in `deploy/firewall/fineco-egress.nft` and
set your own CIDR. Prefer a single admin IP; a broad subnet rule exposes you to
any compromised host on that network.

## Audit logging

The gateway writes **one structured audit line per tool call** to stdout
(captured by journald → `journalctl -u fineco-gateway`). Each record is built by
allowlist — it can only carry metadata, never a payload:

```
{"ts":…,"auth_id":"owner","tool":…,"data_class":…,"outcome":…,"error_code":…,"duration_ms":…,"result_count":…}
```

`result_count` is the number of rows/items returned, never their values; there is
no field that could hold a DTO. An anti-leak test
(`crates/fineco-gateway/tests/audit.rs`) asserts that a portfolio-history call
logs the row count and **not** the underlying values. See the plan §"Logging"
for the rationale.

## Alerting (M8)

The plan's *Observability → Minimum alerts* (scoped to live refresh) are wired by
[`deploy/alerting/fineco-alert.sh`](../deploy/alerting/fineco-alert.sh), driven by
`fineco-alert.timer` (on boot + every ~3 min). Each scan reads only **new** events
since the last run (a journald cursor + last-seen counters under
`/var/lib/fineco-alert`) and pipes any fired alert — a payload-free one-liner
(type + count + timestamp) — to the notifier command in `/etc/fineco/alert.env`
(`FINECO_ALERT_COMMAND`, default `logger -t fineco-alert`). The alerts come from
the gateway audit journal (live-refresh budget/auth/circuit/spike plus
authenticated-market auth/upstream/circuit/recovered-session events), the
nftables deny **counters** (worker egress deny + gateway egress deny), the
worker's `NRestarts` (restart loop), and the scheduled-refresh one-shot journal
(a failed unattended portfolio refresh) — none reads the DB. See
[`docs/LIVE-REFRESH-GATES.md`](LIVE-REFRESH-GATES.md) for the per-alert source map.

```
install -Dm0755 deploy/alerting/fineco-alert.sh  /usr/local/libexec/fineco-alert
install -Dm0644 deploy/systemd/fineco-alert.service /etc/systemd/system/fineco-alert.service
install -Dm0644 deploy/systemd/fineco-alert.timer   /etc/systemd/system/fineco-alert.timer
# Optional: a notifier + thresholds (defaults to journald if absent).
install -Dm0640 -o root -g root /dev/stdin /etc/fineco/alert.env <<< "FINECO_ALERT_COMMAND='logger -t fineco-alert'"
systemctl enable --now fineco-alert.timer
```

Verify (induce a worker egress deny, then run one scan):

```
runuser -u fineco-worker -- curl -s --max-time 5 https://1.1.1.1/ ; true   # denied by egress (expected)
systemctl start fineco-alert.service
journalctl -t fineco-alert -n5 -o cat                                      # the default journald sink
```

## Backup & restore

The SQLite store under `/var/lib/fineco-helper` is the only stateful asset. M8
adds a **daily encrypted backup** + a **restore drill** (plan §"Backup And
Restore") — required before the live worker writes real private rows.

**Pipeline** ([`deploy/backup/fineco-backup.sh`](../deploy/backup/fineco-backup.sh),
driven by `fineco-backup.timer`, run as `fineco-store`):
`fineco-helper backup` does an online `VACUUM INTO` (a consistent copy, no host
`sqlite3` needed), then `gzip`, then `age -r <public recipient>`. The binary itself
stages the copy in a private `0700` dir and writes it `0600` before publishing
(so even a manual `fineco-helper backup` under a permissive umask is never exposed);
the pipeline additionally keeps the plaintext copy only in a private `mktemp` dir
removed on exit. Output lands in
`/var/backups/fineco-helper/{daily,weekly,monthly}/` with retention **7 daily / 8
weekly / 12 monthly**.

**Keys.** Only the **age PUBLIC recipient** lives on the CT (in `backup.env`); the
**private identity stays OFFLINE** (a recovery host / your password manager) — so a
host compromise cannot decrypt the backups. The host volume is also encrypted at
rest (LUKS/encrypted ZFS) as the primary control.

**Install** (added to the Install block above):

```
install -Dm0755 deploy/backup/fineco-backup.sh  /usr/local/libexec/fineco-backup
install -Dm0755 deploy/backup/fineco-restore.sh /usr/local/libexec/fineco-restore
install -Dm0644 deploy/systemd/fineco-backup.service /etc/systemd/system/fineco-backup.service
install -Dm0644 deploy/systemd/fineco-backup.timer   /etc/systemd/system/fineco-backup.timer
install -d -m0700 -o fineco-store -g fineco-store /var/backups/fineco-helper
# backup.env: FINECO_BACKUP_AGE_RECIPIENT=age1...  (+ optional FINECO_BACKUP_DIR)
install -Dm0640 -o root -g fineco-store /dev/stdin /etc/fineco/backup.env <<< 'FINECO_BACKUP_AGE_RECIPIENT=age1...'
systemctl enable --now fineco-backup.timer
```

**Restore drill** (run monthly, on a clean/recovery host with the offline identity
— [`deploy/backup/fineco-restore.sh`](../deploy/backup/fineco-restore.sh)):

```
fineco-restore.sh /var/backups/fineco-helper/daily/fineco-<date>.sqlite.gz.age restored.sqlite <age-identity>
# verify: bring it up read-only and check readiness
FINECO_DB_PATH=restored.sqlite FINECO_QUERY_SOCKET=/tmp/r.sock FINECO_POLICY_PATH=<policy> \
  fineco-helper store-server &    # then a portfolio_get_freshness over /tmp/r.sock returns data
```

The restore script refuses to overwrite an existing target, so it can never
clobber a live DB. A live restore = stop `fineco-store-server`, put the restored
file at `/var/lib/fineco-helper/fineco-history.sqlite` (owner `fineco-store`, mode
`0600`), start it.
