# Docker deployment (best-effort)

A `docker compose` topology for running `fineco-helper` in containers. **The
hardened Proxmox-LXC path ([`docs/SELF-HOSTING.md`](../../docs/SELF-HOSTING.md))
is the security reference** — use Docker for convenience/testing, and read the
caveats below before exposing it.

## Build + run

    # 1. Build the binary (x86_64/glibc) and the runtime image, from the repo root:
    deploy/build/build.sh
    docker build -f deploy/docker/Dockerfile -t fineco-helper:latest .

    # 2. Provide your config — copy the templates and fill them in:
    mkdir -p deploy/docker/config
    cp deploy/config/private-worker.env.example deploy/docker/config/private-worker.env
    cp deploy/config/access.env.example         deploy/docker/config/access.env
    cp deploy/config/enrichment.env.example     deploy/docker/config/enrichment.env   # optional
    cp deploy/config/cloudflared.env.example    deploy/docker/config/cloudflared.env
    cp deploy/policy.json                        deploy/docker/config/policy.json
    #   …then edit each (see deploy/config/README.md). deploy/docker/config/ is gitignored.

    # 3. Set up your Cloudflare Tunnel + Access (identical to the LXC path,
    #    SELF-HOSTING.md step 5; Host header → 127.0.0.1:8799), then:
    docker compose -f deploy/docker/docker-compose.yml up -d

## How the security model maps to Docker

- **Gateway can never reach the live (credential) socket** — preserved by **volume
  separation**, not group isolation: the live socket lives in the `fineco-live`
  volume, which is mounted only in `worker` and `store-server`. The gateway mounts
  `fineco-ipc` (cached-query + refresh) only, so it has no path to the worker's
  socket. Likewise the worker never mounts `fineco-ipc`.
- **No DB / credentials in the gateway** — it mounts neither the data volume nor
  the credential env.
- **Per-service hardening** — `cap_drop: [ALL]`, `no-new-privileges`, a read-only
  rootfs (writable data only via the named volumes + a `/tmp` tmpfs), and the
  store-server runs with `network_mode: none`.

## What Docker does NOT reproduce (vs the LXC)

- **Three OS users.** The compose runs all three processes under one uid
  (`10001`). The container + volume boundaries still enforce the critical
  separations above, but the processes are not user-isolated from each other the
  way the LXC's `fineco-store` / `fineco-gateway` / `fineco-worker` are.
- **systemd sandboxing.** There is no equivalent to the units'
  `SystemCallFilter` / `Protect*` / `Restrict*` seccomp+namespace hardening. The
  `cap_drop`/`no-new-privileges`/read-only-rootfs options are the closest Docker
  primitives, not a replacement.
- **Per-uid egress pinning.** The LXC pins the worker's egress to the resolved
  Fineco IPs with nftables `meta skuid`. Docker has no per-uid pinning — the
  worker reaches Fineco over the bridge network. **Constrain its egress yourself**
  (a firewall on the Docker host, an egress proxy, or a locked-down user-defined
  network) if you need that boundary. The app-layer host pin (HTTPS + SHA-256
  enrichment-host allowlist) and the read-only/no-trade design still hold.

If those tradeoffs matter for your exposure, deploy the LXC path instead.
