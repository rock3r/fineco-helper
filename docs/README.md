# docs/

Committed, durable documentation of `fineco-helper` **as built**. This
complements — and must not duplicate — the spec.

Three tiers, kept distinct:

- **Spec / intent / security reasoning** — the authoritative *what to build and
  why*, maintained as a **private design document** (not part of this repository).
- **Progress / decisions / next step** — a **private worklog** (not published).
- **System as built** → this folder (committed). *How the code is actually
  structured and the conventions it follows.*

Rule: every Markdown doc under `docs/` is listed in the index below. When a change
alters structure, conventions, architecture, or the test/CI/E2E setup, update the
matching doc in the **same session** (stale docs are a regression, per
[`AGENTS.md`](../AGENTS.md)). Add a new area doc when a subsystem grows enough to
need one, and list it here. Do not copy the plan's security spec into `docs/` —
link to it.

## Index

| Document | Use it for |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Crate/module map, process topology, dependency direction, as-built invariants |
| [CONVENTIONS.md](CONVENTIONS.md) | Rust style, error handling, logging discipline, input validation, file/crate placement, git workflow |
| [TESTING.md](TESTING.md) | TDD flow, test layering, Docker E2E harness, mock servers, gate → test mapping |
| [DEPLOYMENT.md](DEPLOYMENT.md) | LXC deployment shape: process topology, users/group, socket permissions, systemd hardening, egress firewall, backup/restore (artifacts in [`deploy/`](../deploy/)) |
| [SELF-HOSTING.md](SELF-HOSTING.md) | From-scratch runbook for deploying your **own** instance (hardened Proxmox LXC + best-effort Docker): prerequisites, build, provision, configure, Cloudflare Tunnel + Access, firewall, verify, backups. Config templates in [`deploy/config/`](../deploy/config/) |
| [LIVE-REFRESH-GATES.md](LIVE-REFRESH-GATES.md) | Remote-Live-Refresh P0 gate-status ledger + the named alerts and their verification sources |
| [CONNECTORS.md](CONNECTORS.md) | Connecting ChatGPT & Claude as remote MCP connectors: transport, OAuth-via-Cloudflare-Access auth, dual-pin, per-client setup, and the data-egress security notes |
