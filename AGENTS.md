# AGENTS.md

Operating rules for any agent working in this repo (Claude Code implements; Codex /
subagents review). Rules only — the spec, progress, and as-built reference live in
the documents this file indexes.

`fineco-helper` is a hardened single Rust binary exposing an **owner-only remote
MCP** over read-only Fineco data + a local SQLite history + third-party enrichment.
Not multi-tenant; the **service** has no public surface (owner-only behind Cloudflare
Access). The **source repo is public** — never commit secrets or personal/infra detail
(see the leak rule under Security invariants). Work lands on **`main`** via reviewed
worktree branches (below).

## Read first, every session (before any other action)

Two **local, gitignored** documents under `.plans/` govern the work — read **both in
full** before writing or modifying any code:

| Document | Use it for |
| --- | --- |
| `.plans/remote-mcp-security-plan.md` | Authoritative spec: architecture, data classes, secret boundaries, tool surface, forbidden fields, logging rules, gates, security invariants. Build to it; never deviate silently. |
| `.plans/worklog.md` | Running progress: milestones, decisions, open threads, gate status, next action. Session-to-session memory — keep it current, prune stale notes. |

If the plan is wrong or underspecified, **stop, propose the change to the owner, and
wait** — do not code around it.

## As-built docs (the index)

Committed reference lives in [`docs/`](docs/README.md) — keep it accurate (stale docs
are a regression). Don't duplicate the plan into `docs/`; link to it.

| Doc | Covers |
| --- | --- |
| [docs/README.md](docs/README.md) | Doc index + the tier model (plan = spec, worklog = progress, docs = as-built) |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Crate/module map, process topology, dependency direction, invariants |
| [CONVENTIONS.md](docs/CONVENTIONS.md) | Rust style, error handling, logging, validation, file placement, git workflow |
| [TESTING.md](docs/TESTING.md) | TDD flow, test layering, Docker E2E harness, gate → test mapping |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | LXC topology, users/sockets, systemd hardening, egress firewall, backup/restore |
| [SELF-HOSTING.md](docs/SELF-HOSTING.md) | From-scratch runbook (Proxmox LXC + Docker) |
| [CONNECTORS.md](docs/CONNECTORS.md) | ChatGPT/Claude connectors: OAuth-via-Access, dual-pin, connector tool scoping |
| [LIVE-REFRESH-GATES.md](docs/LIVE-REFRESH-GATES.md) | P0 gate ledger + named alerts and their sources |

When a change touches a surface a doc describes, update that doc (and `docs/README.md`
for a new doc) in the **same session**.

## Non-negotiables

- **TDD red → green.** Write the failing test first; run it; prove it fails for the
  right reason; implement the minimum to pass; re-run to green; refactor.
- **Never weaken a lint/CI gate to dodge a finding** — `clippy.toml`, `deny.toml`,
  `rustfmt.toml`, `rust-toolchain.toml`, or any CI gate. Fix at the source; if you
  can't, surface it and wait. Avoid `#[allow(...)]`, audit/deny ignores, and new
  `unsafe` (no new `unsafe` without an explicit, reviewed justification).
- **Worktree per task**, under the gitignored `.worktrees/`
  (`git worktree add .worktrees/<slug> -b wt/<slug> main`). Merge back into `main`
  only when green + reviewed + gated, then remove it. **Never commit directly to
  `main`** — land work through a reviewed worktree branch; **keep `main` always green.**
- **Two review passes before every merge:** `codex:review` (adversarial, on the
  milestone diff) and the **alignment-review subagent** (diff vs the plan's
  architecture / data classes / secret boundaries / tool surface / forbidden fields /
  logging / gates). Fix every confirmed finding; reviewers never write product code.
- **Scope / regressions.** Changes relate to the session's milestone; unrelated
  changes only with explicit owner consent. Any unrequested behavior change is a
  regression — flag it. Never leave a feature broken (except phased work explicitly
  agreed with the owner). Refactors must not change behavior.

## Security invariants (never break)

- The internet-facing gateway never holds Fineco credentials/cookies, never reads the
  SQLite DB or backups, never reaches the live socket.
- No generic proxy; no client-supplied `url`/`path`/`headers`/`sql`/`method`/
  `userAgent`/`validateSource`. Enrichment takes an instrument identifier; the server
  builds the allowlisted URL; fetched content is parsed, never executed.
- No payloads or secrets in logs (anti-leak test required); all errors pass through
  the safe error envelope.
- The three secrets stay separate: Cloudflare Access (client → gateway), 1Password
  token (worker → 1Password), Fineco credential (worker → Fineco).
- Read-only: no trading or mutation, ever.
- **Never leak personal or infrastructure detail into anything committed or public.**
  No real hostnames, domains, IPs / LAN addresses, emails, account / tenant IDs, the
  enrichment host, or owner-specific deployment specifics — in code, tests, docs,
  fixtures, config examples, commit messages, PR/issue text, or git history. Always use
  placeholders (`<your-host>`, `<team>`, `<ctid>`, `you@example.com`). The repo is
  **public** — treat every commit as published, and don't paste real values into chat
  that might land in a commit. Real values live ONLY in gitignored config (`.plans/`,
  `deploy/config/*.env`, `e2e/spike/cf-spike.env`).

## Owner approval required (never do unprompted)

- Opening / closing / merging a PR, or any merge to **`main`**.
- Anything touching the **real** Fineco / 1Password / Cloudflare account.
- Adding any **new dependency to the credentialed path**.
- Committing to a branch other than the one the current task works on.

"The owner asked a question about approach" is not approval. Commit or push only when
the owner asks.

## Working style

- Minimize interruptions: hand off a milestone and move on. Clarify upfront (ask all
  questions at once) or not at all; mid-task prefer a safe assumption and note it.
- After ~3 failed attempts at one approach, revert and try a structurally different
  one — don't stack tentative changes.
- Be explicit about the working directory; `cd` to an absolute path before operating
  in another worktree and stay there.
- Prefer dedicated tools over `bash` for file work (Read/Edit/Write/Grep); **never use
  `bash` to write or modify files** (`echo >`, `cat >`, `sed -i`). Keep `bash` atomic
  and read-only where practical.
- Copiable blocks (findings, spec patches, ready-to-paste prompts) use 4-space-indented
  code blocks, never top-level fences.
- No conventional-commit prefixes (`feat:`/`fix:`/`docs:`); write plain, descriptive
  messages.
- If a pull breaks something upstream, assume the owner wants it fixed (CI won't go
  green otherwise) and say what broke; if the breakage is large or ambiguous, stop and
  ask before proceeding.

## Tooling

    cargo build
    cargo nextest run                                    # or: cargo test
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo audit
    cargo deny check

Toolchain pinned via `rust-toolchain.toml`. E2E runs a local Docker topology (see
[TESTING.md](docs/TESTING.md)). CI (GitHub Actions) runs fmt + clippy + audit + deny +
tests + build; green is required before anything merges to `main`.
