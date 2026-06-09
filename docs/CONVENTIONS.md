# Conventions

Rust and repo conventions for `fineco-helper`. Security invariants themselves
live in the plan and `AGENTS.md`; this doc covers *how we code to them*.

## Errors

- Use typed errors (e.g. `thiserror`); reserve `anyhow` for top-level glue, not
  library crates.
- **No `unwrap`/`expect`/`panic!` in production paths.** They are allowed in tests
  and in clearly-unreachable invariants documented with a comment.
- Everything returned over MCP passes through the **safe error envelope**
  (`code` / `class` / `retryable` / `safe_message`). Never surface raw upstream
  Fineco/enrichment bodies, stack traces, or headers to the client.

## Logging

- Log only allowlisted metadata (timestamp, auth id, tool, data class,
  success/failure, safe error code, durations, result counts, snapshot age,
  rate-limit decisions).
- **Never** log credentials, cookies, tokens, payloads, account/transaction ids,
  prices, values, or tax data. An anti-leak test asserts this (see TESTING.md).

## Input validation

- Strict, typed schemas at every boundary; deny unknown fields; bound string
  lengths, array sizes, and date ranges; bound response sizes.
- Forbidden client-supplied fields: `url`, `path`, `headers`, `sql`, `method`,
  `shell_command`, `raw_json_rpc_method`, `userAgent`, `validateSource`,
  free-form command strings. Enrichment takes an instrument identifier; the
  server builds the allowlisted URL.

## Formatting & lint

- `cargo fmt` (config in `rustfmt.toml`), `cargo clippy -- -D warnings`.
- Do not weaken `clippy.toml` / `deny.toml` / `rustfmt.toml` to dodge a finding;
  fix at source (see `AGENTS.md`).

## File / crate placement

- **Product code → `crates/`.** The shipped binary is `crates/fineco-helper`.
  Product crates are added as the milestones that need them land: `fineco-core`
  (leaf), `fineco-store`, `fineco-refresh` (M1/M2), `fineco-worker` (the
  credential holder) and `fineco-market` (credential-free) at M3; the gateway at
  M4.
- **Test-only harness → `e2e/`** — the mock servers, the std-only `httptiny`
  helper, the `smoke` driver, and `fixtures/`. Harness crates are
  `publish = false` and must never be a **normal/build** dependency of product
  code. They may be **dev-dependencies** of a product crate's integration tests
  (e.g. the worker/market tests drive the real client against the mocks over a
  socket) — dev-dependencies are excluded from the shipped build graph.
- Each crate inherits the shared edition / rust-version / license and the
  workspace lints via `*.workspace = true` and `[lints] workspace = true`.
- **Add dependencies only when needed, not up front.** Introduce a crate only in
  the change that uses it, and prefer keeping the credentialed path's dependency
  set minimal.

## Git

- **No conventional-commit prefixes** (`feat:`/`fix:`/`docs:` …). Plain,
  descriptive messages.
- Commit/push only when the owner asks. Land work on `main` through a reviewed
  worktree branch; never commit directly to `main`.
