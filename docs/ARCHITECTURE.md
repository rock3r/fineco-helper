# Architecture

How the **code** is structured. The *why* (threat model, security reasoning,
gates) lives in the project's design spec — a private planning document kept
outside this repository. This doc records the as-built map, not the rationale.

## System shape

A single self-contained Rust binary with subcommands/roles. Per the plan's
topology:

- **gateway** — internet-facing (behind Cloudflare Access); Streamable HTTP MCP;
  holds no Fineco credentials, no DB handle to the SQLite file, no live socket.
- **store-server** — owns the SQLite snapshot-store; answers cached reads on the
  snapshot-query socket; and (M8+) **hosts the controller** on dedicated
  `refresh-control.sock` and, only when explicitly configured,
  `market-control.sock` sockets.
- **private-worker** (M8) — the credential holder; performs allowlisted Fineco
  reads and serves them on `fineco-live.sock`. Holds **no** DB.
- Enrichment (third-party stock data) runs in the **gateway/market path**, never
  in the credential-holding worker.

Cached-read deployment = gateway + store-server over the snapshot-query socket
(no credentials reachable from the gateway). M8 **live refresh** adds the
private-worker process and the controller (on the store-server) so the chain is
**gateway → `refresh-control.sock` → controller → `fineco-live.sock` → worker**.
Authenticated Fineco market reads use the sibling chain **gateway →
`market-control.sock` → controller → `fineco-live.sock` → worker**. The gateway
never touches `fineco-live.sock`; the market-control socket is explicit-only and
not enabled by the checked-in deployment policy. See the plan's
*Single-Owner Simplification*,
*Local IPC*, and *Process Boundaries* sections.

## Crate / module layout

Cargo workspace (`Cargo.toml`, `resolver = "3"`, edition 2024, toolchain pinned
to 1.96 via `rust-toolchain.toml`). The workspace is **zero-external-dependency** at its core;
crates are added only as needed — `rusqlite` (bundled) +
`hmac`/`sha2` in the store (M1/M3), and `ureq` (rustls) + `serde`/`serde_json`
in the Fineco/market fetch paths (M3).

Product (`crates/`):

- **`crates/fineco-helper`** — the single product binary (`fineco-helper`) plus
  its library (`fineco_helper`). Dispatches one of **three long-running roles**
  from `argv` (`serve` module): **`gateway`** hosts the MCP service over **axum**,
  bound to loopback only (`resolve_loopback_bind` refuses any non-loopback bind
  until the M6 authenticated-remote mode); **`store-server`** opens the store and
  answers cached reads on the snapshot-query socket, and — when
  `FINECO_REFRESH_SOCKET` + `FINECO_LIVE_SOCKET` are set (both-or-neither) — also
  spawns the **controller** (M8+, `controller` module) on a refresh-control
  thread and, only when `FINECO_MARKET_CONTROL_SOCKET` is explicitly set, a
  market-control thread; market-control is not a standalone mode and requires
  the same refresh-control + fineco-live configuration; and
  **`private-worker`** (M8) builds the
  credential worker and serves `fineco-live.sock` (`serve_live`), reading its
  Fineco creds from its own env (`FINECO_USER_ID`/`FINECO_PASSWORD`), never the
  config getter. Two auxiliary **one-shot** subcommands round out the binary:
  **`backup`** (`VACUUM INTO` an online DB copy) and **`refresh <area>`** — a
  timer-driven refresh-control *client* that asks the controller to perform a
  scheduled live refresh (only `portfolio`; holds no credentials).
  The gateway/store-server read a **required** capability-policy JSON file
  (`FINECO_POLICY_PATH`, `load_policy`, fail closed) and the rest of their config
  from the environment; the enrichment host stays config-only
  (`FINECO_ENRICHMENT_BASE`/`_HOST_HASHES`/`FINECO_ETF_URL`). Depends on
  `fineco-gateway` + `fineco-query` + `fineco-ipc` (+ core/market/store) and —
  for the M8 worker/controller roles — `fineco-worker` + `fineco-refresh` +
  `fineco-live` (these enter only the binary, never the gateway crate's closure).
- **`crates/fineco-helper` → `controller`** (M8+) — the **controller**:
  `RefreshController<F>` (generic over the fetcher — the live client in prod, a
  fake in tests; holds the `Store` behind a `Mutex`). `handle()` enforces order
  per request: capability re-check (fail closed, independent of the gateway) →
  bounds re-validate → `refresh_preflight` (cooldown/budget/circuit; denials
  create **no** `job_runs` row) → one `refresh_*` call → `RefreshOutcome`
  (op/snapshot **status only**, a row count never a value).
  `RefreshLimitsByArea::defaults` encodes the plan's per-area rate limits. The
  controller does not retry refresh by re-entering the live worker, because each
  worker call can perform a fresh Fineco login and must remain one admitted
  controller operation. This glue lives in the binary (not `fineco-refresh`) because
  it needs the `fineco-live` client, and `fineco-live` already depends on
  `fineco-refresh`.
  `handle_market_control()` separately re-checks `market.authenticated.read`,
  validates bounds, and forwards authenticated Fineco market reads to the
  same live client. Refresh and authenticated-market reads share the
  controller-local one-in-flight live operation lock so both paths coordinate
  Fineco logins; authenticated-market reads additionally enforce their own
  market-only 12 fresh logins/hour budget and 60s fresh-login cooldown, then
  finalize that gate from the worker's status-only session facts and return
  normalized market data only.
- **`crates/fineco-core`** (M2) — the **leaf** shared-types crate (no
  credential/DB/network deps). Holds the **safe error envelope** (`SafeError` /
  `ErrorClass` — boundary errors carry only safe fields) and the **freshness
  model** (`FreshnessState`, `freshness_from_age`, a hand-rolled exact
  ISO-8601-UTC→epoch parse), plus the shared provider-text sanitizer used by
  both external enrichment and authenticated Fineco market parsing. Everything
  depends *down* onto this; it depends on nothing.
- **`crates/fineco-store`** (M1) — the local SQLite history store
  (`rusqlite`, `bundled`). Owns the schema + migrations, typed snapshot capture,
  history queries, full/shareable report generation, `job_runs` recording + the
  refresh lock, integrated `freshness_for`, and health/readiness primitives.
  `rusqlite` is **not** exposed through its public API (no raw SQL crosses the
  boundary). Depends on `fineco-core`. Holds no credentials; in the minimum
  deployment it lives inside the worker.
- **`crates/fineco-refresh`** (M2) — **credential-free** local refresh
  orchestration: acquire the lock (`already_refreshing`), record a `job_runs`
  start, fetch via an **injected fetcher trait**, capture the snapshot, record the
  outcome. Depends on `fineco-core` + `fineco-store`; never holds credentials.
  Fetcher traits: `PortfolioFetcher` (stamps `captured_at` from the orchestrator's
  `now_iso`), the controller-side `OrdersFetcher`/`TaxFetcher`, and the
  worker-side store-free **`RawOrdersFetcher`** (yields un-hashed `RawOrder`s —
  the credential worker holds no DB key, so hashing is controller-side; see
  *Data & storage*). Orchestrators `refresh_portfolio`/`refresh_orders`/
  `refresh_tax` (each = one `job_runs` row), the pre-flight gate
  `refresh_preflight` (cooldown / daily budget (UTC day) / circuit breaker — a
  denial creates no row), and retry helpers that remain available to callers that
  can prove retries do not create extra Fineco logins.
- **`crates/fineco-worker`** (M3) — the **sole credential holder** and the only
  component that mints/holds a Fineco session cookie and reaches the live Fineco
  endpoints. Logs in and performs allowlisted read-only requests against
  **server-built URLs** (`FinecoEndpoints::production`/`for_base`; no
  client-supplied URL/path): positions summary (impl `PortfolioFetcher`),
  authenticated global instrument search (impl `MarketSearchLiveFetcher`, returns
  normalized candidates plus status-only session facts for the controller),
  order-monitor transactions (impl **`RawOrdersFetcher`** → `Vec<RawOrder>`, the
  **raw** `trans_id`; the worker holds **no** DB key, so it never hashes —
  hashing is controller-side; `days ≤ 30` + alphanumeric guards re-validated
  here), and tax carry-forward / minus-by-year (impl `TaxFetcher`; `YYYY-MM-DD`
  validated, `from ≤ to`). A global per-request HTTP timeout (`FINECO_HTTP_TIMEOUT`)
  surfaces a stalled endpoint as `fineco_timeout` (so it can't pin the refresh
  lock). Credentials arrive via a `CredentialSource` trait (env/config now,
  1Password at M6). Login is a two-step handshake mirroring the reference: a
  home-page **preflight** to collect bootstrap cookies, then the login POST. When
  the public home page sets **no** cookie (real Fineco's behaviour), the worker
  **mints synthetic public cookies** (`finecostat`/`XID`/`LBM`/`PORTALSESSIONID`/
  `gdate`/`store-sessionid`/`finecoLogin`) the WAF expects present — random/
  timestamped, non-secret, entropy from `/dev/urandom` (no added dependency) —
  and the reads replay that jar plus the session. Today the worker remains
  **stateless across calls** (login → use on the stack → discard), but market
  live responses already report status-only session facts (`login_performed`,
  `session_reused`, eviction/recovery flags, and optional `Max-Age`-derived
  expiry TTL) across `fineco-live` so controller-side budget/audit can govern
  future reuse without ever seeing cookies or handles. The Fineco **password and
  session cookies are zeroized on drop** (`zeroize::Zeroizing`, owner-approved
  credentialed dep), and the agent **ignores proxy env vars** (`.proxy(None)`)
  so an env-injected proxy can't reroute the credentialed login. Uses
  `ureq`+rustls. Depends on
  `fineco-core`, `fineco-ipc` (market-search types/trait), `fineco-store` (the
  `New*`/`RawOrder` types), `fineco-refresh` (the fetcher traits). No
  payloads/secrets logged; failures map to `SafeError`. Behind the live socket it
  is the server half of `fineco-live` (the binary's `private-worker` role).
- **`crates/fineco-ipc`** (M4) — the **internal command protocol** + Unix-socket
  transport shared by the gateway and the store-query worker. A strict,
  schema-first `Request` **command allowlist** (adjacently tagged JSON,
  `additionalProperties:false` at the envelope and params, bounded
  strings/numbers, validated at both ends) — there is no
  `url`/`path`/`headers`/`sql`/`method`/`userAgent`/`validateSource`/raw-RPC field
  anywhere in the types. Owns the typed reply DTOs (each derives
  `schemars::JsonSchema`), the safe-error wire envelope (`SafeErrorDto`),
  length-prefixed framing, the blocking `serve_blocking`/`Client`, and the
  **capability model** (`Capability`, versioned `Policy` with structural schema
  validation, `Request::required_capability`, `OWNER_AUTH_ID`). It also owns the
  **generic framing** (`write_message`/`read_message`, reused by `fineco-live`)
  and (M8+) the controller protocols: **refresh-control** for live refresh and
  **market-control** for authenticated Fineco market reads. `RefreshRequest`
  (command-enum, `deny_unknown_fields`, no forbidden field; bounds reuse
  `validate_order_request`/`validate_tax_range`), `RefreshOutcome` (op/snapshot
  **status only** — a row count, never a value), `serve_refresh_blocking`/
  `RefreshClient`, and the three `*.live.refresh` capabilities (owner-only; audit
  data class `credentialed_live`) cover refresh.
  `MarketControlRequest::{MarketSearchAsset,MarketGetAssetDetails}`,
  `MarketControlClient`, normalized `MarketSearchResult` /
  `MarketAssetDetailsResult`, status-only
  `MarketSessionStatus` / `MarketSearchLiveResult` /
  `MarketAssetDetailsLiveResult`,
  and `market.authenticated.read` (audit data class `authenticated_market`) cover
  Fineco search/details. Depends on `fineco-core`
  (+ `serde`/`serde_json`/`schemars`).
- **`crates/fineco-live`** (M8) — the **credentialed-boundary protocol** over
  `fineco-live.sock`, between the no-DB private worker (server) and the refresh
  controller (client), reusing `fineco-ipc`'s generic framing. `LiveRequest`/
  `LiveResponse` (command-enum, `deny_unknown_fields`, typed responses — no
  forbidden field); `handle_live_request` + `serve_live_blocking` (the worker
  server, re-validates structurally + via the fetchers' bounds); and `LiveClient`
  (the controller client) which impls `PortfolioFetcher`/`OrdersFetcher`/
  `TaxFetcher`/`MarketSearchLiveFetcher`/`MarketAssetDetailsLiveFetcher` — for orders it hashes the worker's
  `RawOrder`s into store-ready `NewOrder`s with the passed store's key, and for
  authenticated market reads it carries status-only session lifecycle facts
  alongside the normalized result. A worker
  `SafeErrorDto` is rebuilt to a
  `SafeError` via the canonical constructors (`safe_error_from_dto`), preserving
  `retryable`/`code` for the controller's retry+circuit logic without a public
  arbitrary-text `SafeError` constructor. Depends on `fineco-core` + `fineco-store`
  + `fineco-refresh` + `fineco-ipc`. **The gateway must NOT depend on this crate**
  (a build-time barrier; see *Dependency direction & invariants*).
- **`crates/fineco-query`** (M4) — the **store-query worker** behind the
  snapshot-query socket. Holds the `Store` handle + the freshness policy + the
  capability policy, and answers the cached-read commands (freshness, summary,
  full/shareable snapshot, history/allocation/position-history, orders, tax).
  Enforces the capability policy **independently** of the gateway (fail closed)
  and rejects market commands (served in the gateway). Depends on `fineco-core` +
  `fineco-store` + `fineco-ipc`. The internet-facing gateway never depends on
  this crate — it reaches these reads only over the socket.
- **`crates/fineco-gateway`** (M4) — the internet-facing **owner MCP gateway**
  (rmcp Streamable HTTP, a tower `Service`). Maps each cached tool to an
  `fineco_ipc::Request` dispatched over the snapshot-query socket via
  `fineco_ipc::Client` (`spawn_blocking`), and serves the credential-free market
  tools in-process via `fineco-market` (`Option<Arc<MarketClient>>`). Authorizes
  every tool against the loaded `Policy` before dispatch (fail closed without
  one). Holds **no** credentials, DB handle, or live socket. (M8) It also holds an
  `Option<Arc<RefreshClient>>` and serves the three
  `private_*_refresh_live_sensitive` tools by forwarding a `RefreshRequest` over
  **`refresh-control.sock`** (cap authorize → gateway-side bounds → `spawn_blocking`
  → audit; reply is op/snapshot status only); `None` → a safe "not configured"
  error. It also holds an `Option<Arc<MarketControlClient>>` and serves
  authenticated market tools by forwarding a `MarketControlRequest` over
  **`market-control.sock`** for `market_search_asset` and
  `market_get_asset_details`; these require `market.authenticated.read` and are
  hidden from connector defaults. The checked-in deployment policy intentionally
  leaves that capability ungranted until market live-session gates are complete.
  When stock details explicitly request `external_enrichment`, the gateway first
  resolves/fetches the requested Fineco sections through market-control, then
  appends the third-party enrichment section via the credential-free
  `fineco-market` client. If `external_enrichment` is the only requested section,
  the worker stops after Fineco search identity resolution rather than fetching
  default quote/profile/core detail endpoints. The supplemental fetch emits its
  own `external_enrichment` audit line and source entry; the credentialed worker
  never calls the enrichment host.
  Market-control audit logs include only status metadata (login/session booleans),
  never cookies or session handles. The gateway has **no** `fineco-live` client —
  it cannot reach the live socket by any path. Depends on `fineco-core` + `fineco-ipc` + `fineco-market` +
  `rmcp` — **never** `fineco-store`/`fineco-worker`/`fineco-live` (enforced
  structurally; see below). Tool surface: 17 read-only tools (cached reads,
  credential-free market reads, authenticated Fineco market reads, and the 3
  live-refresh tools); `portfolio_get_charts` stays **deferred** (no
  chart/time-series data is captured yet — the store holds
  snapshots/positions/orders/tax only).
- **`crates/fineco-market`** (M3) — **credential-free** market path: stock
  enrichment + the public zero-commission ETF list. Reaches **no** authenticated
  Fineco endpoint and holds **no** credentials. Enrichment is
  **parse-not-execute**: it extracts the embedded `window.__REACT_QUERY_STATE__`
  payload textually (no regex dep), normalizes the one JS-ism (`undefined` →
  `null` outside strings), and parses it with `serde_json` — there is no
  `eval`/`Function`/JS engine. Source URLs are restricted to a **SHA-256-pinned
  host** (`EnrichmentHostAllowlist` — hashes only, no plaintext host in source)
  with a fixed stock-page route. The MCP tool accepts a venue-qualified ticker
  (`<venue>/<symbol>` or `<venue>:<symbol>`), normalizes it to
  `/stock/<venue>/<symbol>`, and optionally verifies the parsed page against an
  `expected_isin` (plain ISIN or ISIN plus suffix). The server builds exactly one
  URL from a configured base + the validated identifier (no client `url`, no
  lookup/guessing, no `validateSource`/`userAgent`).
  The same report shape is also embedded in `market_get_asset_details` when a
  stock details request includes `external_enrichment`; Fineco identity remains
  canonical and cross-source identifier disagreements are bounded warnings.
  Output is bounded/sanitized. `MarketClient` uses `ureq`+rustls (redirects
  disabled). Depends on `fineco-core` (+ `serde`/`serde_json`/`sha2`).

E2E harness (`e2e/`, test infrastructure only — never shipped, all `publish =
false`):

- **`e2e/httptiny`** — std-only minimal HTTP/1.1 server + client shared by the
  harness. Zero external deps; deliberately not a general HTTP stack (client is
  GET plus a minimal POST — custom request headers + parsed response headers +
  body, enough to drive the MCP Streamable HTTP handshake — no TLS/redirects).
  The server captures request headers and can emit response headers (e.g.
  `Set-Cookie`) so the mocks can model authentication; `serve_listener` lets a
  test bind an ephemeral port and point a real client at it.
- **`e2e/mock-fineco`** — mock Fineco server: lib `route(&Request) -> Response`
  (the unit-testable contract) + a thin bin. Models the real endpoints: a `POST`
  login that issues a session cookie, cookie-gated private reads (positions,
  transactions, tax) that return `401` with no data when unauthenticated, and
  the auth-free public ETF list. Serves canned synthetic fixtures.
- **`e2e/mock-enrichment`** — mock third-party enrichment server: same lib+bin
  shape; serves a canned synthetic stock page under the slug route
  (`/stocks/<slug…>`). The page embeds a parseable `window.__REACT_QUERY_STATE__`
  plus a never-run `<script>` for parse-not-execute assertions.
- **`e2e/smoke`** — Docker E2E driver: asserts the mock servers serve their
  fixtures over the network, and (when `GATEWAY_URL` is set) drives a real MCP
  session through the gateway — initialize, a policy-**granted** tool call
  (`portfolio_get_freshness` → structured `missing` result over the empty store,
  proving the full gateway→socket→store-server round-trip), and a
  policy-**denied** tool call (`portfolio_get_latest_snapshot_summary` → refused).
  Exits non-zero on the first failure.
- **`e2e/fixtures/`** — canned **synthetic** data only (no real account data),
  embedded into the mocks via `include_str!`, plus `policy.json` (the E2E
  capability policy, baked into the harness image).

The M4 compose topology adds the real product binary as the two-process boundary
(`store-server` + loopback `gateway` sharing a socket volume); the `smoke`
service shares the gateway's network namespace so the loopback bind is reachable
(as a local `cloudflared` would be in production).

As-built invariant: the product binary depends on **no**
`e2e/` crate, and no `e2e/` crate depends on anything under `crates/`.

## Dependency direction & invariants

The dependency graph must make the security invariants structurally true, not
just conventionally:

- The gateway crate must **not** be able to depend on credential or
  DB-file-access code paths.
- Credential + Fineco-session handling lives only in the worker.
- Shared types (protocol, schemas, error envelope) live in a leaf crate with no
  credential/DB dependencies.

As-built edges (M4, extended at M8):

- `fineco-core` is the leaf (depends on nothing internal).
- `fineco-ipc` → `fineco-core` (protocol + transport + capability model + the M8
  refresh-control protocol; the shared boundary type, depended on by the gateway,
  the store-server, and `fineco-live`).
- `fineco-store` → `fineco-core`. `fineco-refresh` → `fineco-core` +
  `fineco-store` (credential-free; the fetcher is injected).
- `fineco-worker` (the **only** credential holder) → `fineco-core` +
  `fineco-ipc` + `fineco-store` + `fineco-refresh`. It is the single crate pulling the
  credentialed HTTP client; only `fineco-helper` (the `private-worker` role) and
  `fineco-live`'s server use it — the gateway reaches stored data over the socket,
  never via a dependency.
- `fineco-live` (M8) → `fineco-core` + `fineco-store` + `fineco-refresh` +
  `fineco-ipc` (the live-socket protocol + `LiveClient` + worker server). The
  **gateway must not depend on it** (it would otherwise gain a live-socket client).
- `fineco-query` → `fineco-core` + `fineco-store` + `fineco-ipc` (the
  store-server's read path; holds the DB handle).
- `fineco-market` → `fineco-core` only (no `fineco-store`, no credentials, no
  Fineco-auth path). Structurally incapable of reaching the credentialed worker
  or the DB.
- `fineco-gateway` → `fineco-core` + `fineco-ipc` + `fineco-market` + `rmcp`.
  It depends on **none** of `fineco-store`/`fineco-worker`/`fineco-live`, so it
  cannot hold a DB handle, credentials, or a live-socket client — it reaches
  stored data over `snapshot-query.sock`, live refresh over
  `refresh-control.sock`, and authenticated market reads over
  `market-control.sock`.
- `fineco-helper` (binary) → `fineco-gateway` + `fineco-query` + `fineco-ipc`
  (+ core/market/store) and, for the M8 worker/controller roles, `fineco-worker` +
  `fineco-refresh` + `fineco-live`. It composes the roles into processes; these
  M8 edges enter only the binary, never the gateway crate's closure.

**Structural enforcement (M4, extended M8):** `fineco-gateway`'s test
`gateway_runtime_closure_excludes_store_and_worker` walks the `cargo metadata`
dependency graph (normal/build edges only, excluding dev-deps) and fails if
`fineco-store`, `fineco-worker`, **or `fineco-live`** is reachable from the
gateway's runtime closure — so "the gateway never reads the DB / holds credentials
/ has a live-socket client" is a build-gated fact, not a convention. It rides the
normal `cargo nextest` CI step.

## Process topology & boundaries (M4, extended M8)

The cached-read deployment runs two processes over one local socket:

- **store-server** (`fineco-helper store-server`, the `fineco-query` worker) owns
  the SQLite store and answers cached reads on the snapshot-query Unix socket.
- **gateway** (`fineco-helper gateway`) binds **loopback only**, serves MCP, and
  reaches the store *only* over that socket. In production a local `cloudflared`
  is the sole client of the loopback bind (Cloudflare Access verification + the
  verified-identity→`auth_id` mapping land in M6); the gateway refuses any
  non-loopback bind outright.

**M8+ live refresh and authenticated market reads** add a third process, two
live-refresh sockets, and an optional authenticated market-control socket:

- **private-worker** (`fineco-helper private-worker`) holds the Fineco credentials
  and serves `fineco-live.sock` (the `fineco-live` protocol). No DB, no public
  listener.
- The **store-server also hosts the controller** (separate accept loops on
  threads, with its own `Store` connection) on `refresh-control.sock` and,
  when explicitly configured, `market-control.sock`.
- The chain is **gateway → `refresh-control.sock` → controller → `fineco-live.sock`
  → worker** for refresh, and **gateway → `market-control.sock` → controller →
  `fineco-live.sock` → worker** for authenticated market reads. The gateway joins
  the controller paths only; it is **never** a client of `fineco-live.sock`
  (build-time barrier + it holds no `LiveClient`). Each socket
  is prepared/bound/`chmod`-restricted (default `0600`; the multi-user LXC sets
  `0660` + the per-socket IPC group — the gateway is never in `fineco-ipc-live`).

**Internal protocols (`fineco-ipc` + `fineco-live`).** Each socket carries only a
typed command allowlist — schema-validated at **both** ends, bounded, safe-error
envelope on every failure, no generic-proxy/forbidden fields; length-prefixed
framing, 8 MiB cap, plus a per-connection **wall-clock read deadline** on every
serve loop (the per-read socket timeout re-arms on each byte, so a trickling peer
can't otherwise hold the single-consumer accept loop open). `refresh-control`
returns operation/snapshot **status only**
(never a payload); `fineco-live` returns the typed `New*`/`RawOrder` data the
controller captures.

**Capability model (`fineco-ipc::Policy`).** One versioned policy (a **required**
JSON file, schema-validated; unknown/wildcard capabilities and a zero version
fail closed) maps the single `owner` identity to an explicit per-tool capability
allowlist. It is loaded read-only by **both** the gateway and the store-server,
and enforced **independently** at each: the gateway authorizes before dispatch,
the worker re-checks before serving (defense in depth). No `auth_id` string is
trusted inside an IPC message. Capability→tool mapping is by sensitivity:
shareable-safe reads (freshness, shareable report, allocation history) need
`portfolio.shareable.read`; absolute-value reads (summary, full snapshot, history,
position history) need `portfolio.cached.full_read`; orders/tax/market have their
own capabilities. (M8) The three `*.live.refresh` capabilities are **owner-only**
and gate the live-refresh tools: the gateway authorizes before forwarding, and the
refresh controller re-checks **independently** against the same shared policy
before any preflight/refresh (the private worker re-validates the command + bounds
and relies on socket-group isolation; a signed identity-envelope / policy-version
cross-check at the worker is a documented hardening item).

## Data & storage

SQLite (`rusqlite`, statically linked via `bundled`) owned by the store-server,
in `crates/fineco-store`. The store-server opens it twice in the M8 live-refresh
deployment — one connection for the snapshot-query reader, one for the refresh
controller's writer — with `PRAGMA busy_timeout=5000` so a brief lock overlap
waits instead of failing `SQLITE_BUSY`. The credential worker holds **no** DB
handle.

- **Schema** = the plan's *Storage* tables (`src/schema_v1.sql`: `job_runs`,
  `assets`, `portfolio_snapshots`, `position_snapshots`, `fx_rates`, `orders`,
  `tax_carry_forward`, `tax_minus_by_year`) plus `store_meta` (schema v3,
  `src/schema_v3.sql`) holding the per-DB HMAC key, plus `data_captures` (schema
  v4) — a per-area `(data_area, captured_at)` capture marker. Column types/keys
  are chosen here (the plan lists columns): timestamps ISO-8601 UTC `TEXT`,
  values `REAL`, hashed ids stored as the hash `TEXT` only.
- **Empty-capture observability.** Orders/tax are flat tables keyed by
  `captured_at`, so a legitimately empty capture (no open orders, no carried
  losses) inserts no data row. `data_captures` records one marker per capture, so
  `latest_orders`/`latest_tax_*` and `freshness_for` derive "the latest capture"
  from the marker — an empty latest capture returns empty / reports its own
  timestamp instead of re-surfacing the previous non-empty capture. (Portfolio
  already gets this from its per-snapshot `portfolio_snapshots` header row.)
- **Migrations** — versioned via `PRAGMA user_version`; each version applied in
  one transaction on open; idempotent re-open; foreign keys enforced. Bump
  `SCHEMA_VERSION` + add a new `schema_vN.sql` step for future changes.
- **Capture/query/report** are typed: `Store` takes/returns domain structs, never
  raw SQL. Reports come in **full** (owner-only, absolute values) and
  **shareable** (`ShareableRow` — structurally only names/symbols/ISINs, weights,
  percentage performance), with leakage tests (see [TESTING.md](TESTING.md)).
- **Capture** covers portfolio (M1) plus **orders and tax** (M3). The store
  stores whatever hash string it is given; the worker computes ids via the
  store's HMAC hasher. **`trans_id_hash`** = `HMAC-SHA256(per-DB key, transId)`
  (`Store::hash_id`, schema v3 `store_meta` holds a per-DB random key — joins,
  not confidentiality; DB-at-rest encryption is the confidentiality control).
  Positions keep an unhashed `(instr_id, venue_system)` asset key, so
  `position_key_hash` stays unused/`None` pending a multi-lot revisit.
