# Testing

## TDD red → green

Write the failing test first, prove it red, implement the minimum to green, then
refactor. Full policy in `AGENTS.md`. Every new test must have been seen failing
before its production code existed; if unsure, revert the production change and
confirm the test goes red.

## Layers

- **Unit** — pure logic (parsing, matching, schema validation, error mapping).
  Fast, no I/O.
- **Integration** — a crate's public boundary against mock HTTP servers and a
  temp SQLite DB.
- **E2E** — the built binary running the deployment topology under Docker.

Use `cargo nextest run` (fallback `cargo test`).

## E2E harness (Docker)

Lives in `e2e/`. `./e2e/run.sh` builds one image (`e2e/Dockerfile`, pinned
toolchain) and brings up the compose topology (`e2e/docker-compose.yml`),
exiting with the smoke driver's status (`--abort-on-container-exit
--exit-code-from smoke`). CI runs the same script in the `docker e2e` job.

Topology:

- **`mock-fineco`** — models the real Fineco endpoints: a `POST` login that
  issues a session cookie, cookie-gated private reads (positions, transactions,
  tax) that return `401` with no data when unauthenticated, the auth-free public
  ETF list, and `/healthz`. Canned synthetic fixtures in real Fineco shapes.
- **`mock-enrichment`** — canned synthetic stock page under the real
  `/stocks/<slug…>` path, embedding a parseable `window.__REACT_QUERY_STATE__`
  plus a never-run `<script>`, + `/healthz`.
- **`store-server`** + **`gateway`** (M4) — the real product binary as the
  two-process boundary: `store-server` (the `fineco-query` worker) owns the empty
  SQLite store and answers cached reads on a snapshot-query Unix socket in a
  shared volume; `gateway` binds **loopback only**, serves MCP over axum, and
  reaches the store only over that socket. Both load the baked
  `e2e/fixtures/policy.json` capability policy.
- **`smoke`** — waits for both mock servers, asserts the public ETF list, asserts
  an unauthenticated private read is `401` with no leaked data, asserts the
  enrichment page, and (M4) drives a real **MCP session** through the gateway:
  initialize, a policy-**granted** tool (`portfolio_get_freshness` → structured
  `missing` result, proving the gateway→socket→store-server round-trip), and a
  policy-**denied** tool (`portfolio_get_latest_snapshot_summary` → refused). It
  shares the gateway's network namespace to reach the loopback bind. Sets the
  run's exit code.

All harness code is std-only (`e2e/httptiny`, GET + a minimal POST for the MCP
handshake), so the E2E path adds **zero** crates to the supply chain. Beyond the
Docker smoke run, the M3 worker and market crates have **integration tests that
drive the real `ureq` client against these mocks over an ephemeral-port socket**
(`httptiny::serve_listener`): `crates/fineco-worker/tests/reads.rs` (login +
portfolio/orders/tax + input bounds) and `crates/fineco-market/tests/client.rs`
(enrichment fetch, unsafe identifier + off-allowlist rejection, ETF list). The
gateway + store-server tool dispatch is additionally covered by socket-backed
integration tests (`crates/fineco-gateway/tests/`, `crates/fineco-query/tests/`).

Never use real Fineco/1Password/Cloudflare credentials in tests or CI — fixtures
and mocks only, and the fixtures are clearly-marked synthetic data. Real
accounts appear only in owner-supervised phases (M6+).

## Gate → test mapping

Each row of the plan's *Production Gate Checklist* must map to an automated check.
Maintain the mapping here as gates are implemented.

Implemented:

- **Shareable contract** (gate: *fixture outputs contain no values, quantities,
  prices, tax, order, or account data*) → `crates/fineco-store/tests/report.rs`.
  A snapshot is captured with distinctive 5-digit absolutes + a distinctive hash;
  the shareable CSV is asserted to contain **none** of them, to carry only the
  allowed columns, and to still include names/ISINs/percentages. Reinforced
  structurally: `ShareableRow` has no field for any forbidden datum.
- **Enrichment parse-only** (gate: *fetched HTML/JS is parsed as data and never
  executed*) → `crates/fineco-market/tests/enrichment.rs`. Structural: the parse
  path is `extract → normalize → serde_json` with no `eval`/`Function`/JS engine
  anywhere; tests assert a code-looking embedded value is kept verbatim as data
  and that the page's never-run `<script>` has no effect.
- **Enrichment bounds** (gate: *external free text + raw score/metric output are
  size-limited and sanitized*) → same file: oversized page rejected, long text
  truncated, per-section metrics capped, non-primitive values dropped. Plus
  `crates/fineco-market/tests/gzip_bomb.rs` (a gzip body that inflates past the
  **decompressed** cap is rejected, not buffered whole — the `.limit()` cap is on
  compressed bytes only) and unit tests in `report.rs`/`client.rs` (metric/score
  **keys and string values** and the ETF list's string fields are control-stripped
  and length-bounded, like the company free-text fields).
- **Enrichment source allowlist** (gate: *callable only by identifier; fixed host
  allowlist*) → same file + `crates/fineco-market/tests/client.rs`: https + host
  SHA-256 pin + `/stocks/` path; the client builds the URL server-side from a
  validated slug (no client `url`), and an unsafe identifier or off-allowlist
  host is rejected before any request.
- **No generic-proxy / forbidden fields** (gate: *internal protocol is a command
  allowlist; no `url`/`sql`/`headers`/…*) → `crates/fineco-ipc/tests/protocol.rs`:
  unknown commands, proxy-shaped commands, smuggled envelope fields, and unknown
  params are all rejected; bounds are enforced.
- **Capability allowlist** (gate: *every tool allowlisted; owner can call expected
  tools and cannot call generic/proxy tools; unknown/wildcard caps fail*) →
  `crates/fineco-ipc/tests/capability.rs` (owner grants, narrow-policy denials,
  generic/wildcard rejection, schema validation, full command→capability map) +
  enforcement at both ends: `crates/fineco-gateway/tests/tools.rs` (no-policy and
  narrow-policy tool denials) and `crates/fineco-query/tests/handler.rs` (worker
  independent denial). End-to-end in the Docker smoke MCP check (granted +
  denied tool).
- **Gateway cannot read the DB / hold credentials** (gate: *gateway never holds a
  DB handle or credentials*) → structural: `crates/fineco-gateway/tests/architecture.rs`
  fails if `fineco-store`/`fineco-worker` is in the gateway's runtime dependency
  closure.
- **Non-loopback bind refused** (gate: *non-loopback bind is refused unless
  authenticated remote mode is explicit*) → `crates/fineco-helper/tests/serve.rs`:
  `resolve_loopback_bind` accepts loopback v4/v6 and refuses `0.0.0.0`/public/`[::]`;
  `GatewayConfig::from_env` refuses a non-loopback `FINECO_GATEWAY_BIND`.
- **Cloudflare Access JWT verification** (M6; gate: *Access JWT verified —
  issuer, audience, expiry, signature via JWKS; spoofed `Cf-Access-*` headers
  fail*) → `crates/fineco-gateway/tests/access.rs` (12 cases: valid→`owner`,
  expired, wrong iss/aud, unknown kid, tampered sig, HMAC alg-confusion,
  owner-pin, garbage, JWKS fetch+verify, insecure-URL refusal, key-rotation
  swap) + `crates/fineco-helper/tests/access_middleware.rs` (the axum middleware:
  missing/invalid→401, valid owner→200).
- **Host/Origin validation** (M6; gate: *disallowed Host/Origin and
  DNS-rebinding-style requests fail*) → `crates/fineco-gateway/tests/origin.rs`:
  with `allowed_origins` set, a disallowed `Origin`→403, allowed→200,
  missing-Origin (native client)→200; `Host` is validated to loopback by rmcp's
  default.

Further security-focused coverage:

- shareable output omits **names from Fineco account headers** (leakage tests
  cover portfolio absolutes and the account-header name case);
- no secrets/payloads in logs (anti-leak fixture scan);
- the **real-account** Access checks (the Cloudflare Access spike,
  owner-supervised): direct-origin unreachable from LAN/WAN,
  interactive-SSO-vs-service-token, target MCP client compatibility, tested
  revocation.
