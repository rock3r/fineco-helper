# Connecting ChatGPT & Claude (remote MCP connectors)

This gateway is a **remote MCP server over Streamable HTTP**. The same endpoint
that serves your CLI clients (Codex, Claude Code) also works as a **custom
connector** in ChatGPT and Claude — web and mobile. This doc covers the
transport, the auth model, the one-time owner-side Cloudflare setup, and the
per-client steps.

> **Privacy reality check.** When you invoke a tool from a ChatGPT or Claude
> connector, the tool's result is sent to OpenAI / Anthropic as part of the
> conversation — a real expansion of the data boundary from *owner-only* to
> *owner + whichever model provider you use*. To bound that, the connector
> (email/OAuth) channel is restricted to a **tool allowlist** that, by default,
> **excludes the four detailed-portfolio tools** that expose absolute € values
> plus the authenticated Fineco market-read tools
> (your CLI keeps the full set). Orders, tax, the shareable portfolio report,
> allocation history, freshness, the public/third-party market tools, and the
> credentialed live-refresh tools
> *are* reachable by default — the allowlist is configurable (see
> [Connector tool scoping](#connector-tool-scoping-configurable)). Decide, per
> provider, whether you are comfortable before enabling.

## Endpoint & transport

- **Connector URL:** `https://<your-host>/mcp`
- **Transport:** Streamable HTTP (JSON-RPC 2.0 over HTTP `POST` + SSE), rmcp 1.7
  — exactly what ChatGPT and Claude connectors expect. There is no stdio-only or
  SSE-only caveat to work around; the remote HTTP transport already exists.
- The MCP is served on **all** paths, so `/mcp` resolves directly (no redirect).
  Use `/mcp` for connectors; existing CLI clients that point at the bare host
  keep working unchanged.

## Auth model — OAuth via Cloudflare Access (the important part)

ChatGPT and Claude connectors authenticate with **OAuth** (the MCP authorization
spec). They do **not** send custom headers — so the
`CF-Access-Client-Id` / `CF-Access-Client-Secret` **service-token** headers your
CLI uses today will **not** work for them.

The gateway itself does **not** implement OAuth. **Cloudflare Access is the OAuth
layer:** the connector hits `https://<your-host>/mcp`, receives a `401` with a
`WWW-Authenticate` pointing at Cloudflare Access's OAuth discovery, runs the
browser OAuth login against your configured identity provider, and Cloudflare
then forwards authenticated requests to the gateway carrying the
`Cf-Access-Jwt-Assertion` JWT — which the gateway verifies exactly as it does
today (issuer / audience / expiry / signature + the owner-identity pin).

With the self-hosted-app Managed OAuth path above, the connector authenticates as
**your email**, so the gateway receives an `email` JWT and maps it to `owner` on the
**connector** channel — the scoped tool surface. (A `common_name`/service-token JWT
instead maps to the **CLI** channel and the *full* tool surface; that is what the MCP
Server Portal's admin-credential mode would forward, and one more reason not to use
the portal — see the warning below.)

### Dual-pin (set both)

The gateway pins the owner by identity (defense in depth behind the Access
policy). To let the **connectors** (OAuth → `email`) and your **CLI** (service
token → `common_name`) both authenticate as `owner`, set **both** on the gateway
(`/etc/fineco/access.env`):

    FINECO_OWNER_EMAIL=<your-Access-login-email>
    FINECO_ACCESS_OWNER_COMMON_NAME=<your-service-token-Client-ID>

A token matching **either** pin maps to `owner`; a token matching **neither** is
rejected (fail closed). Set only one to restrict to that single path. (Before
this milestone the two pins were mutually exclusive; now they coexist.)

## Connector tool scoping (configurable)

On a **dual-pin** deployment the two Access channels are scoped differently:

- The **CLI** channel (service token → `common_name`) always sees **every** tool.
- The **connector** channel (OAuth → `email`) is restricted to a tool
  **allowlist** — by default, every tool **except** the four detailed-portfolio
  tools that expose absolute € values and the authenticated Fineco market-read
  tools:
  `portfolio_get_latest_snapshot_summary`, `portfolio_get_latest_full_snapshot`,
  `portfolio_get_history`, `portfolio_get_position_history`,
  `market_search_asset`, `market_get_asset_details`.
  Those are hidden from `tools/list` and refused by `tools/call` on the connector
  channel. This also hides the `external_enrichment` details section by default,
  because that section is available only through `market_get_asset_details`;
  the standalone `market_get_stock_enrichment` wrapper remains the
  connector-visible credential-free enrichment path.

Everything else — `portfolio_get_freshness`, `portfolio_get_latest_shareable_report`,
`portfolio_get_allocation_history`, `orders_get_latest_monitor`, both tax tools,
the public/third-party market tools (`market_get_zero_commission_etfs`,
`market_get_stock_enrichment`), and all three `private_*_refresh_live_sensitive`
tools — is in the default connector set.

Override it per deployment with `FINECO_CONNECTOR_TOOLS` in `/etc/fineco/access.env`:

    # unset                  -> the default allowlist (all tools except the blocked set above)
    # FINECO_CONNECTOR_TOOLS="*"      (or "all")  -> no restriction (connectors get every tool)
    # FINECO_CONNECTOR_TOOLS="a,b,c"             -> exactly tools a, b, c

Notes: the connector channel — and therefore this scoping — exists whenever Access
has an **email/OAuth pin** (`FINECO_OWNER_EMAIL`), including a single-email-pin
deployment, not only dual-pin; setting the variable without an email pin is an
error. The default is an **explicit allowlist**, so a newly-added tool stays hidden
from connectors until listed (fail-safe), and an unknown tool name fails closed at
startup.

## Owner-side Cloudflare setup (one-time, on your CF account)

This is on the **real Cloudflare account**, so it is yours to perform. Use the
**self-hosted Access application with Managed OAuth** path — Cloudflare Access sits
in front of the gateway's existing tunnel hostname, runs the OAuth flow with the
connector, and injects the **`Cf-Access-Jwt-Assertion`** header (carrying your
email) to the gateway, which already verifies it. Follow Cloudflare's current docs
for exact UI; the shape is:

1. **Identity provider** — in Zero Trust → Settings → Authentication, add an
   interactive IdP (Google / GitHub / one-time-PIN) that authenticates *your*
   email.
2. **Enable Managed OAuth on the gateway's Access app** — open the existing
   self-hosted Access application for your tunnel hostname (Zero Trust → Access →
   Applications), and in **Advanced settings** enable **Managed OAuth** (this is
   what lets non-browser MCP clients do the OAuth 2.0 flow instead of a browser
   redirect, and emits the `401 + WWW-Authenticate` discovery connectors expect).
3. **Add the connector redirect URIs** — in the same Managed OAuth panel, under
   **Allowed redirect URIs**, add each MCP client's OAuth callback. **This list is
   EMPTY by default, and an empty list rejects every client** with
   `invalid_request: Redirect URI not allowed by application configuration` (the
   most common setup failure). Use the `/*` wildcard form:
   - **ChatGPT:** `https://chatgpt.com/connector/oauth/*`
   - **Claude:** `https://claude.ai/api/mcp/auth_callback` (or `https://claude.ai/*`)

   If a client still errors, its error-URL `redirect_uri=…` shows the exact callback
   to add.
4. **Access policy = your email only** — add an *Allow* policy matching exactly
   your owner email. This is the real gate on who may authenticate; the gateway's
   `FINECO_OWNER_EMAIL` pin is the backstop.
5. **Keep the service-token rule** for the CLI as an additional policy on the same
   app if you still use CLI clients (the gateway's dual-pin accepts both).
6. On the gateway, set `FINECO_OWNER_EMAIL` (matching step 4) and restart
   `fineco-gateway`.

> **Do NOT use the "MCP Server Portal" feature for this gateway.** Per Cloudflare's
> docs, a portal *proxies* to the upstream and authenticates to it with the user's
> OAuth token or an admin credential — so the `Cf-Access-Jwt-Assertion` injection
> this gateway relies on never happens. The gateway would reject every request (no
> JWT it can verify), and the admin-credential mode would also collapse every
> connector onto one identity, bypassing the per-channel tool scoping. The
> self-hosted-app Managed OAuth path above is the one that injects the JWT the
> gateway expects.

## ChatGPT connector (web → mobile)

1. ChatGPT web → **Settings → Apps & Connectors → Advanced settings → Developer
   mode** (enable).
2. **Create connector / app** → paste the connector URL `https://<your-host>/mcp`.
3. Complete the Cloudflare Access OAuth login when prompted; approve.
4. Confirm ChatGPT **discovers the server** and the tools appear.
5. Run one **read-only** call (e.g. `portfolio_get_freshness`), then one realistic
   end-to-end task.
6. After web works, open the **ChatGPT mobile app**, start a fresh chat, confirm
   the connector is available and test a call.

## Claude connector (web → mobile)

1. Claude web → **Settings / Customize → Connectors → Add custom connector**.
2. Paste the connector URL `https://<your-host>/mcp`.
3. Complete the OAuth flow (Cloudflare Access) — Claude opens the login.
4. Confirm Claude **discovers the server** and the tools appear.
5. Run one **read-only** call, then one realistic end-to-end task.
6. After web works, verify in **Claude mobile**, fresh chat, test a call.

## Auth expiry / reconnect

OAuth access tokens expire; when they do, the connector re-runs the Cloudflare
Access login (a fresh browser OAuth). Revocation is enforced **at the Cloudflare
edge**: once you revoke the Access session or the IdP grant, Cloudflare stops
admitting the connector, so it must re-authenticate. Note the gateway itself has
**no revocation check** — it trusts a validly-signed `Cf-Access-Jwt-Assertion`
until its `exp`, so an already-issued JWT keeps working at the gateway until it
expires (Cloudflare Access JWTs are short-lived). There is no separate
gateway-side session to clear; revoke at Cloudflare Access.

## Security notes (read before enabling)

- **Data egress.** Tool results flow to OpenAI / Anthropic. The connector
  allowlist keeps the **absolute-€ detailed-portfolio tools and authenticated
  Fineco market reads off** that path by
  default; the shareable report (`portfolio_get_latest_shareable_report`) carries
  weights / percentages / ISINs only. Note that orders, tax, and public/third-party
  market results *are* sent by default (they're in the default allowlist) — tighten
  `FINECO_CONNECTOR_TOOLS` if you want less.
- **Credentialed live-refresh tools are in the default connector set** (the three
  `private_*_refresh_live_sensitive` tools log in to Fineco). A prompt-injected
  model could call them. Mitigations: **read-only** (no trading or mutation, ever),
  per-area cooldowns + a daily refresh budget, **status-only** returns (never
  values), and an audit log. To keep them off the connector surface, set
  `FINECO_CONNECTOR_TOOLS` to a list that omits them.
- **The Access policy is the real gate** — it must admit only your owner
  identity. `FINECO_OWNER_EMAIL` is the gateway-side backstop, not the primary
  control.
- The gateway never holds Fineco / 1Password secrets and never reaches the SQLite
  DB or the live worker socket — exposing connectors does not change that.

## What's owner-side vs built-in

- **Built-in (this milestone):** Streamable HTTP at `/mcp`, the verified-JWT
  origin, **dual-pin** so an OAuth `email` identity and a service-token
  `common_name` both map to `owner`, and **per-channel tool scoping** (the
  connector channel restricted to a configurable allowlist; the CLI channel full).
- **Owner-side:** the Cloudflare Access OAuth configuration and the per-client
  connector setup are on your accounts. The final end-to-end connector test
  (discovery + a tool call from ChatGPT / Claude) is yours to run; the exact
  Cloudflare MCP/OAuth UI shifts over time, so defer to Cloudflare's docs for
  current steps.

## References

- Cloudflare — secure self-hosted MCP servers with Access (the Managed-OAuth path
  this gateway uses):
  <https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/secure-mcp-servers/>
  (and the 2025-08-26 changelog "Manage and restrict access to internal MCP servers
  with Cloudflare Access"). NB: the separate *MCP server portals* feature is **not**
  used here — see the warning above.
- OpenAI — ChatGPT developer mode / MCP connectors:
  <https://developers.openai.com/api/docs/guides/developer-mode>
- Anthropic — custom connectors (Claude): the *Connectors* section of Claude
  Settings, and Anthropic's connector documentation.
