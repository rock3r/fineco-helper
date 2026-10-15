# fineco-helper

A hardened, single self-contained **Rust binary** that exposes an **owner-only
remote MCP** service over read-only Fineco portfolio, market, tax, and order data —
plus a local SQLite history and third-party stock enrichment. It is for one owner;
it is not multi-tenant and has no public surface.

Architecture and operation live under [`docs/`](docs/README.md).

![Example report using fake demo data](docs/example-report.svg)

## Privacy & security first

- **Credential isolation.** The internet-facing gateway never holds Fineco
  credentials or cookies, never opens the SQLite DB, and never reaches the live
  socket. A separate credential worker performs the (read-only) Fineco login;
  Fineco session cookies are memory-only, never written to disk.
- **Owner-only.** Remote access is gated by Cloudflare Access (the gateway verifies
  the Access JWT and requires a pinned owner identity); there is no built-in
  multi-tenancy and no anonymous surface.
- **Read-only.** No trading or mutation, ever. Live Fineco refresh is an explicitly
  gated capability (cooldowns + a daily budget); cached reads serve the data.
- **Contained.** Each process runs as its own user under systemd hardening, with
  per-uid nftables egress allowlists, payload-free alerting, and encrypted backups.

## Architecture in one paragraph

One binary, several roles: a **gateway** (the MCP service, loopback-bound behind a
Cloudflare Tunnel), a **store-server** (owns the SQLite snapshot store + the
live-refresh controller), and a **private-worker** (the credential holder that talks
to Fineco). They communicate over isolated Unix sockets. A `cloudflared` tunnel is
the only client of the gateway's loopback bind. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## MCP tools (read-only)

Cached reads (instant, from the local store):

- `portfolio_get_freshness`, `portfolio_get_latest_snapshot_summary`,
  `portfolio_get_latest_full_snapshot`, `portfolio_get_latest_shareable_report`
- `portfolio_get_history`, `portfolio_get_allocation_history`,
  `portfolio_get_position_history`
- `orders_get_latest_monitor`
- `tax_get_latest_carry_forward`, `tax_get_latest_minus_by_year`
- `movements_get_latest`, `movements_get_dividends` (the dividend legs of the
  latest movements capture, each gross paired to its withholding). Both are
  outside the default connector allowlist — they carry raw transaction amounts.

Market reads and gated live refresh:

| Tool | Purpose | Live-refresh / enrichment notes |
| --- | --- | --- |
| `market_get_zero_commission_etfs` | Read the public ETF list. | Uses a credential-free market client. Reads outside the store. |
| `market_search_asset` | Search Fineco instruments by ticker, ISIN, or name. | Uses a typed controller path and a live Fineco login. Disabled in the checked-in deployment policy pending a clean market live-session gate review and explicit owner approval. |
| `market_get_asset_details` | Read Fineco stock/ETF details for a venue-qualified identifier. Returns source-wrapped identity, listing, quote, profile, and core stock-or-ETF data. Supports explicit holdings, exposures, returns, risk, and ratios sections. | Uses the same controller and policy gate as `market_search_asset`. Stocks can request `external_enrichment`, fetched by the credential-free market client after Fineco resolution. Enrichment-only requests resolve only the Fineco identity before the external fetch. Source and audit records label this section `external_enrichment`. No standalone enrichment tool exists; fetched content is parsed and never executed. |
| `market_get_indices` | Read Fineco headline indices-bar cards. Does not list every index or venue. | Uses the same controller and policy gate as `market_search_asset`. |
| `private_portfolio_refresh_live_sensitive`, `private_orders_refresh_live_sensitive`, `private_tax_refresh_live_sensitive`, `private_movements_refresh_live_sensitive` | Refresh the corresponding cached data through a real Fineco login. | Rate-limited and gated. Returns status only. Read refreshed values through the cached tools afterward. |

## Run it / deploy it

- **Self-hosting walkthrough:** [`docs/SELF-HOSTING.md`](docs/SELF-HOSTING.md)
- **Deployment (Proxmox LXC) reference:** [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
- **ChatGPT & Claude connectors:** [`docs/CONNECTORS.md`](docs/CONNECTORS.md) — remote
  MCP over OAuth-via-Cloudflare-Access, with the connector channel scoped to a
  configurable tool allowlist (the absolute-€ detailed-portfolio tools and
  authenticated market reads off by default)
- **Testing + E2E:** [`docs/TESTING.md`](docs/TESTING.md)
- **All docs:** [`docs/README.md`](docs/README.md)

Build + check locally:

```sh
cargo build
cargo nextest run
cargo clippy --all-targets --all-features -- -D warnings
```

## Notes

This is an unofficial helper and is not affiliated with FinecoBank. Use it
responsibly and make sure it fits Fineco's terms and your own security expectations.

## License

Apache-2.0
