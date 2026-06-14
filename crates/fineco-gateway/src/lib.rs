//! `fineco-gateway` — the internet-facing owner MCP gateway.
//!
//! Serves the read-only cached tool surface over Streamable HTTP (rmcp), bound
//! to loopback. It holds no credentials, no DB handle, and no live socket:
//! private cached reads go over the snapshot-query socket via
//! [`fineco_ipc::Client`]; credential-free market tools call `fineco-market`
//! in-process; authenticated market reads go through the controller over the
//! market-control socket. This crate must never depend on `fineco-store`,
//! `fineco-worker`, or `fineco-live`.

pub mod access;
pub mod audit;

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use crate::access::AuthChannel;
use fineco_ipc::{
    AllocationHistoryDto, Capability, Client, FreshnessReportDto, FullSnapshotDto, HistoryParams,
    MarketAssetDetailsResult, MarketControlClient, MarketControlOutcome, MarketControlRequest,
    MarketDetailsParams, MarketEnrichmentParams, MarketEtfsParams, MarketSearchParams,
    MarketSearchResult, OWNER_AUTH_ID, OrdersDto, OrdersRefreshParams, Policy, PortfolioHistoryDto,
    PortfolioSummaryDto, PositionHistoryDto, PositionHistoryParams, RefreshClient, RefreshOutcome,
    RefreshRequest, Request, ResponseBody, SafeErrorDto, ShareableReportDto,
    TaxCarryForwardListDto, TaxMinusListDto, TaxRefreshParams,
};
use fineco_market::{EnrichmentReport, MarketClient, ZeroCommissionEtfs};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ListToolsResult, PaginatedRequestParams, ServerInfo,
    Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, Json, ServerHandler, tool, tool_router};

/// The Streamable HTTP MCP service for the gateway. Bind it on loopback only.
/// The served handler is [`ScopedGateway`] (the per-Access-channel tool-scoping
/// wrapper around [`Gateway`]).
pub type GatewayService = StreamableHttpService<ScopedGateway, LocalSessionManager>;

/// The default connector (email/OAuth) tool allowlist: every tool EXCEPT the four
/// detailed-portfolio tools that expose absolute euro values
/// (`portfolio_get_latest_snapshot_summary`, `portfolio_get_latest_full_snapshot`,
/// `portfolio_get_history`, `portfolio_get_position_history`) plus
/// the authenticated market tools (`market_search_asset`,
/// `market_get_asset_details`). This is an EXPLICIT allowlist, not "all minus
/// blocked": a newly-added tool is NOT visible to connectors until it is added
/// here (fail-safe). Per-deployment override via `FINECO_CONNECTOR_TOOLS`. A
/// test asserts every name here is a real tool and that the default-blocked tools
/// are absent.
pub const DEFAULT_CONNECTOR_TOOLS: &[&str] = &[
    "portfolio_get_freshness",
    "portfolio_get_latest_shareable_report",
    "portfolio_get_allocation_history",
    "orders_get_latest_monitor",
    "tax_get_latest_carry_forward",
    "tax_get_latest_minus_by_year",
    "market_get_zero_commission_etfs",
    "market_get_stock_enrichment",
    "private_portfolio_refresh_live_sensitive",
    "private_orders_refresh_live_sensitive",
    "private_tax_refresh_live_sensitive",
];

/// Per-Access-channel tool-scoping wrapper around [`Gateway`]. It delegates every
/// `ServerHandler` method to the inner gateway and ADDS exactly one behaviour: on
/// the **connector** (email/OAuth) channel, when the gateway carries a connector
/// allowlist, `list_tools` hides every non-allowlisted tool and `call_tool` refuses
/// them. The **CLI** (service-token) channel is never restricted, and with no
/// allowlist configured nothing changes. The allowlist is the *only* gate added
/// here; capability-policy and Access-JWT checks are unchanged in the inner gateway
/// / middleware.
#[derive(Clone)]
pub struct ScopedGateway {
    inner: Gateway,
}

/// The Access channel for a request, read from the [`AuthChannel`] the
/// `enforce_access` middleware stamped into the HTTP request extensions (rmcp
/// surfaces the `http::request::Parts` in the request context). An ABSENT marker
/// fails **safe** to the restricted `Connector` channel: that only matters when a
/// connector allowlist is configured (Access enabled with an email pin, where the
/// middleware always stamps the marker), so a lost/un-stamped marker restricts
/// rather than exposes; an Access-disabled dev run has no allowlist, so `Connector`
/// there is still unrestricted.
fn request_channel(context: &RequestContext<RoleServer>) -> AuthChannel {
    context
        .extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<AuthChannel>())
        .copied()
        .unwrap_or(AuthChannel::Connector)
}

impl ScopedGateway {
    /// The tool allowlist that applies to `channel`: the connector allowlist on the
    /// connector channel, and `None` (unrestricted) on the CLI channel or when no
    /// allowlist is configured.
    fn allowlist_for(&self, channel: AuthChannel) -> Option<&HashSet<String>> {
        match channel {
            AuthChannel::Connector => self.inner.connector_allowlist.as_deref(),
            AuthChannel::Cli => None,
        }
    }
}

impl ServerHandler for ScopedGateway {
    fn get_info(&self) -> ServerInfo {
        self.inner.get_info()
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let channel = request_channel(&context);
        let mut result = self.inner.list_tools(request, context).await?;
        if let Some(allow) = self.allowlist_for(channel) {
            result
                .tools
                .retain(|tool| allow.contains(tool.name.as_ref()));
        }
        Ok(result)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let channel = request_channel(&context);
        if self
            .allowlist_for(channel)
            .is_some_and(|allow| !allow.contains(request.name.as_ref()))
        {
            // The same shape the tool router returns for an unknown tool — a
            // connector never sees a blocked tool in `list_tools` either.
            return Err(ErrorData::invalid_params("tool not found", None));
        }
        self.inner.call_tool(request, context).await
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.inner.get_tool(name)
    }
}

/// The MCP gateway. Maps each cached private tool to an internal command sent
/// over the snapshot-query socket; the credential-free market tools call the
/// in-process [`MarketClient`]. Holds no credentials, DB handle, or live socket.
#[derive(Clone)]
pub struct Gateway {
    query_client: Client,
    /// The in-process market reader (public ETF list + parse-not-execute
    /// enrichment). `None` in a private-cached-only deployment; the market tools
    /// then return a safe "not configured" error. The serving binary always sets
    /// it. Held behind `Arc` so async tools can move a clone into `spawn_blocking`.
    market: Option<Arc<MarketClient>>,
    /// The capability policy, enforced before any tool runs. `None` fails closed
    /// (every tool is denied); the serving binary always loads one.
    policy: Option<Arc<Policy>>,
    /// The refresh-control client (live refresh), reaching the refresh controller
    /// over `refresh-control.sock` — **never** the live socket (the gateway has no
    /// live-socket client; the architecture test forbids the dependency). `None`
    /// in a cached-only deployment, where the live-refresh tools return a safe
    /// "not configured" error. Held behind `Arc` so async tools can move a clone
    /// into `spawn_blocking`.
    refresh_client: Option<Arc<RefreshClient>>,
    /// Authenticated market-control client, reaching the controller-owned socket
    /// for Fineco instrument search/details. This is NOT the live socket.
    market_control_client: Option<Arc<MarketControlClient>>,
    /// Allowed `Origin` values for DNS-rebinding protection (M6). Empty leaves
    /// Origin validation off (rmcp still validates `Host` to loopback by
    /// default); the remote deployment sets the Cloudflare/client origins.
    allowed_origins: Vec<String>,
    /// When `Some`, the connector (email/OAuth) Access channel is restricted to
    /// exactly these tool names (an allowlist); the CLI (service-token) channel
    /// always gets the full set. `None` leaves every authenticated channel
    /// unrestricted. Set by the serving binary from `FINECO_CONNECTOR_TOOLS` whenever
    /// an email pin is configured (the connector channel exists). Held behind `Arc` so
    /// the service factory can cheaply clone the handler per connection.
    connector_allowlist: Option<Arc<HashSet<String>>>,
}

#[tool_router(server_handler)]
impl Gateway {
    #[tool(
        name = "portfolio_get_freshness",
        description = "Freshness (fresh/stale/missing/...) of the cached portfolio, orders, and tax data."
    )]
    pub async fn portfolio_get_freshness(&self) -> Result<Json<FreshnessReportDto>, ErrorData> {
        self.call(Request::PortfolioGetFreshness, |body| match body {
            ResponseBody::Freshness(report) => Ok(Json(report)),
            _ => Err(unexpected()),
        })
        .await
    }

    #[tool(
        name = "portfolio_get_latest_snapshot_summary",
        description = "The latest portfolio snapshot's totals (owner-only cached values)."
    )]
    pub async fn portfolio_get_latest_snapshot_summary(
        &self,
    ) -> Result<Json<PortfolioSummaryDto>, ErrorData> {
        self.call(
            Request::PortfolioGetLatestSnapshotSummary,
            |body| match body {
                ResponseBody::PortfolioSummary(summary) => Ok(Json(summary)),
                _ => Err(unexpected()),
            },
        )
        .await
    }

    #[tool(
        name = "portfolio_get_latest_full_snapshot",
        description = "The latest full portfolio snapshot: totals plus every position (owner-only absolutes)."
    )]
    pub async fn portfolio_get_latest_full_snapshot(
        &self,
    ) -> Result<Json<FullSnapshotDto>, ErrorData> {
        self.call(Request::PortfolioGetLatestFullSnapshot, |body| match body {
            ResponseBody::PortfolioFullSnapshot(snapshot) => Ok(Json(snapshot)),
            _ => Err(unexpected()),
        })
        .await
    }

    #[tool(
        name = "portfolio_get_latest_shareable_report",
        description = "The latest shareable portfolio report: names, symbols, ISINs, weights, and percentage performance only — no absolute values."
    )]
    pub async fn portfolio_get_latest_shareable_report(
        &self,
    ) -> Result<Json<ShareableReportDto>, ErrorData> {
        self.call(
            Request::PortfolioGetLatestShareableReport,
            |body| match body {
                ResponseBody::PortfolioShareableReport(report) => Ok(Json(report)),
                _ => Err(unexpected()),
            },
        )
        .await
    }

    #[tool(
        name = "orders_get_latest_monitor",
        description = "The latest order-monitor capture (owner-only cached private data)."
    )]
    pub async fn orders_get_latest_monitor(&self) -> Result<Json<OrdersDto>, ErrorData> {
        self.call(Request::OrdersGetLatestMonitor, |body| match body {
            ResponseBody::Orders(orders) => Ok(Json(orders)),
            _ => Err(unexpected()),
        })
        .await
    }

    #[tool(
        name = "tax_get_latest_carry_forward",
        description = "The latest tax carry-forward capture."
    )]
    pub async fn tax_get_latest_carry_forward(
        &self,
    ) -> Result<Json<TaxCarryForwardListDto>, ErrorData> {
        self.call(Request::TaxGetLatestCarryForward, |body| match body {
            ResponseBody::TaxCarryForward(tax) => Ok(Json(tax)),
            _ => Err(unexpected()),
        })
        .await
    }

    #[tool(
        name = "tax_get_latest_minus_by_year",
        description = "The latest tax minus-by-year capture."
    )]
    pub async fn tax_get_latest_minus_by_year(&self) -> Result<Json<TaxMinusListDto>, ErrorData> {
        self.call(Request::TaxGetLatestMinusByYear, |body| match body {
            ResponseBody::TaxMinus(tax) => Ok(Json(tax)),
            _ => Err(unexpected()),
        })
        .await
    }

    #[tool(
        name = "portfolio_get_history",
        description = "Recent portfolio snapshot totals over time (owner-only cached values), chronological, oldest first. `limit` bounds how many recent snapshots to return (1..=1000)."
    )]
    pub async fn portfolio_get_history(
        &self,
        Parameters(params): Parameters<HistoryParams>,
    ) -> Result<Json<PortfolioHistoryDto>, ErrorData> {
        self.call(Request::PortfolioGetHistory(params), |body| match body {
            ResponseBody::PortfolioHistory(history) => Ok(Json(history)),
            _ => Err(unexpected()),
        })
        .await
    }

    #[tool(
        name = "portfolio_get_allocation_history",
        description = "Per-instrument allocation weights across all stored snapshots, oldest first."
    )]
    pub async fn portfolio_get_allocation_history(
        &self,
    ) -> Result<Json<AllocationHistoryDto>, ErrorData> {
        self.call(Request::PortfolioGetAllocationHistory, |body| match body {
            ResponseBody::AllocationHistory(history) => Ok(Json(history)),
            _ => Err(unexpected()),
        })
        .await
    }

    #[tool(
        name = "portfolio_get_position_history",
        description = "One instrument's history across snapshots (owner-only cached values), oldest first. Identify the instrument by its `instr_id` and `venue_system`."
    )]
    pub async fn portfolio_get_position_history(
        &self,
        Parameters(params): Parameters<PositionHistoryParams>,
    ) -> Result<Json<PositionHistoryDto>, ErrorData> {
        self.call(
            Request::PortfolioGetPositionHistory(params),
            |body| match body {
                ResponseBody::PositionHistory(history) => Ok(Json(history)),
                _ => Err(unexpected()),
            },
        )
        .await
    }

    #[tool(
        name = "market_get_zero_commission_etfs",
        description = "The public list of zero-commission ETFs. Optional `query` filters by a case-insensitive substring of description, issuer, or instrument id."
    )]
    pub async fn market_get_zero_commission_etfs(
        &self,
        Parameters(params): Parameters<MarketEtfsParams>,
    ) -> Result<Json<ZeroCommissionEtfs>, ErrorData> {
        let this = self.clone();
        self.audited_market(
            "market_get_zero_commission_etfs",
            "public_market",
            async move {
                // Authorize and validate at the gateway end, then fetch off the runtime.
                this.authorize(Capability::MarketRead)
                    .map_err(|err| ("policy_denied".to_string(), err))?;
                Request::MarketGetZeroCommissionEtfs(params.clone())
                    .validate()
                    .map_err(audit_market_error)?;
                let market = this
                    .market()
                    .map_err(|err| ("market_unconfigured".to_string(), err))?;
                let now = fineco_core::now_iso8601_utc();
                let mut etfs =
                    tokio::task::spawn_blocking(move || market.fetch_zero_commission_etfs(&now))
                        .await
                        .map_err(|_| {
                            (
                                "worker_unavailable".to_string(),
                                ErrorData::internal_error("market request failed", None),
                            )
                        })?
                        .map_err(audit_market_error)?;
                if let Some(query) = params.query.as_deref() {
                    filter_etfs(&mut etfs, query);
                }
                let count = etfs.instruments.len();
                Ok((Json(etfs), Some(count)))
            },
        )
        .await
    }

    #[tool(
        name = "market_get_stock_enrichment",
        description = "Get enrichment for a public market instrument. `identifier` must be a venue-qualified ticker in `<venue>/<symbol>` or `<venue>:<symbol>` form, for example `LSE/VHYL` or `LSE:VHYL`; bare tickers and ISIN-only identifiers are rejected. `expected_isin`, when provided, verifies the parsed page and may be a plain ISIN or an ISIN with a suffix; suffixes are ignored for comparison. The server builds exactly one allowlisted URL and parses the page as data."
    )]
    pub async fn market_get_stock_enrichment(
        &self,
        Parameters(params): Parameters<MarketEnrichmentParams>,
    ) -> Result<Json<EnrichmentReport>, ErrorData> {
        let this = self.clone();
        self.audited_market(
            "market_get_stock_enrichment",
            "external_enrichment",
            async move {
                this.authorize(Capability::MarketRead)
                    .map_err(|err| ("policy_denied".to_string(), err))?;
                Request::MarketGetStockEnrichment(params.clone())
                    .validate()
                    .map_err(audit_market_error)?;
                let market = this
                    .market()
                    .map_err(|err| ("market_unconfigured".to_string(), err))?;
                let now = fineco_core::now_iso8601_utc();
                let report = tokio::task::spawn_blocking(move || {
                    market.fetch_enrichment(
                        &params.identifier,
                        params.expected_isin.as_deref(),
                        &now,
                    )
                })
                .await
                .map_err(|_| {
                    (
                        "worker_unavailable".to_string(),
                        ErrorData::internal_error("market request failed", None),
                    )
                })?
                .map_err(audit_market_error)?;
                // One instrument report — count is 1 (never the values).
                Ok((Json(report), Some(1)))
            },
        )
        .await
    }

    #[tool(
        name = "market_search_asset",
        description = "Authenticated Fineco instrument search by ticker, ISIN, or name. Returns normalized, source-attributed candidates grouped by asset type; `limit` is 1..=30."
    )]
    pub async fn market_search_asset(
        &self,
        Parameters(params): Parameters<MarketSearchParams>,
    ) -> Result<Json<MarketSearchResult>, ErrorData> {
        self.market_control_call(MarketControlRequest::MarketSearchAsset(params))
            .await
            .and_then(|outcome| match outcome {
                MarketControlOutcome::Search { result, .. } => Ok(Json(result)),
                MarketControlOutcome::Details { .. } => Err(unexpected()),
            })
    }

    #[tool(
        name = "market_get_asset_details",
        description = "Authenticated Fineco stock/ETF details for a venue-qualified identifier such as NASDAQ/AAPL or AFF/VHYL. Defaults to lightweight identity/listing/quote/profile/core asset sections; heavy ETF sections and stock ratios require explicit section names."
    )]
    pub async fn market_get_asset_details(
        &self,
        Parameters(params): Parameters<MarketDetailsParams>,
    ) -> Result<Json<MarketAssetDetailsResult>, ErrorData> {
        self.market_control_call(MarketControlRequest::MarketGetAssetDetails(params))
            .await
            .and_then(|outcome| match outcome {
                MarketControlOutcome::Details { result, .. } => Ok(Json(*result)),
                MarketControlOutcome::Search { .. } => Err(unexpected()),
            })
    }

    #[tool(
        name = "private_portfolio_refresh_live_sensitive",
        description = "HIGH-SENSITIVITY, owner-only: trigger a LIVE Fineco refresh of the portfolio (logs in to Fineco; rate-limited by cooldown and a daily budget). Returns operation/snapshot status only — never values; read the refreshed data afterward via the cached portfolio tools."
    )]
    pub async fn private_portfolio_refresh_live_sensitive(
        &self,
    ) -> Result<Json<RefreshOutcome>, ErrorData> {
        self.refresh_call(RefreshRequest::PortfolioRefreshLive)
            .await
    }

    #[tool(
        name = "private_orders_refresh_live_sensitive",
        description = "HIGH-SENSITIVITY, owner-only: trigger a LIVE Fineco refresh of the order monitor for `instrument_kind` over the last `days` days (max 30). Logs in to Fineco; rate-limited. Returns operation/snapshot status only — read values via the cached orders tool afterward."
    )]
    pub async fn private_orders_refresh_live_sensitive(
        &self,
        Parameters(params): Parameters<OrdersRefreshParams>,
    ) -> Result<Json<RefreshOutcome>, ErrorData> {
        self.refresh_call(RefreshRequest::OrdersRefreshLive(params))
            .await
    }

    #[tool(
        name = "private_tax_refresh_live_sensitive",
        description = "HIGH-SENSITIVITY, owner-only: trigger a LIVE Fineco refresh of tax data (carry-forward for the `date_from`..`date_to` range plus minus-by-year). Logs in to Fineco; rate-limited. Returns operation/snapshot status only — read values via the cached tax tools afterward."
    )]
    pub async fn private_tax_refresh_live_sensitive(
        &self,
        Parameters(params): Parameters<TaxRefreshParams>,
    ) -> Result<Json<RefreshOutcome>, ErrorData> {
        self.refresh_call(RefreshRequest::TaxRefreshLive(params))
            .await
    }
}

impl Gateway {
    /// Build a gateway that reaches the store-query worker at `socket_path`. The
    /// market tools are unconfigured until [`Gateway::with_market`] is called.
    #[must_use]
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            query_client: Client::new(socket_path),
            market: None,
            policy: None,
            allowed_origins: Vec::new(),
            refresh_client: None,
            market_control_client: None,
            connector_allowlist: None,
        }
    }

    /// Restrict the connector (email/OAuth) Access channel to exactly `names` (an
    /// allowlist); the CLI (service-token) channel is unaffected and keeps every
    /// tool. Unset (the default) leaves all channels unrestricted.
    #[must_use]
    pub fn with_connector_allowlist(
        mut self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.connector_allowlist = Some(Arc::new(names.into_iter().map(Into::into).collect()));
        self
    }

    /// Every registered tool name. Used by the serving binary to validate a
    /// configured connector allowlist (fail closed on an unknown tool name) and by
    /// tests to check the default allowlist against the real tool set.
    #[must_use]
    pub fn tool_names() -> Vec<String> {
        Self::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect()
    }

    /// Attach the in-process market reader so the market tools are served.
    #[must_use]
    pub fn with_market(mut self, market: MarketClient) -> Self {
        self.market = Some(Arc::new(market));
        self
    }

    /// Attach the refresh-control client so the live-refresh tools are served.
    /// Without it those tools return a safe "not configured" error. The client
    /// targets `refresh-control.sock`; the gateway has no live-socket client.
    #[must_use]
    pub fn with_refresh_client(mut self, refresh_client: RefreshClient) -> Self {
        self.refresh_client = Some(Arc::new(refresh_client));
        self
    }

    /// Attach the authenticated market-control client. Without it the
    /// authenticated market tools return a safe "not configured" error. The
    /// client targets the controller-owned socket, never `fineco-live.sock`.
    #[must_use]
    pub fn with_market_control_client(mut self, client: MarketControlClient) -> Self {
        self.market_control_client = Some(Arc::new(client));
        self
    }

    /// Set the allowed `Origin` values (DNS-rebinding protection). Empty leaves
    /// Origin validation off (Host validation stays on); the remote deployment
    /// supplies the legitimate Cloudflare/client origins.
    #[must_use]
    pub fn with_allowed_origins(
        mut self,
        origins: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.allowed_origins = origins.into_iter().map(Into::into).collect();
        self
    }

    /// Attach the capability policy. Without it every tool is denied (fail
    /// closed); the serving binary always supplies one.
    #[must_use]
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = Some(Arc::new(policy));
        self
    }

    /// Authorize the (single, implicit) owner identity for `capability` against
    /// the loaded policy. Denies if no policy is configured (fail closed). M6
    /// replaces the implicit owner with a verified Cloudflare Access identity.
    fn authorize(&self, capability: Capability) -> Result<(), ErrorData> {
        let allowed = self
            .policy
            .as_ref()
            .is_some_and(|policy| policy.allows(OWNER_AUTH_ID, capability));
        if allowed {
            Ok(())
        } else {
            Err(ErrorData::invalid_request(
                "the configured policy does not permit this tool",
                None,
            ))
        }
    }

    /// The configured market reader, or a safe error if the gateway runs in a
    /// private-cached-only mode without one.
    fn market(&self) -> Result<Arc<MarketClient>, ErrorData> {
        self.market
            .clone()
            .ok_or_else(|| ErrorData::internal_error("market reads are not configured", None))
    }

    /// Build the Streamable HTTP MCP service hosting this gateway. The default
    /// config restricts inbound `Host` to loopback (DNS-rebinding protection)
    /// and the binary binds it to 127.0.0.1 only; any configured
    /// [`Gateway::with_allowed_origins`] additionally enables `Origin`
    /// validation (the M4-deferred half of the rebinding gate).
    #[must_use]
    pub fn into_service(self) -> GatewayService {
        let config = StreamableHttpServerConfig::default()
            .with_allowed_origins(self.allowed_origins.clone());
        let scoped = ScopedGateway { inner: self };
        StreamableHttpService::new(
            move || Ok(scoped.clone()),
            Arc::new(LocalSessionManager::default()),
            config,
        )
    }

    /// Send `request` over the socket (on a blocking pool, since the client is
    /// blocking) and return the typed reply. The capability is authorized and the
    /// request's bounds are validated here first — MCP parameters never pass
    /// through `Request::from_json`, so this is the gateway end of the plan's
    /// "validate at both ends" rule. Worker errors map to MCP errors.
    async fn call<T>(
        &self,
        request: Request,
        extract: impl FnOnce(ResponseBody) -> Result<T, ErrorData>,
    ) -> Result<T, ErrorData> {
        let tool = request.audit_tool();
        let data_class = request.required_capability().audit_data_class();
        let start = std::time::Instant::now();
        let dispatched = self.dispatch(request).await;
        let duration_ms = start.elapsed().as_millis() as u64;
        // The audit outcome must reflect what the CLIENT receives. A dispatch that
        // succeeds but whose response variant does not match the request (an
        // internal invariant violation surfacing as `unexpected()`) is recorded as
        // an error, never "ok" — so the journal can't claim success while the
        // caller got an internal error.
        let (outcome, error_code, result_count, result) = match dispatched {
            Ok(body) => {
                let count = body.audit_count();
                match extract(body) {
                    Ok(value) => ("ok", None, count, Ok(value)),
                    Err(err) => (
                        "error",
                        Some("unexpected_response".to_string()),
                        None,
                        Err(err),
                    ),
                }
            }
            Err((code, err)) => ("error", Some(code), None, Err(err)),
        };
        audit::emit(&audit::AuditRecord {
            ts: fineco_core::now_iso8601_utc(),
            auth_id: OWNER_AUTH_ID,
            tool,
            data_class,
            outcome,
            error_code,
            duration_ms,
            result_count,
            login_performed: None,
            session_reused: None,
            session_evicted: None,
            reused_session_401_recovered: None,
        });
        result
    }

    /// The cached-read dispatch core. Returns the safe error code alongside the
    /// MCP error so [`Gateway::call`] can record `who/when/tool/outcome/count`
    /// (with a safe code, never a payload) in the audit log.
    async fn dispatch(&self, request: Request) -> Result<ResponseBody, (String, ErrorData)> {
        if let Err(err) = self.authorize(request.required_capability()) {
            return Err(("policy_denied".to_string(), err));
        }
        if let Err(err) = request.validate() {
            let dto = SafeErrorDto::from(&err);
            return Err((dto.code.clone(), error_from_dto(dto)));
        }
        let client = self.query_client.clone();
        match tokio::task::spawn_blocking(move || client.call(&request)).await {
            Err(_) => Err((
                "worker_unavailable".to_string(),
                ErrorData::internal_error("worker request failed", None),
            )),
            Ok(Err(dto)) => Err((dto.code.clone(), error_from_dto(dto))),
            Ok(Ok(body)) => Ok(body),
        }
    }

    /// Forward a live refresh to the refresh controller over `refresh-control.sock`
    /// (on the blocking pool, since the client is blocking), emitting the audit
    /// record. The capability is authorized and the request's bounds are validated
    /// here first (the gateway end of "validate at both ends"); the controller and
    /// worker re-check independently. The reply is operation/snapshot **status
    /// only** — never a payload. Mirrors [`Gateway::call`] for the refresh socket.
    async fn refresh_call(
        &self,
        request: RefreshRequest,
    ) -> Result<Json<RefreshOutcome>, ErrorData> {
        let tool = request.audit_tool();
        let data_class = request.required_capability().audit_data_class();
        let start = std::time::Instant::now();
        let dispatched = self.refresh_dispatch(request).await;
        let duration_ms = start.elapsed().as_millis() as u64;
        let (outcome, error_code, result_count, result) = match dispatched {
            Ok(refresh_outcome) => {
                // `count` is a row count (positions/orders/tax rows), never a value.
                let count = Some(refresh_outcome.count);
                ("ok", None, count, Ok(Json(refresh_outcome)))
            }
            Err((code, err)) => ("error", Some(code), None, Err(err)),
        };
        audit::emit(&audit::AuditRecord {
            ts: fineco_core::now_iso8601_utc(),
            auth_id: OWNER_AUTH_ID,
            tool,
            data_class,
            outcome,
            error_code,
            duration_ms,
            result_count,
            login_performed: None,
            session_reused: None,
            session_evicted: None,
            reused_session_401_recovered: None,
        });
        result
    }

    /// The live-refresh dispatch core: authorize the `*.live.refresh` capability
    /// (fail closed), validate the bounds, then forward to the refresh controller.
    /// Returns the safe error code alongside the MCP error so [`refresh_call`]
    /// records the audit line. A gateway without a configured refresh client
    /// returns a safe "not configured" error — it never reaches the live socket.
    ///
    /// [`refresh_call`]: Gateway::refresh_call
    async fn refresh_dispatch(
        &self,
        request: RefreshRequest,
    ) -> Result<RefreshOutcome, (String, ErrorData)> {
        if let Err(err) = self.authorize(request.required_capability()) {
            return Err(("policy_denied".to_string(), err));
        }
        if let Err(err) = request.validate() {
            let dto = SafeErrorDto::from(&err);
            return Err((dto.code.clone(), error_from_dto(dto)));
        }
        let Some(client) = self.refresh_client.clone() else {
            return Err((
                "live_refresh_unconfigured".to_string(),
                ErrorData::internal_error("live refresh is not configured", None),
            ));
        };
        match tokio::task::spawn_blocking(move || client.call(&request)).await {
            Err(_) => Err((
                "controller_unavailable".to_string(),
                ErrorData::internal_error("refresh request failed", None),
            )),
            Ok(Err(dto)) => Err((dto.code.clone(), error_from_dto(dto))),
            Ok(Ok(outcome)) => Ok(outcome),
        }
    }

    /// Forward authenticated market-data reads to the controller-owned
    /// market-control socket (on the blocking pool, since the client is
    /// blocking), emitting the audit record. The gateway validates and
    /// authorizes first, and it has no live-socket client.
    async fn market_control_call(
        &self,
        request: MarketControlRequest,
    ) -> Result<MarketControlOutcome, ErrorData> {
        let tool = request.audit_tool();
        let data_class = request.required_capability().audit_data_class();
        let start = std::time::Instant::now();
        let dispatched = self.market_control_dispatch(request).await;
        let duration_ms = start.elapsed().as_millis() as u64;
        let (outcome, error_code, result_count, session, result) = match dispatched {
            Ok(MarketControlOutcome::Search { result, session }) => {
                let count = Some(
                    result
                        .groups
                        .iter()
                        .map(|group| group.candidates.len())
                        .sum(),
                );
                (
                    "ok",
                    None,
                    count,
                    Some(session),
                    Ok(MarketControlOutcome::Search { result, session }),
                )
            }
            Ok(MarketControlOutcome::Details { result, session }) => (
                "ok",
                None,
                Some(1),
                Some(session),
                Ok(MarketControlOutcome::Details { result, session }),
            ),
            Err((code, err)) => ("error", Some(code), None, None, Err(err)),
        };
        audit::emit(&audit::AuditRecord {
            ts: fineco_core::now_iso8601_utc(),
            auth_id: OWNER_AUTH_ID,
            tool,
            data_class,
            outcome,
            error_code,
            duration_ms,
            result_count,
            login_performed: session.map(|status| status.login_performed),
            session_reused: session.map(|status| status.session_reused),
            session_evicted: session.map(|status| status.session_evicted),
            reused_session_401_recovered: session.map(|status| status.reused_session_401_recovered),
        });
        result
    }

    /// Authenticated market-control dispatch core: authorize
    /// `market.authenticated.read`, validate bounds, then forward to the
    /// controller socket.
    async fn market_control_dispatch(
        &self,
        request: MarketControlRequest,
    ) -> Result<MarketControlOutcome, (String, ErrorData)> {
        if let Err(err) = self.authorize(request.required_capability()) {
            return Err(("policy_denied".to_string(), err));
        }
        if let Err(err) = request.validate() {
            let dto = SafeErrorDto::from(&err);
            return Err((dto.code.clone(), error_from_dto(dto)));
        }
        let Some(client) = self.market_control_client.clone() else {
            return Err((
                "market_control_unconfigured".to_string(),
                ErrorData::internal_error("authenticated market reads are not configured", None),
            ));
        };
        let expected = request.clone();
        match tokio::task::spawn_blocking(move || client.call(&request)).await {
            Err(_) => Err((
                "controller_unavailable".to_string(),
                ErrorData::internal_error("market request failed", None),
            )),
            Ok(Err(dto)) => Err((dto.code.clone(), error_from_dto(dto))),
            Ok(Ok(outcome)) => validate_market_control_outcome(&expected, outcome),
        }
    }

    /// Run a market-tool body, emit its audit record (tool, data class, outcome,
    /// duration, result count), and return the result. `data_class` is the tool's
    /// plan §"Data Classes" label — the two market tools share `MarketRead` but are
    /// distinct classes (`public_market` for the ETF list vs `external_enrichment`
    /// for a third-party fetch that reveals ticker interest), so it is passed
    /// per-tool. The body yields `(value, result_count)` on success or
    /// `(safe_code, error)` on failure.
    async fn audited_market<T>(
        &self,
        tool: &'static str,
        data_class: &'static str,
        body: impl std::future::Future<Output = Result<(T, Option<usize>), (String, ErrorData)>>,
    ) -> Result<T, ErrorData> {
        let start = std::time::Instant::now();
        let result = body.await;
        let duration_ms = start.elapsed().as_millis() as u64;
        let (outcome, error_code, result_count) = match &result {
            Ok((_, count)) => ("ok", None, *count),
            Err((code, _)) => ("error", Some(code.clone()), None),
        };
        audit::emit(&audit::AuditRecord {
            ts: fineco_core::now_iso8601_utc(),
            auth_id: OWNER_AUTH_ID,
            tool,
            data_class,
            outcome,
            error_code,
            duration_ms,
            result_count,
            login_performed: None,
            session_reused: None,
            session_evicted: None,
            reused_session_401_recovered: None,
        });
        result.map(|(value, _)| value).map_err(|(_, err)| err)
    }
}

/// Map an in-process [`SafeError`] (e.g. from gateway-side bounds validation) to
/// the audit-friendly `(safe code, MCP error)` pair, through the same wire
/// mapping as worker errors. The code is logged; the MCP error is returned.
fn audit_market_error(err: fineco_core::SafeError) -> (String, ErrorData) {
    let dto = SafeErrorDto::from(&err);
    (dto.code.clone(), error_from_dto(dto))
}

fn validate_market_control_outcome(
    request: &MarketControlRequest,
    outcome: MarketControlOutcome,
) -> Result<MarketControlOutcome, (String, ErrorData)> {
    let matches_request = matches!(
        (request, &outcome),
        (
            MarketControlRequest::MarketSearchAsset(_),
            MarketControlOutcome::Search { .. }
        ) | (
            MarketControlRequest::MarketGetAssetDetails(_),
            MarketControlOutcome::Details { .. }
        )
    );
    if !matches_request {
        return Err((
            "controller_protocol_error".to_string(),
            ErrorData::internal_error("market request failed", None),
        ));
    }
    if let MarketControlOutcome::Details { result, .. } = &outcome {
        result
            .validate_response_size()
            .map_err(audit_market_error)?;
    }
    Ok(outcome)
}

/// Retain only ETFs whose description, issuer, or instrument id contains `query`
/// (case-insensitive), and recompute the count. An empty list is a valid result.
fn filter_etfs(etfs: &mut ZeroCommissionEtfs, query: &str) {
    let needle = query.to_lowercase();
    etfs.instruments.retain(|etf| {
        etf.description.to_lowercase().contains(&needle)
            || etf.issuer.to_lowercase().contains(&needle)
            || etf.instr_id.to_lowercase().contains(&needle)
    });
    etfs.count = etfs.instruments.len();
}

/// Map a wire safe-error envelope to an MCP error (safe message only).
fn error_from_dto(dto: SafeErrorDto) -> ErrorData {
    match dto.class.as_str() {
        "validation" => ErrorData::invalid_params(dto.safe_message, None),
        "internal" => ErrorData::internal_error(dto.safe_message, None),
        _ => ErrorData::invalid_request(dto.safe_message, None),
    }
}

/// The worker returned a reply variant that doesn't match the called command —
/// only possible on a protocol mismatch, surfaced as a safe internal error.
fn unexpected() -> ErrorData {
    ErrorData::internal_error("unexpected worker response", None)
}
