//! `fineco-ipc` — the internal command protocol shared by the MCP gateway and
//! the store-query worker.
//!
//! Schema-first JSON with a strict **command allowlist**. The protocol is the
//! security boundary: the gateway translates MCP tool calls into one of these
//! typed [`Request`]s, the worker validates and answers them, and **nothing
//! else crosses the socket**. There is no `url`/`path`/`headers`/`sql`/`method`/
//! `userAgent`/`validateSource`/raw-RPC field anywhere in the types, and an
//! envelope carrying an unknown key, unknown command, unknown param, or an
//! out-of-bounds value is rejected before it reaches any handler.
//!
//! This crate owns the message types + validation only; the Unix-socket I/O
//! lives in the gateway client and the worker server.

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fineco_core::{
    SafeError, normalize_expected_isin, sanitize_text, validate_order_request, validate_tax_range,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

mod capability;
pub use capability::{AuthIdPolicy, Capability, OWNER_AUTH_ID, Policy};

/// Max length of most client-supplied identifier strings in a request.
const MAX_PARAM_LEN: usize = 256;

/// Max characters in an authenticated market search query.
pub const MAX_SEARCH_QUERY_CHARS: usize = 64;

/// Max number of history points a single request may ask for.
const MAX_HISTORY_LIMIT: u32 = 1000;

/// Max number of Fineco search candidates returned to one market-search call.
pub const MAX_TOTAL_CANDIDATES: u32 = 30;

/// Max number of Fineco headline index-bar cards returned in one call.
pub const MAX_INDEX_CARDS: u32 = 50;

/// Cross-call worker-held Fineco market-session reuse window, in seconds (plan
/// D-22). `Some(n)`: the credentialed worker may reuse a still-valid held session
/// across separate market reads whose gap is under `n`, and the controller treats
/// such a read as a reuse (no fresh-login cooldown/budget debit) — so a basket of
/// back-to-back instrument reads rides one login instead of one login per read.
/// `None`: stateless per call (a fresh login every read).
///
/// `180` (3 min) is deliberately conservative: it sits under the only hard floor we
/// have — Fineco's frontend logs an idle browser out at 5 min, and the server session
/// outlives that — while staying well short of any plausible server-side idle timeout
/// (the real threshold is server-enforced and not exposed in the frontend, so this is
/// a fixed safe value, not a derived one). It is tunable from production telemetry:
/// the [`MarketSessionStatus::reused_session_401_recovered`] counter is the feedback
/// signal — rare/zero recoveries mean the window is safe to nudge up; a spike means
/// the server is stricter than assumed and it should come down. A reused session that
/// the server has nonetheless expired is repaired by exactly one fresh-login retry.
pub const MARKET_SESSION_REUSE_TTL_SECS: Option<u64> = Some(180);

/// Max candidate summaries embedded in an ambiguity safe error.
pub const MAX_AMBIGUITY_SUGGESTIONS: usize = 10;

/// Max number of candidates returned in one search result group.
pub const MAX_CANDIDATES_PER_GROUP: usize = 10;

/// Max number of asset-type groups in one market-search result (plan D-20).
/// Fineco's global search exposes a fixed set of asset-type buckets and the
/// normalizer emits one group per populated type, so this bound is already met
/// structurally; it is a named, defensively enforced cap so the limit cannot
/// silently grow if a new bucket is ever added to the search response shape.
pub const MAX_SEARCH_GROUPS: usize = 8;

/// Max characters in a public market-details identifier (`<venue>/<symbol>`).
pub const MAX_IDENTIFIER_CHARS: usize = 64;

/// Max number of explicit sections a market-details request may ask for. Must be
/// at least the number of v0-supported sections so a client can request the full
/// advertised set in one call (13 since the `bond` section was added).
pub const MAX_SECTIONS: usize = 13;

/// Max ETF holdings returned in a details response.
pub const MAX_HOLDINGS: usize = 25;

/// Max exposure rows returned for any one exposure group.
pub const MAX_EXPOSURE_ROWS_PER_GROUP: usize = 25;

/// Max return rows returned for one details response.
pub const MAX_RETURNS_ROWS: usize = 40;

/// Max stock ratio rows returned for one details response.
pub const MAX_STOCK_RATIOS: usize = 80;

/// Max warnings returned in a details response.
pub const MAX_WARNINGS: usize = 20;

/// Max source records returned in a details response.
pub const MAX_SOURCES: usize = 20;

/// Max serialized JSON bytes returned by one market-details response.
pub const MAX_DETAILS_RESPONSE_BYTES: usize = 98_304;

/// Max framed message size on the socket (bounds memory against a hostile or
/// buggy peer); applies to both requests and replies.
const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// Read/write timeout on a socket connection. Bounds a stalled or half-open peer
/// so it cannot block the worker's accept loop (server) or hang an async gateway
/// task in the blocking pool (client). Local cached reads are fast; this is a
/// generous hang-stop, not a latency budget.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);

/// A validated command from the gateway to the worker. Adjacently tagged as
/// `{"command": "...", "params": {...}}`; commands without parameters omit
/// `params`. The full surface is the cached read tools — there is no live-refresh
/// or generic-proxy command here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "command", content = "params", rename_all = "snake_case")]
pub enum Request {
    PortfolioGetFreshness,
    PortfolioGetLatestSnapshotSummary,
    PortfolioGetLatestFullSnapshot,
    PortfolioGetLatestShareableReport,
    OrdersGetLatestMonitor,
    TaxGetLatestCarryForward,
    TaxGetLatestMinusByYear,
    PortfolioGetHistory(HistoryParams),
    PortfolioGetAllocationHistory,
    PortfolioGetPositionHistory(PositionHistoryParams),
    MarketGetZeroCommissionEtfs(MarketEtfsParams),
}

impl Request {
    /// The capability a caller must hold to issue this command (plan "Capability
    /// Model"). The gateway checks it before dispatch and the worker re-checks it
    /// independently. Reads that expose owner-only absolutes require
    /// `portfolio.cached.full_read`; shareable-safe reads (freshness metadata,
    /// the shareable report, allocation weights) require only
    /// `portfolio.shareable.read`.
    #[must_use]
    pub fn required_capability(&self) -> Capability {
        match self {
            Request::PortfolioGetFreshness
            | Request::PortfolioGetLatestShareableReport
            | Request::PortfolioGetAllocationHistory => Capability::PortfolioShareableRead,
            Request::PortfolioGetLatestSnapshotSummary
            | Request::PortfolioGetLatestFullSnapshot
            | Request::PortfolioGetHistory(_)
            | Request::PortfolioGetPositionHistory(_) => Capability::PortfolioCachedFullRead,
            Request::OrdersGetLatestMonitor => Capability::OrdersCachedRead,
            Request::TaxGetLatestCarryForward | Request::TaxGetLatestMinusByYear => {
                Capability::TaxCachedRead
            }
            Request::MarketGetZeroCommissionEtfs(_) => Capability::MarketRead,
        }
    }

    /// The MCP tool name this request backs, for the audit log. A stable label
    /// (no parameters/payload), matching the gateway's `#[tool(name = …)]`.
    #[must_use]
    pub fn audit_tool(&self) -> &'static str {
        match self {
            Request::PortfolioGetFreshness => "portfolio_get_freshness",
            Request::PortfolioGetLatestSnapshotSummary => "portfolio_get_latest_snapshot_summary",
            Request::PortfolioGetLatestFullSnapshot => "portfolio_get_latest_full_snapshot",
            Request::PortfolioGetLatestShareableReport => "portfolio_get_latest_shareable_report",
            Request::OrdersGetLatestMonitor => "orders_get_latest_monitor",
            Request::TaxGetLatestCarryForward => "tax_get_latest_carry_forward",
            Request::TaxGetLatestMinusByYear => "tax_get_latest_minus_by_year",
            Request::PortfolioGetHistory(_) => "portfolio_get_history",
            Request::PortfolioGetAllocationHistory => "portfolio_get_allocation_history",
            Request::PortfolioGetPositionHistory(_) => "portfolio_get_position_history",
            Request::MarketGetZeroCommissionEtfs(_) => "market_get_zero_commission_etfs",
        }
    }
}

/// Parameters for `portfolio_get_history`: how many recent snapshots to return.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HistoryParams {
    pub limit: u32,
}

/// Parameters for `portfolio_get_position_history`: one instrument by its
/// `(instr_id, venue_system)` key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PositionHistoryParams {
    pub instr_id: String,
    pub venue_system: String,
}

/// Parameters for `market_get_zero_commission_etfs` (an optional filter query).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MarketEtfsParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
}

/// Fineco asset groups normalized from the authenticated instrument search.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MarketAssetType {
    Stock,
    Etf,
    Bond,
    Cfd,
    FixedLeverage,
    Turbo,
    Knockout,
    FxCfd,
    Unknown,
}

impl MarketAssetType {
    /// Stable lowercase label used in normalized JSON and safe error context.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            MarketAssetType::Stock => "stock",
            MarketAssetType::Etf => "etf",
            MarketAssetType::Bond => "bond",
            MarketAssetType::Cfd => "cfd",
            MarketAssetType::FixedLeverage => "fixed_leverage",
            MarketAssetType::Turbo => "turbo",
            MarketAssetType::Knockout => "knockout",
            MarketAssetType::FxCfd => "fx_cfd",
            MarketAssetType::Unknown => "unknown",
        }
    }
}

/// Parameters for `market_search_asset`: a free-text ticker/name/ISIN query,
/// optional asset-type filter, and bounded candidate limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MarketSearchParams {
    pub query: String,
    #[serde(rename = "type")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_type: Option<MarketAssetType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One normalized instrument candidate from Fineco search.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketSearchCandidate {
    /// Non-secret Fineco lookup key (`instr_id.venue`), useful for follow-up tools.
    pub fineco_key: String,
    /// Public follow-up identifier in the approved `<fineco_venue>/<symbol>` form.
    pub identifier: String,
    pub name: String,
    pub venue: String,
    /// Symbol base without Fineco's display suffix where one is present.
    pub symbol: String,
    /// Fineco display symbol, such as `VHYL.MI`, `VHYL.AS`, or `AAPL.O`.
    pub display_symbol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(rename = "type")]
    pub asset_type: MarketAssetType,
    /// Fineco's own "best execution"/preferred marker when present.
    pub preferred: bool,
}

/// Search candidates grouped by normalized asset type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketSearchGroup {
    #[serde(rename = "type")]
    pub asset_type: MarketAssetType,
    pub result_count: usize,
    pub candidates: Vec<MarketSearchCandidate>,
}

/// Authenticated Fineco search result. `captured_at` is fetch time, not a
/// provider-reported quote/NAV timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketSearchResult {
    pub query: String,
    pub data_class: String,
    pub source: String,
    pub captured_at: String,
    pub groups: Vec<MarketSearchGroup>,
}

/// Optional coarse region filter for `market_get_indices`. This is a bounded
/// local filter over Fineco's headline index-bar widget, not a venue registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MarketIndexRegion {
    Europe,
    Americas,
    AsiaPacific,
    Other,
}

/// Parameters for `market_get_indices`: a bounded read of Fineco's headline
/// indices-bar cards with an optional coarse local region filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct MarketIndicesParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<MarketIndexRegion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One normalized card from Fineco's headline indices-bar widget. Despite the
/// tool name, Fineco also includes a few FX/commodity/crypto/spread cards; v0
/// preserves them as headline cards and does not infer a market universe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketIndexCard {
    pub symbol: MarketField<String>,
    pub label: MarketField<String>,
    pub region: MarketIndexRegion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_percent: Option<MarketField<f64>>,
}

/// Normalized result for `market_get_indices`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketIndicesResult {
    pub schema_version: u32,
    pub data_class: String,
    pub source: String,
    pub captured_at: String,
    pub indices: Vec<MarketIndexCard>,
    pub warnings: Vec<MarketWarning>,
}

/// Optional sections for `market_get_asset_details`. Defaults are selected by
/// the controller/worker; heavy sections are returned only when explicitly
/// requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MarketDetailsSection {
    Identity,
    Listing,
    Quote,
    Profile,
    Etf,
    Stock,
    Bond,
    Holdings,
    Exposures,
    Returns,
    Risk,
    Ratios,
    Chart,
    Events,
    News,
    Similar,
    ExternalEnrichment,
}

/// Parameters for `market_get_asset_details`: a venue-qualified public
/// identifier, optional ISIN verifier, and an optional bounded section set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MarketDetailsParams {
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_isin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sections: Option<Vec<MarketDetailsSection>>,
}

/// Field-level confidence label for normalized market details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MarketConfidence {
    High,
    Medium,
    Low,
}

/// A normalized provider field with source and freshness provenance. `as_of` is
/// the provider-reported datum timestamp when present; `captured_at` is this
/// service's fetch time and is never used as a silent substitute.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketField<T> {
    pub value: T,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    pub source: String,
    pub data_class: String,
    pub source_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_of: Option<String>,
    pub captured_at: String,
    pub confidence: MarketConfidence,
}

impl<T> MarketField<T> {
    #[must_use]
    pub fn high(
        value: T,
        unit: Option<&str>,
        source: &str,
        data_class: &str,
        source_ref: &str,
        as_of: Option<&str>,
        captured_at: &str,
    ) -> Self {
        Self {
            value,
            unit: sanitize_optional_metadata(unit),
            source: source.to_string(),
            data_class: data_class.to_string(),
            source_ref: source_ref.to_string(),
            as_of: sanitize_optional_metadata(as_of),
            captured_at: captured_at.to_string(),
            confidence: MarketConfidence::High,
        }
    }

    #[must_use]
    pub fn medium(
        value: T,
        unit: Option<&str>,
        source: &str,
        data_class: &str,
        source_ref: &str,
        as_of: Option<&str>,
        captured_at: &str,
    ) -> Self {
        Self {
            value,
            unit: sanitize_optional_metadata(unit),
            source: source.to_string(),
            data_class: data_class.to_string(),
            source_ref: source_ref.to_string(),
            as_of: sanitize_optional_metadata(as_of),
            captured_at: captured_at.to_string(),
            confidence: MarketConfidence::Medium,
        }
    }

    #[must_use]
    pub fn low(
        value: T,
        unit: Option<&str>,
        source: &str,
        data_class: &str,
        source_ref: &str,
        as_of: Option<&str>,
        captured_at: &str,
    ) -> Self {
        Self {
            value,
            unit: sanitize_optional_metadata(unit),
            source: source.to_string(),
            data_class: data_class.to_string(),
            source_ref: source_ref.to_string(),
            as_of: sanitize_optional_metadata(as_of),
            captured_at: captured_at.to_string(),
            confidence: MarketConfidence::Low,
        }
    }
}

fn sanitize_optional_metadata(value: Option<&str>) -> Option<String> {
    value
        .map(sanitize_text)
        .filter(|cleaned| !cleaned.is_empty())
}

impl MarketField<String> {
    #[must_use]
    pub fn high_string(
        value: &str,
        source: &str,
        data_class: &str,
        source_ref: &str,
        captured_at: &str,
    ) -> Self {
        Self::high(
            value.to_string(),
            None,
            source,
            data_class,
            source_ref,
            None,
            captured_at,
        )
    }

    #[must_use]
    pub fn medium_string(
        value: &str,
        source: &str,
        data_class: &str,
        source_ref: &str,
        captured_at: &str,
    ) -> Self {
        Self::medium(
            value.to_string(),
            None,
            source,
            data_class,
            source_ref,
            None,
            captured_at,
        )
    }
}

/// Normalized asset identity returned by `market_get_asset_details`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketAssetIdentity {
    pub identifier: String,
    pub fineco_key: MarketField<String>,
    #[serde(rename = "type")]
    pub asset_type: MarketField<MarketAssetType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isin: Option<MarketField<String>>,
    pub venue: MarketField<String>,
    pub symbol: MarketField<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_symbol: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<MarketField<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketListingSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_date: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_venue: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid_url: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub esg_taxonomy: Option<MarketField<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketQuoteSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bid: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_close: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_percent: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<MarketField<f64>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketProfileSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sector: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub industry: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub investment_strategy: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inception_date: Option<MarketField<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketEtfSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ongoing_charge: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_fee: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aum: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nav: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ucits: Option<MarketField<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub morningstar_rating: Option<MarketField<f64>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct MarketStockSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_cap: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pe: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eps: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roe: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dividend: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dividend_yield: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range_52w_high: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range_52w_low: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance_1w: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance_3m: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance_6m: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance_1y: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_price: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_count: Option<MarketField<f64>>,
}

/// Normalized fixed-income facts for a bond, sourced from Fineco's static
/// instrument record (`static.search`) plus its live quote/yield snapshot.
///
/// Coupon is reported three ways to make Fineco's per-payment semantics explicit:
/// `coupon_rate` is the annual nominal rate, `coupon_rate_per_period` is the raw
/// per-payment rate Fineco reports, and `coupon_payments_per_year` is the
/// multiplier. `maturity_date` is the real redemption date; `next_coupon_date` is
/// the upcoming coupon. `dirty_price` is computed (clean + accrued), not provider
/// reported. Rating fields are Fineco-reported point-in-time labels with no agency,
/// date, or outlook; an accompanying warning flags that.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct MarketBondSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coupon_rate: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coupon_rate_per_period: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coupon_payments_per_year: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coupon_type: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coupon_frequency: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maturity_date: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_coupon_date: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_date: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_price: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accrued_interest: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clean_price: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dirty_price: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yield_to_maturity_gross: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yield_to_maturity_net: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rating: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_rating: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subordinated: Option<MarketField<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_lot: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub par_value: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bail_in: Option<MarketField<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priips: Option<MarketField<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_at_risk: Option<MarketField<f64>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketRatio {
    pub group: MarketField<String>,
    pub name: MarketField<String>,
    pub value: MarketField<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct MarketRatiosSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_available_date: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ratios: Vec<MarketRatio>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketHolding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isin: Option<MarketField<String>>,
    pub name: MarketField<String>,
    pub weight: MarketField<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketExposure {
    pub label: MarketField<String>,
    pub value: MarketField<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct MarketExposuresSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asset_allocation: Vec<MarketExposure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<MarketExposure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sectors: Vec<MarketExposure>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketReturn {
    pub period: String,
    pub value: MarketField<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct MarketReturnsSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cumulative: Vec<MarketReturn>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annual: Vec<MarketReturn>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarterly: Vec<MarketReturn>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct MarketRiskSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard_deviation_m36: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sharpe_ratio_m36: Option<MarketField<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beta_m36: Option<MarketField<f64>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketExternalCompanyOverview {
    pub name: String,
    pub ticker: String,
    pub exchange: String,
    pub isin: String,
    pub country: String,
    pub website: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketExternalEnrichmentSection {
    pub data_class: String,
    pub captured_at: String,
    pub source_url: String,
    pub company: MarketExternalCompanyOverview,
    pub scores: serde_json::Value,
    pub metrics: serde_json::Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Third-party ETF reference data (the `external_enrichment` data class), keyed by
/// ISIN. Distinct from [`MarketExternalEnrichmentSection`] (stock-oriented, plain
/// strings + score/metric bags): ETF enrichment is a fixed set of named fund
/// attributes, each a typed [`MarketField`] so numerics (TER, fund size, 1-year
/// volatility) carry units and provenance like the rest of the response. Every
/// field is optional — present only when the source exposed it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct MarketEtfExternalEnrichment {
    pub data_class: String,
    pub captured_at: String,
    pub source_url: String,
    /// Total expense ratio, percent per annum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ter: Option<MarketField<f64>>,
    /// Total fund size; `unit` carries the currency + magnitude (e.g. "EUR million").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fund_size: Option<MarketField<f64>>,
    /// 1-year volatility, percent (as published, in the source's reference currency).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volatility_1y: Option<MarketField<f64>>,
    /// Replication method, e.g. "Physical (Optimized sampling)" / "Synthetic".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replication: Option<MarketField<String>>,
    /// Legal structure, e.g. "ETF".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_structure: Option<MarketField<String>>,
    /// Fund domicile country, e.g. "Ireland".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domicile: Option<MarketField<String>>,
    /// Fund provider / issuer, e.g. "iShares".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fund_provider: Option<MarketField<String>>,
    /// Distribution policy, e.g. "Accumulating" / "Distributing".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution_policy: Option<MarketField<String>>,
    /// Distribution frequency, e.g. "Quarterly" (absent for accumulating funds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distribution_frequency: Option<MarketField<String>>,
    /// Fund (share-class) currency, e.g. "USD".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fund_currency: Option<MarketField<String>>,
    /// Currency hedging, e.g. "Currency unhedged".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency_hedge: Option<MarketField<String>>,
    /// Tracked index name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_name: Option<MarketField<String>>,
    /// Investment focus, e.g. "Equity, World, Dividend".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub investment_focus: Option<MarketField<String>>,
    /// Launch / inception date, as published text (e.g. "21 May 2013").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_date: Option<MarketField<String>>,
    /// Strategy / risk descriptor, e.g. "Long-only".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_risk: Option<MarketField<String>>,
    /// Sustainability flag as published, e.g. "Yes" / "No".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sustainable: Option<MarketField<String>>,
    /// Securities lending flag, e.g. "Yes" / "No".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub securities_lending: Option<MarketField<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Normalized details sections. Missing sections mean not requested, not
/// available, or not applicable; explicit warnings explain important absences.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct MarketAssetSections {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing: Option<MarketListingSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<MarketQuoteSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<MarketProfileSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etf: Option<MarketEtfSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stock: Option<MarketStockSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond: Option<MarketBondSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratios: Option<MarketRatiosSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holdings: Option<Vec<MarketHolding>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposures: Option<MarketExposuresSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub returns: Option<MarketReturnsSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk: Option<MarketRiskSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_enrichment: Option<MarketExternalEnrichmentSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etf_external_enrichment: Option<MarketEtfExternalEnrichment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketSource {
    pub source: String,
    pub data_class: String,
    pub source_ref: String,
    pub captured_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketWarning {
    pub code: String,
    pub message: String,
}

/// Normalized result for `market_get_asset_details`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketAssetDetailsResult {
    pub schema_version: u32,
    pub data_class: String,
    pub captured_at: String,
    pub asset: MarketAssetIdentity,
    pub sections: MarketAssetSections,
    pub sources: Vec<MarketSource>,
    pub warnings: Vec<MarketWarning>,
}

impl MarketAssetDetailsResult {
    /// Enforce the model-visible details response byte cap after normalization.
    ///
    /// # Errors
    /// [`SafeError::market_unexpected_response`] if the serialized JSON result
    /// exceeds [`MAX_DETAILS_RESPONSE_BYTES`].
    pub fn validate_response_size(&self) -> Result<(), SafeError> {
        let bytes = serde_json::to_vec(self).map_err(|_| SafeError::internal())?;
        if bytes.len() > MAX_DETAILS_RESPONSE_BYTES {
            return Err(SafeError::market_unexpected_response());
        }
        Ok(())
    }
}

/// Authenticated Fineco details result plus status-only worker session facts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketAssetDetailsLiveResult {
    pub result: MarketAssetDetailsResult,
    pub session: MarketSessionStatus,
}

/// Authenticated Fineco indices-bar result plus status-only worker session facts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketIndicesLiveResult {
    pub result: MarketIndicesResult,
    pub session: MarketSessionStatus,
}

/// Status-only Fineco session facts returned by the credentialed worker. This
/// intentionally carries no cookie values, auth headers, raw `Set-Cookie`, or
/// reusable session handles.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct MarketSessionStatus {
    pub login_performed: bool,
    pub session_reused: bool,
    pub session_evicted: bool,
    pub reused_session_401_recovered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_expires_in_secs: Option<u64>,
}

impl MarketDetailsParams {
    /// Validate details request bounds at every boundary.
    ///
    /// # Errors
    /// [`SafeError::invalid_request`] if the identifier/ISIN/sections are
    /// malformed or out of bounds.
    pub fn validate(&self) -> Result<(), SafeError> {
        if self.identifier.chars().count() > MAX_IDENTIFIER_CHARS {
            return Err(SafeError::invalid_request(
                "identifier must be at most 64 characters.",
            ));
        }
        validate_market_identifier(&self.identifier)?;
        if let Some(expected_isin) = &self.expected_isin {
            normalize_expected_isin(expected_isin)?;
        }
        if let Some(sections) = &self.sections
            && sections.len() > MAX_SECTIONS
        {
            return Err(SafeError::invalid_request(
                "sections must contain at most 13 entries.",
            ));
        }
        if let Some(sections) = &self.sections
            && sections
                .iter()
                .any(|section| !market_details_section_supported_in_v0(*section))
        {
            return Err(SafeError::invalid_request(
                "section is not supported by market details v0.",
            ));
        }
        Ok(())
    }
}

impl MarketSessionStatus {
    /// Status for the current stateless worker behavior: one fresh login, no
    /// retained/reused session. Later slices can tighten this to real reuse
    /// without changing the controller boundary again.
    #[must_use]
    pub fn fresh_login() -> Self {
        Self::fresh_login_with_expiry(None)
    }

    /// Fresh-login status with optional status-only session lifetime metadata.
    ///
    /// The value is derived from cookie lifetime metadata such as `Max-Age` or
    /// `Expires`, never from cookie values or a reusable session handle.
    #[must_use]
    pub fn fresh_login_with_expiry(session_expires_in_secs: Option<u64>) -> Self {
        Self {
            login_performed: true,
            session_reused: false,
            session_evicted: false,
            reused_session_401_recovered: false,
            session_expires_in_secs,
        }
    }
}

/// Authenticated market result plus the status-only session lifecycle facts the
/// controller needs for budgeting/audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarketSearchLiveResult {
    pub result: MarketSearchResult,
    pub session: MarketSessionStatus,
}

/// Authenticated market-data fetches served by the private worker. The gateway
/// never implements this trait; the controller-side live client does, so
/// market-control can route through the credentialed boundary.
pub trait MarketSearchLiveFetcher {
    /// Search Fineco instruments using the allowlisted authenticated endpoint.
    ///
    /// # Errors
    /// [`SafeError`] on validation/auth/upstream/internal failure.
    fn fetch_market_search(
        &self,
        params: &MarketSearchParams,
        now_iso: &str,
    ) -> Result<MarketSearchLiveResult, SafeError>;
}

/// Authenticated market details fetcher served by the credentialed live worker.
pub trait MarketAssetDetailsLiveFetcher {
    /// Resolve and fetch normalized Fineco details for one supported asset.
    ///
    /// # Errors
    /// [`SafeError`] on validation/auth/upstream/internal failure.
    fn fetch_market_asset_details(
        &self,
        params: &MarketDetailsParams,
        now_iso: &str,
    ) -> Result<MarketAssetDetailsLiveResult, SafeError>;
}

/// Authenticated market indices-bar fetcher served by the credentialed live worker.
pub trait MarketIndicesLiveFetcher {
    /// Fetch Fineco's normalized headline index-bar cards.
    ///
    /// # Errors
    /// [`SafeError`] on validation/auth/upstream/internal failure.
    fn fetch_market_indices(
        &self,
        params: &MarketIndicesParams,
        now_iso: &str,
    ) -> Result<MarketIndicesLiveResult, SafeError>;
}

impl MarketSearchParams {
    /// Validate search bounds at every boundary (gateway, controller, worker).
    ///
    /// # Errors
    /// [`SafeError::invalid_request`] if the query is empty/too long or the
    /// limit is outside `1..=30`.
    pub fn validate(&self) -> Result<(), SafeError> {
        if self.query.trim().is_empty() {
            return Err(SafeError::invalid_request("query must not be empty."));
        }
        if self.query.chars().count() > MAX_SEARCH_QUERY_CHARS {
            return Err(SafeError::invalid_request(
                "query must be at most 64 characters.",
            ));
        }
        if let Some(limit) = self.limit
            && (limit == 0 || limit > MAX_TOTAL_CANDIDATES)
        {
            return Err(SafeError::invalid_request("limit must be 1..=30."));
        }
        Ok(())
    }
}

impl MarketIndicesParams {
    /// Validate indices request bounds at every boundary.
    ///
    /// # Errors
    /// [`SafeError::invalid_request`] if the limit is outside `1..=50`.
    pub fn validate(&self) -> Result<(), SafeError> {
        if let Some(limit) = self.limit
            && (limit == 0 || limit > MAX_INDEX_CARDS)
        {
            return Err(SafeError::invalid_request("limit must be 1..=50."));
        }
        Ok(())
    }
}

fn validate_market_identifier(identifier: &str) -> Result<(), SafeError> {
    if identifier.contains("://") {
        return Err(SafeError::invalid_request(
            "identifier must be venue-qualified.",
        ));
    }
    let separator_count = identifier
        .chars()
        .filter(|ch| matches!(ch, '/' | ':'))
        .count();
    if separator_count != 1 {
        return Err(SafeError::invalid_request(
            "identifier must be venue-qualified.",
        ));
    }
    let mut parts = identifier.split(['/', ':']);
    let venue = parts.next().unwrap_or_default();
    let symbol = parts.next().unwrap_or_default();
    if venue.is_empty() || symbol.is_empty() {
        return Err(SafeError::invalid_request(
            "identifier must be venue-qualified.",
        ));
    }
    Ok(())
}

fn market_details_section_supported_in_v0(section: MarketDetailsSection) -> bool {
    matches!(
        section,
        MarketDetailsSection::Identity
            | MarketDetailsSection::Listing
            | MarketDetailsSection::Quote
            | MarketDetailsSection::Profile
            | MarketDetailsSection::Etf
            | MarketDetailsSection::Stock
            | MarketDetailsSection::Bond
            | MarketDetailsSection::Holdings
            | MarketDetailsSection::Exposures
            | MarketDetailsSection::Returns
            | MarketDetailsSection::Risk
            | MarketDetailsSection::Ratios
            | MarketDetailsSection::ExternalEnrichment
    )
}

impl Request {
    /// Parse and fully validate a request envelope from JSON.
    ///
    /// Enforces, in order: the envelope is an object with keys ⊆
    /// `{command, params}` (no smuggled fields); the command is on the
    /// allowlist and its params carry no unknown fields (`deny_unknown_fields`);
    /// and every string is within bounds.
    ///
    /// # Errors
    /// [`SafeError::invalid_request`] with a payload-free message on any
    /// violation. The offending value is never echoed.
    pub fn from_json(json: &str) -> Result<Self, SafeError> {
        let value: serde_json::Value = serde_json::from_str(json)
            .map_err(|_| SafeError::invalid_request("Request is not valid JSON."))?;
        validate_envelope_keys(&value)?;

        let request: Request = serde_json::from_value(value)
            .map_err(|_| SafeError::invalid_request("Request is not an allowed command."))?;
        request.validate_bounds()?;
        Ok(request)
    }

    /// Serialize the request to its JSON envelope.
    ///
    /// # Errors
    /// [`SafeError::internal`] if serialization fails (should not happen).
    pub fn to_json(&self) -> Result<String, SafeError> {
        serde_json::to_string(self).map_err(|_| SafeError::internal())
    }

    /// Validate this request's bounds (string lengths, numeric ranges,
    /// non-empty identifiers). The gateway builds requests from typed MCP
    /// parameters that never pass through [`Request::from_json`], so it calls
    /// this to enforce the same bounds at its end (the plan's "validate at both
    /// ends" rule).
    ///
    /// # Errors
    /// [`SafeError::invalid_request`] with a payload-free message on any
    /// violation. The offending value is never echoed.
    pub fn validate(&self) -> Result<(), SafeError> {
        self.validate_bounds()
    }

    /// Bound every client-supplied string to [`MAX_PARAM_LEN`].
    fn validate_bounds(&self) -> Result<(), SafeError> {
        let check = |s: &str| -> Result<(), SafeError> {
            if s.chars().count() > MAX_PARAM_LEN {
                Err(SafeError::invalid_request("A request field is too long."))
            } else {
                Ok(())
            }
        };
        match self {
            Request::MarketGetZeroCommissionEtfs(p) => {
                if let Some(query) = &p.query {
                    check(query)?;
                }
            }
            Request::PortfolioGetHistory(p) => {
                if p.limit == 0 || p.limit > MAX_HISTORY_LIMIT {
                    return Err(SafeError::invalid_request("limit must be 1..=1000."));
                }
            }
            Request::PortfolioGetPositionHistory(p) => {
                check(&p.instr_id)?;
                check(&p.venue_system)?;
                if p.instr_id.is_empty() || p.venue_system.is_empty() {
                    return Err(SafeError::invalid_request(
                        "instr_id and venue_system must not be empty.",
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Reject an envelope that is not an object, or that carries any key beyond
/// `command`/`params` (e.g. a smuggled `url`/`sql`/`headers`). This is the
/// `additionalProperties: false` guard that serde's `deny_unknown_fields` does
/// not provide on a tagged enum.
/// Reject any top-level key other than `command`/`params` in a command envelope.
/// Both IPC protocols are adjacently-tagged enums (`{command, params}`) — serde
/// alone would silently *ignore* extra top-level keys, so every server-side
/// decode path validates the envelope with this before deserializing, giving the
/// `fineco-live` socket the same closed-envelope guarantee as refresh-control.
///
/// # Errors
/// [`SafeError::invalid_request`] (payload-free) if `value` is not an object or
/// carries an unexpected key.
pub fn validate_envelope_keys(value: &serde_json::Value) -> Result<(), SafeError> {
    let object = value
        .as_object()
        .ok_or_else(|| SafeError::invalid_request("Request must be a JSON object."))?;
    for key in object.keys() {
        if key != "command" && key != "params" {
            return Err(SafeError::invalid_request(
                "Request carries an unexpected field.",
            ));
        }
    }
    Ok(())
}

/// A successful command result. Typed per command (the plan forbids generic raw
/// JSON for private payloads); variants are added as each command is wired.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "result", content = "data", rename_all = "snake_case")]
pub enum ResponseBody {
    /// `portfolio_get_freshness`: the freshness of every data area at once.
    Freshness(FreshnessReportDto),
    /// `orders_get_latest_monitor`: the latest order-monitor capture.
    Orders(OrdersDto),
    /// `tax_get_latest_carry_forward`: the latest tax carry-forward capture.
    TaxCarryForward(TaxCarryForwardListDto),
    /// `tax_get_latest_minus_by_year`: the latest tax minus-by-year capture.
    TaxMinus(TaxMinusListDto),
    /// `portfolio_get_latest_snapshot_summary`: the latest snapshot's totals.
    PortfolioSummary(PortfolioSummaryDto),
    /// `portfolio_get_latest_full_snapshot`: totals + every position (owner-only
    /// crown-jewel absolutes).
    PortfolioFullSnapshot(FullSnapshotDto),
    /// `portfolio_get_latest_shareable_report`: the shareable rows only — names,
    /// symbols, ISINs, weights, and percentage performance, no absolute values.
    PortfolioShareableReport(ShareableReportDto),
    /// `portfolio_get_history`: recent snapshot totals over time.
    PortfolioHistory(PortfolioHistoryDto),
    /// `portfolio_get_allocation_history`: per-instrument weights over time.
    AllocationHistory(AllocationHistoryDto),
    /// `portfolio_get_position_history`: one instrument's history over time.
    PositionHistory(PositionHistoryDto),
}

impl ResponseBody {
    /// The number of items in this response's primary collection, for the audit
    /// log — a count only, never the values. `None` for scalar/per-area reports
    /// (a summary or freshness report has no single meaningful row count).
    #[must_use]
    pub fn audit_count(&self) -> Option<usize> {
        match self {
            ResponseBody::Freshness(_) | ResponseBody::PortfolioSummary(_) => None,
            ResponseBody::Orders(dto) => Some(dto.orders.len()),
            ResponseBody::TaxCarryForward(dto) => Some(dto.entries.len()),
            ResponseBody::TaxMinus(dto) => Some(dto.entries.len()),
            ResponseBody::PortfolioFullSnapshot(dto) => Some(dto.positions.len()),
            ResponseBody::PortfolioShareableReport(dto) => Some(dto.rows.len()),
            ResponseBody::PortfolioHistory(dto) => Some(dto.points.len()),
            ResponseBody::AllocationHistory(dto) => Some(dto.points.len()),
            ResponseBody::PositionHistory(dto) => Some(dto.points.len()),
        }
    }
}

/// Recent portfolio snapshot totals, chronological (oldest first).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PortfolioHistoryDto {
    pub points: Vec<PortfolioHistoryPointDto>,
}

/// One snapshot's totals in [`PortfolioHistoryDto`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PortfolioHistoryPointDto {
    pub captured_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub book_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profit_loss: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profit_loss_perc: Option<f64>,
}

/// Per-instrument allocation weights across snapshots.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AllocationHistoryDto {
    pub points: Vec<AllocationPointDto>,
}

/// One `(snapshot, instrument)` allocation point.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AllocationPointDto {
    pub captured_at: String,
    pub instr_id: String,
    pub venue_system: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight_perc: Option<f64>,
}

/// A single instrument's history across snapshots.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PositionHistoryDto {
    pub points: Vec<PositionHistoryPointDto>,
}

/// One point in an instrument's history (owner-only `market_value`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PositionHistoryPointDto {
    pub captured_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight_perc: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profit_loss_perc: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_value: Option<f64>,
}

/// The latest portfolio snapshot's totals (all `None` if no snapshot exists).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PortfolioSummaryDto {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub book_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profit_loss: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profit_loss_perc: Option<f64>,
}

/// The latest full snapshot: totals + every position.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FullSnapshotDto {
    pub summary: PortfolioSummaryDto,
    pub positions: Vec<PositionDto>,
}

/// A position in a full snapshot (owner-only absolutes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PositionDto {
    pub instr_id: String,
    pub venue_system: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qty: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_price: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_price: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub book_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profit_loss: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profit_loss_perc: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight_perc: Option<f64>,
}

/// The shareable report (structurally cannot carry absolute values).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ShareableReportDto {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    pub rows: Vec<ShareableRowDto>,
}

/// A shareable row: identity + weights + percentage performance only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ShareableRowDto {
    pub description: String,
    pub symbol: String,
    pub instr_id: String,
    pub venue_system: String,
    pub kind: String,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight_perc: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profit_loss_perc: Option<f64>,
}

/// The latest order-monitor capture (owner-only cached private data).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrdersDto {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    pub orders: Vec<OrderDto>,
}

/// A single order in [`OrdersDto`]. The transaction id is the stored HMAC hash,
/// never the raw id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OrderDto {
    pub trans_id_hash: String,
    pub instr_id: String,
    pub venue_system: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_size: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_filled: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_price: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submit_time: Option<String>,
}

/// The latest tax carry-forward capture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaxCarryForwardListDto {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    pub entries: Vec<TaxCarryForwardDto>,
}

/// A single tax carry-forward entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaxCarryForwardDto {
    pub date_from: String,
    pub date_to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
}

/// The latest tax minus-by-year capture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaxMinusListDto {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    pub entries: Vec<TaxMinusDto>,
}

/// A single tax minus-by-year entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TaxMinusDto {
    pub year: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minus_residue: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,
}

/// Freshness of all data areas, as returned by `portfolio_get_freshness`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreshnessReportDto {
    pub portfolio: FreshnessDto,
    pub orders: FreshnessDto,
    pub tax: FreshnessDto,
}

/// Freshness of a single data area, as carried on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreshnessDto {
    /// `fresh` | `stale` | `missing` | `refreshing` | `auth_required` |
    /// `refresh_failed` (the worker maps `FreshnessState` to this).
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
}

/// The safe error envelope as carried on the wire — only the allowlisted,
/// non-sensitive fields of [`SafeError`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SafeErrorDto {
    pub code: String,
    pub class: String,
    pub retryable: bool,
    pub safe_message: String,
}

impl From<&SafeError> for SafeErrorDto {
    fn from(error: &SafeError) -> Self {
        Self {
            code: error.code().to_string(),
            class: error.class().as_str().to_string(),
            retryable: error.retryable(),
            safe_message: error.safe_message().to_string(),
        }
    }
}

/// A reply to a [`Request`]: either a typed result or a safe error envelope.
/// Every worker failure crosses the socket as the `err` form — never a raw
/// message or payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", content = "body", rename_all = "snake_case")]
pub enum WireReply {
    Ok(ResponseBody),
    Err(SafeErrorDto),
}

impl WireReply {
    /// Build a reply from a handler's result, mapping the error to its safe DTO.
    #[must_use]
    pub fn from_result(result: Result<ResponseBody, SafeError>) -> Self {
        match result {
            Ok(body) => WireReply::Ok(body),
            Err(error) => WireReply::Err(SafeErrorDto::from(&error)),
        }
    }

    /// Collapse the reply into a `Result`, surfacing the safe error DTO.
    ///
    /// # Errors
    /// Returns the [`SafeErrorDto`] when the reply is the `err` form.
    pub fn into_result(self) -> Result<ResponseBody, SafeErrorDto> {
        match self {
            WireReply::Ok(body) => Ok(body),
            WireReply::Err(error) => Err(error),
        }
    }
}

/// Write a length-prefixed frame (4-byte big-endian length + raw bytes).
fn write_frame<W: Write>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message exceeds size limit",
        ));
    }
    let len = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

/// A `Read` adapter over a `UnixStream` that bounds the TOTAL wall-clock of a
/// framed read to a `deadline`.
///
/// The socket read timeout (`SO_RCVTIMEO`) re-arms on *every* partial read, so a
/// peer that trickles one byte just under the timeout could hold a connection —
/// and the single-consumer accept loop — open indefinitely. Before each read this
/// caps the stream's read timeout to the REMAINING budget, so even a single
/// blocking read cannot run past the deadline (a deadline check between reads
/// alone would let the last read overshoot by up to a full timeout). A
/// non-positive budget fails closed with `TimedOut`.
pub struct DeadlineReader<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl<'a> DeadlineReader<'a> {
    /// Wrap `stream`, bounding reads to `deadline`.
    #[must_use]
    pub fn new(stream: &'a mut UnixStream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(remaining) = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|budget| !budget.is_zero())
        else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection deadline exceeded",
            ));
        };
        // Cap THIS read to the remaining budget so a blocking socket read cannot run
        // past the deadline.
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buf)
    }
}

/// Read one length-prefixed frame, bounding the body before allocating.
fn read_frame<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "framed message exceeds size limit",
        ));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    Ok(body)
}

/// Write a length-prefixed JSON message (4-byte big-endian length + body).
///
/// # Errors
/// I/O errors, or an oversized message exceeding [`MAX_MESSAGE_BYTES`].
pub fn write_message<W: Write, T: Serialize>(writer: &mut W, message: &T) -> io::Result<()> {
    let bytes =
        serde_json::to_vec(message).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_frame(writer, &bytes)
}

/// Read a length-prefixed JSON message written by [`write_message`].
///
/// # Errors
/// I/O errors, a length over [`MAX_MESSAGE_BYTES`], or a body that does not
/// deserialize into `T`.
pub fn read_message<R: Read, T: DeserializeOwned>(reader: &mut R) -> io::Result<T> {
    let body = read_frame(reader)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Read one framed command envelope, reject unknown TOP-LEVEL keys, then decode
/// to `T`. The shared server-side decode for an adjacently-tagged command enum
/// (`{command, params}`): serde alone would silently ignore extra envelope keys,
/// so both the refresh-control and `fineco-live` sockets route their decode
/// through this for the same closed-envelope guarantee.
///
/// # Errors
/// [`SafeError::invalid_request`] (payload-free) on an I/O/frame error, an
/// unexpected envelope key, or a body that does not deserialize into `T`.
pub fn read_command_message<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, SafeError> {
    let value: serde_json::Value = read_message(reader)
        .map_err(|_| SafeError::invalid_request("the request could not be decoded"))?;
    validate_envelope_keys(&value)?;
    serde_json::from_value(value)
        .map_err(|_| SafeError::invalid_request("the request could not be decoded"))
}

/// Serve validated requests on `listener`, one request/reply per connection.
///
/// The server **re-validates** every request via [`Request::from_json`]
/// (schema validation at both ends), so a hostile or over-permissive peer
/// cannot reach `handler` with an unknown command, a smuggled field, or an
/// out-of-bounds value. A single connection's failure never stops the server.
///
/// # Errors
/// Returns an error only if accepting connections fails irrecoverably.
pub fn serve_blocking<H>(listener: &UnixListener, handler: H) -> io::Result<()>
where
    H: Fn(Request) -> Result<ResponseBody, SafeError>,
{
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = serve_one(&mut stream, &handler);
    }
    Ok(())
}

/// Handle exactly one request/reply on `stream`.
fn serve_one<H>(stream: &mut UnixStream, handler: &H) -> io::Result<()>
where
    H: Fn(Request) -> Result<ResponseBody, SafeError>,
{
    // Bound a stalled peer so one half-open connection cannot pin the accept loop.
    let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
    // Bound the TOTAL read time, not just each read: the per-read `SO_RCVTIMEO`
    // re-arms on every byte, so a trickling peer needs a wall-clock deadline too.
    let raw = {
        let mut reader = DeadlineReader::new(stream, Instant::now() + SOCKET_TIMEOUT);
        read_frame(&mut reader)?
    };
    let validated = std::str::from_utf8(&raw)
        .map_err(|_| SafeError::invalid_request("Request is not valid UTF-8."))
        .and_then(Request::from_json);
    let reply = match validated {
        Ok(request) => WireReply::from_result(handler(request)),
        Err(error) => WireReply::Err(SafeErrorDto::from(&error)),
    };
    write_message(stream, &reply)
}

/// A blocking client for the store-query socket — one connection per call.
#[derive(Debug, Clone)]
pub struct Client {
    path: PathBuf,
}

impl Client {
    /// Target the socket at `path`. No connection is made until [`Client::call`].
    #[must_use]
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Send `request` and return the worker's reply. Transport failures and the
    /// worker's failures both surface as the safe error envelope ([`SafeErrorDto`]);
    /// no raw transport detail leaks.
    ///
    /// # Errors
    /// The [`SafeErrorDto`] the worker returned, or an `internal` envelope on a
    /// connect/transport failure.
    pub fn call(&self, request: &Request) -> Result<ResponseBody, SafeErrorDto> {
        let internal = || SafeErrorDto::from(&SafeError::internal());
        let mut stream = UnixStream::connect(&self.path).map_err(|_| internal())?;
        // Bound a stalled worker so an async gateway task cannot hang the blocking
        // pool waiting on a reply that never comes.
        let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
        let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
        write_message(&mut stream, request).map_err(|_| internal())?;
        let reply: WireReply = read_message(&mut stream).map_err(|_| internal())?;
        reply.into_result()
    }
}

// ===== Authenticated market-control protocol (gateway <-> controller) =======
//
// A sibling of refresh-control on a controller-owned socket. The gateway may ask
// for allowlisted authenticated Fineco market data, but still never talks to the
// credentialed live socket directly.

/// An authenticated market command from the gateway to the controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "command", content = "params", rename_all = "snake_case")]
pub enum MarketControlRequest {
    MarketSearchAsset(MarketSearchParams),
    MarketGetAssetDetails(MarketDetailsParams),
    MarketGetIndices(MarketIndicesParams),
}

impl MarketControlRequest {
    /// Parse and fully validate a market-control envelope from JSON.
    ///
    /// # Errors
    /// [`SafeError::invalid_request`] on malformed JSON, unknown fields,
    /// unknown commands, or out-of-bounds params.
    pub fn from_json(json: &str) -> Result<Self, SafeError> {
        let value: serde_json::Value = serde_json::from_str(json)
            .map_err(|_| SafeError::invalid_request("Request is not valid JSON."))?;
        validate_envelope_keys(&value)?;
        let request: MarketControlRequest = serde_json::from_value(value)
            .map_err(|_| SafeError::invalid_request("Request is not an allowed command."))?;
        request.validate()?;
        Ok(request)
    }

    /// Serialize the request to its JSON envelope.
    ///
    /// # Errors
    /// [`SafeError::internal`] if serialization fails (should not happen).
    pub fn to_json(&self) -> Result<String, SafeError> {
        serde_json::to_string(self).map_err(|_| SafeError::internal())
    }

    /// The capability required for this market-control command.
    #[must_use]
    pub fn required_capability(&self) -> Capability {
        match self {
            MarketControlRequest::MarketSearchAsset(_)
            | MarketControlRequest::MarketGetAssetDetails(_)
            | MarketControlRequest::MarketGetIndices(_) => Capability::MarketAuthenticatedRead,
        }
    }

    /// Stable audit tool label.
    #[must_use]
    pub fn audit_tool(&self) -> &'static str {
        match self {
            MarketControlRequest::MarketSearchAsset(_) => "market_search_asset",
            MarketControlRequest::MarketGetAssetDetails(_) => "market_get_asset_details",
            MarketControlRequest::MarketGetIndices(_) => "market_get_indices",
        }
    }

    /// Validate request bounds.
    ///
    /// # Errors
    /// [`SafeError::invalid_request`] on out-of-bounds params.
    pub fn validate(&self) -> Result<(), SafeError> {
        match self {
            MarketControlRequest::MarketSearchAsset(params) => params.validate(),
            MarketControlRequest::MarketGetAssetDetails(params) => params.validate(),
            MarketControlRequest::MarketGetIndices(params) => params.validate(),
        }
    }
}

/// A successful market-control result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "result", content = "data", rename_all = "snake_case")]
pub enum MarketControlOutcome {
    Search {
        result: MarketSearchResult,
        session: MarketSessionStatus,
    },
    Details {
        result: Box<MarketAssetDetailsResult>,
        session: MarketSessionStatus,
    },
    Indices {
        result: MarketIndicesResult,
        session: MarketSessionStatus,
    },
}

/// A reply to a [`MarketControlRequest`]: typed outcome or safe error envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", content = "body", rename_all = "snake_case")]
pub enum MarketControlWireReply {
    Ok(MarketControlOutcome),
    Err(SafeErrorDto),
}

impl MarketControlWireReply {
    /// Build a reply from a handler result.
    #[must_use]
    pub fn from_result(result: Result<MarketControlOutcome, SafeError>) -> Self {
        match result {
            Ok(outcome) => MarketControlWireReply::Ok(outcome),
            Err(error) => MarketControlWireReply::Err(SafeErrorDto::from(&error)),
        }
    }

    /// Collapse the reply into a `Result`, surfacing the safe error DTO.
    ///
    /// # Errors
    /// Returns the [`SafeErrorDto`] when the reply is the `err` form.
    pub fn into_result(self) -> Result<MarketControlOutcome, SafeErrorDto> {
        match self {
            MarketControlWireReply::Ok(outcome) => Ok(outcome),
            MarketControlWireReply::Err(error) => Err(error),
        }
    }
}

/// Read timeout for market search replies. The controller's live-client timeout
/// for search is sized to the worker's bounded retry budget; the gateway timeout
/// needs extra margin because it starts before the controller begins its own
/// live-socket wait.
const MARKET_SEARCH_REPLY_TIMEOUT: Duration = Duration::from_secs(240);

/// Read timeout for market details replies. Details can fan out across retried
/// authenticated Fineco endpoints; this must exceed the live client details
/// timeout so the gateway does not fail locally while the controller keeps
/// spending the login.
const MARKET_DETAILS_REPLY_TIMEOUT: Duration = Duration::from_secs(1020);

fn market_reply_timeout_for(request: &MarketControlRequest) -> Duration {
    match request {
        MarketControlRequest::MarketSearchAsset(_) | MarketControlRequest::MarketGetIndices(_) => {
            MARKET_SEARCH_REPLY_TIMEOUT
        }
        MarketControlRequest::MarketGetAssetDetails(_) => MARKET_DETAILS_REPLY_TIMEOUT,
    }
}

/// Serve validated market-control commands on `listener`.
///
/// # Errors
/// Returns an error only if accepting connections fails irrecoverably.
pub fn serve_market_control_blocking<H>(listener: &UnixListener, handler: H) -> io::Result<()>
where
    H: Fn(MarketControlRequest) -> Result<MarketControlOutcome, SafeError>,
{
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = serve_one_market_control(&mut stream, &handler);
    }
    Ok(())
}

/// Handle exactly one market-control request/reply on `stream`.
fn serve_one_market_control<H>(stream: &mut UnixStream, handler: &H) -> io::Result<()>
where
    H: Fn(MarketControlRequest) -> Result<MarketControlOutcome, SafeError>,
{
    let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
    let raw = {
        let mut reader = DeadlineReader::new(stream, Instant::now() + SOCKET_TIMEOUT);
        read_frame(&mut reader)?
    };
    let validated = std::str::from_utf8(&raw)
        .map_err(|_| SafeError::invalid_request("Request is not valid UTF-8."))
        .and_then(MarketControlRequest::from_json);
    let reply = match validated {
        Ok(request) => {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(request))) {
                Ok(result) => MarketControlWireReply::from_result(result),
                Err(_) => MarketControlWireReply::Err(SafeErrorDto::from(&SafeError::internal())),
            }
        }
        Err(error) => MarketControlWireReply::Err(SafeErrorDto::from(&error)),
    };
    write_message(stream, &reply)
}

/// A blocking client for the authenticated market-control socket.
#[derive(Debug, Clone)]
pub struct MarketControlClient {
    path: PathBuf,
}

impl MarketControlClient {
    /// Target the market-control socket at `path`. No connection until [`call`].
    ///
    /// [`call`]: MarketControlClient::call
    #[must_use]
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Send `request` and return the controller outcome.
    ///
    /// # Errors
    /// The [`SafeErrorDto`] the controller returned, or an `internal` envelope on
    /// connect/transport failure.
    pub fn call(
        &self,
        request: &MarketControlRequest,
    ) -> Result<MarketControlOutcome, SafeErrorDto> {
        let internal = || SafeErrorDto::from(&SafeError::internal());
        let mut stream = UnixStream::connect(&self.path).map_err(|_| internal())?;
        let _ = stream.set_read_timeout(Some(market_reply_timeout_for(request)));
        let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
        write_message(&mut stream, request).map_err(|_| internal())?;
        let reply: MarketControlWireReply = read_message(&mut stream).map_err(|_| internal())?;
        reply.into_result()
    }
}

// ===== Refresh-control protocol (gateway <-> refresh controller) =============
//
// A SECOND, dedicated protocol on its own socket (`refresh-control.sock`), kept
// separate from the snapshot-query protocol above: distinct socket, distinct IPC
// group, distinct capabilities. The gateway forwards a live-refresh command here;
// the controller runs the capability check, preflight (cooldown/budget/circuit),
// and the refresh, then returns operation/snapshot **status only** — never the
// refreshed payload. The gateway never reaches the live socket; only the
// controller does (plan "Local IPC" / "Remote Live Refresh P0").

/// Read timeout for a live-refresh reply on the gateway's client. The controller
/// must do a live Fineco fetch (login + read), possibly with bounded retries,
/// before it can answer — far longer than a cached read. If it still exceeds
/// this, the gateway returns a safe error while the controller's refresh runs to
/// completion and writes the snapshot; the client then reads the result via the
/// cached tools. A generous hang-stop, not a latency budget.
const REFRESH_REPLY_TIMEOUT: Duration = Duration::from_secs(180);

/// A live-refresh command from the gateway to the refresh controller. Adjacently
/// tagged `{"command": "...", "params": {...}}` (commands without params omit
/// `params`). Command-enum only — no generic proxy. Each maps to a
/// `*.live.refresh` [`Capability`] the controller re-checks independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "command", content = "params", rename_all = "snake_case")]
pub enum RefreshRequest {
    PortfolioRefreshLive,
    OrdersRefreshLive(OrdersRefreshParams),
    TaxRefreshLive(TaxRefreshParams),
}

/// Parameters for `private_orders_refresh_live_sensitive`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrdersRefreshParams {
    pub instrument_kind: String,
    pub days: u32,
}

/// Parameters for `private_tax_refresh_live_sensitive`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaxRefreshParams {
    pub date_from: String,
    pub date_to: String,
}

impl RefreshRequest {
    /// The `*.live.refresh` capability a caller must hold to issue this command.
    /// Checked by the gateway and re-checked by the controller (defense in depth).
    #[must_use]
    pub fn required_capability(&self) -> Capability {
        match self {
            RefreshRequest::PortfolioRefreshLive => Capability::PortfolioLiveRefresh,
            RefreshRequest::OrdersRefreshLive(_) => Capability::OrdersLiveRefresh,
            RefreshRequest::TaxRefreshLive(_) => Capability::TaxLiveRefresh,
        }
    }

    /// The MCP tool name this request backs, for the audit log (a stable label,
    /// no parameters) — matching the gateway's `#[tool(name = …)]`.
    #[must_use]
    pub fn audit_tool(&self) -> &'static str {
        match self {
            RefreshRequest::PortfolioRefreshLive => "private_portfolio_refresh_live_sensitive",
            RefreshRequest::OrdersRefreshLive(_) => "private_orders_refresh_live_sensitive",
            RefreshRequest::TaxRefreshLive(_) => "private_tax_refresh_live_sensitive",
        }
    }

    /// The data area this refresh targets (`portfolio` / `orders` / `tax`) — the
    /// key for the per-area lock, cooldown, budget, and circuit breaker.
    #[must_use]
    pub fn data_area(&self) -> &'static str {
        match self {
            RefreshRequest::PortfolioRefreshLive => "portfolio",
            RefreshRequest::OrdersRefreshLive(_) => "orders",
            RefreshRequest::TaxRefreshLive(_) => "tax",
        }
    }

    /// Parse and fully validate a refresh envelope from JSON. Same discipline as
    /// [`Request::from_json`]: keys ⊆ `{command, params}`, an allowlisted command,
    /// `deny_unknown_fields` params, and the shared parameter bounds.
    ///
    /// # Errors
    /// [`SafeError::invalid_request`] (payload-free) on any violation.
    pub fn from_json(json: &str) -> Result<Self, SafeError> {
        let value: serde_json::Value = serde_json::from_str(json)
            .map_err(|_| SafeError::invalid_request("Request is not valid JSON."))?;
        validate_envelope_keys(&value)?;
        let request: RefreshRequest = serde_json::from_value(value)
            .map_err(|_| SafeError::invalid_request("Request is not an allowed command."))?;
        request.validate()?;
        Ok(request)
    }

    /// Serialize the request to its JSON envelope.
    ///
    /// # Errors
    /// [`SafeError::internal`] if serialization fails (should not happen).
    pub fn to_json(&self) -> Result<String, SafeError> {
        serde_json::to_string(self).map_err(|_| SafeError::internal())
    }

    /// Validate the request's bounds with the **same** shared validators the
    /// controller and worker apply (`fineco_core::validate_order_request` /
    /// `validate_tax_range`) — so the gateway, controller, and worker can never
    /// diverge on what a valid refresh is.
    ///
    /// # Errors
    /// [`SafeError::invalid_request`] (payload-free) on an out-of-bounds value.
    pub fn validate(&self) -> Result<(), SafeError> {
        match self {
            RefreshRequest::PortfolioRefreshLive => Ok(()),
            RefreshRequest::OrdersRefreshLive(p) => {
                validate_order_request(&p.instrument_kind, p.days)
            }
            RefreshRequest::TaxRefreshLive(p) => validate_tax_range(&p.date_from, &p.date_to),
        }
    }
}

/// The controller's reply to a live refresh: operation/snapshot **status only**,
/// never the refreshed payload (the client reads values via the
/// cached tools after the refresh completes). `count` is a row count
/// (positions / orders / tax rows), never a value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RefreshOutcome {
    /// `portfolio` / `orders` / `tax`.
    pub data_area: String,
    /// The capture timestamp stamped on the refreshed snapshot (ISO-8601 UTC).
    pub captured_at: String,
    /// The new portfolio snapshot id (portfolio only; `None` for orders/tax).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<i64>,
    /// Rows captured — positions / orders / tax rows. A count, never a value.
    pub count: usize,
}

/// A reply to a [`RefreshRequest`]: a typed [`RefreshOutcome`] or the safe error
/// envelope. Mirrors [`WireReply`] for the refresh-control socket; every failure
/// (including `already_refreshing`, cooldown/budget, `auth_required`) crosses as
/// the `err` form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", content = "body", rename_all = "snake_case")]
pub enum RefreshWireReply {
    Ok(RefreshOutcome),
    Err(SafeErrorDto),
}

impl RefreshWireReply {
    /// Build a reply from a handler's result, mapping the error to its safe DTO.
    #[must_use]
    pub fn from_result(result: Result<RefreshOutcome, SafeError>) -> Self {
        match result {
            Ok(outcome) => RefreshWireReply::Ok(outcome),
            Err(error) => RefreshWireReply::Err(SafeErrorDto::from(&error)),
        }
    }

    /// Collapse the reply into a `Result`, surfacing the safe error DTO.
    ///
    /// # Errors
    /// Returns the [`SafeErrorDto`] when the reply is the `err` form.
    pub fn into_result(self) -> Result<RefreshOutcome, SafeErrorDto> {
        match self {
            RefreshWireReply::Ok(outcome) => Ok(outcome),
            RefreshWireReply::Err(error) => Err(error),
        }
    }
}

/// Serve validated refresh commands on `listener`, one request/reply per
/// connection. Like [`serve_blocking`], the server **re-validates** every request
/// via [`RefreshRequest::from_json`] (schema validation at both ends), so a
/// hostile or over-permissive peer cannot reach `handler` with an unknown command,
/// a smuggled field, or an out-of-bounds value. `handler` (in the controller) runs
/// the capability check, preflight, and refresh. A single connection's failure
/// never stops the server.
///
/// # Errors
/// Returns an error only if accepting connections fails irrecoverably.
pub fn serve_refresh_blocking<H>(listener: &UnixListener, handler: H) -> io::Result<()>
where
    H: Fn(RefreshRequest) -> Result<RefreshOutcome, SafeError>,
{
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = serve_one_refresh(&mut stream, &handler);
    }
    Ok(())
}

/// Handle exactly one refresh request/reply on `stream`.
fn serve_one_refresh<H>(stream: &mut UnixStream, handler: &H) -> io::Result<()>
where
    H: Fn(RefreshRequest) -> Result<RefreshOutcome, SafeError>,
{
    let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
    // Bound the TOTAL read time, not just each read (see `serve_one`).
    let raw = {
        let mut reader = DeadlineReader::new(stream, Instant::now() + SOCKET_TIMEOUT);
        read_frame(&mut reader)?
    };
    let validated = std::str::from_utf8(&raw)
        .map_err(|_| SafeError::invalid_request("Request is not valid UTF-8."))
        .and_then(RefreshRequest::from_json);
    let reply = match validated {
        // Run the handler under `catch_unwind`: this serve loop runs on a DETACHED
        // thread (the store-server's refresh controller), so a handler panic must
        // not unwind out of the accept loop and silently take live refresh down
        // until a manual restart. A panic becomes the safe `internal` envelope and
        // the loop keeps serving. (The controller tolerates a poisoned store mutex,
        // so subsequent requests degrade to `internal` rather than re-panicking.)
        Ok(request) => {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(request))) {
                Ok(result) => RefreshWireReply::from_result(result),
                Err(_) => RefreshWireReply::Err(SafeErrorDto::from(&SafeError::internal())),
            }
        }
        Err(error) => RefreshWireReply::Err(SafeErrorDto::from(&error)),
    };
    write_message(stream, &reply)
}

/// A blocking client for the refresh-control socket — one connection per call,
/// used by the gateway's live-refresh tools.
#[derive(Debug, Clone)]
pub struct RefreshClient {
    path: PathBuf,
}

impl RefreshClient {
    /// Target the refresh-control socket at `path`. No connection until [`call`].
    ///
    /// [`call`]: RefreshClient::call
    #[must_use]
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Send `request` and return the controller's outcome. Transport failures and
    /// the controller's failures both surface as the safe error envelope; no raw
    /// transport detail leaks.
    ///
    /// # Errors
    /// The [`SafeErrorDto`] the controller returned, or an `internal` envelope on
    /// a connect/transport failure.
    pub fn call(&self, request: &RefreshRequest) -> Result<RefreshOutcome, SafeErrorDto> {
        let internal = || SafeErrorDto::from(&SafeError::internal());
        let mut stream = UnixStream::connect(&self.path).map_err(|_| internal())?;
        // Generous read timeout: a live refresh (login + fetch + bounded retries)
        // far exceeds a cached read.
        let _ = stream.set_read_timeout(Some(REFRESH_REPLY_TIMEOUT));
        let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
        write_message(&mut stream, request).map_err(|_| internal())?;
        let reply: RefreshWireReply = read_message(&mut stream).map_err(|_| internal())?;
        reply.into_result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etf_external_enrichment_section_round_trips() {
        let section = MarketEtfExternalEnrichment {
            data_class: "external_enrichment".to_string(),
            captured_at: "2026-06-17T09:00:00Z".to_string(),
            source_url: "https://example.test/etf-profile.html?isin=IE00B5BMR087".to_string(),
            ter: Some(MarketField::medium(
                0.07,
                Some("percent"),
                "external_enrichment",
                "external_enrichment",
                "external_enrichment.basics",
                None,
                "2026-06-17T09:00:00Z",
            )),
            fund_size: Some(MarketField::medium(
                129_586.0,
                Some("EUR million"),
                "external_enrichment",
                "external_enrichment",
                "external_enrichment.basics",
                None,
                "2026-06-17T09:00:00Z",
            )),
            distribution_policy: Some(MarketField::medium_string(
                "Accumulating",
                "external_enrichment",
                "external_enrichment",
                "external_enrichment.basics",
                "2026-06-17T09:00:00Z",
            )),
            warnings: vec!["example warning".to_string()],
            ..Default::default()
        };

        let json = serde_json::to_string(&section).expect("serialize");
        let back: MarketEtfExternalEnrichment = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(section, back);
        // Absent optional fields are skipped, not serialized as null.
        assert!(!json.contains("\"domicile\""));
        assert_eq!(back.ter.unwrap().value, 0.07);

        // It slots into the sections envelope under its own key.
        let sections = MarketAssetSections {
            etf_external_enrichment: Some(section),
            ..Default::default()
        };
        let sections_json = serde_json::to_string(&sections).expect("serialize sections");
        assert!(sections_json.contains("etf_external_enrichment"));
    }

    #[test]
    fn market_field_metadata_is_sanitized() {
        let field = MarketField::high(
            42.0,
            Some(" EUR\n\x1b[31m percent "),
            "fineco",
            "authenticated_market",
            "stock.snapshot",
            Some(" 2026-06-14\tclose "),
            "2026-06-15T08:30:00Z",
        );

        assert_eq!(field.unit.as_deref(), Some("EUR [31m percent"));
        assert_eq!(field.as_of.as_deref(), Some("2026-06-14 close"));
    }

    #[test]
    fn market_details_uses_a_fanout_sized_reply_timeout() {
        use std::time::Duration;

        let search = MarketControlRequest::MarketSearchAsset(MarketSearchParams {
            query: "AAPL".to_string(),
            asset_type: None,
            limit: None,
        });
        let details = MarketControlRequest::MarketGetAssetDetails(MarketDetailsParams {
            identifier: "NASDAQ/AAPL".to_string(),
            expected_isin: None,
            sections: None,
        });

        assert_eq!(
            market_reply_timeout_for(&search),
            MARKET_SEARCH_REPLY_TIMEOUT
        );
        assert_eq!(
            market_reply_timeout_for(&details),
            MARKET_DETAILS_REPLY_TIMEOUT
        );
        assert!(MARKET_SEARCH_REPLY_TIMEOUT > REFRESH_REPLY_TIMEOUT);
        assert!(MARKET_SEARCH_REPLY_TIMEOUT >= Duration::from_secs(240));
        assert!(MARKET_DETAILS_REPLY_TIMEOUT > MARKET_SEARCH_REPLY_TIMEOUT);
        assert!(MARKET_DETAILS_REPLY_TIMEOUT >= Duration::from_secs(1020));
    }
}
