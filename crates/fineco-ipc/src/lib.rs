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

use fineco_core::{SafeError, validate_order_request, validate_tax_range};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

mod capability;
pub use capability::{AuthIdPolicy, Capability, OWNER_AUTH_ID, Policy};

/// Max length of any client-supplied identifier/query string in a request.
const MAX_PARAM_LEN: usize = 256;

/// Max number of history points a single request may ask for.
const MAX_HISTORY_LIMIT: u32 = 1000;

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
    MarketGetStockEnrichment(MarketEnrichmentParams),
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
            Request::MarketGetZeroCommissionEtfs(_) | Request::MarketGetStockEnrichment(_) => {
                Capability::MarketRead
            }
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
            Request::MarketGetStockEnrichment(_) => "market_get_stock_enrichment",
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

/// Parameters for `market_get_stock_enrichment`: an instrument identifier (the
/// server builds the allowlisted URL) and an optional Fineco title to match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MarketEnrichmentParams {
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fineco_title: Option<String>,
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
            Request::MarketGetStockEnrichment(p) => {
                check(&p.identifier)?;
                if p.identifier.is_empty() {
                    return Err(SafeError::invalid_request("identifier must not be empty."));
                }
                if let Some(title) = &p.fineco_title {
                    check(title)?;
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
