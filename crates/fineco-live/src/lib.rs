//! `fineco-live` — the credentialed-boundary protocol over `fineco-live.sock`.
//!
//! This is the wire between two trusted local processes:
//!
//! - the no-DB **private worker** (the server): holds the Fineco credentials,
//!   reaches the live Fineco endpoints, logs in, fetches, and parses; and
//! - the **refresh controller** (the client): owns the SQLite DB and its per-DB
//!   HMAC key, runs the refresh orchestration (locks, budgets, circuit breaker),
//!   and writes the resulting snapshots.
//!
//! The controller's [`LiveClient`] implements the credential-free fetcher traits
//! ([`PortfolioFetcher`]/[`OrdersFetcher`]/[`TaxFetcher`]) by round-tripping a
//! typed [`LiveRequest`]/[`LiveResponse`] over the socket, reusing
//! `fineco-ipc`'s length-prefixed JSON framing. Two security properties are
//! structural here:
//!
//! - **The worker never holds the DB key.** Orders come back as un-hashed
//!   [`RawOrder`]s; the `LiveClient` hashes them into store-ready `NewOrder`s with
//!   the passed [`Store`]'s key. Portfolio and tax don't use the key, so they
//!   cross as their `New*` types directly.
//! - **The internet-facing gateway must never depend on this crate.** That is a
//!   compile-time barrier on top of the runtime socket-group isolation
//!   (`fineco-ipc-live`), so even a compromised gateway has no client for the
//!   live socket. The gateway's architecture test enforces the build-time half.
//!
//! Command-enum only, `deny_unknown_fields` params, typed responses: there is no
//! generic proxy and no `url`/`path`/`headers`/`sql`/`method` field anywhere.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fineco_core::SafeError;
pub use fineco_ipc::{MarketAssetDetailsLiveFetcher, MarketSearchLiveFetcher};
use fineco_ipc::{
    MarketAssetDetailsLiveResult, MarketDetailsParams, MarketSearchLiveResult, MarketSearchParams,
    SafeErrorDto,
};
use fineco_refresh::{OrdersFetcher, PortfolioFetcher, RawOrdersFetcher, TaxFetcher};
use fineco_store::{
    NewOrder, NewPortfolioSnapshot, NewTaxCarryForward, NewTaxMinusByYear, RawOrder, Store,
};
use serde::{Deserialize, Serialize};

/// Server-side socket read/write timeout. Bounds the controller→worker request
/// read and the reply write — NOT the Fineco fetch between them, which the worker
/// bounds with its own per-request HTTP timeout. A stalled or half-open peer
/// cannot pin the worker's accept loop.
const LIVE_SERVER_TIMEOUT: Duration = Duration::from_secs(30);

/// Client-side socket read timeout. Must exceed the worker's worst-case
/// login + fetch so a legitimately slow bank read is not aborted mid-flight: the
/// worker may do a preflight, a login, and the read, each independently bounded
/// by its own ~30s HTTP timeout. The controller's retry/circuit logic wraps the
/// whole call, so this is a generous hang-stop, not a latency budget.
const LIVE_CLIENT_TIMEOUT: Duration = Duration::from_secs(120);

/// Market details may fan out across authenticated search, static identity,
/// snapshot, and stock/ETF report endpoints under one worker-held session. Its
/// live-socket read timeout must cover the allowed retried fan-out (preflight +
/// login, up to four alias searches, and the optional ETF composition/returns
/// endpoints) so the controller does not report a local transport failure while
/// the worker is still making bounded Fineco reads.
const LIVE_MARKET_DETAILS_CLIENT_TIMEOUT: Duration = Duration::from_secs(960);

/// A command from the refresh controller to the private worker. Adjacently tagged
/// as `{"command": "...", "params": {...}}` (commands without params omit it).
/// Command-enum only — there is no generic proxy, URL, or raw field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", content = "params", rename_all = "snake_case")]
pub enum LiveRequest {
    /// Fetch a fresh portfolio snapshot, stamped with the controller's clock.
    Portfolio(LivePortfolioParams),
    /// Fetch order-monitor transactions (returned un-hashed; the controller hashes).
    Orders(LiveOrdersParams),
    /// Fetch the tax carry-forward total for an explicit date range.
    TaxCarryForward(LiveTaxCarryForwardParams),
    /// Fetch the tax minus-by-year residues.
    TaxMinusByYear,
    /// Search authenticated Fineco market instruments, stamped with controller time.
    MarketSearch(LiveMarketSearchParams),
    /// Resolve and fetch authenticated Fineco market details, stamped with controller time.
    MarketAssetDetails(LiveMarketDetailsParams),
}

/// Parameters for [`LiveRequest::Portfolio`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivePortfolioParams {
    /// The controller's clock (ISO-8601 UTC); the worker stamps the snapshot's
    /// `captured_at` with it, so the snapshot timestamp matches the job's.
    pub now_iso: String,
}

/// Parameters for [`LiveRequest::Orders`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveOrdersParams {
    pub instrument_kind: String,
    pub days: u32,
}

/// Parameters for [`LiveRequest::TaxCarryForward`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveTaxCarryForwardParams {
    pub date_from: String,
    pub date_to: String,
}

/// Parameters for [`LiveRequest::MarketSearch`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveMarketSearchParams {
    pub search: MarketSearchParams,
    /// The controller's clock (ISO-8601 UTC); used as result `captured_at`.
    pub now_iso: String,
}

/// Parameters for [`LiveRequest::MarketAssetDetails`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveMarketDetailsParams {
    pub details: MarketDetailsParams,
    /// The controller's clock (ISO-8601 UTC); used as result `captured_at`.
    pub now_iso: String,
}

/// A successful worker result, typed per command (the plan forbids generic raw
/// JSON for private payloads). Orders are [`RawOrder`]s — the worker holds no DB
/// key — and are hashed by the controller after they cross the socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", content = "data", rename_all = "snake_case")]
pub enum LiveResponse {
    Portfolio(NewPortfolioSnapshot),
    Orders(Vec<RawOrder>),
    TaxCarryForward(NewTaxCarryForward),
    TaxMinusByYear(Vec<NewTaxMinusByYear>),
    MarketSearch(MarketSearchLiveResult),
    MarketAssetDetails(Box<MarketAssetDetailsLiveResult>),
}

/// The worker's reply: a typed result or the safe error envelope. Every worker
/// failure crosses as the `err` form — never a raw message or payload. Internal
/// wire detail (both server and client live in this crate).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "body", rename_all = "snake_case")]
enum LiveReply {
    Ok(LiveResponse),
    Err(SafeErrorDto),
}

/// Dispatch one [`LiveRequest`] to the worker's fetchers, producing a
/// [`LiveResponse`]. The fetchers re-validate the bounded params independently
/// (defense in depth — the controller validated before the lock). The worker
/// holds no DB key, so orders are returned un-hashed.
///
/// # Errors
/// The fetcher's [`SafeError`] on validation/auth/upstream/internal failure.
pub fn handle_live_request<F>(fetcher: &F, request: LiveRequest) -> Result<LiveResponse, SafeError>
where
    F: PortfolioFetcher
        + RawOrdersFetcher
        + TaxFetcher
        + MarketSearchLiveFetcher
        + MarketAssetDetailsLiveFetcher
        + ?Sized,
{
    match request {
        LiveRequest::Portfolio(p) => fetcher
            .fetch_portfolio(&p.now_iso)
            .map(LiveResponse::Portfolio),
        LiveRequest::Orders(p) => fetcher
            .fetch_raw_orders(&p.instrument_kind, p.days)
            .map(LiveResponse::Orders),
        LiveRequest::TaxCarryForward(p) => fetcher
            .fetch_tax_carry_forward(&p.date_from, &p.date_to)
            .map(LiveResponse::TaxCarryForward),
        LiveRequest::TaxMinusByYear => fetcher
            .fetch_tax_minus_by_year()
            .map(LiveResponse::TaxMinusByYear),
        LiveRequest::MarketSearch(p) => fetcher
            .fetch_market_search(&p.search, &p.now_iso)
            .map(LiveResponse::MarketSearch),
        LiveRequest::MarketAssetDetails(p) => fetcher
            .fetch_market_asset_details(&p.details, &p.now_iso)
            .map(|result| LiveResponse::MarketAssetDetails(Box::new(result))),
    }
}

/// Serve live-fetch requests on `listener`, one request/reply per connection,
/// dispatching each to `fetcher`. A single connection's failure never stops the
/// server. The ONLY legitimate caller is the refresh controller; deployment
/// enforces that with `fineco-live.sock`'s owner/group/mode (the gateway is never
/// in `fineco-ipc-live`).
///
/// # Errors
/// Returns an error only if accepting connections fails irrecoverably.
pub fn serve_live_blocking<F>(listener: &UnixListener, fetcher: &F) -> std::io::Result<()>
where
    F: PortfolioFetcher
        + RawOrdersFetcher
        + TaxFetcher
        + MarketSearchLiveFetcher
        + MarketAssetDetailsLiveFetcher
        + ?Sized,
{
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = serve_one(&mut stream, fetcher);
    }
    Ok(())
}

/// Handle exactly one request/reply on `stream`.
fn serve_one<F>(stream: &mut UnixStream, fetcher: &F) -> std::io::Result<()>
where
    F: PortfolioFetcher
        + RawOrdersFetcher
        + TaxFetcher
        + MarketSearchLiveFetcher
        + MarketAssetDetailsLiveFetcher
        + ?Sized,
{
    // Bound a stalled peer so one half-open connection cannot pin the accept loop.
    let _ = stream.set_read_timeout(Some(LIVE_SERVER_TIMEOUT));
    let _ = stream.set_write_timeout(Some(LIVE_SERVER_TIMEOUT));
    // Decode the typed request. An unknown command and `deny_unknown_fields`
    // params are rejected by serde; unknown TOP-LEVEL envelope keys are rejected
    // explicitly via `validate_envelope_keys` (the adjacently-tagged enum alone
    // would silently ignore them) — so a malformed or hostile frame never reaches
    // a fetcher; it becomes a safe error envelope instead.
    // Bound the TOTAL read time too, not just each read: the per-read timeout
    // re-arms on every byte, so a trickling peer needs a wall-clock deadline.
    let decoded = {
        let mut reader = fineco_ipc::DeadlineReader::new(
            stream,
            std::time::Instant::now() + LIVE_SERVER_TIMEOUT,
        );
        fineco_ipc::read_command_message::<_, LiveRequest>(&mut reader)
    };
    let reply = match decoded {
        Ok(request) => match handle_live_request(fetcher, request) {
            Ok(body) => LiveReply::Ok(body),
            Err(error) => LiveReply::Err(SafeErrorDto::from(&error)),
        },
        Err(error) => LiveReply::Err(SafeErrorDto::from(&error)),
    };
    fineco_ipc::write_message(stream, &reply)
}

/// A blocking client for `fineco-live.sock`, used by the refresh controller. One
/// connection per fetch. It implements the credential-free fetcher traits by
/// round-tripping a typed request; for orders it hashes the worker's [`RawOrder`]s
/// into store-ready [`NewOrder`]s with the passed store's key.
///
/// The refresh controller calls it once per admitted live operation so its shared
/// login budget matches the worker's Fineco login footprint. Any future retry must
/// either debit/report each fresh worker login or happen inside the worker under
/// one authenticated session.
#[derive(Debug, Clone)]
pub struct LiveClient {
    path: PathBuf,
}

impl LiveClient {
    /// Target the live socket at `path`. No connection is made until a fetch.
    #[must_use]
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Send one request and decode the worker's reply. A worker failure is
    /// reconstructed from its wire DTO via [`safe_error_from_dto`] so the
    /// controller's retry and circuit-breaker logic keys on the right `code` and
    /// `retryable`. A transport failure surfaces as `internal` (not retryable).
    fn call(&self, request: &LiveRequest) -> Result<LiveResponse, SafeError> {
        let mut stream = UnixStream::connect(&self.path).map_err(|_| SafeError::internal())?;
        let _ = stream.set_read_timeout(Some(client_timeout_for(request)));
        let _ = stream.set_write_timeout(Some(LIVE_SERVER_TIMEOUT));
        fineco_ipc::write_message(&mut stream, request).map_err(|_| SafeError::internal())?;
        let reply: LiveReply =
            fineco_ipc::read_message(&mut stream).map_err(|_| SafeError::internal())?;
        match reply {
            LiveReply::Ok(body) => Ok(body),
            LiveReply::Err(dto) => Err(safe_error_from_dto(&dto)),
        }
    }
}

fn client_timeout_for(request: &LiveRequest) -> Duration {
    match request {
        LiveRequest::MarketAssetDetails(_) => LIVE_MARKET_DETAILS_CLIENT_TIMEOUT,
        LiveRequest::Portfolio(_)
        | LiveRequest::Orders(_)
        | LiveRequest::TaxCarryForward(_)
        | LiveRequest::TaxMinusByYear
        | LiveRequest::MarketSearch(_) => LIVE_CLIENT_TIMEOUT,
    }
}

impl PortfolioFetcher for LiveClient {
    fn fetch_portfolio(&self, now_iso: &str) -> Result<NewPortfolioSnapshot, SafeError> {
        match self.call(&LiveRequest::Portfolio(LivePortfolioParams {
            now_iso: now_iso.to_string(),
        }))? {
            LiveResponse::Portfolio(snapshot) => Ok(snapshot),
            // The worker answered a portfolio request with the wrong response
            // type: a protocol violation, never surfaced as a payload.
            _ => Err(SafeError::internal()),
        }
    }
}

impl LiveClient {
    /// Return the authenticated Fineco market search with status-only worker
    /// session facts. This is the controller-facing form; callers that only need
    /// the normalized candidates can use the trait method and unwrap `.result`.
    ///
    /// # Errors
    /// [`SafeError`] on worker/transport failure.
    pub fn fetch_market_search_live(
        &self,
        params: &MarketSearchParams,
        now_iso: &str,
    ) -> Result<MarketSearchLiveResult, SafeError> {
        match self.call(&LiveRequest::MarketSearch(LiveMarketSearchParams {
            search: params.clone(),
            now_iso: now_iso.to_string(),
        }))? {
            LiveResponse::MarketSearch(result) => Ok(result),
            _ => Err(SafeError::internal()),
        }
    }

    /// Return authenticated Fineco market details with status-only worker
    /// session facts.
    ///
    /// # Errors
    /// [`SafeError`] on worker/transport failure.
    pub fn fetch_market_asset_details_live(
        &self,
        params: &MarketDetailsParams,
        now_iso: &str,
    ) -> Result<MarketAssetDetailsLiveResult, SafeError> {
        match self.call(&LiveRequest::MarketAssetDetails(LiveMarketDetailsParams {
            details: params.clone(),
            now_iso: now_iso.to_string(),
        }))? {
            LiveResponse::MarketAssetDetails(result) => Ok(*result),
            _ => Err(SafeError::internal()),
        }
    }
}

impl MarketSearchLiveFetcher for LiveClient {
    fn fetch_market_search(
        &self,
        params: &MarketSearchParams,
        now_iso: &str,
    ) -> Result<MarketSearchLiveResult, SafeError> {
        self.fetch_market_search_live(params, now_iso)
    }
}

impl MarketAssetDetailsLiveFetcher for LiveClient {
    fn fetch_market_asset_details(
        &self,
        params: &MarketDetailsParams,
        now_iso: &str,
    ) -> Result<MarketAssetDetailsLiveResult, SafeError> {
        self.fetch_market_asset_details_live(params, now_iso)
    }
}
impl OrdersFetcher for LiveClient {
    fn fetch_orders(
        &self,
        store: &Store,
        instrument_kind: &str,
        days: u32,
    ) -> Result<Vec<NewOrder>, SafeError> {
        match self.call(&LiveRequest::Orders(LiveOrdersParams {
            instrument_kind: instrument_kind.to_string(),
            days,
        }))? {
            // Hash the raw broker ids controller-side (the worker has no key).
            LiveResponse::Orders(raw_orders) => raw_orders
                .iter()
                .map(|raw| store.hash_raw_order(raw).map_err(|_| SafeError::internal()))
                .collect(),
            _ => Err(SafeError::internal()),
        }
    }
}

impl TaxFetcher for LiveClient {
    fn fetch_tax_carry_forward(
        &self,
        date_from: &str,
        date_to: &str,
    ) -> Result<NewTaxCarryForward, SafeError> {
        match self.call(&LiveRequest::TaxCarryForward(LiveTaxCarryForwardParams {
            date_from: date_from.to_string(),
            date_to: date_to.to_string(),
        }))? {
            LiveResponse::TaxCarryForward(carry_forward) => Ok(carry_forward),
            _ => Err(SafeError::internal()),
        }
    }

    fn fetch_tax_minus_by_year(&self) -> Result<Vec<NewTaxMinusByYear>, SafeError> {
        match self.call(&LiveRequest::TaxMinusByYear)? {
            LiveResponse::TaxMinusByYear(rows) => Ok(rows),
            _ => Err(SafeError::internal()),
        }
    }
}

/// Reconstruct a [`SafeError`] from the worker's wire [`SafeErrorDto`], routing
/// through fineco-core's canonical constructors. This preserves the `code`,
/// `class`, and `retryable` the controller's retry and circuit-breaker logic key
/// on (`fineco_timeout`/`fineco_upstream_error`/`auth_required`/…) without a
/// public "arbitrary text" `SafeError` constructor — so a raw payload can never
/// enter the envelope. An unrecognized code maps to `internal`.
fn safe_error_from_dto(dto: &SafeErrorDto) -> SafeError {
    match dto.code.as_str() {
        "auth_required" => SafeError::auth_required(),
        "fineco_timeout" => SafeError::fineco_timeout(),
        // The canonical retryable upstream error (the 5xx mapping). The circuit
        // breaker keys on this code; a rare non-retryable weird-status collapses
        // to retryable here, costing at most a couple of wasted in-job retries.
        "fineco_upstream_error" => SafeError::from_upstream_status(500),
        "not_found" => SafeError::not_found(),
        "rate_limited" => SafeError::rate_limited(),
        "market_auth_required" => SafeError::market_auth_required(),
        "market_not_found" => SafeError::market_not_found(),
        "market_ambiguous_identifier" => {
            SafeError::market_ambiguous_identifier_from_safe_message(&dto.safe_message)
        }
        "market_unsupported_asset_type" => {
            SafeError::market_unsupported_asset_type_from_safe_message(&dto.safe_message)
        }
        "market_rate_limited" => SafeError::market_rate_limited(),
        "market_upstream_failure" => SafeError::market_upstream_failure(),
        "market_circuit_open" => SafeError::market_circuit_open(),
        "market_unexpected_response" => SafeError::market_unexpected_response(),
        "already_refreshing" => SafeError::already_refreshing(),
        // The worker re-validates as defense in depth; the controller already
        // validated, so the specific message is not needed across the socket.
        "invalid_request" => SafeError::invalid_request("the live worker rejected the request"),
        _ => SafeError::internal(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        LIVE_CLIENT_TIMEOUT, LIVE_MARKET_DETAILS_CLIENT_TIMEOUT, LiveMarketDetailsParams,
        LiveRequest, client_timeout_for,
    };
    use fineco_ipc::MarketDetailsParams;

    #[test]
    fn market_details_uses_a_fanout_sized_client_timeout() {
        let request = LiveRequest::MarketAssetDetails(LiveMarketDetailsParams {
            details: MarketDetailsParams {
                identifier: "AFF/VHYL".to_string(),
                expected_isin: Some("IE00B8GKDB10".to_string()),
                sections: None,
            },
            now_iso: "2026-06-14T09:30:00Z".to_string(),
        });

        assert_eq!(
            client_timeout_for(&request),
            LIVE_MARKET_DETAILS_CLIENT_TIMEOUT
        );
        assert!(LIVE_MARKET_DETAILS_CLIENT_TIMEOUT > LIVE_CLIENT_TIMEOUT);
        assert!(LIVE_MARKET_DETAILS_CLIENT_TIMEOUT >= Duration::from_secs(960));
    }
}
