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
pub use fineco_ipc::{
    MarketAssetDetailsLiveFetcher, MarketIndicesLiveFetcher, MarketSearchLiveFetcher,
};
use fineco_ipc::{
    MarketAssetDetailsLiveResult, MarketDetailsParams, MarketIndicesLiveResult,
    MarketIndicesParams, MarketLiveError, MarketSearchLiveResult, MarketSearchParams, SafeErrorDto,
};
use fineco_refresh::{
    MovementsFetcher, OrdersFetcher, PortfolioFetcher, RawMovementsFetcher, RawOrdersFetcher,
    TaxFetcher,
};
use fineco_store::{
    NewMovement, NewOrder, NewPortfolioSnapshot, NewTaxCarryForward, NewTaxMinusByYear,
    RawMovement, RawOrder, Store,
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

/// Authenticated market search can retry Fineco's global-search endpoint inside
/// the worker after a preflight + login. This must cover the worker's bounded
/// worst case (roughly 30s preflight + 30s login + 3 * 30s search attempts)
/// with margin, so the controller does not give up before the worker's own retry
/// budget is exhausted.
const LIVE_MARKET_SEARCH_CLIENT_TIMEOUT: Duration = Duration::from_secs(180);

/// Market details may fan out across authenticated search, static identity,
/// snapshot, and stock/ETF report endpoints under one worker-held session. Its
/// live-socket read timeout must cover the allowed retried fan-out (preflight +
/// login, up to four alias searches, and the optional ETF composition/returns
/// endpoints) so the controller does not report a local transport failure while
/// the worker is still making bounded Fineco reads.
const LIVE_MARKET_DETAILS_CLIENT_TIMEOUT: Duration = Duration::from_secs(960);

/// A movements refresh logs in once and then **paginates** — up to many sequential
/// page POSTs under one worker-held session (each bounded by the worker's own
/// per-request HTTP timeout). The generic 120s budget can be too short for a busy
/// 90-day statement, which would make the controller record a failed refresh while
/// the worker is still legitimately paging. This covers a realistically large
/// paginated fetch (login + the page loop); a true runaway is still bounded by the
/// worker's own page cap.
const LIVE_MOVEMENTS_CLIENT_TIMEOUT: Duration = Duration::from_secs(900);

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
    /// Fetch Fineco headline index-bar cards, stamped with controller time.
    MarketIndices(LiveMarketIndicesParams),
    /// Fetch bank account movements for a date range.
    Movements(LiveMovementsParams),
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

/// Parameters for [`LiveRequest::MarketIndices`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveMarketIndicesParams {
    pub indices: MarketIndicesParams,
    /// The controller's clock (ISO-8601 UTC); used as result `captured_at`.
    pub now_iso: String,
}

/// Parameters for [`LiveRequest::Movements`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveMovementsParams {
    pub date_from: String,
    pub date_to: String,
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
    MarketIndices(MarketIndicesLiveResult),
    Movements(Vec<RawMovement>),
}

/// The worker's reply: a typed result or the safe error envelope. Every worker
/// failure crosses as the `err` form — never a raw message or payload. Internal
/// wire detail (both server and client live in this crate).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", content = "body", rename_all = "snake_case")]
enum LiveReply {
    Ok(LiveResponse),
    Err {
        error: SafeErrorDto,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        market_session: Option<fineco_ipc::MarketSessionStatus>,
    },
}

#[derive(Debug, Clone)]
struct LiveError {
    error: SafeError,
    market_session: Option<fineco_ipc::MarketSessionStatus>,
}

impl LiveError {
    fn new(error: SafeError, market_session: Option<fineco_ipc::MarketSessionStatus>) -> Self {
        Self {
            error,
            market_session,
        }
    }
}

impl From<SafeError> for LiveError {
    fn from(error: SafeError) -> Self {
        Self::new(error, None)
    }
}

impl From<MarketLiveError> for LiveError {
    fn from(error: MarketLiveError) -> Self {
        Self::new(error.error, error.session)
    }
}

#[derive(Debug, Clone)]
struct LiveCallError {
    error: SafeError,
    market_session: Option<fineco_ipc::MarketSessionStatus>,
}

impl LiveCallError {
    fn safe(error: SafeError) -> Self {
        Self {
            error,
            market_session: None,
        }
    }

    fn into_safe_error(self) -> SafeError {
        self.error
    }

    fn into_market_error(self) -> MarketLiveError {
        MarketLiveError::new(self.error, self.market_session)
    }
}

/// Dispatch one [`LiveRequest`] to the worker's fetchers, producing a
/// [`LiveResponse`]. The fetchers re-validate the bounded params independently
/// (defense in depth — the controller validated before the lock). The worker
/// holds no DB key, so orders are returned un-hashed.
///
/// # Errors
/// The fetcher's [`SafeError`] on validation/auth/upstream/internal failure.
fn handle_live_request<F>(fetcher: &F, request: LiveRequest) -> Result<LiveResponse, LiveError>
where
    F: PortfolioFetcher
        + RawOrdersFetcher
        + RawMovementsFetcher
        + TaxFetcher
        + MarketSearchLiveFetcher
        + MarketAssetDetailsLiveFetcher
        + MarketIndicesLiveFetcher
        + ?Sized,
{
    match request {
        LiveRequest::Portfolio(p) => fetcher
            .fetch_portfolio(&p.now_iso)
            .map_err(LiveError::from)
            .map(LiveResponse::Portfolio),
        LiveRequest::Orders(p) => fetcher
            .fetch_raw_orders(&p.instrument_kind, p.days)
            .map_err(LiveError::from)
            .map(LiveResponse::Orders),
        LiveRequest::TaxCarryForward(p) => fetcher
            .fetch_tax_carry_forward(&p.date_from, &p.date_to)
            .map_err(LiveError::from)
            .map(LiveResponse::TaxCarryForward),
        LiveRequest::TaxMinusByYear => fetcher
            .fetch_tax_minus_by_year()
            .map_err(LiveError::from)
            .map(LiveResponse::TaxMinusByYear),
        LiveRequest::MarketSearch(p) => fetcher
            .fetch_market_search(&p.search, &p.now_iso)
            .map_err(LiveError::from)
            .map(LiveResponse::MarketSearch),
        LiveRequest::MarketAssetDetails(p) => fetcher
            .fetch_market_asset_details(&p.details, &p.now_iso)
            .map_err(LiveError::from)
            .map(|result| LiveResponse::MarketAssetDetails(Box::new(result))),
        LiveRequest::MarketIndices(p) => fetcher
            .fetch_market_indices(&p.indices, &p.now_iso)
            .map_err(LiveError::from)
            .map(LiveResponse::MarketIndices),
        LiveRequest::Movements(p) => fetcher
            .fetch_raw_movements(&p.date_from, &p.date_to)
            .map_err(LiveError::from)
            .map(LiveResponse::Movements),
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
        + RawMovementsFetcher
        + TaxFetcher
        + MarketSearchLiveFetcher
        + MarketAssetDetailsLiveFetcher
        + MarketIndicesLiveFetcher
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
        + RawMovementsFetcher
        + TaxFetcher
        + MarketSearchLiveFetcher
        + MarketAssetDetailsLiveFetcher
        + MarketIndicesLiveFetcher
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
            Err(error) => LiveReply::Err {
                error: SafeErrorDto::from(&error.error),
                market_session: error.market_session,
            },
        },
        Err(error) => LiveReply::Err {
            error: SafeErrorDto::from(&error),
            market_session: None,
        },
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
    /// `retryable`. A local connect/write failure surfaces as
    /// `live_transport_failure` so the controller does not infer that a worker
    /// Fineco login happened. Once the request is written, a missing reply is
    /// ambiguous and stays `internal`; the controller debits conservatively.
    fn call(&self, request: &LiveRequest) -> Result<LiveResponse, LiveCallError> {
        let mut stream = UnixStream::connect(&self.path)
            .map_err(|_| LiveCallError::safe(SafeError::live_transport_failure()))?;
        let _ = stream.set_read_timeout(Some(client_timeout_for(request)));
        let _ = stream.set_write_timeout(Some(LIVE_SERVER_TIMEOUT));
        fineco_ipc::write_message(&mut stream, request)
            .map_err(|_| LiveCallError::safe(SafeError::live_transport_failure()))?;
        let reply: LiveReply = fineco_ipc::read_message(&mut stream)
            .map_err(|_| LiveCallError::safe(SafeError::internal()))?;
        match reply {
            LiveReply::Ok(body) => Ok(body),
            LiveReply::Err {
                error,
                market_session,
            } => Err(LiveCallError {
                error: safe_error_from_dto(&error),
                market_session,
            }),
        }
    }
}

fn client_timeout_for(request: &LiveRequest) -> Duration {
    match request {
        LiveRequest::MarketSearch(_) | LiveRequest::MarketIndices(_) => {
            LIVE_MARKET_SEARCH_CLIENT_TIMEOUT
        }
        LiveRequest::MarketAssetDetails(_) => LIVE_MARKET_DETAILS_CLIENT_TIMEOUT,
        LiveRequest::Movements(_) => LIVE_MOVEMENTS_CLIENT_TIMEOUT,
        LiveRequest::Portfolio(_)
        | LiveRequest::Orders(_)
        | LiveRequest::TaxCarryForward(_)
        | LiveRequest::TaxMinusByYear => LIVE_CLIENT_TIMEOUT,
    }
}

impl PortfolioFetcher for LiveClient {
    fn fetch_portfolio(&self, now_iso: &str) -> Result<NewPortfolioSnapshot, SafeError> {
        match self
            .call(&LiveRequest::Portfolio(LivePortfolioParams {
                now_iso: now_iso.to_string(),
            }))
            .map_err(LiveCallError::into_safe_error)?
        {
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
    /// [`MarketLiveError`] on worker/transport failure, optionally with
    /// status-only session facts for market read errors.
    pub fn fetch_market_search_live(
        &self,
        params: &MarketSearchParams,
        now_iso: &str,
    ) -> Result<MarketSearchLiveResult, MarketLiveError> {
        match self
            .call(&LiveRequest::MarketSearch(LiveMarketSearchParams {
                search: params.clone(),
                now_iso: now_iso.to_string(),
            }))
            .map_err(LiveCallError::into_market_error)?
        {
            LiveResponse::MarketSearch(result) => Ok(result),
            _ => Err(MarketLiveError::from(SafeError::internal())),
        }
    }

    /// Return authenticated Fineco market details with status-only worker
    /// session facts.
    ///
    /// # Errors
    /// [`MarketLiveError`] on worker/transport failure, optionally with
    /// status-only session facts for market read errors.
    pub fn fetch_market_asset_details_live(
        &self,
        params: &MarketDetailsParams,
        now_iso: &str,
    ) -> Result<MarketAssetDetailsLiveResult, MarketLiveError> {
        match self
            .call(&LiveRequest::MarketAssetDetails(LiveMarketDetailsParams {
                details: params.clone(),
                now_iso: now_iso.to_string(),
            }))
            .map_err(LiveCallError::into_market_error)?
        {
            LiveResponse::MarketAssetDetails(result) => Ok(*result),
            _ => Err(MarketLiveError::from(SafeError::internal())),
        }
    }

    /// Return authenticated Fineco index-bar cards with status-only worker
    /// session facts.
    ///
    /// # Errors
    /// [`MarketLiveError`] on worker/transport failure, optionally with
    /// status-only session facts for market read errors.
    pub fn fetch_market_indices_live(
        &self,
        params: &MarketIndicesParams,
        now_iso: &str,
    ) -> Result<MarketIndicesLiveResult, MarketLiveError> {
        match self
            .call(&LiveRequest::MarketIndices(LiveMarketIndicesParams {
                indices: params.clone(),
                now_iso: now_iso.to_string(),
            }))
            .map_err(LiveCallError::into_market_error)?
        {
            LiveResponse::MarketIndices(result) => Ok(result),
            _ => Err(MarketLiveError::from(SafeError::internal())),
        }
    }
}

impl MarketSearchLiveFetcher for LiveClient {
    fn fetch_market_search(
        &self,
        params: &MarketSearchParams,
        now_iso: &str,
    ) -> Result<MarketSearchLiveResult, MarketLiveError> {
        self.fetch_market_search_live(params, now_iso)
    }
}

impl MarketAssetDetailsLiveFetcher for LiveClient {
    fn fetch_market_asset_details(
        &self,
        params: &MarketDetailsParams,
        now_iso: &str,
    ) -> Result<MarketAssetDetailsLiveResult, MarketLiveError> {
        self.fetch_market_asset_details_live(params, now_iso)
    }
}

impl MarketIndicesLiveFetcher for LiveClient {
    fn fetch_market_indices(
        &self,
        params: &MarketIndicesParams,
        now_iso: &str,
    ) -> Result<MarketIndicesLiveResult, MarketLiveError> {
        self.fetch_market_indices_live(params, now_iso)
    }
}
impl OrdersFetcher for LiveClient {
    fn fetch_orders(
        &self,
        store: &Store,
        instrument_kind: &str,
        days: u32,
    ) -> Result<Vec<NewOrder>, SafeError> {
        match self
            .call(&LiveRequest::Orders(LiveOrdersParams {
                instrument_kind: instrument_kind.to_string(),
                days,
            }))
            .map_err(LiveCallError::into_safe_error)?
        {
            // Hash the raw broker ids controller-side (the worker has no key).
            LiveResponse::Orders(raw_orders) => raw_orders
                .iter()
                .map(|raw| store.hash_raw_order(raw).map_err(|_| SafeError::internal()))
                .collect(),
            _ => Err(SafeError::internal()),
        }
    }
}

impl RawMovementsFetcher for LiveClient {
    fn fetch_raw_movements(
        &self,
        date_from: &str,
        date_to: &str,
    ) -> Result<Vec<RawMovement>, SafeError> {
        match self
            .call(&LiveRequest::Movements(LiveMovementsParams {
                date_from: date_from.to_string(),
                date_to: date_to.to_string(),
            }))
            .map_err(LiveCallError::into_safe_error)?
        {
            LiveResponse::Movements(raw_movements) => Ok(raw_movements),
            _ => Err(SafeError::internal()),
        }
    }
}

impl MovementsFetcher for LiveClient {
    fn fetch_movements(
        &self,
        store: &Store,
        date_from: &str,
        date_to: &str,
    ) -> Result<Vec<NewMovement>, SafeError> {
        let raw = self.fetch_raw_movements(date_from, date_to)?;
        raw.iter()
            .map(|r| {
                store
                    .hash_raw_movement(r)
                    .map_err(|_| SafeError::internal())
            })
            .collect()
    }
}

impl TaxFetcher for LiveClient {
    fn fetch_tax_carry_forward(
        &self,
        date_from: &str,
        date_to: &str,
    ) -> Result<NewTaxCarryForward, SafeError> {
        match self
            .call(&LiveRequest::TaxCarryForward(LiveTaxCarryForwardParams {
                date_from: date_from.to_string(),
                date_to: date_to.to_string(),
            }))
            .map_err(LiveCallError::into_safe_error)?
        {
            LiveResponse::TaxCarryForward(carry_forward) => Ok(carry_forward),
            _ => Err(SafeError::internal()),
        }
    }

    fn fetch_tax_minus_by_year(&self) -> Result<Vec<NewTaxMinusByYear>, SafeError> {
        match self
            .call(&LiveRequest::TaxMinusByYear)
            .map_err(LiveCallError::into_safe_error)?
        {
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
        // Tier 1 step-up: keep it distinct across the socket so the controller's
        // freshness reporting and the client see the legible remediation state,
        // not a generic `internal`. Non-retryable (re-login won't clear it).
        "step_up_required" => SafeError::step_up_required(),
        "market_step_up_required" => SafeError::market_step_up_required(),
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
        "live_transport_failure" => SafeError::live_transport_failure(),
        "already_refreshing" => SafeError::already_refreshing(),
        // The worker re-validates as defense in depth; the controller already
        // validated, so the specific message is not needed across the socket.
        "invalid_request" => SafeError::invalid_request("the live worker rejected the request"),
        _ => SafeError::internal(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::thread;
    use std::time::Duration;

    use super::{
        LIVE_CLIENT_TIMEOUT, LIVE_MARKET_DETAILS_CLIENT_TIMEOUT, LIVE_MARKET_SEARCH_CLIENT_TIMEOUT,
        LIVE_MOVEMENTS_CLIENT_TIMEOUT, LiveClient, LiveMarketDetailsParams, LiveMarketSearchParams,
        LiveMovementsParams, LiveRequest, client_timeout_for,
    };
    use fineco_ipc::{MarketDetailsParams, MarketSearchParams};

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

    #[test]
    fn market_search_uses_a_retry_sized_client_timeout() {
        let request = LiveRequest::MarketSearch(LiveMarketSearchParams {
            search: MarketSearchParams {
                query: "VHYL".to_string(),
                asset_type: None,
                limit: None,
            },
            now_iso: "2026-06-14T09:30:00Z".to_string(),
        });

        assert_eq!(
            client_timeout_for(&request),
            LIVE_MARKET_SEARCH_CLIENT_TIMEOUT
        );
        assert!(LIVE_MARKET_SEARCH_CLIENT_TIMEOUT > LIVE_CLIENT_TIMEOUT);
        assert!(LIVE_MARKET_SEARCH_CLIENT_TIMEOUT >= Duration::from_secs(180));
    }

    #[test]
    fn movements_uses_a_pagination_sized_client_timeout() {
        let request = LiveRequest::Movements(LiveMovementsParams {
            date_from: "2026-03-25".to_string(),
            date_to: "2026-06-23".to_string(),
        });

        assert_eq!(client_timeout_for(&request), LIVE_MOVEMENTS_CLIENT_TIMEOUT);
        assert!(LIVE_MOVEMENTS_CLIENT_TIMEOUT > LIVE_CLIENT_TIMEOUT);
        assert!(LIVE_MOVEMENTS_CLIENT_TIMEOUT >= Duration::from_secs(900));
    }

    #[test]
    fn local_live_socket_failure_uses_transport_error_code() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fineco-live-missing-{}-{}.sock",
            std::process::id(),
            "transport-error"
        ));
        let _ = std::fs::remove_file(&path);
        let client = LiveClient::new(&path);

        let err = client
            .fetch_market_search_live(
                &MarketSearchParams {
                    query: "VHYL".to_string(),
                    limit: None,
                    asset_type: None,
                },
                "2026-06-14T09:30:00Z",
            )
            .expect_err("missing live socket is a local transport failure");

        assert_eq!(err.error.code(), "live_transport_failure");
    }

    #[test]
    fn missing_live_socket_reply_after_write_uses_internal_error_code() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fineco-live-drop-reply-{}-{}.sock",
            std::process::id(),
            "transport-error"
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind live socket");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let _: LiveRequest = fineco_ipc::read_message(&mut stream).expect("read request");
        });
        let client = LiveClient::new(&path);

        let err = client
            .fetch_market_search_live(
                &MarketSearchParams {
                    query: "VHYL".to_string(),
                    limit: None,
                    asset_type: None,
                },
                "2026-06-14T09:30:00Z",
            )
            .expect_err("server accepted the request but did not reply");

        server.join().expect("server joined");
        let _ = std::fs::remove_file(&path);
        assert_eq!(err.error.code(), "internal");
    }
}
