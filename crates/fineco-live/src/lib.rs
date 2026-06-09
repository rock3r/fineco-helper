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
use fineco_ipc::SafeErrorDto;
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
    F: PortfolioFetcher + RawOrdersFetcher + TaxFetcher + ?Sized,
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
    F: PortfolioFetcher + RawOrdersFetcher + TaxFetcher + ?Sized,
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
    F: PortfolioFetcher + RawOrdersFetcher + TaxFetcher + ?Sized,
{
    // Bound a stalled peer so one half-open connection cannot pin the accept loop.
    let _ = stream.set_read_timeout(Some(LIVE_SERVER_TIMEOUT));
    let _ = stream.set_write_timeout(Some(LIVE_SERVER_TIMEOUT));
    // Decode the typed request. An unknown command and `deny_unknown_fields`
    // params are rejected by serde; unknown TOP-LEVEL envelope keys are rejected
    // explicitly via `validate_envelope_keys` (the adjacently-tagged enum alone
    // would silently ignore them) — so a malformed or hostile frame never reaches
    // a fetcher; it becomes a safe error envelope instead.
    let reply = match fineco_ipc::read_command_message::<_, LiveRequest>(stream) {
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
/// Wrap it in `fineco_refresh::Retrying` to absorb a transient Fineco blip within
/// one refresh (one `job_runs` row): the worker's retryable failures cross the
/// socket as their safe codes and are reconstructed with `retryable` intact.
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
        let _ = stream.set_read_timeout(Some(LIVE_CLIENT_TIMEOUT));
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
        "already_refreshing" => SafeError::already_refreshing(),
        // The worker re-validates as defense in depth; the controller already
        // validated, so the specific message is not needed across the socket.
        "invalid_request" => SafeError::invalid_request("the live worker rejected the request"),
        _ => SafeError::internal(),
    }
}
