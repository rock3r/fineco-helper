//! The refresh controller: the store-server's live-refresh brain.
//!
//! It owns the DB side of live refresh. For each [`RefreshRequest`] arriving on
//! `refresh-control.sock` it: re-checks the `*.live.refresh` capability against
//! the shared policy (defense in depth — the gateway checked first); re-validates
//! the bounded params; runs the pre-flight gate (cooldown / daily budget /
//! circuit breaker, whose denials create no `job_runs` row); then runs the
//! refresh against an injected fetcher exactly once, while sharing the
//! controller-local in-flight login lock with authenticated market reads. It returns
//! operation/snapshot **status only** — never the refreshed payload.
//!
//! The fetcher is generic: in production it is the
//! [`fineco_live::LiveClient`](fineco_live::LiveClient) reaching the credential
//! worker over `fineco-live.sock`; in tests it is a fake. The controller holds
//! the `Store` behind a `Mutex` so the (sequential) refresh accept loop can mutate
//! it while the snapshot-query loop reads the DB over its own connection.

use std::collections::VecDeque;
use std::sync::Mutex;

use fineco_core::{SafeError, parse_iso8601_utc};
use fineco_ipc::{
    MARKET_SESSION_REUSE_TTL_SECS, MarketAssetDetailsLiveFetcher, MarketControlOutcome,
    MarketControlRequest, MarketIndicesLiveFetcher, MarketSearchLiveFetcher, MarketSessionStatus,
    OWNER_AUTH_ID, Policy, RefreshOutcome, RefreshRequest,
};
use fineco_refresh::{
    OrdersFetcher, PortfolioFetcher, RefreshLimits, TaxFetcher, refresh_orders, refresh_portfolio,
    refresh_preflight, refresh_tax,
};
use fineco_store::Store;

/// Initial market login budget from the authenticated-market plan. Applies to
/// controller-governed on-demand Fineco market reads, counted per account/hour.
pub const MARKET_LOGIN_BUDGET_PER_ACCOUNT_PER_HOUR: u32 = 12;

/// Minimum spacing between controller-admitted fresh Fineco logins for market
/// reads until cookie-lifetime evidence is reviewed and a broader session reuse
/// window is explicitly approved.
pub const MARKET_LOGIN_MIN_COOLDOWN_SECS: u64 = 60;

/// Market live reads are single-account and login-sensitive, so only one
/// session operation may run at a time for the account.
pub const MARKET_MAX_CONCURRENT_LIVE_SESSION_OPS_PER_ACCOUNT: u32 = 1;

/// A stale reused session may be repaired with at most one fresh login retry.
pub const MARKET_REUSED_SESSION_401_RELOGIN_ATTEMPTS: u32 = 1;

// The cross-call reuse window itself lives in `fineco_ipc` so the credentialed
// worker (which holds the session) and this controller (which governs the
// per-login cooldown/budget) agree on one value: see
// [`fineco_ipc::MARKET_SESSION_REUSE_TTL_SECS`].

/// Open the authenticated-market circuit after this many consecutive
/// upstream/timeout failures.
pub const MARKET_CIRCUIT_CONSECUTIVE_FAILURES: u32 = 3;

/// Keep the authenticated-market circuit open this many seconds after the most
/// recent upstream/timeout failure, then allow one half-open probe.
pub const MARKET_CIRCUIT_COOLDOWN_SECS: u64 = 600;

const MARKET_LOGIN_BUDGET_WINDOW_SECS: i64 = 60 * 60;

/// Per-area live-refresh limits. Defaults follow the plan's "Rate Limits And
/// Circuit Breakers": tighter cooldown/budget on the heavier areas; a shared
/// circuit-breaker posture (open after repeated upstream failures, half-open
/// after a cooldown).
#[derive(Debug, Clone, Copy)]
pub struct RefreshLimitsByArea {
    pub portfolio: RefreshLimits,
    pub orders: RefreshLimits,
    pub tax: RefreshLimits,
}

impl RefreshLimitsByArea {
    /// The plan-derived defaults. Portfolio: 30-min cooldown, 4/day. Orders:
    /// 10-min cooldown, 6/day. Tax: 30-min cooldown, 6/day. All: open the circuit
    /// after 3 consecutive upstream/timeout failures, half-open after 10 min.
    #[must_use]
    pub fn defaults() -> Self {
        let circuit_failures = 3;
        let circuit_cooldown = 600;
        Self {
            portfolio: RefreshLimits {
                cooldown_secs: 1800,
                daily_budget: 4,
                circuit_consecutive_failures: circuit_failures,
                circuit_cooldown_secs: circuit_cooldown,
            },
            orders: RefreshLimits {
                cooldown_secs: 600,
                daily_budget: 6,
                circuit_consecutive_failures: circuit_failures,
                circuit_cooldown_secs: circuit_cooldown,
            },
            tax: RefreshLimits {
                cooldown_secs: 1800,
                daily_budget: 6,
                circuit_consecutive_failures: circuit_failures,
                circuit_cooldown_secs: circuit_cooldown,
            },
        }
    }

    /// The limits for a data area (`portfolio` / `orders` / `tax`). An unknown
    /// area falls back to the strictest (portfolio) limits — defensive, though the
    /// typed [`RefreshRequest`] never yields an unknown area.
    #[must_use]
    fn for_area(&self, area: &str) -> RefreshLimits {
        match area {
            "orders" => self.orders,
            "tax" => self.tax,
            _ => self.portfolio,
        }
    }
}

/// The refresh controller. Generic over the fetcher (the live client in
/// production, a fake in tests).
pub struct RefreshController<F> {
    store: Mutex<Store>,
    fetcher: F,
    policy: Policy,
    limits: RefreshLimitsByArea,
    live_login_state: Mutex<LiveLoginState>,
    market_circuit_state: Mutex<MarketCircuitState>,
}

#[derive(Debug, Default)]
struct LiveLoginState {
    in_flight: bool,
    pending_epoch: Option<i64>,
    last_login_epoch: Option<i64>,
    login_attempts: VecDeque<i64>,
    /// Controller-clock epoch until which the worker is presumed to hold a
    /// reusable market session (plan D-22). A market read admitted while this is
    /// in the future is treated as a reuse — no fresh login, so the per-login
    /// cooldown/budget do not apply. Mirrors the worker's held-session validity
    /// (same TTL + last-activity), so the two agree except across a worker
    /// restart, where the worker simply logs in fresh and reports it.
    market_session_valid_until: Option<i64>,
}

/// The reuse window ending at `now_epoch + MARKET_SESSION_REUSE_TTL_SECS`, or
/// `None` when cross-call reuse is disabled.
fn reuse_window_from(now_epoch: i64) -> Option<i64> {
    MARKET_SESSION_REUSE_TTL_SECS
        .map(|ttl| now_epoch.saturating_add(i64::try_from(ttl).unwrap_or(i64::MAX)))
}

impl LiveLoginState {
    fn admit_refresh_operation(&mut self) -> Result<(), SafeError> {
        if self.in_flight {
            return Err(SafeError::already_refreshing());
        }
        self.in_flight = true;
        // A refresh logs in fresh, which evicts the worker's held market session
        // (D-22 G-2): drop the reuse window so the next market read is admitted as
        // a fresh login, not a now-invalid reuse.
        self.market_session_valid_until = None;
        debug_assert!(self.pending_epoch.is_none());
        Ok(())
    }

    fn admit_market_operation(&mut self, now_iso: &str) -> Result<(), SafeError> {
        let now_epoch = parse_iso8601_utc(now_iso).ok_or_else(SafeError::internal)?;
        if self.in_flight {
            return Err(SafeError::market_rate_limited());
        }
        // A still-valid held session is reused (no fresh login), so the per-login
        // cooldown and hourly budget do not apply — otherwise a basket of
        // back-to-back reads would be throttled to one read per cooldown. The
        // window is only ever set when reuse is enabled, so this preserves the
        // stateless-per-call behavior when the TTL is `None`.
        let reuse_eligible = self
            .market_session_valid_until
            .is_some_and(|until| now_epoch < until);
        if !reuse_eligible {
            if let Some(last_login) = self.last_login_epoch {
                let age = now_epoch.saturating_sub(last_login);
                if age
                    < i64::try_from(MARKET_LOGIN_MIN_COOLDOWN_SECS)
                        .map_err(|_| SafeError::internal())?
                {
                    return Err(SafeError::market_rate_limited());
                }
            }
            while self.login_attempts.front().is_some_and(|attempt| {
                now_epoch.saturating_sub(*attempt) >= MARKET_LOGIN_BUDGET_WINDOW_SECS
            }) {
                let _ = self.login_attempts.pop_front();
            }
            if self.login_attempts.len()
                >= usize::try_from(MARKET_LOGIN_BUDGET_PER_ACCOUNT_PER_HOUR)
                    .map_err(|_| SafeError::internal())?
            {
                return Err(SafeError::market_rate_limited());
            }
        }
        self.in_flight = true;
        self.pending_epoch = Some(now_epoch);
        Ok(())
    }

    fn finish(&mut self, should_record_login: bool) {
        if should_record_login && let Some(epoch) = self.pending_epoch {
            self.last_login_epoch = Some(epoch);
            self.login_attempts.push_back(epoch);
        }
        self.in_flight = false;
        self.pending_epoch = None;
    }

    /// Finish a market operation, keying budget/audit on the worker's status-only
    /// facts rather than the admit-time prediction. `performed_login` debits the
    /// login budget/cooldown (a fresh login or a reused-session-401 recovery);
    /// `holds_session` opens the reuse window from `now_epoch` (a successful read
    /// leaves a held session) or clears it (an error leaves the session state
    /// uncertain, so the next read re-checks the cooldown).
    fn finish_market(&mut self, performed_login: bool, holds_session: bool, now_epoch: i64) {
        if performed_login {
            self.last_login_epoch = Some(now_epoch);
            self.login_attempts.push_back(now_epoch);
        }
        self.market_session_valid_until = if holds_session {
            reuse_window_from(now_epoch)
        } else {
            None
        };
        self.in_flight = false;
        self.pending_epoch = None;
    }
}

#[derive(Debug, Default)]
struct MarketCircuitState {
    consecutive_upstream_failures: u32,
    newest_failure_epoch: Option<i64>,
}

impl MarketCircuitState {
    fn check_closed(&self, now_iso: &str) -> Result<(), SafeError> {
        if self.consecutive_upstream_failures < MARKET_CIRCUIT_CONSECUTIVE_FAILURES {
            return Ok(());
        }
        let Some(newest_failure_epoch) = self.newest_failure_epoch else {
            return Ok(());
        };
        let now_epoch = parse_iso8601_utc(now_iso).ok_or_else(SafeError::internal)?;
        let cooldown =
            i64::try_from(MARKET_CIRCUIT_COOLDOWN_SECS).map_err(|_| SafeError::internal())?;
        if now_epoch.saturating_sub(newest_failure_epoch) < cooldown {
            return Err(SafeError::market_circuit_open());
        }
        Ok(())
    }

    fn record_outcome(
        &mut self,
        now_iso: &str,
        error: Option<&SafeError>,
    ) -> Result<(), SafeError> {
        if error.is_some_and(is_market_upstream_failure) {
            let now_epoch = parse_iso8601_utc(now_iso).ok_or_else(SafeError::internal)?;
            self.consecutive_upstream_failures =
                self.consecutive_upstream_failures.saturating_add(1);
            self.newest_failure_epoch = Some(now_epoch);
        } else {
            self.consecutive_upstream_failures = 0;
            self.newest_failure_epoch = None;
        }
        Ok(())
    }
}

fn is_market_upstream_failure(error: &SafeError) -> bool {
    matches!(
        error.code(),
        "market_upstream_failure" | "fineco_timeout" | "fineco_upstream_error"
    )
}

struct LiveLoginPermit<'a> {
    state: &'a Mutex<LiveLoginState>,
    finished: bool,
}

impl LiveLoginPermit<'_> {
    /// Finish a failed market operation: clear the reuse window (the session
    /// state is now uncertain) and debit a login unless the failure proves none
    /// happened (a local transport failure).
    fn finish_after_error(self, error: &SafeError, now_epoch: i64) -> Result<(), SafeError> {
        self.finish_market_state(should_record_assumed_fresh_login(error), false, now_epoch)
    }

    /// Finish a successful market operation: open the reuse window from
    /// `now_epoch` (a session is held) and debit a login only when the worker's
    /// status says one happened (a fresh login or a reused-session-401 recovery).
    fn finish_with_session_status(
        self,
        session: MarketSessionStatus,
        now_epoch: i64,
    ) -> Result<(), SafeError> {
        self.finish_market_state(
            session.login_performed || session.reused_session_401_recovered,
            true,
            now_epoch,
        )
    }

    fn finish_market_state(
        mut self,
        performed_login: bool,
        holds_session: bool,
        now_epoch: i64,
    ) -> Result<(), SafeError> {
        self.state
            .lock()
            .map_err(|_| SafeError::internal())?
            .finish_market(performed_login, holds_session, now_epoch);
        self.finished = true;
        Ok(())
    }

    fn finish_recording(mut self, should_record_login: bool) -> Result<(), SafeError> {
        self.state
            .lock()
            .map_err(|_| SafeError::internal())?
            .finish(should_record_login);
        self.finished = true;
        Ok(())
    }
}

fn should_record_assumed_fresh_login(error: &SafeError) -> bool {
    error.code() != "live_transport_failure"
}

impl Drop for LiveLoginPermit<'_> {
    fn drop(&mut self) {
        if !self.finished
            && let Ok(mut state) = self.state.lock()
        {
            state.finish(false);
        }
    }
}

impl<F> RefreshController<F> {
    fn begin_refresh_live_operation(&self) -> Result<LiveLoginPermit<'_>, SafeError> {
        self.live_login_state
            .lock()
            .map_err(|_| SafeError::internal())?
            .admit_refresh_operation()?;
        Ok(LiveLoginPermit {
            state: &self.live_login_state,
            finished: false,
        })
    }

    fn begin_market_live_operation(&self, now_iso: &str) -> Result<LiveLoginPermit<'_>, SafeError> {
        self.live_login_state
            .lock()
            .map_err(|_| SafeError::internal())?
            .admit_market_operation(now_iso)?;
        Ok(LiveLoginPermit {
            state: &self.live_login_state,
            finished: false,
        })
    }
}

impl<F> RefreshController<F>
where
    F: PortfolioFetcher + OrdersFetcher + TaxFetcher,
{
    /// Build a controller over `store`, sourcing fresh data from `fetcher`.
    #[must_use]
    pub fn new(store: Store, fetcher: F, policy: Policy, limits: RefreshLimitsByArea) -> Self {
        Self {
            store: Mutex::new(store),
            fetcher,
            policy,
            limits,
            live_login_state: Mutex::new(LiveLoginState::default()),
            market_circuit_state: Mutex::new(MarketCircuitState::default()),
        }
    }

    /// Handle one refresh request, stamping the resulting capture with `now_iso`.
    ///
    /// Order matters: capability → bounds → pre-flight (cooldown/budget/circuit) →
    /// refresh. The pre-flight denials and a capability/bounds rejection all
    /// create **no** `job_runs` row, so they never burn budget or cooldown.
    ///
    /// # Errors
    /// - [`SafeError::invalid_request`] if the policy does not grant the
    ///   `*.live.refresh` capability, or the params are out of bounds.
    /// - The pre-flight denial (`already_refreshing` / `refresh_cooldown` /
    ///   `refresh_budget_exhausted` / `refresh_circuit_open`).
    /// - The fetch failure (`auth_required` / `fineco_timeout` / …).
    /// - [`SafeError::internal`] on a storage or lock failure.
    pub fn handle(
        &self,
        request: RefreshRequest,
        now_iso: &str,
    ) -> Result<RefreshOutcome, SafeError> {
        // 1. Capability re-check (defense in depth; the gateway already checked,
        //    but the controller must enforce the same policy independently).
        if !self
            .policy
            .allows(OWNER_AUTH_ID, request.required_capability())
        {
            return Err(SafeError::invalid_request(
                "the configured policy does not permit this refresh.",
            ));
        }
        // 2. Re-validate the bounded params with the SAME shared validators.
        request.validate()?;

        let area = request.data_area();
        let limits = self.limits.for_area(area);
        let mut store = self.store.lock().map_err(|_| SafeError::internal())?;

        // 3. Pre-flight gate: a denial here creates no job_runs row.
        refresh_preflight(&store, area, &limits, now_iso)?;

        // 4. Run the refresh once. Controller-level retries would re-enter the
        // credentialed worker and may perform multiple Fineco logins under one
        // admitted live-login permit.
        let permit = self.begin_refresh_live_operation()?;
        let result = match &request {
            RefreshRequest::PortfolioRefreshLive => {
                refresh_portfolio(&mut store, &self.fetcher, OWNER_AUTH_ID, now_iso).and_then(
                    |snapshot_id| {
                        // A row count (positions), never the values. A failure reading it
                        // back right after the capture is a genuine storage error, not an
                        // empty snapshot — surface it rather than masking it as count=0.
                        let count = store
                            .positions_for_snapshot(snapshot_id)
                            .map_err(|_| SafeError::internal())?
                            .len();
                        Ok(RefreshOutcome {
                            data_area: area.to_string(),
                            captured_at: now_iso.to_string(),
                            snapshot_id: Some(snapshot_id),
                            count,
                        })
                    },
                )
            }
            RefreshRequest::OrdersRefreshLive(params) => refresh_orders(
                &mut store,
                &self.fetcher,
                OWNER_AUTH_ID,
                &params.instrument_kind,
                params.days,
                now_iso,
            )
            .map(|count| RefreshOutcome {
                data_area: area.to_string(),
                captured_at: now_iso.to_string(),
                snapshot_id: None,
                count,
            }),
            RefreshRequest::TaxRefreshLive(params) => refresh_tax(
                &mut store,
                &self.fetcher,
                OWNER_AUTH_ID,
                &params.date_from,
                &params.date_to,
                now_iso,
            )
            .map(|count| RefreshOutcome {
                data_area: area.to_string(),
                captured_at: now_iso.to_string(),
                snapshot_id: None,
                count,
            }),
        };
        permit.finish_recording(false)?;
        result
    }
}

impl<F> RefreshController<F>
where
    F: MarketSearchLiveFetcher + MarketAssetDetailsLiveFetcher + MarketIndicesLiveFetcher,
{
    /// Handle one authenticated market-control request, stamping the resulting
    /// payload with `now_iso`. Capability and bounds are re-checked here even
    /// though the gateway already checked them.
    ///
    /// # Errors
    /// [`SafeError::invalid_request`] on denied capability or invalid params, or
    /// the fetcher's safe error on auth/upstream/internal failure.
    pub fn handle_market_control(
        &self,
        request: MarketControlRequest,
        now_iso: &str,
    ) -> Result<MarketControlOutcome, SafeError> {
        if !self
            .policy
            .allows(OWNER_AUTH_ID, request.required_capability())
        {
            return Err(SafeError::invalid_request(
                "the configured policy does not permit this market read.",
            ));
        }
        request.validate()?;
        // The same controller clock the admit/finish accounting and the reuse
        // window key on.
        let now_epoch = parse_iso8601_utc(now_iso).ok_or_else(SafeError::internal)?;
        self.market_circuit_state
            .lock()
            .map_err(|_| SafeError::internal())?
            .check_closed(now_iso)?;
        let permit = self.begin_market_live_operation(now_iso)?;
        match request {
            MarketControlRequest::MarketSearchAsset(params) => {
                let live = self.fetcher.fetch_market_search(&params, now_iso);
                match live {
                    Ok(live) => {
                        let session = live.session;
                        permit.finish_with_session_status(session, now_epoch)?;
                        self.market_circuit_state
                            .lock()
                            .map_err(|_| SafeError::internal())?
                            .record_outcome(now_iso, None)?;
                        Ok(MarketControlOutcome::Search {
                            result: live.result,
                            session,
                        })
                    }
                    Err(error) => {
                        permit.finish_after_error(&error, now_epoch)?;
                        self.market_circuit_state
                            .lock()
                            .map_err(|_| SafeError::internal())?
                            .record_outcome(now_iso, Some(&error))?;
                        Err(error)
                    }
                }
            }
            MarketControlRequest::MarketGetAssetDetails(params) => {
                let live = self.fetcher.fetch_market_asset_details(&params, now_iso);
                match live {
                    Ok(live) => {
                        let session = live.session;
                        permit.finish_with_session_status(session, now_epoch)?;
                        let validation = live.result.validate_response_size();
                        self.market_circuit_state
                            .lock()
                            .map_err(|_| SafeError::internal())?
                            .record_outcome(now_iso, validation.as_ref().err())?;
                        validation?;
                        Ok(MarketControlOutcome::Details {
                            result: Box::new(live.result),
                            session,
                        })
                    }
                    Err(error) => {
                        permit.finish_after_error(&error, now_epoch)?;
                        self.market_circuit_state
                            .lock()
                            .map_err(|_| SafeError::internal())?
                            .record_outcome(now_iso, Some(&error))?;
                        Err(error)
                    }
                }
            }
            MarketControlRequest::MarketGetIndices(params) => {
                let live = self.fetcher.fetch_market_indices(&params, now_iso);
                match live {
                    Ok(live) => {
                        let session = live.session;
                        permit.finish_with_session_status(session, now_epoch)?;
                        self.market_circuit_state
                            .lock()
                            .map_err(|_| SafeError::internal())?
                            .record_outcome(now_iso, None)?;
                        Ok(MarketControlOutcome::Indices {
                            result: live.result,
                            session,
                        })
                    }
                    Err(error) => {
                        permit.finish_after_error(&error, now_epoch)?;
                        self.market_circuit_state
                            .lock()
                            .map_err(|_| SafeError::internal())?
                            .record_outcome(now_iso, Some(&error))?;
                        Err(error)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LiveLoginState, MARKET_CIRCUIT_CONSECUTIVE_FAILURES, MARKET_CIRCUIT_COOLDOWN_SECS,
        MARKET_LOGIN_BUDGET_PER_ACCOUNT_PER_HOUR, MARKET_LOGIN_MIN_COOLDOWN_SECS,
        MARKET_MAX_CONCURRENT_LIVE_SESSION_OPS_PER_ACCOUNT,
        MARKET_REUSED_SESSION_401_RELOGIN_ATTEMPTS, MARKET_SESSION_REUSE_TTL_SECS,
        RefreshController, RefreshLimitsByArea, parse_iso8601_utc,
    };
    use fineco_core::SafeError;
    use fineco_ipc::{
        MarketAssetDetailsLiveResult, MarketAssetDetailsResult, MarketAssetIdentity,
        MarketAssetSections, MarketAssetType, MarketControlOutcome, MarketControlRequest,
        MarketDetailsParams, MarketField, MarketIndexCard, MarketIndexRegion,
        MarketIndicesLiveResult, MarketIndicesParams, MarketIndicesResult, MarketSearchCandidate,
        MarketSearchGroup, MarketSearchLiveResult, MarketSearchParams, MarketSearchResult,
        MarketSessionStatus, OrdersRefreshParams, Policy, RefreshRequest, TaxRefreshParams,
    };
    use fineco_refresh::{OrdersFetcher, PortfolioFetcher, RefreshLimits, TaxFetcher};
    use fineco_store::{
        NewAsset, NewPortfolioSnapshot, NewPosition, NewTaxCarryForward, NewTaxMinusByYear,
        RawOrder, Store,
    };
    use std::cell::Cell;
    use std::rc::Rc;

    const NOW: &str = "2026-06-05T10:00:00Z";

    /// A fake worker the controller drives. Each fetch returns a canned result; a
    /// `Cell` counts portfolio fetches so tests can prove the controller does not
    /// re-enter the worker after one admitted live-login operation.
    struct FakeWorker {
        portfolio: Box<dyn Fn() -> Result<NewPortfolioSnapshot, SafeError>>,
        orders: Result<Vec<RawOrder>, SafeError>,
        carry_forward: Result<NewTaxCarryForward, SafeError>,
        minus_by_year: Result<Vec<NewTaxMinusByYear>, SafeError>,
        /// The status-only session facts the fake reports per market call. A
        /// closure so a test can simulate the real worker (fresh login first,
        /// reuse afterwards) by capturing a counter.
        market_session: Box<dyn Fn() -> MarketSessionStatus>,
        market_result: Box<dyn Fn() -> Result<(), SafeError>>,
    }

    impl FakeWorker {
        fn ok() -> Self {
            Self {
                portfolio: Box::new(|| Ok(one_position_snapshot())),
                orders: Ok(vec![a_raw_order()]),
                carry_forward: Ok(NewTaxCarryForward {
                    date_from: String::new(),
                    date_to: String::new(),
                    total: Some(0.0),
                }),
                minus_by_year: Ok(vec![NewTaxMinusByYear {
                    year: 2025,
                    minus_residue: Some(0.0),
                    expiration_date: None,
                }]),
                market_session: Box::new(MarketSessionStatus::fresh_login),
                market_result: Box::new(|| Ok(())),
            }
        }
    }

    impl PortfolioFetcher for FakeWorker {
        fn fetch_portfolio(&self, now_iso: &str) -> Result<NewPortfolioSnapshot, SafeError> {
            (self.portfolio)().map(|mut snapshot| {
                snapshot.captured_at = now_iso.to_string();
                snapshot
            })
        }
    }

    impl OrdersFetcher for FakeWorker {
        fn fetch_orders(
            &self,
            store: &Store,
            _instrument_kind: &str,
            _days: u32,
        ) -> Result<Vec<fineco_store::NewOrder>, SafeError> {
            // Mirror the LiveClient: hash the raw orders controller-side.
            self.orders
                .clone()?
                .iter()
                .map(|raw| store.hash_raw_order(raw).map_err(|_| SafeError::internal()))
                .collect()
        }
    }

    impl TaxFetcher for FakeWorker {
        fn fetch_tax_carry_forward(
            &self,
            _date_from: &str,
            _date_to: &str,
        ) -> Result<NewTaxCarryForward, SafeError> {
            self.carry_forward.clone()
        }
        fn fetch_tax_minus_by_year(&self) -> Result<Vec<NewTaxMinusByYear>, SafeError> {
            self.minus_by_year.clone()
        }
    }

    impl fineco_ipc::MarketSearchLiveFetcher for FakeWorker {
        fn fetch_market_search(
            &self,
            params: &MarketSearchParams,
            now_iso: &str,
        ) -> Result<MarketSearchLiveResult, SafeError> {
            (self.market_result)()?;
            Ok(MarketSearchLiveResult {
                result: MarketSearchResult {
                    query: params.query.clone(),
                    data_class: "authenticated_market".to_string(),
                    source: "fineco.search.global".to_string(),
                    captured_at: now_iso.to_string(),
                    groups: vec![MarketSearchGroup {
                        asset_type: MarketAssetType::Etf,
                        result_count: 1,
                        candidates: vec![MarketSearchCandidate {
                            fineco_key: "IE00B8GKDB10.AFF".to_string(),
                            identifier: "AFF/VHYL".to_string(),
                            name: "Vanguard FTSE All-World High Dividend Yield UCITS ETF Dis"
                                .to_string(),
                            venue: "AFF".to_string(),
                            symbol: "VHYL".to_string(),
                            display_symbol: "VHYL.MI".to_string(),
                            isin: Some("IE00B8GKDB10".to_string()),
                            currency: Some("EUR".to_string()),
                            asset_type: MarketAssetType::Etf,
                            preferred: true,
                        }],
                    }],
                },
                session: (self.market_session)(),
            })
        }
    }

    impl fineco_ipc::MarketAssetDetailsLiveFetcher for FakeWorker {
        fn fetch_market_asset_details(
            &self,
            params: &MarketDetailsParams,
            now_iso: &str,
        ) -> Result<MarketAssetDetailsLiveResult, SafeError> {
            (self.market_result)()?;
            Ok(MarketAssetDetailsLiveResult {
                result: MarketAssetDetailsResult {
                    schema_version: 1,
                    data_class: "authenticated_market".to_string(),
                    captured_at: now_iso.to_string(),
                    asset: MarketAssetIdentity {
                        identifier: params.identifier.clone(),
                        fineco_key: MarketField::high_string(
                            "IE00B8GKDB10.AFF",
                            "fineco",
                            "authenticated_market",
                            "search.global",
                            now_iso,
                        ),
                        asset_type: MarketField::high(
                            MarketAssetType::Etf,
                            None,
                            "fineco",
                            "authenticated_market",
                            "search.global",
                            None,
                            now_iso,
                        ),
                        name: None,
                        isin: Some(MarketField::high_string(
                            "IE00B8GKDB10",
                            "fineco",
                            "authenticated_market",
                            "search.global",
                            now_iso,
                        )),
                        venue: MarketField::high_string(
                            "AFF",
                            "fineco",
                            "authenticated_market",
                            "search.global",
                            now_iso,
                        ),
                        symbol: MarketField::medium_string(
                            "VHYL",
                            "fineco",
                            "authenticated_market",
                            "search.global",
                            now_iso,
                        ),
                        display_symbol: Some(MarketField::medium_string(
                            "VHYL.MI",
                            "fineco",
                            "authenticated_market",
                            "search.global",
                            now_iso,
                        )),
                        currency: Some(MarketField::high_string(
                            "EUR",
                            "fineco",
                            "authenticated_market",
                            "search.global",
                            now_iso,
                        )),
                    },
                    sections: MarketAssetSections::default(),
                    sources: vec![],
                    warnings: vec![],
                },
                session: (self.market_session)(),
            })
        }
    }

    impl fineco_ipc::MarketIndicesLiveFetcher for FakeWorker {
        fn fetch_market_indices(
            &self,
            _params: &MarketIndicesParams,
            now_iso: &str,
        ) -> Result<MarketIndicesLiveResult, SafeError> {
            (self.market_result)()?;
            Ok(MarketIndicesLiveResult {
                result: MarketIndicesResult {
                    schema_version: 1,
                    data_class: "authenticated_market".to_string(),
                    source: "fineco.indicesbar".to_string(),
                    captured_at: now_iso.to_string(),
                    indices: vec![MarketIndexCard {
                        symbol: MarketField::high_string(
                            "^FTMIB.affIdx",
                            "fineco.indicesbar",
                            "authenticated_market",
                            "indicesbar",
                            now_iso,
                        ),
                        label: MarketField::high_string(
                            "Ftse mib",
                            "fineco.indicesbar",
                            "authenticated_market",
                            "indicesbar",
                            now_iso,
                        ),
                        region: MarketIndexRegion::Europe,
                        value: None,
                        change_percent: Some(MarketField::medium(
                            1.97,
                            Some("percent"),
                            "fineco.indicesbar",
                            "authenticated_market",
                            "indicesbar",
                            None,
                            now_iso,
                        )),
                    }],
                    warnings: vec![],
                },
                session: (self.market_session)(),
            })
        }
    }

    fn one_position_snapshot() -> NewPortfolioSnapshot {
        NewPortfolioSnapshot {
            captured_at: String::new(),
            source: "fineco".to_string(),
            market_value: Some(1000.0),
            book_value: Some(900.0),
            profit_loss: Some(100.0),
            profit_loss_perc: Some(11.11),
            positions: vec![NewPosition {
                asset: NewAsset {
                    instr_id: "A".to_string(),
                    venue_system: "V".to_string(),
                    symbol: Some("SYM".to_string()),
                    description: None,
                    kind: None,
                    currency: Some("EUR".to_string()),
                },
                position_key_hash: None,
                qty: Some(10.0),
                avg_price: Some(90.0),
                market_price: Some(100.0),
                book_value: Some(900.0),
                market_value: Some(1000.0),
                profit_loss: Some(100.0),
                profit_loss_perc: Some(11.11),
                weight_perc: Some(100.0),
            }],
            fx_rates: vec![],
        }
    }

    fn a_raw_order() -> RawOrder {
        RawOrder {
            trans_id: "TX-1".to_string(),
            asset: NewAsset {
                instr_id: "A".to_string(),
                venue_system: "V".to_string(),
                symbol: None,
                description: None,
                kind: None,
                currency: None,
            },
            status: Some("EXECUTED".to_string()),
            sign: Some("BUY".to_string()),
            order_size: Some(1.0),
            size_filled: Some(1.0),
            avg_price: Some(10.0),
            submit_time: Some(NOW.to_string()),
        }
    }

    fn live_policy() -> Policy {
        Policy::from_json(
            r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
                "portfolio.live.refresh","orders.live.refresh","tax.live.refresh"]}}}"#,
        )
        .expect("policy")
    }

    fn market_policy() -> Policy {
        Policy::from_json(
            r#"{"version":1,"auth_ids":{"owner":{"capabilities":["market.authenticated.read"]}}}"#,
        )
        .expect("policy")
    }

    fn market_search_request() -> MarketControlRequest {
        MarketControlRequest::MarketSearchAsset(MarketSearchParams {
            query: "VHYL".to_string(),
            asset_type: Some(MarketAssetType::Etf),
            limit: Some(5),
        })
    }

    fn cached_only_policy() -> Policy {
        Policy::from_json(
            r#"{"version":1,"auth_ids":{"owner":{"capabilities":["portfolio.cached.full_read"]}}}"#,
        )
        .expect("policy")
    }

    fn controller(worker: FakeWorker, policy: Policy) -> RefreshController<FakeWorker> {
        RefreshController::new(
            Store::open_in_memory().expect("store"),
            worker,
            policy,
            RefreshLimitsByArea::defaults(),
        )
    }

    fn controller_with_limits(
        worker: FakeWorker,
        policy: Policy,
        limits: RefreshLimitsByArea,
    ) -> RefreshController<FakeWorker> {
        RefreshController::new(
            Store::open_in_memory().expect("store"),
            worker,
            policy,
            limits,
        )
    }

    fn permissive_refresh_limits() -> RefreshLimitsByArea {
        let area = RefreshLimits {
            cooldown_secs: 0,
            daily_budget: MARKET_LOGIN_BUDGET_PER_ACCOUNT_PER_HOUR + 1,
            circuit_consecutive_failures: MARKET_LOGIN_BUDGET_PER_ACCOUNT_PER_HOUR + 1,
            circuit_cooldown_secs: 0,
        };
        RefreshLimitsByArea {
            portfolio: area,
            orders: area,
            tax: area,
        }
    }

    #[test]
    fn market_live_session_defaults_match_the_ratified_plan() {
        assert_eq!(MARKET_LOGIN_BUDGET_PER_ACCOUNT_PER_HOUR, 12);
        assert_eq!(MARKET_LOGIN_MIN_COOLDOWN_SECS, 60);
        assert_eq!(MARKET_MAX_CONCURRENT_LIVE_SESSION_OPS_PER_ACCOUNT, 1);
        assert_eq!(MARKET_REUSED_SESSION_401_RELOGIN_ATTEMPTS, 1);
        assert_eq!(MARKET_SESSION_REUSE_TTL_SECS, Some(120));
        assert_eq!(MARKET_CIRCUIT_CONSECUTIVE_FAILURES, 3);
        assert_eq!(MARKET_CIRCUIT_COOLDOWN_SECS, 600);
    }

    #[test]
    fn refresh_and_market_operations_share_one_in_flight_login_lock() {
        let mut state = LiveLoginState::default();
        state
            .admit_refresh_operation()
            .expect("refresh admitted first");
        let err = state
            .admit_market_operation("2026-06-14T10:00:00Z")
            .expect_err("market waits while refresh is in flight");
        assert_eq!(err.code(), "market_rate_limited");

        state.finish(false);
        state
            .admit_market_operation("2026-06-14T10:00:00Z")
            .expect("market admitted first");
        let err = state
            .admit_refresh_operation()
            .expect_err("refresh waits while market is in flight");
        assert_eq!(err.code(), "already_refreshing");
    }

    /// A fake whose first market call reports a fresh login and every later one
    /// reports a reuse — modelling the real worker holding a session across reads.
    fn sequenced_session_worker() -> FakeWorker {
        let calls = Rc::new(Cell::new(0u32));
        let mut worker = FakeWorker::ok();
        worker.market_session = Box::new(move || {
            let n = calls.get();
            calls.set(n + 1);
            if n == 0 {
                MarketSessionStatus::fresh_login()
            } else {
                MarketSessionStatus {
                    login_performed: false,
                    session_reused: true,
                    session_evicted: false,
                    reused_session_401_recovered: false,
                    session_expires_in_secs: Some(300),
                }
            }
        });
        worker
    }

    fn market_session_of(outcome: &MarketControlOutcome) -> MarketSessionStatus {
        match outcome {
            MarketControlOutcome::Search { session, .. }
            | MarketControlOutcome::Details { session, .. }
            | MarketControlOutcome::Indices { session, .. } => *session,
        }
    }

    #[test]
    fn market_reads_within_the_reuse_window_skip_the_login_cooldown() {
        // First read logs in; a follow-up inside the reuse window reuses the held
        // session, so the 60s fresh-login cooldown does NOT apply — a basket of
        // back-to-back reads must not be throttled to one read per cooldown.
        let ctrl = controller(sequenced_session_worker(), market_policy());
        let first = ctrl
            .handle_market_control(market_search_request(), "2026-06-14T10:00:00Z")
            .expect("first search logs in");
        assert!(market_session_of(&first).login_performed);

        let second = ctrl
            .handle_market_control(market_search_request(), "2026-06-14T10:00:30Z")
            .expect("second search reuses within the window, not cooldown-blocked");
        assert!(market_session_of(&second).session_reused);
    }

    /// Direct `LiveLoginState` checks for the reuse-window admission model, where
    /// the held-session lifecycle can be driven deterministically (the fake
    /// worker reports status independently of the controller's prediction).
    #[test]
    fn reuse_window_admission_skips_cooldown_then_re_applies_it() {
        let ttl = MARKET_SESSION_REUSE_TTL_SECS.expect("reuse enabled");
        let t0 = parse_iso8601_utc("2026-06-14T10:00:00Z").expect("epoch");
        let iso = |offset: i64| fineco_core::epoch_to_iso8601_utc(t0 + offset);

        let mut state = LiveLoginState::default();
        state.admit_market_operation(&iso(0)).expect("first admit");
        // A successful fresh login opens the reuse window and arms the cooldown.
        state.finish_market(true, true, t0);

        // 30s later (< 60s cooldown) but within the window → reuse, admitted.
        state
            .admit_market_operation(&iso(30))
            .expect("reuse skips the cooldown");
        state.finish_market(false, true, t0 + 30);

        // Past the window (last activity t0+30, +ttl): a fresh login is needed, and
        // it is now well past the cooldown, so it is admitted and re-arms the window.
        let expired = 30 + i64::try_from(ttl).unwrap() + 1;
        state
            .admit_market_operation(&iso(expired))
            .expect("a fresh login past the window is admitted");
    }

    #[test]
    fn a_failed_read_clears_the_reuse_window_so_the_cooldown_applies() {
        let t0 = parse_iso8601_utc("2026-06-14T10:00:00Z").expect("epoch");
        let iso = |offset: i64| fineco_core::epoch_to_iso8601_utc(t0 + offset);

        let mut state = LiveLoginState::default();
        state.admit_market_operation(&iso(0)).expect("admit");
        // An error debits the login but clears the window (session state unknown).
        state.finish_market(true, false, t0);

        // 30s later: no window → the fresh-login cooldown applies.
        let err = state
            .admit_market_operation(&iso(30))
            .expect_err("cleared window re-arms the cooldown");
        assert_eq!(err.code(), "market_rate_limited");
    }

    #[test]
    fn a_refresh_admission_clears_the_market_reuse_window() {
        let t0 = parse_iso8601_utc("2026-06-14T10:00:00Z").expect("epoch");
        let iso = |offset: i64| fineco_core::epoch_to_iso8601_utc(t0 + offset);

        let mut state = LiveLoginState::default();
        state.admit_market_operation(&iso(0)).expect("market admit");
        state.finish_market(true, true, t0); // holds a session, window open

        // A refresh logs in fresh and evicts the market session (D-22 G-2): the
        // window must be dropped so the next market read is not a stale reuse.
        state.admit_refresh_operation().expect("refresh admit");
        state.finish(false);

        // 30s after the original login: window gone → cooldown applies.
        let err = state
            .admit_market_operation(&iso(30))
            .expect_err("refresh cleared the reuse window");
        assert_eq!(err.code(), "market_rate_limited");
    }

    #[test]
    fn market_search_reused_session_status_does_not_burn_fresh_login_cooldown() {
        let mut worker = FakeWorker::ok();
        worker.market_session = Box::new(|| MarketSessionStatus {
            login_performed: false,
            session_reused: true,
            session_evicted: false,
            reused_session_401_recovered: false,
            session_expires_in_secs: Some(300),
        });
        let ctrl = controller(worker, market_policy());
        ctrl.handle_market_control(market_search_request(), "2026-06-14T10:00:00Z")
            .expect("reused-session search admitted");

        ctrl.handle_market_control(market_search_request(), "2026-06-14T10:00:01Z")
            .expect("reused session does not burn fresh-login cooldown");
    }

    #[test]
    fn recovered_reused_session_401_is_reported_and_debits_a_login() {
        // The worker repaired a stale reused session with one fresh login: the read
        // succeeds and reports the recovery.
        let mut worker = FakeWorker::ok();
        worker.market_session = Box::new(|| MarketSessionStatus {
            login_performed: false,
            session_reused: true,
            session_evicted: true,
            reused_session_401_recovered: true,
            session_expires_in_secs: None,
        });
        let ctrl = controller(worker, market_policy());
        let outcome = ctrl
            .handle_market_control(market_search_request(), "2026-06-14T10:00:00Z")
            .expect("recovered reused-session search admitted");
        assert!(market_session_of(&outcome).reused_session_401_recovered);

        // That recovery performed a fresh login, so it must debit the login budget.
        let t0 = parse_iso8601_utc("2026-06-14T10:00:00Z").expect("epoch");
        let mut state = LiveLoginState::default();
        let recovered = MarketSessionStatus {
            login_performed: false,
            session_reused: true,
            session_evicted: true,
            reused_session_401_recovered: true,
            session_expires_in_secs: None,
        };
        state.finish_market(
            recovered.login_performed || recovered.reused_session_401_recovered,
            true,
            t0,
        );
        assert_eq!(state.last_login_epoch, Some(t0));
        assert_eq!(state.login_attempts.len(), 1);
    }

    #[test]
    fn market_search_enforces_the_hourly_login_budget() {
        let ctrl = controller(FakeWorker::ok(), market_policy());
        // Space reads 3 minutes apart — past the 120s reuse window, so each is a
        // fresh login (a back-to-back basket would instead reuse one login).
        for i in 0..MARKET_LOGIN_BUDGET_PER_ACCOUNT_PER_HOUR {
            let minute = i * 3;
            let now = format!("2026-06-14T10:{minute:02}:00Z");
            ctrl.handle_market_control(market_search_request(), &now)
                .expect("within market login budget");
        }

        let err = ctrl
            .handle_market_control(market_search_request(), "2026-06-14T10:36:00Z")
            .expect_err("13th fresh login inside the rolling hour is denied");
        assert_eq!(err.code(), "market_rate_limited");
    }

    #[test]
    fn market_search_cooldown_does_not_block_refresh_policy() {
        let policy = Policy::from_json(
            r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
                "market.authenticated.read","portfolio.live.refresh"]}}}"#,
        )
        .expect("policy");
        let ctrl = controller_with_limits(FakeWorker::ok(), policy, permissive_refresh_limits());
        ctrl.handle_market_control(market_search_request(), "2026-06-14T10:00:00Z")
            .expect("market search admitted");

        ctrl.handle(RefreshRequest::PortfolioRefreshLive, "2026-06-14T10:00:30Z")
            .expect("refresh uses its own policy after market search");
    }

    #[test]
    fn refresh_does_not_clear_an_active_market_login_cooldown() {
        let policy = Policy::from_json(
            r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
                "market.authenticated.read","portfolio.live.refresh"]}}}"#,
        )
        .expect("policy");
        let ctrl = controller_with_limits(FakeWorker::ok(), policy, permissive_refresh_limits());
        ctrl.handle_market_control(market_search_request(), "2026-06-14T10:00:00Z")
            .expect("market search admitted");
        ctrl.handle(RefreshRequest::PortfolioRefreshLive, "2026-06-14T10:00:30Z")
            .expect("refresh does not obey market cooldown");

        let err = ctrl
            .handle_market_control(market_search_request(), "2026-06-14T10:00:45Z")
            .expect_err("market cooldown still applies after the refresh");
        assert_eq!(err.code(), "market_rate_limited");
    }

    #[test]
    fn refresh_does_not_burn_market_login_cooldown() {
        let policy = Policy::from_json(
            r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
                "market.authenticated.read","portfolio.live.refresh"]}}}"#,
        )
        .expect("policy");
        let ctrl = controller_with_limits(FakeWorker::ok(), policy, permissive_refresh_limits());
        ctrl.handle(RefreshRequest::PortfolioRefreshLive, "2026-06-14T10:00:00Z")
            .expect("refresh admitted");

        ctrl.handle_market_control(market_search_request(), "2026-06-14T10:00:30Z")
            .expect("refresh login does not burn market cooldown");
    }

    #[test]
    fn failed_refresh_does_not_burn_market_login_cooldown() {
        let policy = Policy::from_json(
            r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
                "market.authenticated.read","portfolio.live.refresh"]}}}"#,
        )
        .expect("policy");
        let mut worker = FakeWorker::ok();
        worker.portfolio = Box::new(|| Err(SafeError::auth_required()));
        let ctrl = controller(worker, policy);

        let refresh_err = ctrl
            .handle(RefreshRequest::PortfolioRefreshLive, "2026-06-14T10:00:00Z")
            .expect_err("fresh-login refresh failure");
        assert_eq!(refresh_err.code(), "auth_required");

        ctrl.handle_market_control(market_search_request(), "2026-06-14T10:00:30Z")
            .expect("failed refresh login does not burn market cooldown");
    }

    #[test]
    fn failed_refreshes_do_not_burn_the_market_hourly_login_budget() {
        let policy = Policy::from_json(
            r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
                "market.authenticated.read","portfolio.live.refresh"]}}}"#,
        )
        .expect("policy");
        let mut worker = FakeWorker::ok();
        worker.portfolio = Box::new(|| Err(SafeError::auth_required()));
        let ctrl = controller_with_limits(worker, policy, permissive_refresh_limits());

        for minute in 0..MARKET_LOGIN_BUDGET_PER_ACCOUNT_PER_HOUR {
            let now = format!("2026-06-14T10:{minute:02}:00Z");
            let err = ctrl
                .handle(RefreshRequest::PortfolioRefreshLive, &now)
                .expect_err("failed refresh reached Fineco");
            assert_eq!(err.code(), "auth_required");
        }

        ctrl.handle_market_control(market_search_request(), "2026-06-14T10:12:00Z")
            .expect("failed refresh logins do not exhaust the market budget");
    }

    #[test]
    fn market_search_opens_the_market_circuit_after_repeated_upstream_failures() {
        let mut worker = FakeWorker::ok();
        worker.market_result = Box::new(|| Err(SafeError::market_upstream_failure()));
        let ctrl = controller(worker, market_policy());

        for minute in 0..MARKET_CIRCUIT_CONSECUTIVE_FAILURES {
            let now = format!("2026-06-14T10:{minute:02}:00Z");
            let err = ctrl
                .handle_market_control(market_search_request(), &now)
                .expect_err("upstream failure reaches Fineco");
            assert_eq!(err.code(), "market_upstream_failure");
        }

        let err = ctrl
            .handle_market_control(market_search_request(), "2026-06-14T10:03:00Z")
            .expect_err("market circuit is open");
        assert_eq!(err.code(), "market_circuit_open");
    }

    #[test]
    fn controller_does_not_retry_the_whole_market_worker_call() {
        let calls = std::rc::Rc::new(Cell::new(0u32));
        let calls_in = std::rc::Rc::clone(&calls);
        let mut worker = FakeWorker::ok();
        worker.market_result = Box::new(move || {
            calls_in.set(calls_in.get() + 1);
            Err(SafeError::market_upstream_failure())
        });
        let ctrl = controller(worker, market_policy());

        let err = ctrl
            .handle_market_control(market_search_request(), NOW)
            .expect_err("upstream failure propagates");

        assert_eq!(err.code(), "market_upstream_failure");
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn market_transport_failure_does_not_burn_fresh_login_cooldown() {
        let mut worker = FakeWorker::ok();
        worker.market_result = Box::new(|| Err(SafeError::live_transport_failure()));
        let ctrl = controller(worker, market_policy());

        let err = ctrl
            .handle_market_control(market_search_request(), "2026-06-14T10:00:00Z")
            .expect_err("local transport failure");
        assert_eq!(err.code(), "live_transport_failure");

        let second_err = ctrl
            .handle_market_control(market_search_request(), "2026-06-14T10:00:30Z")
            .expect_err("worker is still failing, but the login cooldown was not burned");
        assert_eq!(second_err.code(), "live_transport_failure");
    }

    #[test]
    fn market_worker_internal_failure_burns_fresh_login_cooldown() {
        let mut worker = FakeWorker::ok();
        worker.market_result = Box::new(|| Err(SafeError::internal()));
        let ctrl = controller(worker, market_policy());

        let err = ctrl
            .handle_market_control(market_search_request(), "2026-06-14T10:00:00Z")
            .expect_err("worker-side failure after the live call was admitted");
        assert_eq!(err.code(), "internal");

        let second_err = ctrl
            .handle_market_control(market_search_request(), "2026-06-14T10:00:30Z")
            .expect_err("worker internal failure burned the login cooldown");
        assert_eq!(second_err.code(), "market_rate_limited");
    }

    #[test]
    fn refresh_transport_internal_failure_does_not_burn_market_login_cooldown() {
        let policy = Policy::from_json(
            r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
                "market.authenticated.read","portfolio.live.refresh"]}}}"#,
        )
        .expect("policy");
        let mut worker = FakeWorker::ok();
        worker.portfolio = Box::new(|| Err(SafeError::internal()));
        let ctrl = controller(worker, policy);

        let refresh_err = ctrl
            .handle(RefreshRequest::PortfolioRefreshLive, "2026-06-14T10:00:00Z")
            .expect_err("local transport failure");
        assert_eq!(refresh_err.code(), "internal");

        ctrl.handle_market_control(market_search_request(), "2026-06-14T10:00:30Z")
            .expect("transport failure did not burn market login cooldown");
    }

    #[test]
    fn market_search_circuit_half_opens_after_cooldown_and_closes_on_success() {
        let mut worker = FakeWorker::ok();
        let failures_remaining = std::rc::Rc::new(Cell::new(MARKET_CIRCUIT_CONSECUTIVE_FAILURES));
        let failures_in = std::rc::Rc::clone(&failures_remaining);
        worker.market_result = Box::new(move || {
            if failures_in.get() > 0 {
                failures_in.set(failures_in.get() - 1);
                Err(SafeError::market_upstream_failure())
            } else {
                Ok(())
            }
        });
        let ctrl = controller(worker, market_policy());

        for minute in 0..MARKET_CIRCUIT_CONSECUTIVE_FAILURES {
            let now = format!("2026-06-14T10:{minute:02}:00Z");
            let _ = ctrl
                .handle_market_control(market_search_request(), &now)
                .expect_err("upstream failure reaches Fineco");
        }

        let err = ctrl
            .handle_market_control(market_search_request(), "2026-06-14T10:03:00Z")
            .expect_err("circuit open before cooldown");
        assert_eq!(err.code(), "market_circuit_open");

        ctrl.handle_market_control(market_search_request(), "2026-06-14T10:12:00Z")
            .expect("half-open probe succeeds and closes the circuit");

        ctrl.handle_market_control(market_search_request(), "2026-06-14T10:13:00Z")
            .expect("success cleared the market upstream failure streak");
    }

    #[test]
    fn market_auth_failures_do_not_trip_the_upstream_circuit() {
        let mut worker = FakeWorker::ok();
        worker.market_result = Box::new(|| Err(SafeError::market_auth_required()));
        let ctrl = controller(worker, market_policy());

        for minute in 0..MARKET_CIRCUIT_CONSECUTIVE_FAILURES {
            let now = format!("2026-06-14T10:{minute:02}:00Z");
            let err = ctrl
                .handle_market_control(market_search_request(), &now)
                .expect_err("auth failure reaches Fineco");
            assert_eq!(err.code(), "market_auth_required");
        }

        let err = ctrl
            .handle_market_control(market_search_request(), "2026-06-14T10:03:00Z")
            .expect_err("auth failure does not become circuit-open");
        assert_eq!(err.code(), "market_auth_required");
    }

    #[test]
    fn portfolio_refresh_captures_and_returns_status_only() {
        let ctrl = controller(FakeWorker::ok(), live_policy());
        let outcome = ctrl
            .handle(RefreshRequest::PortfolioRefreshLive, NOW)
            .expect("refresh");
        assert_eq!(outcome.data_area, "portfolio");
        assert!(outcome.snapshot_id.is_some());
        assert_eq!(outcome.count, 1); // one position — a count, never a value
        assert_eq!(outcome.captured_at, NOW);
    }

    #[test]
    fn orders_and_tax_refresh_report_their_row_counts() {
        let ctrl = controller(FakeWorker::ok(), live_policy());
        let orders = ctrl
            .handle(
                RefreshRequest::OrdersRefreshLive(OrdersRefreshParams {
                    instrument_kind: "equity".to_string(),
                    days: 7,
                }),
                NOW,
            )
            .expect("orders refresh");
        assert_eq!(orders.data_area, "orders");
        assert_eq!(orders.snapshot_id, None);
        assert_eq!(orders.count, 1);

        let tax = ctrl
            .handle(
                RefreshRequest::TaxRefreshLive(TaxRefreshParams {
                    date_from: "2026-01-01".to_string(),
                    date_to: "2026-01-31".to_string(),
                }),
                "2026-06-05T10:01:00Z",
            )
            .expect("tax refresh");
        assert_eq!(tax.data_area, "tax");
        assert_eq!(tax.count, 2); // 1 carry-forward + 1 minus-by-year
    }

    #[test]
    fn a_policy_without_the_live_capability_denies_and_creates_no_job_row() {
        let ctrl = controller(FakeWorker::ok(), cached_only_policy());
        let err = ctrl
            .handle(RefreshRequest::PortfolioRefreshLive, NOW)
            .expect_err("denied");
        assert_eq!(err.code(), "invalid_request");
        // No job row: the denial happened before the lock.
        let store = ctrl.store.lock().expect("lock");
        assert!(store.latest_job_run("portfolio").expect("q").is_none());
    }

    #[test]
    fn an_auth_failure_propagates_without_retry_and_records_the_job() {
        let calls = std::rc::Rc::new(Cell::new(0u32));
        let calls_in = std::rc::Rc::clone(&calls);
        let mut worker = FakeWorker::ok();
        worker.portfolio = Box::new(move || {
            calls_in.set(calls_in.get() + 1);
            Err(SafeError::auth_required())
        });
        let ctrl = controller(worker, live_policy());
        let err = ctrl
            .handle(RefreshRequest::PortfolioRefreshLive, NOW)
            .expect_err("auth fails");
        assert_eq!(err.code(), "auth_required");
        // 4xx auth failures are NOT retried (the fetch ran exactly once).
        assert_eq!(calls.get(), 1);
        // The attempt reached Fineco, so it IS recorded (failed) — budget counts it.
        let store = ctrl.store.lock().expect("lock");
        let job = store
            .latest_job_run("portfolio")
            .expect("q")
            .expect("a job");
        assert_eq!(job.status, "failed");
        assert_eq!(job.safe_error_code.as_deref(), Some("auth_required"));
    }

    #[test]
    fn a_transient_timeout_does_not_reenter_the_live_worker() {
        let calls = std::rc::Rc::new(Cell::new(0u32));
        let calls_in = std::rc::Rc::clone(&calls);
        let mut worker = FakeWorker::ok();
        worker.portfolio = Box::new(move || {
            calls_in.set(calls_in.get() + 1);
            Err(SafeError::fineco_timeout())
        });
        let ctrl = controller(worker, live_policy());
        let err = ctrl
            .handle(RefreshRequest::PortfolioRefreshLive, NOW)
            .expect_err("timeout propagates without a controller-level retry");
        assert_eq!(err.code(), "fineco_timeout");
        // Retrying here would re-enter LiveClient and make another fresh Fineco
        // login inside one admitted controller operation.
        assert_eq!(calls.get(), 1);
        let store = ctrl.store.lock().expect("lock");
        assert_eq!(
            store
                .count_jobs_on_utc_date("portfolio", "2026-06-05")
                .expect("q"),
            1
        );
        let job = store
            .latest_job_run("portfolio")
            .expect("q")
            .expect("a job");
        assert_eq!(job.status, "failed");
        assert_eq!(job.safe_error_code.as_deref(), Some("fineco_timeout"));
    }

    #[test]
    fn the_daily_budget_is_enforced_by_the_controller() {
        let ctrl = controller(FakeWorker::ok(), live_policy());
        // Portfolio budget default is 4/day; run it to exhaustion at well-spaced
        // times (past the 30-min cooldown) on the same UTC day.
        let times = [
            "2026-06-05T00:00:00Z",
            "2026-06-05T01:00:00Z",
            "2026-06-05T02:00:00Z",
            "2026-06-05T03:00:00Z",
        ];
        for now in times {
            ctrl.handle(RefreshRequest::PortfolioRefreshLive, now)
                .expect("within budget");
        }
        // The 5th is over budget.
        let err = ctrl
            .handle(RefreshRequest::PortfolioRefreshLive, "2026-06-05T04:00:00Z")
            .expect_err("over budget");
        assert_eq!(err.code(), "refresh_budget_exhausted");
    }
}
