//! `fineco-refresh` — local refresh orchestration.
//!
//! Ties the lock (`already_refreshing`), `job_runs` recording, and snapshot
//! capture together. It holds **no Fineco credentials**: the data source is an
//! injected [`PortfolioFetcher`] trait, so the real Fineco fetch can live in the
//! M3 private worker while this crate stays credential-free and testable.

use fineco_core::{
    SafeError, parse_iso8601_utc, validate_movements_request, validate_order_request,
    validate_tax_range,
};
use fineco_store::{
    JobOutcome, MovementsSummary, NewMovement, NewOrder, NewPortfolioSnapshot, NewTaxCarryForward,
    NewTaxMinusByYear, RawMovement, RawOrder, Store,
};

/// A running refresh older than this is presumed dead (e.g. its finish write
/// failed) and is reclaimed when the next refresh acquires the lock, so a stuck
/// job cannot block refreshes forever.
const STALE_REFRESH_SECS: i64 = 15 * 60;

/// Source of a fresh portfolio snapshot. Implementations may hit Fineco (M3) or
/// be fakes (tests). Errors are already safe envelopes.
pub trait PortfolioFetcher {
    /// Fetch a fresh portfolio snapshot, stamping it with `now_iso` as its
    /// `captured_at`. The clock is the orchestrator's (the fetcher itself holds
    /// no wall clock), so the snapshot's timestamp matches the job's.
    ///
    /// # Errors
    /// Returns a [`SafeError`] if the fetch fails (e.g. auth/timeout).
    fn fetch_portfolio(&self, now_iso: &str) -> Result<NewPortfolioSnapshot, SafeError>;
}

/// Run a local portfolio refresh: acquire the per-area lock, record a job, fetch,
/// capture the snapshot, and record the outcome. Returns the new snapshot id.
///
/// # Errors
/// - [`SafeError::already_refreshing`] if a portfolio refresh is already running.
/// - The fetcher's [`SafeError`] (recorded as the job's `safe_error_code`) on
///   fetch failure.
/// - [`SafeError::internal`] on a storage failure.
pub fn refresh_portfolio(
    store: &mut Store,
    fetcher: &dyn PortfolioFetcher,
    auth_id: &str,
    now_iso: &str,
) -> Result<i64, SafeError> {
    // Atomically acquire the per-area lock: the INSERT is the lock. `None` means
    // a refresh is already running for this data area (no check-then-insert race).
    let job_id = match store
        .try_begin_job(auth_id, "portfolio", now_iso, STALE_REFRESH_SECS)
        .map_err(|_| SafeError::internal())?
    {
        Some(id) => id,
        None => return Err(SafeError::already_refreshing()),
    };

    match fetcher.fetch_portfolio(now_iso) {
        Ok(snapshot) => match store.capture_portfolio_snapshot(&snapshot) {
            Ok(snapshot_id) => {
                // Snapshot captured. Mark the job completed. `record_job_finish`
                // reporting `false` means the job was reclaimed/superseded
                // mid-flight — only possible with concurrent writers, which the
                // single-writer minimum topology precludes — and the captured
                // snapshot is still valid, so we return it either way.
                store
                    .record_job_finish(job_id, now_iso, JobOutcome::Completed, None)
                    .map_err(|_| SafeError::internal())?;
                Ok(snapshot_id)
            }
            Err(_) => {
                let _ =
                    store.record_job_finish(job_id, now_iso, JobOutcome::Failed, Some("internal"));
                Err(SafeError::internal())
            }
        },
        Err(fetch_err) => {
            let _ = store.record_job_finish(
                job_id,
                now_iso,
                JobOutcome::Failed,
                Some(fetch_err.code()),
            );
            Err(fetch_err)
        }
    }
}

/// Source of fresh order-monitor data, **controller-side**: it yields store-ready
/// [`NewOrder`]s, so it takes `store` because order-id hashing is keyed by the
/// store's HMAC. The fineco-live `LiveClient` implements this (it fetches raw
/// orders from the no-DB worker over the socket, then hashes them with the
/// passed store); fakes implement it directly in tests.
pub trait OrdersFetcher {
    /// Fetch order-monitor transactions for `instrument_kind` over the last
    /// `days` days, mapped to store-ready [`NewOrder`]s.
    ///
    /// # Errors
    /// Returns a [`SafeError`] if validation or the fetch fails (e.g. auth/timeout).
    fn fetch_orders(
        &self,
        store: &Store,
        instrument_kind: &str,
        days: u32,
    ) -> Result<Vec<NewOrder>, SafeError>;
}

/// Source of fresh order-monitor data, **worker-side**: it yields un-hashed
/// [`RawOrder`]s and takes **no** `store`, because the credential-holding worker
/// holds no DB key. The controller turns the `RawOrder`s into [`NewOrder`]s via
/// [`Store::hash_raw_order`]. The private worker implements this; the fineco-live
/// server dispatches an orders request to it.
pub trait RawOrdersFetcher {
    /// Fetch order-monitor transactions for `instrument_kind` over the last
    /// `days` days, parsed to [`RawOrder`]s (raw broker `trans_id`, never hashed).
    ///
    /// # Errors
    /// Returns a [`SafeError`] if validation or the fetch fails (e.g. auth/timeout).
    fn fetch_raw_orders(
        &self,
        instrument_kind: &str,
        days: u32,
    ) -> Result<Vec<RawOrder>, SafeError>;
}

/// Run a local orders refresh: acquire the per-area lock, record a job, fetch,
/// capture the orders, and record the outcome. Returns the number of orders
/// captured (a count, never the order values).
///
/// # Errors
/// - [`SafeError::already_refreshing`] if an orders refresh is already running.
/// - The fetcher's [`SafeError`] (recorded as the job's `safe_error_code`) on
///   fetch failure.
/// - [`SafeError::internal`] on a storage failure.
pub fn refresh_orders(
    store: &mut Store,
    fetcher: &dyn OrdersFetcher,
    auth_id: &str,
    instrument_kind: &str,
    days: u32,
    now_iso: &str,
) -> Result<usize, SafeError> {
    // Validate the request BEFORE taking the lock: an invalid request must not
    // create a job_runs row (which would burn budget/cooldown without ever
    // reaching Fineco). The worker re-validates as defense in depth.
    validate_order_request(instrument_kind, days)?;

    // The INSERT is the lock; `None` means a refresh is already running for this
    // data area. A job_runs row therefore exists only for an attempt that took
    // the lock and will reach Fineco — the eligibility boundary the budget,
    // cooldown, and circuit-breaker derivations rely on.
    let job_id = match store
        .try_begin_job(auth_id, "orders", now_iso, STALE_REFRESH_SECS)
        .map_err(|_| SafeError::internal())?
    {
        Some(id) => id,
        None => return Err(SafeError::already_refreshing()),
    };

    match fetcher.fetch_orders(store, instrument_kind, days) {
        Ok(orders) => match store.capture_orders(now_iso, &orders) {
            Ok(()) => {
                store
                    .record_job_finish(job_id, now_iso, JobOutcome::Completed, None)
                    .map_err(|_| SafeError::internal())?;
                Ok(orders.len())
            }
            Err(_) => {
                let _ =
                    store.record_job_finish(job_id, now_iso, JobOutcome::Failed, Some("internal"));
                Err(SafeError::internal())
            }
        },
        Err(fetch_err) => {
            let _ = store.record_job_finish(
                job_id,
                now_iso,
                JobOutcome::Failed,
                Some(fetch_err.code()),
            );
            Err(fetch_err)
        }
    }
}

/// Source of fresh tax data (carry-forward + minus-by-year). Both are part of the
/// single `tax` data area, captured together.
pub trait TaxFetcher {
    /// Fetch the tax carry-forward total for an explicit `YYYY-MM-DD` range.
    ///
    /// # Errors
    /// Returns a [`SafeError`] if validation or the fetch fails.
    fn fetch_tax_carry_forward(
        &self,
        date_from: &str,
        date_to: &str,
    ) -> Result<NewTaxCarryForward, SafeError>;

    /// Fetch the tax minus-by-year residues.
    ///
    /// # Errors
    /// Returns a [`SafeError`] if the fetch fails.
    fn fetch_tax_minus_by_year(&self) -> Result<Vec<NewTaxMinusByYear>, SafeError>;
}

/// Run a local tax refresh: acquire the per-area lock, record a job, fetch BOTH
/// the carry-forward (for the given range) and the minus-by-year residues,
/// capture them together, and record the outcome. Returns the number of tax rows
/// captured (a count, never the tax values). If either fetch fails, nothing is
/// captured and the job records the safe code.
///
/// # Errors
/// - [`SafeError::already_refreshing`] if a tax refresh is already running.
/// - The fetcher's [`SafeError`] (recorded as the job's `safe_error_code`).
/// - [`SafeError::internal`] on a storage failure.
pub fn refresh_tax(
    store: &mut Store,
    fetcher: &dyn TaxFetcher,
    auth_id: &str,
    date_from: &str,
    date_to: &str,
    now_iso: &str,
) -> Result<usize, SafeError> {
    // Validate before the lock (see `refresh_orders`): an invalid date range must
    // not create a job_runs row. The worker re-validates as defense in depth.
    validate_tax_range(date_from, date_to)?;

    let job_id = match store
        .try_begin_job(auth_id, "tax", now_iso, STALE_REFRESH_SECS)
        .map_err(|_| SafeError::internal())?
    {
        Some(id) => id,
        None => return Err(SafeError::already_refreshing()),
    };

    // Fetch both halves before capturing anything: a partial tax snapshot would
    // be misleading, so either both succeed or the job fails with no capture.
    let fetched = fetcher
        .fetch_tax_carry_forward(date_from, date_to)
        .and_then(|carry_forward| {
            fetcher
                .fetch_tax_minus_by_year()
                .map(|minus_by_year| (carry_forward, minus_by_year))
        });

    match fetched {
        Ok((carry_forward, minus_by_year)) => {
            match store.capture_tax(now_iso, &[carry_forward], &minus_by_year) {
                Ok(()) => {
                    store
                        .record_job_finish(job_id, now_iso, JobOutcome::Completed, None)
                        .map_err(|_| SafeError::internal())?;
                    Ok(1 + minus_by_year.len())
                }
                Err(_) => {
                    let _ = store.record_job_finish(
                        job_id,
                        now_iso,
                        JobOutcome::Failed,
                        Some("internal"),
                    );
                    Err(SafeError::internal())
                }
            }
        }
        Err(fetch_err) => {
            let _ = store.record_job_finish(
                job_id,
                now_iso,
                JobOutcome::Failed,
                Some(fetch_err.code()),
            );
            Err(fetch_err)
        }
    }
}

/// Source of fresh movements data, **controller-side**: yields store-ready
/// [`NewMovement`]s, takes `store` for HMAC-hashing the raw movement ids.
/// The fineco-live `LiveClient` implements this; fakes implement it in tests.
pub trait MovementsFetcher {
    /// Fetch bank account movements for the last `days` days (`date_from` to
    /// `date_to`, YYYY-MM-DD), mapped to store-ready [`NewMovement`]s plus the
    /// per-capture account [`MovementsSummary`] read from the response envelope.
    ///
    /// # Errors
    /// Returns a [`SafeError`] if the fetch fails (e.g. auth/timeout).
    fn fetch_movements(
        &self,
        store: &Store,
        date_from: &str,
        date_to: &str,
    ) -> Result<(Vec<NewMovement>, MovementsSummary), SafeError>;
}

/// Source of fresh movements data, **worker-side**: yields un-hashed
/// [`RawMovement`]s with no DB key. The controller hashes them via
/// [`fineco_store::Store::hash_raw_movement`].
pub trait RawMovementsFetcher {
    /// Fetch bank account movements for the `date_from`..`date_to` date range
    /// (`YYYY-MM-DD`), parsed to [`RawMovement`]s (raw ids, never hashed) plus the
    /// per-capture account [`MovementsSummary`] from the response envelope (read from
    /// the first page).
    ///
    /// # Errors
    /// Returns a [`SafeError`] if the fetch fails.
    fn fetch_raw_movements(
        &self,
        date_from: &str,
        date_to: &str,
    ) -> Result<(Vec<RawMovement>, MovementsSummary), SafeError>;
}

/// Run a local movements refresh: acquire the per-area lock, record a job, fetch,
/// capture the movements, and record the outcome. Returns the number of movements
/// captured (a count, never the values). `date_from`/`date_to` are YYYY-MM-DD
/// strings already derived from the validated `days` param by the controller.
///
/// # Errors
/// - [`SafeError::already_refreshing`] if a movements refresh is already running.
/// - The fetcher's [`SafeError`] on fetch failure.
/// - [`SafeError::internal`] on a storage failure.
pub fn refresh_movements(
    store: &mut Store,
    fetcher: &dyn MovementsFetcher,
    auth_id: &str,
    days: u32,
    date_from: &str,
    date_to: &str,
    now_iso: &str,
) -> Result<usize, SafeError> {
    validate_movements_request(days)?;

    let job_id = match store
        .try_begin_job(auth_id, "movements", now_iso, STALE_REFRESH_SECS)
        .map_err(|_| SafeError::internal())?
    {
        Some(id) => id,
        None => return Err(SafeError::already_refreshing()),
    };

    match fetcher.fetch_movements(store, date_from, date_to) {
        Ok((movements, summary)) => {
            // An all-None summary means the fetch carried no account-level fields;
            // don't persist a row for it, so `movements_get_latest` omits
            // `account_summary` rather than emitting an empty object.
            let summary_ref = (!summary.is_empty()).then_some(&summary);
            match store.capture_movements(now_iso, &movements, summary_ref) {
                Ok(()) => {
                    store
                        .record_job_finish(job_id, now_iso, JobOutcome::Completed, None)
                        .map_err(|_| SafeError::internal())?;
                    Ok(movements.len())
                }
                Err(_) => {
                    let _ = store.record_job_finish(
                        job_id,
                        now_iso,
                        JobOutcome::Failed,
                        Some("internal"),
                    );
                    Err(SafeError::internal())
                }
            }
        }
        Err(fetch_err) => {
            let _ = store.record_job_finish(
                job_id,
                now_iso,
                JobOutcome::Failed,
                Some(fetch_err.code()),
            );
            Err(fetch_err)
        }
    }
}

/// Per-area live-refresh limits, enforced as a pre-flight gate *before* the lock
/// is acquired — so a denial never creates a `job_runs` row and never counts
/// against the budget.
#[derive(Debug, Clone, Copy)]
pub struct RefreshLimits {
    /// Minimum seconds between refresh attempts for a data area (`0` disables).
    pub cooldown_secs: i64,
    /// Maximum lock-acquired refresh attempts per UTC day for a data area.
    pub daily_budget: u32,
    /// Open the circuit (block refreshes) when the most recent this-many terminal
    /// attempts for the area are ALL upstream/timeout failures (`0` disables).
    pub circuit_consecutive_failures: u32,
    /// How long the circuit stays open after the most recent failure before it
    /// half-opens (allows one probe attempt through). A successful probe closes
    /// it; another failure re-opens it for this window. Prevents a permanently
    /// stuck breaker.
    pub circuit_cooldown_secs: i64,
}

/// Pre-flight gate for a live refresh of `data_area`. Returns the first denial it
/// finds — cooldown, budget exhausted, or circuit open — *without* creating a
/// `job_runs` row, so denials don't consume budget. `Ok(())` means the refresh
/// may proceed to acquire the lock. The controller calls this before
/// [`refresh_portfolio`]/[`refresh_orders`]/[`refresh_tax`].
///
/// # Errors
/// - [`SafeError::refresh_cooldown`] if within the cooldown window.
/// - [`SafeError::refresh_budget_exhausted`] if at/over the daily budget.
/// - [`SafeError::refresh_circuit_open`] if the breaker is open.
/// - [`SafeError::internal`] on a storage or clock-parse failure.
pub fn refresh_preflight(
    store: &Store,
    data_area: &str,
    limits: &RefreshLimits,
    now_iso: &str,
) -> Result<(), SafeError> {
    let now_epoch = parse_iso8601_utc(now_iso).ok_or_else(SafeError::internal)?;

    // The latest attempt drives both the in-flight lock check and the cooldown.
    // (With the per-area running lock, a running row is always the latest row —
    // no newer attempt can start while one runs.)
    if let Some(latest) = store
        .latest_job_run(data_area)
        .map_err(|_| SafeError::internal())?
    {
        // Fail CLOSED on an unparseable stored timestamp: a clock-parse failure is
        // `internal`, never a silent skip (which would disable the cooldown).
        let started = parse_iso8601_utc(&latest.started_at).ok_or_else(SafeError::internal)?;
        let age = now_epoch.saturating_sub(started);

        // A STALE running job is presumed dead (a crashed/killed refresh): a dead
        // lock that produced no data. It must fall through past BOTH the
        // `already_refreshing` check AND the cooldown below to reach `try_begin_job`
        // — the only code that reclaims the stale row.
        let stale_running = latest.status == "running" && age > STALE_REFRESH_SECS;

        // A refresh genuinely in flight (a NON-stale running job) is
        // `already_refreshing`, not cooldown/budget.
        if latest.status == "running" && !stale_running {
            return Err(SafeError::already_refreshing());
        }

        // Cooldown: too soon since the latest attempt (any outcome) — EXCEPT a
        // stale running job, which is exempt so it can reach reclamation. (Without
        // this, a stale row was re-blocked for the STALE_REFRESH_SECS..cooldown
        // window and never reclaimed until the cooldown expired — the cooldown,
        // 30 min, outlasts the 15 min stale threshold. The daily budget + circuit
        // breaker still bound retries, so a crash-loop cannot hammer Fineco.)
        if !stale_running && limits.cooldown_secs > 0 && age < limits.cooldown_secs {
            return Err(SafeError::refresh_cooldown());
        }
    }

    // Budget: at or over the daily cap for the current UTC day? `started_at` is
    // UTC ISO-8601, so its first 10 chars are the UTC calendar date.
    let utc_date = now_iso.get(..10).unwrap_or(now_iso);
    let today = store
        .count_jobs_on_utc_date(data_area, utc_date)
        .map_err(|_| SafeError::internal())?;
    if today >= i64::from(limits.daily_budget) {
        return Err(SafeError::refresh_budget_exhausted());
    }

    // Circuit: open after N consecutive recent upstream/timeout failures?
    if circuit_is_open(store, data_area, limits, now_epoch)? {
        return Err(SafeError::refresh_circuit_open());
    }

    Ok(())
}

/// True when the breaker is open: the most recent `circuit_consecutive_failures`
/// *terminal* attempts for the area are ALL upstream/timeout failures AND the
/// newest of them is still within `circuit_cooldown_secs`. Once that window
/// elapses the breaker **half-opens** (returns `false`) to let exactly one probe
/// through — a completed probe closes it; another failure re-opens the window.
/// A completed attempt or a non-upstream failure also keeps it closed, as does
/// having fewer than `n` terminal attempts.
fn circuit_is_open(
    store: &Store,
    data_area: &str,
    limits: &RefreshLimits,
    now_epoch: i64,
) -> Result<bool, SafeError> {
    let n = limits.circuit_consecutive_failures;
    if n == 0 {
        return Ok(false);
    }
    let recent = store
        .recent_job_outcomes(data_area, n)
        .map_err(|_| SafeError::internal())?;
    if recent.len() < n as usize {
        return Ok(false);
    }
    let all_upstream_failures = recent
        .iter()
        .all(|(_, status, code)| status == "failed" && is_upstream_failure(code.as_deref()));
    if !all_upstream_failures {
        return Ok(false);
    }
    // Half-open after the cooldown: let one probe through so a recovered upstream
    // can close the breaker. `recent` is newest-first, so element 0 is the most
    // recent failure; if its timestamp is unparseable, stay open (fail safe).
    match parse_iso8601_utc(&recent[0].0) {
        Some(newest_failed) => {
            Ok(now_epoch.saturating_sub(newest_failed) < limits.circuit_cooldown_secs)
        }
        None => Ok(true),
    }
}

/// Whether a job's `safe_error_code` is a transient upstream/timeout failure (the
/// kind that trips the live-refresh circuit breaker) rather than an
/// auth/validation/internal one (which must not).
fn is_upstream_failure(code: Option<&str>) -> bool {
    matches!(code, Some("fineco_timeout" | "fineco_upstream_error"))
}

/// Retry policy for a single Fineco fetch within one refresh attempt. The retry
/// happens INSIDE the one fetch call, so a refresh remains exactly one `job_runs`
/// row no matter how many transient tries it took.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Total attempts including the first (`1` = no retry).
    pub max_attempts: u32,
    /// Base backoff; before retry `n` the call sleeps `base * 2^(n-1)`.
    pub backoff_base: std::time::Duration,
}

impl RetryPolicy {
    /// `attempts` total tries with NO backoff (immediate) — for tests and callers
    /// that must not sleep.
    #[must_use]
    pub const fn immediate(attempts: u32) -> Self {
        Self {
            max_attempts: attempts,
            backoff_base: std::time::Duration::ZERO,
        }
    }
}

/// Run `op`, retrying ONLY on transient upstream/timeout failures (the same
/// `fineco_timeout`/`fineco_upstream_error` codes that trip the circuit breaker —
/// see [`is_upstream_failure`]) up to `policy.max_attempts`, sleeping
/// `base * 2^(n-1)` before retry `n`. Everything else returns immediately —
/// crucially a 429 (`rate_limited`): although it is `retryable` in the
/// client-facing sense (try LATER), re-driving the fetch in-job re-runs the login
/// POST and hammers a bank that just rate-limited us. Auth/validation/not-found
/// failures are likewise not hammered.
///
/// # Errors
/// The last error from `op` once attempts are exhausted, or the first
/// non-retried error.
pub fn with_retry<T>(
    policy: &RetryPolicy,
    mut op: impl FnMut() -> Result<T, SafeError>,
) -> Result<T, SafeError> {
    // A misconfigured `max_attempts: 0` still means at least one try (a refresh
    // must attempt the fetch); normalize it so the bound is unambiguous.
    let max_attempts = policy.max_attempts.max(1);
    let mut attempt: u32 = 1;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(err)
                if err.retryable()
                    && is_upstream_failure(Some(err.code()))
                    && attempt < max_attempts =>
            {
                let backoff = policy
                    .backoff_base
                    .saturating_mul(2u32.saturating_pow(attempt - 1));
                if !backoff.is_zero() {
                    std::thread::sleep(backoff);
                }
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

/// A fetcher decorator that retries the inner fetch on retryable (5xx/timeout)
/// errors per [`RetryPolicy`]. This is safe only for fetchers where retrying the
/// call does not create an unaccounted fresh Fineco login. Do not wrap
/// `fineco_live::LiveClient` in the controller unless each worker login attempt
/// is separately debited/reported, or the retry happens worker-side under one
/// authenticated session.
pub struct Retrying<'a, F: ?Sized> {
    inner: &'a F,
    policy: RetryPolicy,
}

impl<'a, F: ?Sized> Retrying<'a, F> {
    /// Wrap `inner`, retrying its fetches per `policy`.
    #[must_use]
    pub fn new(inner: &'a F, policy: RetryPolicy) -> Self {
        Self { inner, policy }
    }
}

impl<F: PortfolioFetcher + ?Sized> PortfolioFetcher for Retrying<'_, F> {
    fn fetch_portfolio(&self, now_iso: &str) -> Result<NewPortfolioSnapshot, SafeError> {
        with_retry(&self.policy, || self.inner.fetch_portfolio(now_iso))
    }
}

impl<F: OrdersFetcher + ?Sized> OrdersFetcher for Retrying<'_, F> {
    fn fetch_orders(
        &self,
        store: &Store,
        instrument_kind: &str,
        days: u32,
    ) -> Result<Vec<NewOrder>, SafeError> {
        with_retry(&self.policy, || {
            self.inner.fetch_orders(store, instrument_kind, days)
        })
    }
}

impl<F: TaxFetcher + ?Sized> TaxFetcher for Retrying<'_, F> {
    fn fetch_tax_carry_forward(
        &self,
        date_from: &str,
        date_to: &str,
    ) -> Result<NewTaxCarryForward, SafeError> {
        with_retry(&self.policy, || {
            self.inner.fetch_tax_carry_forward(date_from, date_to)
        })
    }

    fn fetch_tax_minus_by_year(&self) -> Result<Vec<NewTaxMinusByYear>, SafeError> {
        with_retry(&self.policy, || self.inner.fetch_tax_minus_by_year())
    }
}

impl<F: MovementsFetcher + ?Sized> MovementsFetcher for Retrying<'_, F> {
    fn fetch_movements(
        &self,
        store: &Store,
        date_from: &str,
        date_to: &str,
    ) -> Result<(Vec<NewMovement>, MovementsSummary), SafeError> {
        with_retry(&self.policy, || {
            self.inner.fetch_movements(store, date_from, date_to)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MovementsFetcher, OrdersFetcher, PortfolioFetcher, RefreshLimits, RetryPolicy, Retrying,
        TaxFetcher, refresh_movements, refresh_orders, refresh_portfolio, refresh_preflight,
        refresh_tax, with_retry,
    };
    use fineco_core::SafeError;
    use fineco_store::{
        JobOutcome, MovementsSummary, NewMovement, NewOrder, NewPortfolioSnapshot,
        NewTaxCarryForward, NewTaxMinusByYear, Store,
    };
    use std::cell::Cell;

    /// Record a terminal job_runs row for an area at `at` with the given outcome.
    fn finish_job(
        store: &mut Store,
        area: &str,
        at: &str,
        outcome: JobOutcome,
        code: Option<&str>,
    ) {
        let id = store.record_job_start("owner", area, at).expect("start");
        store
            .record_job_finish(id, at, outcome, code)
            .expect("finish");
    }

    fn limits(cooldown_secs: i64, daily_budget: u32, circuit: u32) -> RefreshLimits {
        // A long circuit window so circuit tests stay "open" at their probe time
        // unless they opt into a short one via `limits_cc`.
        limits_cc(cooldown_secs, daily_budget, circuit, 86_400)
    }

    fn limits_cc(
        cooldown_secs: i64,
        daily_budget: u32,
        circuit: u32,
        circuit_cooldown_secs: i64,
    ) -> RefreshLimits {
        RefreshLimits {
            cooldown_secs,
            daily_budget,
            circuit_consecutive_failures: circuit,
            circuit_cooldown_secs,
        }
    }

    #[test]
    fn preflight_allows_when_clean() {
        let store = Store::open_in_memory().expect("open");
        refresh_preflight(
            &store,
            "portfolio",
            &limits(600, 3, 2),
            "2026-01-01T00:00:00Z",
        )
        .expect("a clean area is allowed");
    }

    #[test]
    fn preflight_rejects_within_cooldown() {
        let mut store = Store::open_in_memory().expect("open");
        finish_job(
            &mut store,
            "portfolio",
            "2026-01-01T00:00:00Z",
            JobOutcome::Completed,
            None,
        );
        // 5 min later, cooldown is 10 min.
        let err = refresh_preflight(
            &store,
            "portfolio",
            &limits(600, 99, 0),
            "2026-01-01T00:05:00Z",
        )
        .expect_err("within cooldown");
        assert_eq!(err.code(), "refresh_cooldown");
    }

    #[test]
    fn preflight_allows_after_cooldown() {
        let mut store = Store::open_in_memory().expect("open");
        finish_job(
            &mut store,
            "portfolio",
            "2026-01-01T00:00:00Z",
            JobOutcome::Completed,
            None,
        );
        refresh_preflight(
            &store,
            "portfolio",
            &limits(600, 99, 0),
            "2026-01-01T00:11:00Z",
        )
        .expect("past the cooldown");
    }

    #[test]
    fn preflight_rejects_over_daily_budget() {
        let mut store = Store::open_in_memory().expect("open");
        // Two attempts today, spaced past the cooldown; budget is 2.
        finish_job(
            &mut store,
            "orders",
            "2026-01-01T00:00:00Z",
            JobOutcome::Completed,
            None,
        );
        finish_job(
            &mut store,
            "orders",
            "2026-01-01T00:11:00Z",
            JobOutcome::Completed,
            None,
        );
        let err = refresh_preflight(&store, "orders", &limits(600, 2, 0), "2026-01-01T00:22:00Z")
            .expect_err("over budget");
        assert_eq!(err.code(), "refresh_budget_exhausted");
    }

    #[test]
    fn preflight_budget_resets_next_utc_day() {
        let mut store = Store::open_in_memory().expect("open");
        finish_job(
            &mut store,
            "orders",
            "2026-01-01T00:00:00Z",
            JobOutcome::Completed,
            None,
        );
        finish_job(
            &mut store,
            "orders",
            "2026-01-01T12:00:00Z",
            JobOutcome::Completed,
            None,
        );
        // The next UTC day: yesterday's count does not apply.
        refresh_preflight(&store, "orders", &limits(0, 2, 0), "2026-01-02T00:00:00Z")
            .expect("budget resets on the new UTC day");
    }

    #[test]
    fn preflight_opens_circuit_after_consecutive_upstream_failures() {
        let mut store = Store::open_in_memory().expect("open");
        finish_job(
            &mut store,
            "tax",
            "2026-01-01T00:00:00Z",
            JobOutcome::Failed,
            Some("fineco_upstream_error"),
        );
        finish_job(
            &mut store,
            "tax",
            "2026-01-01T01:00:00Z",
            JobOutcome::Failed,
            Some("fineco_timeout"),
        );
        let err = refresh_preflight(&store, "tax", &limits(0, 99, 2), "2026-01-01T02:00:00Z")
            .expect_err("circuit open");
        assert_eq!(err.code(), "refresh_circuit_open");
    }

    #[test]
    fn preflight_circuit_resets_on_a_completed_attempt() {
        let mut store = Store::open_in_memory().expect("open");
        finish_job(
            &mut store,
            "tax",
            "2026-01-01T00:00:00Z",
            JobOutcome::Failed,
            Some("fineco_timeout"),
        );
        // The most recent attempt completed: the breaker stays closed.
        finish_job(
            &mut store,
            "tax",
            "2026-01-01T01:00:00Z",
            JobOutcome::Completed,
            None,
        );
        refresh_preflight(&store, "tax", &limits(0, 99, 2), "2026-01-01T02:00:00Z")
            .expect("a completed attempt closes the breaker");
    }

    #[test]
    fn preflight_circuit_ignores_non_upstream_failures() {
        let mut store = Store::open_in_memory().expect("open");
        // Auth failures are a credential problem, not a transient upstream one:
        // they must not trip the breaker.
        finish_job(
            &mut store,
            "tax",
            "2026-01-01T00:00:00Z",
            JobOutcome::Failed,
            Some("auth_required"),
        );
        finish_job(
            &mut store,
            "tax",
            "2026-01-01T01:00:00Z",
            JobOutcome::Failed,
            Some("auth_required"),
        );
        refresh_preflight(&store, "tax", &limits(0, 99, 2), "2026-01-01T02:00:00Z")
            .expect("auth failures do not open the breaker");
    }

    #[test]
    fn preflight_circuit_half_opens_after_the_cooldown() {
        let mut store = Store::open_in_memory().expect("open");
        finish_job(
            &mut store,
            "tax",
            "2026-01-01T00:00:00Z",
            JobOutcome::Failed,
            Some("fineco_timeout"),
        );
        finish_job(
            &mut store,
            "tax",
            "2026-01-01T01:00:00Z",
            JobOutcome::Failed,
            Some("fineco_timeout"),
        );
        // Circuit cooldown is 30 min; 1h after the newest failure it half-opens so
        // a probe can run (otherwise the breaker could never close).
        refresh_preflight(
            &store,
            "tax",
            &limits_cc(0, 99, 2, 1800),
            "2026-01-01T02:00:00Z",
        )
        .expect("the breaker half-opens after its cooldown");
    }

    #[test]
    fn preflight_reports_already_refreshing_over_cooldown_when_a_job_is_running() {
        let mut store = Store::open_in_memory().expect("open");
        // A running (un-finished) job — and cooldown enabled. The running lock
        // must win: the contract's code is `already_refreshing`, not cooldown.
        store
            .record_job_start("owner", "portfolio", "2026-01-01T00:00:00Z")
            .expect("start");
        let err = refresh_preflight(
            &store,
            "portfolio",
            &limits(600, 99, 0),
            "2026-01-01T00:01:00Z",
        )
        .expect_err("a running job is reported");
        assert_eq!(err.code(), "already_refreshing");
    }

    #[test]
    fn preflight_does_not_block_on_a_stale_running_job() {
        // A running row older than the stale threshold (STALE_REFRESH_SECS = 15
        // min) is presumed dead (a crashed/killed refresh). The preflight must NOT
        // report `already_refreshing` — it must fall through so the refresh reaches
        // `try_begin_job`, which reclaims the stale row. Regression: the preflight
        // used to reject on ANY running row, permanently locking the area.
        let mut store = Store::open_in_memory().expect("open");
        store
            .record_job_start("owner", "portfolio", "2026-01-01T00:00:00Z")
            .expect("start");
        // 20 min later (> 15-min stale threshold), cooldown disabled.
        refresh_preflight(
            &store,
            "portfolio",
            &limits(0, 99, 0),
            "2026-01-01T00:20:00Z",
        )
        .expect("a stale running job must not permanently block the refresh");
    }

    #[test]
    fn preflight_exempts_a_stale_running_job_from_cooldown() {
        // The cooldown (here 30 min) outlasts the 15-min stale threshold, so a
        // stale running job must ALSO be exempt from cooldown — otherwise it is
        // re-blocked for the 15..30-min window and never reaches `try_begin_job`
        // (the reclaimer). Regression for the Codex follow-up on the stale-job fix.
        let mut store = Store::open_in_memory().expect("open");
        store
            .record_job_start("owner", "portfolio", "2026-01-01T00:00:00Z")
            .expect("start");
        // 20 min later: stale (> 15 min) but within the 30-min cooldown window.
        refresh_preflight(
            &store,
            "portfolio",
            &limits(1800, 99, 0),
            "2026-01-01T00:20:00Z",
        )
        .expect("a stale running job is exempt from cooldown so it can be reclaimed");
    }

    #[test]
    fn preflight_fails_closed_on_an_unparseable_stored_timestamp() {
        // A corrupt `started_at` must surface as `internal` (fail closed), never
        // silently skip the cooldown.
        let mut store = Store::open_in_memory().expect("open");
        store
            .record_job_start("owner", "portfolio", "not-a-timestamp")
            .expect("start");
        let err = refresh_preflight(
            &store,
            "portfolio",
            &limits(600, 99, 0),
            "2026-01-01T00:05:00Z",
        )
        .expect_err("an unparseable stored timestamp must fail closed");
        assert_eq!(err.code(), "internal");
    }

    #[test]
    fn refresh_orders_rejects_invalid_params_without_creating_a_job_row() {
        let mut store = Store::open_in_memory().expect("open");
        let fetcher = FakeOrdersFetcher(Ok(vec![]));
        // days over the cap: must fail BEFORE the lock, leaving no job_runs row
        // (so it can't burn budget/cooldown without reaching Fineco).
        let err = refresh_orders(
            &mut store,
            &fetcher,
            "owner",
            "shares",
            999,
            "2026-01-01T00:00:00Z",
        )
        .expect_err("invalid days rejected");
        assert_eq!(err.code(), "invalid_request");
        assert_eq!(
            store
                .count_jobs_on_utc_date("orders", "2026-01-01")
                .expect("q"),
            0
        );
        assert!(store.latest_job_run("orders").expect("q").is_none());
    }

    #[test]
    fn refresh_tax_rejects_invalid_dates_without_creating_a_job_row() {
        let mut store = Store::open_in_memory().expect("open");
        let fetcher = FakeTaxFetcher {
            carry_forward: Ok(a_carry_forward()),
            minus_by_year: Ok(vec![]),
        };
        let err = refresh_tax(
            &mut store,
            &fetcher,
            "owner",
            "2026-13-01", // invalid month
            "2026-12-31",
            "2026-01-01T00:00:00Z",
        )
        .expect_err("invalid date rejected");
        assert_eq!(err.code(), "invalid_request");
        assert_eq!(
            store
                .count_jobs_on_utc_date("tax", "2026-01-01")
                .expect("q"),
            0
        );
    }

    #[test]
    fn with_retry_treats_zero_max_attempts_as_one() {
        let calls = Cell::new(0u32);
        let out: Result<u8, SafeError> = with_retry(&RetryPolicy::immediate(0), || {
            calls.set(calls.get() + 1);
            Err(SafeError::fineco_timeout())
        });
        assert_eq!(out.expect_err("fails").code(), "fineco_timeout");
        assert_eq!(calls.get(), 1, "zero max_attempts still runs exactly once");
    }

    #[test]
    fn with_retry_returns_first_success_without_retrying() {
        let calls = Cell::new(0u32);
        let out: Result<u8, SafeError> = with_retry(&RetryPolicy::immediate(3), || {
            calls.set(calls.get() + 1);
            Ok(7)
        });
        assert_eq!(out.expect("ok"), 7);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn with_retry_retries_a_retryable_error_then_succeeds() {
        let calls = Cell::new(0u32);
        let out: Result<u8, SafeError> = with_retry(&RetryPolicy::immediate(3), || {
            calls.set(calls.get() + 1);
            if calls.get() < 3 {
                Err(SafeError::fineco_timeout())
            } else {
                Ok(9)
            }
        });
        assert_eq!(out.expect("eventually ok"), 9);
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn with_retry_does_not_retry_a_non_retryable_error() {
        let calls = Cell::new(0u32);
        let out: Result<u8, SafeError> = with_retry(&RetryPolicy::immediate(5), || {
            calls.set(calls.get() + 1);
            Err(SafeError::auth_required())
        });
        assert_eq!(out.expect_err("auth not retried").code(), "auth_required");
        assert_eq!(calls.get(), 1, "auth failures must not be retried");
    }

    #[test]
    fn with_retry_does_not_retry_a_rate_limit() {
        // A 429 from Fineco is `retryable` (a client may try LATER) but must NOT be
        // auto-retried in-job: re-driving the fetch immediately re-runs the login
        // POST and hammers a bank that just rate-limited us (risking lockout). Only
        // transient upstream/timeout failures are retried in-job.
        let calls = Cell::new(0u32);
        let out: Result<u8, SafeError> = with_retry(&RetryPolicy::immediate(5), || {
            calls.set(calls.get() + 1);
            Err(SafeError::rate_limited())
        });
        assert_eq!(
            out.expect_err("rate limit not retried").code(),
            "rate_limited"
        );
        assert_eq!(calls.get(), 1, "a 429 must not be auto-retried in-job");
    }

    #[test]
    fn with_retry_exhausts_attempts_and_returns_the_last_error() {
        let calls = Cell::new(0u32);
        let out: Result<u8, SafeError> = with_retry(&RetryPolicy::immediate(2), || {
            calls.set(calls.get() + 1);
            Err(SafeError::fineco_timeout())
        });
        assert_eq!(out.expect_err("exhausted").code(), "fineco_timeout");
        assert_eq!(calls.get(), 2, "exactly max_attempts tries");
    }

    /// A local fake fetcher that fails with a transient timeout `fails` times,
    /// then succeeds. It proves the decorator behavior for non-live fetchers; the
    /// live controller must not use this to hide extra worker logins.
    struct FlakyPortfolio {
        fails_remaining: Cell<u32>,
    }
    impl PortfolioFetcher for FlakyPortfolio {
        fn fetch_portfolio(&self, captured_at: &str) -> Result<NewPortfolioSnapshot, SafeError> {
            if self.fails_remaining.get() > 0 {
                self.fails_remaining.set(self.fails_remaining.get() - 1);
                return Err(SafeError::fineco_timeout());
            }
            Ok(empty_snapshot(captured_at))
        }
    }

    #[test]
    fn retrying_decorator_can_wrap_a_local_fetcher() {
        let mut store = Store::open_in_memory().expect("open");
        let flaky = FlakyPortfolio {
            fails_remaining: Cell::new(1),
        };
        let retrying = Retrying::new(&flaky, RetryPolicy::immediate(3));
        let id = refresh_portfolio(&mut store, &retrying, "owner", "2026-01-01T00:00:00Z")
            .expect("the local transient timeout is absorbed");
        assert!(id > 0);
        // Exactly one job_runs row, completed. This assertion is about the local
        // decorator contract, not the live-controller login budget.
        let job = store
            .latest_job_run("portfolio")
            .expect("q")
            .expect("a job");
        assert_eq!(job.status, "completed");
        assert_eq!(
            store
                .count_jobs_on_utc_date("portfolio", "2026-01-01")
                .expect("q"),
            1
        );
    }

    struct FakeFetcher(Result<NewPortfolioSnapshot, SafeError>);
    impl PortfolioFetcher for FakeFetcher {
        fn fetch_portfolio(&self, _now_iso: &str) -> Result<NewPortfolioSnapshot, SafeError> {
            self.0.clone()
        }
    }

    struct FakeOrdersFetcher(Result<Vec<NewOrder>, SafeError>);
    impl OrdersFetcher for FakeOrdersFetcher {
        fn fetch_orders(
            &self,
            _store: &Store,
            _instrument_kind: &str,
            _days: u32,
        ) -> Result<Vec<NewOrder>, SafeError> {
            self.0.clone()
        }
    }

    #[test]
    fn orders_refresh_captures_and_completes() {
        let mut store = Store::open_in_memory().expect("open");
        let fetcher = FakeOrdersFetcher(Ok(vec![]));
        let count = refresh_orders(
            &mut store,
            &fetcher,
            "owner",
            "shares",
            7,
            "2026-01-01T00:00:00Z",
        )
        .expect("refresh");
        assert_eq!(count, 0);
        let job = store.latest_job_run("orders").expect("q").expect("a job");
        assert_eq!(job.status, "completed");
        assert_eq!(job.safe_error_code, None);
        assert_eq!(store.running_job_for("orders").expect("q"), None);
    }

    #[test]
    fn orders_refresh_failure_records_safe_code_and_propagates() {
        let mut store = Store::open_in_memory().expect("open");
        let fetcher = FakeOrdersFetcher(Err(SafeError::auth_required()));
        let err = refresh_orders(
            &mut store,
            &fetcher,
            "owner",
            "shares",
            7,
            "2026-01-01T00:00:00Z",
        )
        .expect_err("should fail");
        assert_eq!(err.code(), "auth_required");
        let job = store.latest_job_run("orders").expect("q").expect("a job");
        assert_eq!(job.status, "failed");
        assert_eq!(job.safe_error_code.as_deref(), Some("auth_required"));
    }

    #[test]
    fn orders_refresh_rejects_when_already_running() {
        let mut store = Store::open_in_memory().expect("open");
        store
            .record_job_start("owner", "orders", "2026-01-01T00:00:00Z")
            .expect("start");
        let fetcher = FakeOrdersFetcher(Ok(vec![]));
        let err = refresh_orders(
            &mut store,
            &fetcher,
            "owner",
            "shares",
            7,
            "2026-01-01T00:01:00Z",
        )
        .expect_err("should be locked");
        assert_eq!(err.code(), "already_refreshing");
    }

    struct FakeTaxFetcher {
        carry_forward: Result<NewTaxCarryForward, SafeError>,
        minus_by_year: Result<Vec<NewTaxMinusByYear>, SafeError>,
    }
    impl TaxFetcher for FakeTaxFetcher {
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

    fn a_carry_forward() -> NewTaxCarryForward {
        NewTaxCarryForward {
            date_from: "2026-01-01".to_string(),
            date_to: "2026-12-31".to_string(),
            total: Some(0.0),
        }
    }

    #[test]
    fn tax_refresh_captures_both_and_completes() {
        let mut store = Store::open_in_memory().expect("open");
        let fetcher = FakeTaxFetcher {
            carry_forward: Ok(a_carry_forward()),
            minus_by_year: Ok(vec![NewTaxMinusByYear {
                year: 2025,
                minus_residue: Some(0.0),
                expiration_date: None,
            }]),
        };
        let count = refresh_tax(
            &mut store,
            &fetcher,
            "owner",
            "2026-01-01",
            "2026-12-31",
            "2026-01-01T00:00:00Z",
        )
        .expect("refresh");
        assert_eq!(count, 2); // 1 carry-forward + 1 minus-by-year row
        let job = store.latest_job_run("tax").expect("q").expect("a job");
        assert_eq!(job.status, "completed");
        assert_eq!(store.latest_tax_carry_forward().expect("q").len(), 1);
        assert_eq!(store.latest_tax_minus_by_year().expect("q").len(), 1);
    }

    #[test]
    fn tax_refresh_failure_records_safe_code_and_propagates() {
        let mut store = Store::open_in_memory().expect("open");
        // The minus-by-year fetch fails after carry-forward succeeds: nothing is
        // captured and the job records the safe code.
        let fetcher = FakeTaxFetcher {
            carry_forward: Ok(a_carry_forward()),
            minus_by_year: Err(SafeError::auth_required()),
        };
        let err = refresh_tax(
            &mut store,
            &fetcher,
            "owner",
            "2026-01-01",
            "2026-12-31",
            "2026-01-01T00:00:00Z",
        )
        .expect_err("should fail");
        assert_eq!(err.code(), "auth_required");
        let job = store.latest_job_run("tax").expect("q").expect("a job");
        assert_eq!(job.status, "failed");
        assert_eq!(job.safe_error_code.as_deref(), Some("auth_required"));
        assert!(store.latest_tax_carry_forward().expect("q").is_empty());
    }

    #[test]
    fn tax_refresh_rejects_when_already_running() {
        let mut store = Store::open_in_memory().expect("open");
        store
            .record_job_start("owner", "tax", "2026-01-01T00:00:00Z")
            .expect("start");
        let fetcher = FakeTaxFetcher {
            carry_forward: Ok(a_carry_forward()),
            minus_by_year: Ok(vec![]),
        };
        let err = refresh_tax(
            &mut store,
            &fetcher,
            "owner",
            "2026-01-01",
            "2026-12-31",
            "2026-01-01T00:01:00Z",
        )
        .expect_err("should be locked");
        assert_eq!(err.code(), "already_refreshing");
    }

    struct FakeMovementsFetcher(Result<(Vec<NewMovement>, MovementsSummary), SafeError>);
    impl MovementsFetcher for FakeMovementsFetcher {
        fn fetch_movements(
            &self,
            _store: &Store,
            _date_from: &str,
            _date_to: &str,
        ) -> Result<(Vec<NewMovement>, MovementsSummary), SafeError> {
            self.0.clone()
        }
    }

    fn a_summary() -> MovementsSummary {
        MovementsSummary {
            balance_at_movement: Some(1234.56),
            balance_at_search_date: Some(1200.0),
            current_month_credit_spending: Some(500.0),
            current_month_debit_spending: Some(-321.0),
        }
    }

    fn a_movement() -> NewMovement {
        NewMovement {
            movement_id_hash: "H1".to_string(),
            causale: Some("BONIFICO".to_string()),
            descrizione: Some("synthetic".to_string()),
            descrizione_breve: Some("synthetic".to_string()),
            importo: Some(-25.0),
            tipo_movimento: Some("MOVIMENTO_CONTO".to_string()),
            data_operazione: Some("2026-01-01".to_string()),
            data_registrazione: Some("2026-01-01".to_string()),
            data_valuta: Some("2026-01-02".to_string()),
            causale_movimento: Some("48".to_string()),
            categoria_id: Some("12".to_string()),
            sottocategoria_id: Some("34".to_string()),
        }
    }

    #[test]
    fn movements_refresh_captures_and_completes() {
        let mut store = Store::open_in_memory().expect("open");
        let fetcher = FakeMovementsFetcher(Ok((vec![a_movement()], a_summary())));
        let count = refresh_movements(
            &mut store,
            &fetcher,
            "owner",
            30,
            "2025-12-02",
            "2026-01-01",
            "2026-01-01T00:00:00Z",
        )
        .expect("refresh");
        assert_eq!(count, 1);
        let job = store.latest_job_run("movements").expect("q").expect("job");
        assert_eq!(job.status, "completed");
        assert_eq!(job.safe_error_code, None);
        assert_eq!(store.latest_movements().expect("q").len(), 1);
        // The per-capture account summary is captured alongside the rows.
        assert_eq!(
            store.latest_movements_summary().expect("q"),
            Some(a_summary())
        );
        assert_eq!(store.running_job_for("movements").expect("q"), None);
    }

    #[test]
    fn movements_refresh_does_not_persist_an_all_none_summary() {
        // A fetch that carried no account-level fields yields an all-None summary.
        // It must NOT be stored as a row — otherwise `movements_get_latest` would
        // emit `account_summary: {}` instead of omitting it, conflating "no summary
        // returned" with "an empty summary object".
        let mut store = Store::open_in_memory().expect("open");
        let fetcher = FakeMovementsFetcher(Ok((vec![a_movement()], MovementsSummary::default())));
        refresh_movements(
            &mut store,
            &fetcher,
            "owner",
            30,
            "2025-12-02",
            "2026-01-01",
            "2026-01-01T00:00:00Z",
        )
        .expect("refresh");
        assert_eq!(store.latest_movements().expect("q").len(), 1);
        assert_eq!(
            store.latest_movements_summary().expect("q"),
            None,
            "an all-None summary is treated as no summary and not persisted"
        );
    }

    #[test]
    fn movements_refresh_failure_records_safe_code_and_propagates() {
        let mut store = Store::open_in_memory().expect("open");
        let fetcher = FakeMovementsFetcher(Err(SafeError::auth_required()));
        let err = refresh_movements(
            &mut store,
            &fetcher,
            "owner",
            30,
            "2025-12-02",
            "2026-01-01",
            "2026-01-01T00:00:00Z",
        )
        .expect_err("should fail");
        assert_eq!(err.code(), "auth_required");
        let job = store.latest_job_run("movements").expect("q").expect("job");
        assert_eq!(job.status, "failed");
        assert_eq!(job.safe_error_code.as_deref(), Some("auth_required"));
        assert!(store.latest_movements().expect("q").is_empty());
    }

    #[test]
    fn movements_refresh_rejects_invalid_days_without_creating_a_job_row() {
        let mut store = Store::open_in_memory().expect("open");
        let fetcher = FakeMovementsFetcher(Ok((vec![], MovementsSummary::default())));
        let err = refresh_movements(
            &mut store,
            &fetcher,
            "owner",
            91, // over the 90-day cap
            "2025-10-03",
            "2026-01-01",
            "2026-01-01T00:00:00Z",
        )
        .expect_err("should reject");
        assert_eq!(err.code(), "invalid_request");
        // No job row created — the cap is a pre-lock gate.
        assert!(store.latest_job_run("movements").expect("q").is_none());
    }

    #[test]
    fn movements_refresh_rejects_when_already_running() {
        let mut store = Store::open_in_memory().expect("open");
        store
            .record_job_start("owner", "movements", "2026-01-01T00:00:00Z")
            .expect("start");
        let fetcher = FakeMovementsFetcher(Ok((vec![], MovementsSummary::default())));
        let err = refresh_movements(
            &mut store,
            &fetcher,
            "owner",
            30,
            "2025-12-02",
            "2026-01-01",
            "2026-01-01T00:01:00Z",
        )
        .expect_err("should be locked");
        assert_eq!(err.code(), "already_refreshing");
    }

    fn empty_snapshot(captured_at: &str) -> NewPortfolioSnapshot {
        NewPortfolioSnapshot {
            captured_at: captured_at.to_string(),
            source: "refresh".to_string(),
            market_value: None,
            book_value: None,
            profit_loss: None,
            profit_loss_perc: None,
            positions: vec![],
            fx_rates: vec![],
        }
    }

    #[test]
    fn success_captures_snapshot_and_completes_job() {
        let mut store = Store::open_in_memory().expect("open");
        let fetcher = FakeFetcher(Ok(empty_snapshot("2026-01-01T00:00:00Z")));
        let id = refresh_portfolio(&mut store, &fetcher, "owner", "2026-01-01T00:00:00Z")
            .expect("refresh");
        assert!(id > 0);
        assert!(store.latest_portfolio_snapshot().expect("q").is_some());
        let job = store
            .latest_job_run("portfolio")
            .expect("q")
            .expect("a job");
        assert_eq!(job.status, "completed");
        assert_eq!(job.safe_error_code, None);
        assert_eq!(store.running_job_for("portfolio").expect("q"), None);
    }

    #[test]
    fn fetch_failure_records_safe_code_and_propagates() {
        let mut store = Store::open_in_memory().expect("open");
        let fetcher = FakeFetcher(Err(SafeError::auth_required()));
        let err = refresh_portfolio(&mut store, &fetcher, "owner", "2026-01-01T00:00:00Z")
            .expect_err("should fail");
        assert_eq!(err.code(), "auth_required");
        let job = store
            .latest_job_run("portfolio")
            .expect("q")
            .expect("a job");
        assert_eq!(job.status, "failed");
        assert_eq!(job.safe_error_code.as_deref(), Some("auth_required"));
        // No snapshot captured on failure.
        assert!(store.latest_portfolio_snapshot().expect("q").is_none());
    }

    #[test]
    fn rejects_when_a_refresh_is_already_running() {
        let mut store = Store::open_in_memory().expect("open");
        store
            .record_job_start("owner", "portfolio", "2026-01-01T00:00:00Z")
            .expect("start");
        let fetcher = FakeFetcher(Ok(empty_snapshot("2026-01-01T00:00:00Z")));
        let err = refresh_portfolio(&mut store, &fetcher, "owner", "2026-01-01T00:01:00Z")
            .expect_err("should be locked");
        assert_eq!(err.code(), "already_refreshing");
    }
}
