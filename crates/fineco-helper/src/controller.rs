//! The refresh controller: the store-server's live-refresh brain.
//!
//! It owns the DB side of live refresh. For each [`RefreshRequest`] arriving on
//! `refresh-control.sock` it: re-checks the `*.live.refresh` capability against
//! the shared policy (defense in depth — the gateway checked first); re-validates
//! the bounded params; runs the pre-flight gate (cooldown / daily budget /
//! circuit breaker, whose denials create no `job_runs` row); then runs the
//! refresh against an injected fetcher wrapped in [`Retrying`] (so a transient
//! Fineco blip is absorbed within one `job_runs` row). It returns
//! operation/snapshot **status only** — never the refreshed payload.
//!
//! The fetcher is generic: in production it is the
//! [`fineco_live::LiveClient`](fineco_live::LiveClient) reaching the credential
//! worker over `fineco-live.sock`; in tests it is a fake. The controller holds
//! the `Store` behind a `Mutex` so the (sequential) refresh accept loop can mutate
//! it while the snapshot-query loop reads the DB over its own connection.

use std::sync::Mutex;

use fineco_core::SafeError;
use fineco_ipc::{OWNER_AUTH_ID, Policy, RefreshOutcome, RefreshRequest};
use fineco_refresh::{
    OrdersFetcher, PortfolioFetcher, RefreshLimits, RetryPolicy, Retrying, TaxFetcher,
    refresh_orders, refresh_portfolio, refresh_preflight, refresh_tax,
};
use fineco_store::Store;

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

/// The default per-fetch retry policy: up to 3 attempts with a 500ms base
/// exponential backoff. Retries happen INSIDE one fetch, so the refresh remains a
/// single `job_runs` row no matter how many transient tries it took. Only
/// retryable (5xx/timeout) errors are retried.
#[must_use]
pub fn default_retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 3,
        backoff_base: std::time::Duration::from_millis(500),
    }
}

/// The refresh controller. Generic over the fetcher (the live client in
/// production, a fake in tests).
pub struct RefreshController<F> {
    store: Mutex<Store>,
    fetcher: F,
    policy: Policy,
    limits: RefreshLimitsByArea,
    retry: RetryPolicy,
}

impl<F> RefreshController<F>
where
    F: PortfolioFetcher + OrdersFetcher + TaxFetcher,
{
    /// Build a controller over `store`, sourcing fresh data from `fetcher`.
    #[must_use]
    pub fn new(
        store: Store,
        fetcher: F,
        policy: Policy,
        limits: RefreshLimitsByArea,
        retry: RetryPolicy,
    ) -> Self {
        Self {
            store: Mutex::new(store),
            fetcher,
            policy,
            limits,
            retry,
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

        // 4. Run the refresh against the retrying fetcher (one job_runs row).
        let retrying = Retrying::new(&self.fetcher, self.retry);
        match &request {
            RefreshRequest::PortfolioRefreshLive => {
                let snapshot_id = refresh_portfolio(&mut store, &retrying, OWNER_AUTH_ID, now_iso)?;
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
            }
            RefreshRequest::OrdersRefreshLive(params) => {
                let count = refresh_orders(
                    &mut store,
                    &retrying,
                    OWNER_AUTH_ID,
                    &params.instrument_kind,
                    params.days,
                    now_iso,
                )?;
                Ok(RefreshOutcome {
                    data_area: area.to_string(),
                    captured_at: now_iso.to_string(),
                    snapshot_id: None,
                    count,
                })
            }
            RefreshRequest::TaxRefreshLive(params) => {
                let count = refresh_tax(
                    &mut store,
                    &retrying,
                    OWNER_AUTH_ID,
                    &params.date_from,
                    &params.date_to,
                    now_iso,
                )?;
                Ok(RefreshOutcome {
                    data_area: area.to_string(),
                    captured_at: now_iso.to_string(),
                    snapshot_id: None,
                    count,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RefreshController, RefreshLimitsByArea};
    use fineco_core::SafeError;
    use fineco_ipc::{OrdersRefreshParams, Policy, RefreshRequest, TaxRefreshParams};
    use fineco_refresh::{OrdersFetcher, PortfolioFetcher, RetryPolicy, TaxFetcher};
    use fineco_store::{
        NewAsset, NewPortfolioSnapshot, NewPosition, NewTaxCarryForward, NewTaxMinusByYear,
        RawOrder, Store,
    };
    use std::cell::Cell;

    const NOW: &str = "2026-06-05T10:00:00Z";

    /// A fake worker the controller drives. Each fetch returns a canned result; a
    /// `Cell` counts portfolio fetches so a test can prove the retry happens
    /// inside one refresh.
    struct FakeWorker {
        portfolio: Box<dyn Fn() -> Result<NewPortfolioSnapshot, SafeError>>,
        orders: Result<Vec<RawOrder>, SafeError>,
        carry_forward: Result<NewTaxCarryForward, SafeError>,
        minus_by_year: Result<Vec<NewTaxMinusByYear>, SafeError>,
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
            // Immediate (no real sleeps) so retry tests are fast.
            RetryPolicy::immediate(3),
        )
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
                NOW,
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
    fn a_transient_timeout_is_absorbed_within_one_refresh() {
        // Fail once with a retryable timeout, then succeed — the Retrying wrapper
        // absorbs it within a single job_runs row.
        let remaining = std::rc::Rc::new(Cell::new(1u32));
        let remaining_in = std::rc::Rc::clone(&remaining);
        let mut worker = FakeWorker::ok();
        worker.portfolio = Box::new(move || {
            if remaining_in.get() > 0 {
                remaining_in.set(remaining_in.get() - 1);
                Err(SafeError::fineco_timeout())
            } else {
                Ok(one_position_snapshot())
            }
        });
        let ctrl = controller(worker, live_policy());
        let outcome = ctrl
            .handle(RefreshRequest::PortfolioRefreshLive, NOW)
            .expect("the transient timeout is absorbed");
        assert!(outcome.snapshot_id.is_some());
        let store = ctrl.store.lock().expect("lock");
        // Exactly one job row, completed — the retry was inside the one fetch.
        assert_eq!(
            store
                .count_jobs_on_utc_date("portfolio", "2026-06-05")
                .expect("q"),
            1
        );
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
