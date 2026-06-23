//! Round-trip tests for the fineco-live protocol over a real Unix socket: a fake
//! worker (the server) drives [`fineco_live::serve_live_blocking`]; the
//! controller's [`LiveClient`] talks to it. These lock in the credentialed-
//! boundary contract — the worker returns un-hashed orders and the controller
//! hashes them, the controller's clock stamps the snapshot, and a worker failure
//! crosses the socket as a safe error with its `code`/`retryable` intact.

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use fineco_ipc::{
    MarketAssetDetailsLiveFetcher, MarketAssetDetailsLiveResult, MarketAssetDetailsResult,
    MarketAssetIdentity, MarketAssetSections, MarketAssetType, MarketDetailsParams,
    MarketDetailsSection, MarketField, MarketIndexCard, MarketIndexRegion,
    MarketIndicesLiveFetcher, MarketIndicesLiveResult, MarketIndicesParams, MarketIndicesResult,
    MarketLiveError, MarketSearchCandidate, MarketSearchGroup, MarketSearchLiveResult,
    MarketSearchParams, MarketSearchResult, MarketSessionStatus,
};
use fineco_live::{LiveClient, MarketSearchLiveFetcher, serve_live_blocking};
use fineco_refresh::{
    MovementsFetcher, OrdersFetcher, PortfolioFetcher, RawMovementsFetcher, RawOrdersFetcher,
    TaxFetcher,
};
use fineco_store::{
    MovementsSummary, NewAsset, NewMovement, NewPortfolioSnapshot, NewTaxCarryForward,
    NewTaxMinusByYear, RawMovement, RawOrder, Store,
};

use fineco_core::SafeError;

/// A fake worker: each fetch returns a canned result (or error). Stands in for the
/// credential-holding `FinecoWorker` so these tests need no network or creds.
struct FakeWorker {
    portfolio: Result<NewPortfolioSnapshot, SafeError>,
    orders: Result<Vec<RawOrder>, SafeError>,
    carry_forward: Result<NewTaxCarryForward, SafeError>,
    minus_by_year: Result<Vec<NewTaxMinusByYear>, SafeError>,
    market_search: Result<MarketSearchLiveResult, SafeError>,
    market_details: Result<MarketAssetDetailsLiveResult, SafeError>,
    market_indices: Result<MarketIndicesLiveResult, SafeError>,
}

impl FakeWorker {
    /// A worker whose every fetch succeeds with empty/echoed data.
    fn ok() -> Self {
        Self {
            portfolio: Ok(empty_snapshot("")),
            orders: Ok(vec![]),
            carry_forward: Ok(NewTaxCarryForward {
                date_from: String::new(),
                date_to: String::new(),
                total: None,
            }),
            minus_by_year: Ok(vec![]),
            market_search: Ok(MarketSearchLiveResult {
                result: MarketSearchResult {
                    query: String::new(),
                    data_class: "authenticated_market".to_string(),
                    source: "fineco.search.global".to_string(),
                    captured_at: String::new(),
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
                session: MarketSessionStatus {
                    login_performed: true,
                    session_reused: false,
                    session_evicted: false,
                    reused_session_401_recovered: false,
                    session_expires_in_secs: None,
                },
            }),
            market_details: Ok(MarketAssetDetailsLiveResult {
                result: sample_details(""),
                session: MarketSessionStatus::fresh_login(),
            }),
            market_indices: Ok(MarketIndicesLiveResult {
                result: sample_indices(""),
                session: MarketSessionStatus::fresh_login(),
            }),
        }
    }
}

impl PortfolioFetcher for FakeWorker {
    fn fetch_portfolio(&self, now_iso: &str) -> Result<NewPortfolioSnapshot, SafeError> {
        // Echo the controller's clock into captured_at (as the real worker does),
        // so the test can prove now_iso crosses the socket and stamps the snapshot.
        self.portfolio.clone().map(|mut snapshot| {
            snapshot.captured_at = now_iso.to_string();
            snapshot
        })
    }
}

impl RawOrdersFetcher for FakeWorker {
    fn fetch_raw_orders(
        &self,
        _instrument_kind: &str,
        _days: u32,
    ) -> Result<Vec<RawOrder>, SafeError> {
        self.orders.clone()
    }
}

impl TaxFetcher for FakeWorker {
    fn fetch_tax_carry_forward(
        &self,
        date_from: &str,
        date_to: &str,
    ) -> Result<NewTaxCarryForward, SafeError> {
        self.carry_forward.clone().map(|mut cf| {
            cf.date_from = date_from.to_string();
            cf.date_to = date_to.to_string();
            cf
        })
    }

    fn fetch_tax_minus_by_year(&self) -> Result<Vec<NewTaxMinusByYear>, SafeError> {
        self.minus_by_year.clone()
    }
}

impl MarketSearchLiveFetcher for FakeWorker {
    fn fetch_market_search(
        &self,
        params: &MarketSearchParams,
        now_iso: &str,
    ) -> Result<MarketSearchLiveResult, MarketLiveError> {
        self.market_search
            .clone()
            .map_err(MarketLiveError::from)
            .map(|mut result| {
                result.result.query = params.query.clone();
                result.result.captured_at = now_iso.to_string();
                result
            })
    }
}

impl MarketAssetDetailsLiveFetcher for FakeWorker {
    fn fetch_market_asset_details(
        &self,
        params: &MarketDetailsParams,
        now_iso: &str,
    ) -> Result<MarketAssetDetailsLiveResult, MarketLiveError> {
        self.market_details
            .clone()
            .map_err(MarketLiveError::from)
            .map(|mut result| {
                result.result.asset.identifier = params.identifier.clone();
                result.result.captured_at = now_iso.to_string();
                result
            })
    }
}

impl MarketIndicesLiveFetcher for FakeWorker {
    fn fetch_market_indices(
        &self,
        _params: &MarketIndicesParams,
        now_iso: &str,
    ) -> Result<MarketIndicesLiveResult, MarketLiveError> {
        self.market_indices
            .clone()
            .map_err(MarketLiveError::from)
            .map(|mut result| {
                result.result.captured_at = now_iso.to_string();
                result
            })
    }
}

/// The canned per-capture account summary the fake worker returns, so a round-trip
/// test can prove the envelope fields survive the socket.
fn fake_movements_summary() -> MovementsSummary {
    MovementsSummary {
        balance_at_movement: Some(1234.56),
        balance_at_search_date: Some(1200.0),
        current_month_credit_spending: Some(500.0),
        current_month_debit_spending: Some(-321.0),
    }
}

impl RawMovementsFetcher for FakeWorker {
    fn fetch_raw_movements(
        &self,
        _date_from: &str,
        _date_to: &str,
    ) -> Result<(Vec<RawMovement>, MovementsSummary), SafeError> {
        Ok((vec![], fake_movements_summary()))
    }
}

impl MovementsFetcher for FakeWorker {
    fn fetch_movements(
        &self,
        store: &Store,
        date_from: &str,
        date_to: &str,
    ) -> Result<(Vec<NewMovement>, MovementsSummary), SafeError> {
        let (raw, summary) = self.fetch_raw_movements(date_from, date_to)?;
        let hashed = raw
            .iter()
            .map(|r| {
                store
                    .hash_raw_movement(r)
                    .map_err(|_| SafeError::internal())
            })
            .collect::<Result<Vec<NewMovement>, SafeError>>()?;
        Ok((hashed, summary))
    }
}

fn sample_details(captured_at: &str) -> MarketAssetDetailsResult {
    MarketAssetDetailsResult {
        schema_version: 1,
        data_class: "authenticated_market".to_string(),
        captured_at: captured_at.to_string(),
        asset: MarketAssetIdentity {
            identifier: "AFF/VHYL".to_string(),
            fineco_key: MarketField::high_string(
                "IE00B8GKDB10.AFF",
                "fineco",
                "authenticated_market",
                "search.global",
                captured_at,
            ),
            asset_type: MarketField::high(
                MarketAssetType::Etf,
                None,
                "fineco",
                "authenticated_market",
                "search.global",
                None,
                captured_at,
            ),
            name: None,
            isin: Some(MarketField::high_string(
                "IE00B8GKDB10",
                "fineco",
                "authenticated_market",
                "search.global",
                captured_at,
            )),
            venue: MarketField::high_string(
                "AFF",
                "fineco",
                "authenticated_market",
                "search.global",
                captured_at,
            ),
            symbol: MarketField::medium_string(
                "VHYL",
                "fineco",
                "authenticated_market",
                "search.global",
                captured_at,
            ),
            display_symbol: Some(MarketField::medium_string(
                "VHYL.MI",
                "fineco",
                "authenticated_market",
                "search.global",
                captured_at,
            )),
            currency: Some(MarketField::high_string(
                "EUR",
                "fineco",
                "authenticated_market",
                "search.global",
                captured_at,
            )),
        },
        sections: MarketAssetSections::default(),
        sources: vec![],
        warnings: vec![],
    }
}

fn sample_indices(captured_at: &str) -> MarketIndicesResult {
    MarketIndicesResult {
        schema_version: 1,
        data_class: "authenticated_market".to_string(),
        source: "fineco.indicesbar".to_string(),
        captured_at: captured_at.to_string(),
        indices: vec![MarketIndexCard {
            symbol: MarketField::high_string(
                "^FTMIB.affIdx",
                "fineco.indicesbar",
                "authenticated_market",
                "indicesbar",
                captured_at,
            ),
            label: MarketField::high_string(
                "Ftse mib",
                "fineco.indicesbar",
                "authenticated_market",
                "indicesbar",
                captured_at,
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
                captured_at,
            )),
        }],
        warnings: vec![],
    }
}

fn empty_snapshot(captured_at: &str) -> NewPortfolioSnapshot {
    NewPortfolioSnapshot {
        captured_at: captured_at.to_string(),
        source: "fineco".to_string(),
        market_value: None,
        book_value: None,
        profit_loss: None,
        profit_loss_perc: None,
        positions: vec![],
        fx_rates: vec![],
    }
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Bind a uniquely-named live socket, serve `worker` on a background thread, and
/// return a `LiveClient` plus the socket path (kept for cleanup).
fn serve(worker: FakeWorker) -> (LiveClient, PathBuf) {
    let mut path = std::env::temp_dir();
    let tag = COUNTER.fetch_add(1, Ordering::Relaxed);
    path.push(format!("fineco-live-{}-{tag}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind live socket");
    thread::spawn(move || {
        let _ = serve_live_blocking(&listener, &worker);
    });
    (LiveClient::new(&path), path)
}

#[test]
fn portfolio_round_trips_and_is_stamped_with_the_controller_clock() {
    let (client, path) = serve(FakeWorker::ok());
    let snapshot = client
        .fetch_portfolio("2026-06-05T10:00:00Z")
        .expect("portfolio fetch");
    // The worker stamped the snapshot with the now_iso the controller sent.
    assert_eq!(snapshot.captured_at, "2026-06-05T10:00:00Z");
    assert_eq!(snapshot.source, "fineco");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn orders_cross_raw_and_are_hashed_controller_side() {
    let raw = RawOrder {
        trans_id: "SYNTH-TX-0001".to_string(),
        asset: NewAsset {
            instr_id: "A".to_string(),
            venue_system: "V".to_string(),
            symbol: Some("SYM".to_string()),
            description: None,
            kind: None,
            currency: Some("EUR".to_string()),
        },
        status: Some("EXECUTED".to_string()),
        sign: Some("BUY".to_string()),
        order_size: Some(10.0),
        size_filled: Some(10.0),
        avg_price: Some(100.0),
        submit_time: Some("2026-01-01T09:30:00Z".to_string()),
    };
    let mut worker = FakeWorker::ok();
    worker.orders = Ok(vec![raw]);
    let (client, path) = serve(worker);

    // The controller owns the store/key; the LiveClient hashes the worker's raw
    // orders with it.
    let store = Store::open_in_memory().expect("open store");
    let orders = client
        .fetch_orders(&store, "equity", 7)
        .expect("orders fetch");
    assert_eq!(orders.len(), 1);
    let order = &orders[0];
    // The raw trans_id was hashed exactly as the store would hash it — and the
    // raw id is not recoverable from the produced order.
    assert_eq!(
        order.trans_id_hash,
        store.hash_id("SYNTH-TX-0001").expect("hash")
    );
    assert!(!order.trans_id_hash.contains("SYNTH-TX-0001"));
    assert_eq!(order.asset.instr_id, "A");
    assert_eq!(order.status.as_deref(), Some("EXECUTED"));
    assert_eq!(order.avg_price, Some(100.0));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn movements_account_summary_survives_the_socket_round_trip() {
    let (client, path) = serve(FakeWorker::ok());
    let store = Store::open_in_memory().expect("open store");
    let (movements, summary) = client
        .fetch_movements(&store, "2026-03-25", "2026-06-23")
        .expect("movements fetch");
    // The fake returns no rows but a populated account summary; the four envelope
    // fields must cross the socket intact (not silently dropped or zeroed).
    assert!(movements.is_empty());
    assert_eq!(summary, fake_movements_summary());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn tax_carry_forward_and_minus_round_trip() {
    let mut worker = FakeWorker::ok();
    worker.carry_forward = Ok(NewTaxCarryForward {
        date_from: String::new(),
        date_to: String::new(),
        total: Some(1234.56),
    });
    worker.minus_by_year = Ok(vec![NewTaxMinusByYear {
        year: 2026,
        minus_residue: Some(500.0),
        expiration_date: Some("2030-12-31".to_string()),
    }]);
    let (client, path) = serve(worker);

    let cf = client
        .fetch_tax_carry_forward("2026-01-01", "2026-01-31")
        .expect("carry-forward fetch");
    // The requested range crossed the socket and was echoed back.
    assert_eq!(cf.date_from, "2026-01-01");
    assert_eq!(cf.date_to, "2026-01-31");
    assert_eq!(cf.total, Some(1234.56));

    let minus = client
        .fetch_tax_minus_by_year()
        .expect("minus-by-year fetch");
    assert_eq!(minus.len(), 1);
    assert_eq!(minus[0].year, 2026);
    assert_eq!(minus[0].minus_residue, Some(500.0));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn market_search_round_trips_and_is_stamped_with_the_controller_clock() {
    let (client, path) = serve(FakeWorker::ok());
    let result = client
        .fetch_market_search(
            &MarketSearchParams {
                query: "VHYL".to_string(),
                asset_type: Some(MarketAssetType::Etf),
                limit: Some(5),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("market search")
        .result;

    assert_eq!(result.query, "VHYL");
    assert_eq!(result.captured_at, "2026-06-14T09:30:00Z");
    assert_eq!(result.groups[0].asset_type, MarketAssetType::Etf);
    assert_eq!(
        result.groups[0].candidates[0].fineco_key,
        "IE00B8GKDB10.AFF"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn market_search_round_trip_carries_status_facts_without_cookie_values() {
    let (client, path) = serve(FakeWorker::ok());
    let live = client
        .fetch_market_search_live(
            &MarketSearchParams {
                query: "VHYL".to_string(),
                asset_type: Some(MarketAssetType::Etf),
                limit: Some(5),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("market search");

    assert_eq!(live.result.query, "VHYL");
    assert!(live.session.login_performed);
    assert!(!live.session.session_reused);
    assert!(!live.session.session_evicted);
    assert!(!live.session.reused_session_401_recovered);
    assert_eq!(live.session.session_expires_in_secs, None);
    let encoded = serde_json::to_string(&live.session).expect("session status JSON");
    assert!(!encoded.contains("cookie"));
    assert!(!encoded.contains("session_id"));
    assert!(!encoded.contains("auth"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn market_search_round_trip_carries_status_only_expiry_ttl() {
    let mut worker = FakeWorker::ok();
    worker
        .market_search
        .as_mut()
        .expect("market search")
        .session = MarketSessionStatus::fresh_login_with_expiry(Some(3600));
    let (client, path) = serve(worker);
    let live = client
        .fetch_market_search_live(
            &MarketSearchParams {
                query: "VHYL".to_string(),
                asset_type: Some(MarketAssetType::Etf),
                limit: Some(5),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("market search");

    assert_eq!(live.session.session_expires_in_secs, Some(3600));
    let encoded = serde_json::to_string(&live.session).expect("session status JSON");
    assert!(encoded.contains("session_expires_in_secs"));
    assert!(!encoded.contains("cookie"));
    assert!(!encoded.contains("set-cookie"));
    assert!(!encoded.contains("session_id"));
    assert!(!encoded.contains("auth"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn market_indices_round_trip_carries_status_facts_without_cookie_values() {
    let (client, path) = serve(FakeWorker::ok());
    let live = client
        .fetch_market_indices_live(
            &MarketIndicesParams {
                region: Some(MarketIndexRegion::Europe),
                limit: Some(10),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("market indices");

    assert_eq!(live.result.captured_at, "2026-06-14T09:30:00Z");
    assert_eq!(live.result.indices[0].symbol.value, "^FTMIB.affIdx");
    assert!(live.session.login_performed);
    let encoded = serde_json::to_string(&live.session).expect("session status JSON");
    assert!(!encoded.contains("cookie"));
    assert!(!encoded.contains("session_id"));
    assert!(!encoded.contains("auth"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn market_details_round_trips_and_is_stamped_with_the_controller_clock() {
    let (client, path) = serve(FakeWorker::ok());
    let live = client
        .fetch_market_asset_details(
            &MarketDetailsParams {
                identifier: "AFF/VHYL".to_string(),
                expected_isin: Some("IE00B8GKDB10".to_string()),
                sections: Some(vec![
                    MarketDetailsSection::Identity,
                    MarketDetailsSection::Etf,
                ]),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("market details");

    assert_eq!(live.result.asset.identifier, "AFF/VHYL");
    assert_eq!(live.result.captured_at, "2026-06-14T09:30:00Z");
    assert_eq!(live.result.asset.fineco_key.value, "IE00B8GKDB10.AFF");
    assert!(live.session.login_performed);
    let encoded = serde_json::to_string(&live.session).expect("session status JSON");
    assert!(!encoded.contains("cookie"));
    assert!(!encoded.contains("session_id"));
    assert!(!encoded.contains("auth"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_retryable_worker_failure_keeps_its_code_and_retryable_bit() {
    // A Fineco timeout at the worker must reach the controller as `fineco_timeout`
    // AND retryable — both are what the controller's retry + circuit logic key on.
    let mut worker = FakeWorker::ok();
    worker.portfolio = Err(SafeError::fineco_timeout());
    let (client, path) = serve(worker);

    let err = client
        .fetch_portfolio("2026-06-05T10:00:00Z")
        .expect_err("a worker timeout must surface");
    assert_eq!(err.code(), "fineco_timeout");
    assert!(
        err.retryable(),
        "a timeout must remain retryable across the socket"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_step_up_failure_keeps_its_code_across_the_socket() {
    // A read-time SCA step-up at the worker must reach the controller as
    // `step_up_required` (NOT collapse to `internal` through the DTO bridge) and
    // stay non-retryable — re-login won't clear a session step-up.
    let mut worker = FakeWorker::ok();
    worker.orders = Err(SafeError::step_up_required());
    let (client, path) = serve(worker);

    let store = Store::open_in_memory().expect("open store");
    let err = client
        .fetch_orders(&store, "equity", 7)
        .expect_err("a worker step-up must surface");
    assert_eq!(err.code(), "step_up_required");
    assert!(
        !err.retryable(),
        "step-up must not be retried (no automatic re-login)"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_auth_failure_is_not_retryable_across_the_socket() {
    let mut worker = FakeWorker::ok();
    worker.orders = Err(SafeError::auth_required());
    let (client, path) = serve(worker);

    let store = Store::open_in_memory().expect("open store");
    let err = client
        .fetch_orders(&store, "equity", 7)
        .expect_err("a worker auth failure must surface");
    assert_eq!(err.code(), "auth_required");
    assert!(
        !err.retryable(),
        "auth failures must not be retried (no automatic re-login)"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_unknown_command_is_rejected_with_a_safe_error_not_a_crash() {
    // A hostile/malformed frame (unknown command, smuggled `url`) must never reach
    // a fetcher: the server replies with a safe error envelope and stays up.
    use std::os::unix::net::UnixStream;

    let (_client, path) = serve(FakeWorker::ok());
    let mut stream = UnixStream::connect(&path).expect("connect");
    fineco_ipc::write_message(
        &mut stream,
        &serde_json::json!({ "command": "evil_proxy", "params": { "url": "http://attacker" } }),
    )
    .expect("write forged frame");
    let reply: serde_json::Value = fineco_ipc::read_message(&mut stream).expect("read reply");
    assert_eq!(
        reply.get("status").and_then(|s| s.as_str()),
        Some("err"),
        "an unknown command must be rejected as a safe error"
    );

    // The server is still alive: a subsequent valid request still works.
    let client2 = LiveClient::new(&path);
    client2
        .fetch_tax_minus_by_year()
        .expect("server survives a bad frame and serves the next request");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_valid_command_with_a_smuggled_envelope_key_is_rejected() {
    // A frame with a VALID command but an extra TOP-LEVEL key must be rejected:
    // the adjacently-tagged enum alone would silently ignore the extra key, but
    // the envelope-key validation closes that gap (parity with refresh-control).
    use std::os::unix::net::UnixStream;

    let (_client, path) = serve(FakeWorker::ok());
    let mut stream = UnixStream::connect(&path).expect("connect");
    fineco_ipc::write_message(
        &mut stream,
        &serde_json::json!({ "command": "tax_minus_by_year", "url": "http://attacker" }),
    )
    .expect("write frame with a smuggled envelope key");
    let reply: serde_json::Value = fineco_ipc::read_message(&mut stream).expect("read reply");
    assert_eq!(
        reply.get("status").and_then(|s| s.as_str()),
        Some("err"),
        "a smuggled top-level envelope key must be rejected, not silently ignored"
    );

    // The server survives and serves a subsequent valid request.
    let client2 = LiveClient::new(&path);
    client2
        .fetch_tax_minus_by_year()
        .expect("server survives a smuggled-key frame and serves the next request");
    let _ = std::fs::remove_file(&path);
}
