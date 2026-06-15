//! Integration tests: the worker logs in against the SYNTHETIC mock Fineco over
//! a real socket and parses each authenticated read into store-ready types. No
//! real credentials — the mock accepts any login. Input bounds are enforced
//! before any request is made.

use std::net::TcpListener;
use std::thread;

use fineco_ipc::{
    MarketAssetDetailsLiveFetcher, MarketAssetType, MarketDetailsParams, MarketDetailsSection,
    MarketSearchLiveFetcher, MarketSearchParams,
};
use fineco_refresh::{PortfolioFetcher, RawOrdersFetcher, TaxFetcher};
use fineco_worker::{FinecoEndpoints, FinecoWorker, StaticCredentialSource};

const NOW: &str = "2026-06-03T12:00:00Z";

/// Bind an ephemeral port, serve the mock Fineco on a background thread, and
/// return its base URL.
fn spawn_mock_fineco() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, mock_fineco::route);
    });
    format!("http://{addr}")
}

/// Like [`spawn_mock_fineco`], but the home preflight sets NO cookie (mirrors
/// real Fineco): login then requires the synthetic public cookies the worker
/// must mint, and 403s without them.
fn spawn_mock_fineco_cookieless_home() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, mock_fineco::route_cookieless_home);
    });
    format!("http://{addr}")
}

fn spawn_mock_fineco_with_broken_quote_snapshot() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, |req| {
            let path = req.path.split('?').next().unwrap_or(&req.path);
            if req.method == "GET" && path == "/v1/private/tol/instruments/snapshot" {
                return httptiny::Response::json(503, "{\"error\":\"snapshot unavailable\"}");
            }
            mock_fineco::route(req)
        });
    });
    format!("http://{addr}")
}

fn worker_for(base: &str) -> FinecoWorker {
    FinecoWorker::new(
        FinecoEndpoints::for_base(base),
        Box::new(StaticCredentialSource::new(
            "synthetic-user",
            "synthetic-pass",
        )),
    )
}

/// A worker pointed at a port nothing listens on. Used by the input-bound tests,
/// which must reject before any network call — so the dead endpoint is never hit.
fn worker_offline() -> FinecoWorker {
    worker_for("http://127.0.0.1:9")
}

#[test]
fn logs_in_and_parses_portfolio_snapshot() {
    let base = spawn_mock_fineco();
    let snapshot = worker_for(&base)
        .fetch_portfolio(NOW)
        .expect("portfolio fetch should succeed");

    // captured_at is stamped by the caller's clock, not invented by the worker.
    assert_eq!(snapshot.captured_at, NOW);
    assert_eq!(snapshot.source, "fineco");

    // Totals come from summary.show.
    assert_eq!(snapshot.market_value, Some(1750.0));
    assert_eq!(snapshot.book_value, Some(1500.0));
    assert_eq!(snapshot.profit_loss, Some(250.0));

    assert_eq!(snapshot.positions.len(), 2);
    let first = &snapshot.positions[0];
    assert_eq!(first.asset.instr_id, "SYNTH0000001");
    assert_eq!(first.asset.venue_system, "SYNTHV");
    assert_eq!(first.asset.symbol.as_deref(), Some("SYNTH-A"));
    assert_eq!(
        first.asset.description.as_deref(),
        Some("SYNTHETIC Alpha Corp")
    );
    assert_eq!(first.asset.kind.as_deref(), Some("EQUITY"));
    assert_eq!(first.asset.currency.as_deref(), Some("EUR"));
    assert_eq!(first.qty, Some(10.0));
    assert_eq!(first.avg_price, Some(100.0));
    assert_eq!(first.market_price, Some(120.0));
    assert_eq!(first.book_value, Some(1000.0));
    assert_eq!(first.market_value, Some(1200.0));
    assert_eq!(first.profit_loss, Some(200.0));
    assert_eq!(first.profit_loss_perc, Some(20.0));
    // Positions are identified by their unhashed asset key; no hash needed here.
    assert_eq!(first.position_key_hash, None);
    // weight_perc is derived from the portfolio total (1200 / 1750 * 100).
    let weight = first
        .weight_perc
        .expect("weight should be derived from totals");
    assert!(
        (weight - 68.5714).abs() < 0.01,
        "unexpected weight_perc {weight}"
    );
}

#[test]
fn mints_synthetic_cookies_when_home_preflight_sets_none() {
    // Real Fineco's public home page sets no cookie. With no preflight cookie to
    // replay, the worker must mint the synthetic public cookies (finecostat, XID,
    // LBM, PORTALSESSIONID, gdate, store-sessionid, finecoLogin) and send them on
    // the login POST — exactly as the TS reference's syntheticPublicCookies()
    // does. The mock 403s the login (the real auth.invalid.credentials shape)
    // unless those cookies are present, so a successful fetch proves they were.
    let base = spawn_mock_fineco_cookieless_home();
    let snapshot = worker_for(&base)
        .fetch_portfolio(NOW)
        .expect("login must mint synthetic cookies and succeed against a cookieless home");
    assert_eq!(snapshot.source, "fineco");
    assert_eq!(snapshot.positions.len(), 2);
}

#[test]
fn login_failure_surfaces_a_safe_error() {
    // Point the worker at a base whose login path 404s; the worker must return a
    // safe envelope, never panic or leak the upstream body.
    let base = spawn_mock_fineco();
    let worker = FinecoWorker::new(
        FinecoEndpoints::for_base(&format!("{base}/nonexistent-prefix")),
        Box::new(StaticCredentialSource::new(
            "synthetic-user",
            "synthetic-pass",
        )),
    );
    let err = worker
        .fetch_portfolio(NOW)
        .expect_err("login against a missing endpoint must fail");
    assert!(!err.safe_message().is_empty());
    assert!(!err.safe_message().contains("SYNTHETIC"));
}

#[test]
fn market_search_login_failure_uses_a_market_error_code() {
    let base = spawn_mock_fineco();
    let worker = FinecoWorker::new(
        FinecoEndpoints::for_base(&format!("{base}/nonexistent-prefix")),
        Box::new(StaticCredentialSource::new(
            "synthetic-user",
            "synthetic-pass",
        )),
    );
    let err = worker
        .fetch_market_search(
            &MarketSearchParams {
                query: "VHYL".to_string(),
                asset_type: Some(MarketAssetType::Etf),
                limit: Some(5),
            },
            NOW,
        )
        .expect_err("market login against a missing endpoint must fail");
    assert_eq!(err.code(), "market_unexpected_response");
    assert!(!err.safe_message().contains("SYNTHETIC"));
}

#[test]
fn refuses_cleartext_to_a_non_loopback_host() {
    // A misconfigured http endpoint to a real host must fail closed before the
    // credential or cookie is ever sent — never leak over cleartext.
    let worker = FinecoWorker::new(
        FinecoEndpoints::for_base("http://fineco.example"),
        Box::new(StaticCredentialSource::new(
            "synthetic-user",
            "synthetic-pass",
        )),
    );
    let err = worker
        .fetch_portfolio(NOW)
        .expect_err("cleartext to a non-loopback host must be rejected");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn fetches_orders_as_raw_unhashed() {
    // The worker holds no DB key, so it returns the raw broker trans_id; the
    // controller hashes it after it crosses the fineco-live socket.
    let base = spawn_mock_fineco();
    let worker = worker_for(&base);

    let orders = worker
        .fetch_raw_orders("equity", 0)
        .expect("orders fetch should succeed");
    assert_eq!(orders.len(), 2);

    let first = &orders[0];
    assert_eq!(first.asset.instr_id, "SYNTH0000001");
    assert_eq!(first.asset.venue_system, "SYNTHV");
    assert_eq!(first.status.as_deref(), Some("EXECUTED"));
    assert_eq!(first.sign.as_deref(), Some("BUY"));
    assert_eq!(first.order_size, Some(10.0));
    assert_eq!(first.size_filled, Some(10.0));
    assert_eq!(first.avg_price, Some(100.0));
    assert_eq!(first.submit_time.as_deref(), Some("2026-01-01T09:30:00Z"));

    // The transaction id is carried raw (the worker does not hash); hashing is
    // the controller's job once the order reaches the DB side.
    assert_eq!(first.trans_id, "SYNTH-TX-0001");

    // The pending order carries a null avgPrice and a SELL sign.
    assert_eq!(orders[1].avg_price, None);
    assert_eq!(orders[1].sign.as_deref(), Some("SELL"));
}

#[test]
fn rejects_excessive_order_day_window() {
    let err = worker_offline()
        .fetch_raw_orders("equity", 31)
        .expect_err("days over the cap must be rejected");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn rejects_non_alphanumeric_instrument_kind() {
    // A non-alphanumeric kind could smuggle extra query parameters; reject it.
    let err = worker_offline()
        .fetch_raw_orders("equity&days=999", 0)
        .expect_err("query-injecting kind must be rejected");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn fetches_tax_carry_forward() {
    let base = spawn_mock_fineco();
    let carry_forward = worker_for(&base)
        .fetch_tax_carry_forward("2026-01-01", "2026-01-31")
        .expect("tax carry-forward fetch should succeed");
    assert_eq!(carry_forward.date_from, "2026-01-01");
    assert_eq!(carry_forward.date_to, "2026-01-31");
    assert_eq!(carry_forward.total, Some(1234.56));
}

#[test]
fn rejects_malformed_tax_date() {
    let err = worker_offline()
        .fetch_tax_carry_forward("2026-13-01", "2026-01-31")
        .expect_err("an out-of-range month must be rejected");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn rejects_inverted_tax_range() {
    let err = worker_offline()
        .fetch_tax_carry_forward("2026-01-31", "2026-01-01")
        .expect_err("date_from after date_to must be rejected");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn fetches_tax_minus_by_year() {
    let base = spawn_mock_fineco();
    let rows = worker_for(&base)
        .fetch_tax_minus_by_year()
        .expect("tax minus fetch should succeed");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].year, 2026);
    assert_eq!(rows[0].minus_residue, Some(500.0));
    assert_eq!(rows[0].expiration_date.as_deref(), Some("2030-12-31"));
}

#[test]
fn logs_in_and_fetches_authenticated_market_search() {
    let base = spawn_mock_fineco();
    let live = worker_for(&base)
        .fetch_market_search(
            &MarketSearchParams {
                query: "VHYL".to_string(),
                asset_type: Some(MarketAssetType::Etf),
                limit: Some(10),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("market search fetch should succeed");
    let result = live.result;

    assert_eq!(result.query, "VHYL");
    assert_eq!(result.data_class, "authenticated_market");
    assert_eq!(result.source, "fineco.search.global");
    assert_eq!(result.groups.len(), 1);
    assert_eq!(result.groups[0].asset_type, MarketAssetType::Etf);
    assert_eq!(result.groups[0].candidates.len(), 2);
    assert_eq!(result.groups[0].candidates[1].identifier, "AFF/VHYL");
    assert_eq!(result.groups[0].candidates[1].symbol, "VHYL");
    assert_eq!(result.groups[0].candidates[1].display_symbol, "VHYL.MI");
    assert_eq!(
        result.groups[0].candidates[1].fineco_key,
        "IE00B8GKDB10.AFF"
    );
    assert!(live.session.login_performed);
    assert!(!live.session.session_reused);
}

#[test]
fn logs_in_and_fetches_authenticated_etf_details() {
    let base = spawn_mock_fineco();
    let live = worker_for(&base)
        .fetch_market_asset_details(
            &MarketDetailsParams {
                identifier: "AFF/VHYL".to_string(),
                expected_isin: Some("IE00B8GKDB10.AFF".to_string()),
                sections: Some(vec![
                    MarketDetailsSection::Identity,
                    MarketDetailsSection::Listing,
                    MarketDetailsSection::Quote,
                    MarketDetailsSection::Profile,
                    MarketDetailsSection::Etf,
                    MarketDetailsSection::Holdings,
                    MarketDetailsSection::Exposures,
                    MarketDetailsSection::Returns,
                    MarketDetailsSection::Risk,
                ]),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("ETF details fetch should succeed");
    let result = live.result;

    assert_eq!(result.schema_version, 1);
    assert_eq!(result.data_class, "authenticated_market");
    assert_eq!(result.asset.identifier, "AFF/VHYL");
    assert_eq!(result.asset.fineco_key.value, "IE00B8GKDB10.AFF");
    assert_eq!(result.asset.isin.expect("isin").value, "IE00B8GKDB10");
    let quote = result.sections.quote.expect("quote");
    assert_eq!(
        quote.last.expect("last").as_of.as_deref(),
        Some("2026-06-12T15:35:29Z")
    );
    let etf = result.sections.etf.expect("etf");
    assert_eq!(etf.ongoing_charge.expect("ongoing charge").value, 0.32);
    assert_eq!(
        etf.management_fee.expect("management fee").unit.as_deref(),
        Some("percent")
    );
    let holdings = result.sections.holdings.expect("holdings");
    assert_eq!(holdings.len(), 2);
    assert_eq!(holdings[0].name.value, "Microsoft Corp");
    assert!(holdings[0].weight.value >= holdings[1].weight.value);
    let exposures = result.sections.exposures.expect("exposures");
    assert_eq!(exposures.asset_allocation[0].label.value, "Azioni");
    assert_eq!(exposures.regions[0].label.value, "Stati Uniti");
    let returns = result.sections.returns.expect("returns");
    assert!(returns.cumulative.iter().any(|row| row.period == "12M"));
    let risk = result.sections.risk.expect("risk");
    assert_eq!(risk.beta_m36.expect("beta").value, 1.01);
    assert!(live.session.login_performed);
}

#[test]
fn logs_in_and_fetches_authenticated_stock_details() {
    let base = spawn_mock_fineco();
    let live = worker_for(&base)
        .fetch_market_asset_details(
            &MarketDetailsParams {
                identifier: "NASDAQ/AAPL".to_string(),
                expected_isin: Some("US0378331005".to_string()),
                sections: Some(vec![
                    MarketDetailsSection::Identity,
                    MarketDetailsSection::Listing,
                    MarketDetailsSection::Quote,
                    MarketDetailsSection::Profile,
                    MarketDetailsSection::Stock,
                    MarketDetailsSection::Ratios,
                ]),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("stock details fetch should succeed");
    let result = live.result;

    assert_eq!(result.schema_version, 1);
    assert_eq!(result.data_class, "authenticated_market");
    assert_eq!(result.asset.identifier, "NASDAQ/AAPL");
    assert_eq!(result.asset.fineco_key.value, "US0378331005.NASDAQ");
    assert_eq!(result.asset.asset_type.value, MarketAssetType::Stock);
    assert_eq!(result.asset.isin.expect("isin").value, "US0378331005");
    assert_eq!(result.asset.symbol.value, "AAPL");
    let profile = result.sections.profile.expect("profile");
    assert_eq!(profile.sector.expect("sector").value, "Technology");
    assert_eq!(
        profile.industry.expect("industry").value,
        "Consumer Electronics"
    );
    let quote = result.sections.quote.expect("quote");
    assert_eq!(
        quote.last.expect("last").as_of.as_deref(),
        Some("2026-06-12T20:00:00Z")
    );
    let stock = result.sections.stock.expect("stock");
    assert_eq!(stock.pe.expect("pe").value, 35.35);
    assert_eq!(
        stock.target_price.expect("target").unit.as_deref(),
        Some("USD")
    );
    let ratios = result.sections.ratios.expect("ratios");
    assert!(ratios.ratios.iter().any(|row| row.name.value == "NPRICE"));
    assert!(live.session.login_performed);
}

#[test]
fn stock_details_skip_quote_snapshot_when_quote_section_is_not_requested() {
    let base = spawn_mock_fineco_with_broken_quote_snapshot();
    let live = worker_for(&base)
        .fetch_market_asset_details(
            &MarketDetailsParams {
                identifier: "NASDAQ/AAPL".to_string(),
                expected_isin: Some("US0378331005".to_string()),
                sections: Some(vec![MarketDetailsSection::Profile]),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("profile-only stock details should not require quote snapshot");
    let result = live.result;

    assert_eq!(result.asset.identifier, "NASDAQ/AAPL");
    assert!(result.sections.quote.is_none());
    assert_eq!(
        result
            .sections
            .profile
            .expect("profile")
            .sector
            .expect("sector")
            .value,
        "Technology"
    );
}

#[test]
fn unsupported_asset_details_stop_after_resolution() {
    let base = spawn_mock_fineco();
    let err = worker_for(&base)
        .fetch_market_asset_details(
            &MarketDetailsParams {
                identifier: "MOT/T56094".to_string(),
                expected_isin: Some("IT0005560948.MOT".to_string()),
                sections: None,
            },
            "2026-06-14T09:30:00Z",
        )
        .expect_err("unsupported details should fail closed after search resolution");

    assert_eq!(err.code(), "market_unsupported_asset_type");
    assert!(err.safe_message().contains("bond"));
}
