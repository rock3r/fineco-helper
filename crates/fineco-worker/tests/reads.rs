//! Integration tests: the worker logs in against the SYNTHETIC mock Fineco over
//! a real socket and parses each authenticated read into store-ready types. No
//! real credentials — the mock accepts any login. Input bounds are enforced
//! before any request is made.

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use fineco_ipc::{
    MarketAssetDetailsLiveFetcher, MarketAssetType, MarketDetailsParams, MarketDetailsSection,
    MarketIndexRegion, MarketIndicesLiveFetcher, MarketIndicesParams, MarketSearchLiveFetcher,
    MarketSearchParams,
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

fn spawn_mock_fineco_with_broken_etf_detail_snapshot() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, |req| {
            let path = req.path.split('?').next().unwrap_or(&req.path);
            if req.method == "GET"
                && path == "/v1/private/tol/etf/query"
                && req.path.contains("view=snapshot")
            {
                return httptiny::Response::json(503, "{\"error\":\"etf snapshot unavailable\"}");
            }
            mock_fineco::route(req)
        });
    });
    format!("http://{addr}")
}

fn spawn_mock_fineco_with_broken_stock_detail_snapshot() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, |req| {
            let path = req.path.split('?').next().unwrap_or(&req.path);
            if req.method == "GET" && path == "/v1/private/snapshot/NASDAQ/US0378331005" {
                return httptiny::Response::json(503, "{\"error\":\"stock snapshot unavailable\"}");
            }
            mock_fineco::route(req)
        });
    });
    format!("http://{addr}")
}

fn spawn_mock_fineco_search_only() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, |req| {
            let path = req.path.split('?').next().unwrap_or(&req.path);
            if path == "/"
                || path == "/v1/public/authentications/web/login"
                || path == "/v1/private/tol/stocklists/search/global"
            {
                mock_fineco::route(req)
            } else {
                httptiny::Response::json(500, r#"{"error":"details endpoint should not be hit"}"#)
            }
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
    assert_eq!(live.session.session_expires_in_secs, Some(3600));
}

#[test]
fn logs_in_and_fetches_authenticated_market_indices() {
    let base = spawn_mock_fineco();
    let live = worker_for(&base)
        .fetch_market_indices(
            &MarketIndicesParams {
                region: Some(MarketIndexRegion::Europe),
                limit: Some(10),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("market indices fetch should succeed");
    let result = live.result;

    assert_eq!(result.schema_version, 1);
    assert_eq!(result.data_class, "authenticated_market");
    assert_eq!(result.source, "fineco.indicesbar");
    assert_eq!(result.indices.len(), 2);
    assert_eq!(result.indices[0].symbol.value, "^FTMIB.affIdx");
    assert_eq!(result.indices[0].region, MarketIndexRegion::Europe);
    assert_eq!(
        result.indices[0]
            .change_percent
            .as_ref()
            .map(|field| field.value),
        Some(1.97)
    );
    assert!(live.session.login_performed);
    assert!(!live.session.session_reused);
    assert_eq!(live.session.session_expires_in_secs, Some(3600));
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
    assert_eq!(live.session.session_expires_in_secs, Some(3600));
}

#[test]
fn etf_details_skip_quote_snapshot_when_quote_section_is_not_requested() {
    let base = spawn_mock_fineco_with_broken_quote_snapshot();
    let live = worker_for(&base)
        .fetch_market_asset_details(
            &MarketDetailsParams {
                identifier: "AFF/VHYL".to_string(),
                expected_isin: Some("IE00B8GKDB10.AFF".to_string()),
                sections: Some(vec![MarketDetailsSection::Etf]),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("ETF details without quote should not require quote snapshot");
    let result = live.result;

    assert_eq!(result.asset.identifier, "AFF/VHYL");
    assert!(result.sections.quote.is_none());
    assert_eq!(
        result
            .sections
            .etf
            .expect("etf")
            .ongoing_charge
            .expect("ongoing charge")
            .value,
        0.32
    );
    let sources: Vec<_> = result
        .sources
        .iter()
        .map(|source| source.source_ref.as_str())
        .collect();
    assert!(sources.contains(&"etf.query.snapshot"));
    assert!(!sources.contains(&"snapshot"));
}

#[test]
fn etf_details_skip_detail_snapshot_for_identity_and_listing_only() {
    let base = spawn_mock_fineco_with_broken_etf_detail_snapshot();
    let live = worker_for(&base)
        .fetch_market_asset_details(
            &MarketDetailsParams {
                identifier: "AFF/VHYL".to_string(),
                expected_isin: Some("IE00B8GKDB10.AFF".to_string()),
                sections: Some(vec![
                    MarketDetailsSection::Identity,
                    MarketDetailsSection::Listing,
                ]),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("identity/listing-only ETF details should not require ETF snapshot");
    let result = live.result;

    assert_eq!(result.asset.identifier, "AFF/VHYL");
    assert!(result.sections.listing.is_some());
    assert!(result.sections.profile.is_none());
    assert!(result.sections.etf.is_none());
    let sources: Vec<_> = result
        .sources
        .iter()
        .map(|source| source.source_ref.as_str())
        .collect();
    assert!(sources.contains(&"static.search"));
    assert!(!sources.contains(&"etf.query.snapshot"));
}

#[test]
fn identity_only_stock_details_stop_after_search_resolution() {
    let base = spawn_mock_fineco_search_only();
    let live = worker_for(&base)
        .fetch_market_asset_details(
            &MarketDetailsParams {
                identifier: "NASDAQ/AAPL".to_string(),
                expected_isin: Some("US0378331005".to_string()),
                sections: Some(vec![MarketDetailsSection::Identity]),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("identity-only details should not fetch static/snapshot endpoints");

    let result = live.result;
    assert_eq!(result.asset.identifier, "NASDAQ/AAPL");
    assert_eq!(result.asset.fineco_key.value, "US0378331005.NASDAQ");
    assert_eq!(result.asset.asset_type.value, MarketAssetType::Stock);
    assert!(result.sections.stock.is_none());
    assert!(result.sections.quote.is_none());
    assert_eq!(result.sources[0].source_ref, "search.global");
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
fn stock_details_skip_detail_snapshot_for_listing_and_ratios_only() {
    let base = spawn_mock_fineco_with_broken_stock_detail_snapshot();
    let live = worker_for(&base)
        .fetch_market_asset_details(
            &MarketDetailsParams {
                identifier: "NASDAQ/AAPL".to_string(),
                expected_isin: Some("US0378331005".to_string()),
                sections: Some(vec![
                    MarketDetailsSection::Listing,
                    MarketDetailsSection::Ratios,
                ]),
            },
            "2026-06-14T09:30:00Z",
        )
        .expect("listing/ratios-only stock details should not require stock snapshot");
    let result = live.result;

    assert_eq!(result.asset.identifier, "NASDAQ/AAPL");
    assert!(result.sections.listing.is_some());
    assert!(result.sections.ratios.is_some());
    assert!(result.sections.profile.is_none());
    assert!(result.sections.stock.is_none());
    let sources: Vec<_> = result
        .sources
        .iter()
        .map(|source| source.source_ref.as_str())
        .collect();
    assert!(sources.contains(&"static.search"));
    assert!(sources.contains(&"stock.reports"));
    assert!(!sources.contains(&"stock.snapshot"));
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
    let sources: Vec<_> = result
        .sources
        .iter()
        .map(|source| source.source_ref.as_str())
        .collect();
    assert!(sources.contains(&"stock.snapshot"));
    assert!(!sources.contains(&"snapshot"));
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

/// A mock that counts login POSTs (so a test can prove how many fresh logins a
/// sequence of reads triggered), delegating everything else to the real mock.
fn spawn_login_counting_mock(logins: Arc<AtomicUsize>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, move |req| {
            let path = req.path.split('?').next().unwrap_or(&req.path);
            if req.method == "POST" && path == "/v1/public/authentications/web/login" {
                logins.fetch_add(1, Ordering::SeqCst);
            }
            mock_fineco::route(req)
        });
    });
    format!("http://{addr}")
}

/// Like [`spawn_login_counting_mock`], but a one-shot `poison` flag makes the NEXT
/// private read return 401 (modelling a server-side session expiry), then clears.
fn spawn_poisoning_mock(logins: Arc<AtomicUsize>, poison: Arc<AtomicBool>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, move |req| {
            let path = req.path.split('?').next().unwrap_or(&req.path);
            if req.method == "POST" && path == "/v1/public/authentications/web/login" {
                logins.fetch_add(1, Ordering::SeqCst);
                return mock_fineco::route(req);
            }
            if path.starts_with("/v1/private/") && poison.swap(false, Ordering::SeqCst) {
                return httptiny::Response::json(401, "{\"error\":\"session expired\"}");
            }
            mock_fineco::route(req)
        });
    });
    format!("http://{addr}")
}

fn indices_params() -> MarketIndicesParams {
    MarketIndicesParams {
        region: None,
        limit: None,
    }
}

#[test]
fn market_reads_reuse_a_held_session_within_the_ttl() {
    let logins = Arc::new(AtomicUsize::new(0));
    let base = spawn_login_counting_mock(Arc::clone(&logins));
    let worker = worker_for(&base);

    let first = worker
        .fetch_market_indices(&indices_params(), "2026-06-03T12:00:00Z")
        .expect("first read");
    assert!(first.session.login_performed);
    assert!(!first.session.session_reused);

    // +30s, then +140s from the first read: each is within the rolling 120s window
    // (the window resets on every read), so both reuse the held session.
    let second = worker
        .fetch_market_indices(&indices_params(), "2026-06-03T12:00:30Z")
        .expect("second read reuses");
    assert!(second.session.session_reused);
    assert!(!second.session.login_performed);

    let third = worker
        .fetch_market_indices(&indices_params(), "2026-06-03T12:02:20Z")
        .expect("third read reuses");
    assert!(third.session.session_reused);

    assert_eq!(
        logins.load(Ordering::SeqCst),
        1,
        "one login served three reads"
    );

    // Past the window (last read 12:02:20 + 120s = 12:04:20): a fresh login.
    let fourth = worker
        .fetch_market_indices(&indices_params(), "2026-06-03T12:05:00Z")
        .expect("fourth read re-logs in");
    assert!(fourth.session.login_performed);
    assert!(!fourth.session.session_reused);
    assert_eq!(logins.load(Ordering::SeqCst), 2);
}

#[test]
fn market_reads_log_in_fresh_when_reuse_ttl_is_disabled() {
    let logins = Arc::new(AtomicUsize::new(0));
    let base = spawn_login_counting_mock(Arc::clone(&logins));
    let worker = worker_for(&base).with_market_reuse_ttl(None);

    for now in ["2026-06-03T12:00:00Z", "2026-06-03T12:00:30Z"] {
        let read = worker
            .fetch_market_indices(&indices_params(), now)
            .expect("read");
        assert!(read.session.login_performed);
        assert!(!read.session.session_reused);
    }
    assert_eq!(
        logins.load(Ordering::SeqCst),
        2,
        "reuse disabled: a fresh login per read"
    );
}

#[test]
fn reused_market_session_401_recovers_with_one_fresh_login() {
    let logins = Arc::new(AtomicUsize::new(0));
    let poison = Arc::new(AtomicBool::new(false));
    let base = spawn_poisoning_mock(Arc::clone(&logins), Arc::clone(&poison));
    let worker = worker_for(&base);

    worker
        .fetch_market_indices(&indices_params(), "2026-06-03T12:00:00Z")
        .expect("first read");
    assert_eq!(logins.load(Ordering::SeqCst), 1);

    // The server has since killed the session: the next (reused) private read 401s.
    poison.store(true, Ordering::SeqCst);
    let recovered = worker
        .fetch_market_indices(&indices_params(), "2026-06-03T12:00:30Z")
        .expect("reused-session 401 is repaired by one fresh login");

    assert!(recovered.session.reused_session_401_recovered);
    assert!(recovered.session.session_evicted);
    assert!(recovered.session.login_performed);
    assert_eq!(
        logins.load(Ordering::SeqCst),
        2,
        "exactly one extra login repaired the stale reused session"
    );
}

#[test]
fn a_refresh_login_evicts_the_held_market_session() {
    let logins = Arc::new(AtomicUsize::new(0));
    let base = spawn_login_counting_mock(Arc::clone(&logins));
    let worker = worker_for(&base);

    worker
        .fetch_market_indices(&indices_params(), "2026-06-03T12:00:00Z")
        .expect("market read");
    assert_eq!(logins.load(Ordering::SeqCst), 1);

    // A refresh logs in fresh; that must evict the held market session (D-22 G-2)
    // so the worker can't later reuse a session a refresh login may have poisoned.
    worker
        .fetch_portfolio("2026-06-03T12:00:30Z")
        .expect("refresh login");
    assert_eq!(logins.load(Ordering::SeqCst), 2);

    // Within the 120s window, but the held session was evicted → fresh login.
    let after = worker
        .fetch_market_indices(&indices_params(), "2026-06-03T12:00:45Z")
        .expect("market read after refresh");
    assert!(after.session.login_performed);
    assert!(!after.session.session_reused);
    assert_eq!(logins.load(Ordering::SeqCst), 3);
}

#[test]
fn a_fresh_login_401_evicts_the_session_so_the_next_read_relogs_in() {
    let logins = Arc::new(AtomicUsize::new(0));
    // Poison the FIRST private read: the freshly-logged-in session 401s on use.
    let poison = Arc::new(AtomicBool::new(true));
    let base = spawn_poisoning_mock(Arc::clone(&logins), Arc::clone(&poison));
    let worker = worker_for(&base);

    // A fresh-login 401 is NOT recovered (stays market_auth_required), and the
    // known-bad session must be evicted, not held for reuse.
    let err = worker
        .fetch_market_indices(&indices_params(), "2026-06-03T12:00:00Z")
        .expect_err("a fresh-login 401 surfaces as market_auth_required");
    assert_eq!(err.code(), "market_auth_required");
    assert_eq!(logins.load(Ordering::SeqCst), 1);

    // The next read within the window must re-login (the bad session was evicted),
    // not reuse the known-bad cookie.
    let after = worker
        .fetch_market_indices(&indices_params(), "2026-06-03T12:00:30Z")
        .expect("the next read logs in fresh");
    assert!(after.session.login_performed);
    assert!(!after.session.session_reused);
    assert_eq!(logins.load(Ordering::SeqCst), 2);
}
