//! Integration test: the market client fetches the ETF reference-data report over
//! a real socket against a SYNTHETIC mock profile server. No real host is used;
//! the ETF allowlist pins the loopback mock.

use std::net::TcpListener;
use std::thread;

use fineco_market::{EnrichmentHostAllowlist, MarketClient};

const NOW: &str = "2026-06-17T09:00:00Z";
// The zero-commission ETF list is never fetched in these tests, so its URL is a
// placeholder that is never contacted.
const UNUSED_LIST_URL: &str = "http://unused.invalid/list";

fn spawn<F>(handler: F) -> String
where
    F: Fn(&httptiny::Request) -> httptiny::Response + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, handler);
    });
    format!("http://{addr}")
}

/// A synthetic ETF-profile page: the `data-testid` basics contract with fictional
/// values and no real host/provider reference.
fn synthetic_profile(isin: &str) -> String {
    format!(
        "<html><body>\
         <span data-testid=\"etf-profile-header_isin-value\">{isin}</span>\
         <td data-testid=\"tl_etf-basics_value_ter\">0.29% p.a.</td>\
         <div data-testid=\"etf-profile-header_fund-size-value-wrapper\"> <span>EUR 8,622</span> m <span data-testid=\"etf-profile-header_fund-size-indicator\"></span></div>\
         <tr data-testid=\"etf-basics_row_fund-size\"><td class=\"vallabel\">Fund size</td><td><div>EUR 8,622 m <span data-testid=\"tl_etf-basics_value_fund-size_indicator\"></span></div></td></tr>\
         <td data-testid=\"tl_etf-basics_value_domicile-country\">Ireland</td>\
         <td data-testid=\"tl_etf-basics_value_distribution-policy\">Distributing</td>\
         <td data-testid=\"tl_etf-basics_value_replication\">Physical (Optimized sampling)</td>\
         </body></html>"
    )
}

#[test]
fn fetches_and_parses_etf_enrichment_over_http() {
    let isin = "IE00B8GKDB10";
    let profile = spawn(move |req| {
        let path = req.path.split('?').next().unwrap_or(&req.path);
        if req.method == "GET" && path == "/en/etf-profile.html" {
            httptiny::Response::html(200, synthetic_profile("IE00B8GKDB10"))
        } else {
            httptiny::Response::not_found()
        }
    });

    // ETF enrichment is enabled WITHOUT stock enrichment (decoupled).
    let client = MarketClient::list_only(UNUSED_LIST_URL).with_etf_enrichment(
        &profile,
        EnrichmentHostAllowlist::from_allowed_hosts(["127.0.0.1"]),
    );

    assert!(client.etf_enrichment_enabled());
    assert!(!client.stock_enrichment_enabled());

    let report = client
        .fetch_etf_enrichment(isin, Some(isin), NOW)
        .expect("etf enrichment fetch should succeed");

    assert_eq!(report.isin, "IE00B8GKDB10");
    assert_eq!(report.ter_percent, Some(0.29));
    assert_eq!(report.domicile.as_deref(), Some("Ireland"));
    assert_eq!(report.distribution_policy.as_deref(), Some("Distributing"));
    let size = report.fund_size.expect("fund size");
    assert_eq!(size.value, 8622.0);
    assert_eq!(size.unit, "EUR million");
    assert_eq!(
        report.source_url,
        format!("{profile}/en/etf-profile.html?isin=IE00B8GKDB10")
    );
}

#[test]
fn unconfigured_etf_enrichment_is_a_clean_error() {
    let client = MarketClient::list_only(UNUSED_LIST_URL);
    assert!(!client.etf_enrichment_enabled());
    let err = client
        .fetch_etf_enrichment("IE00B8GKDB10", None, NOW)
        .expect_err("unconfigured ETF enrichment must error cleanly");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn malformed_isin_is_rejected_before_any_fetch() {
    let client = MarketClient::list_only(UNUSED_LIST_URL).with_etf_enrichment(
        "http://127.0.0.1:1",
        EnrichmentHostAllowlist::from_allowed_hosts(["127.0.0.1"]),
    );
    let err = client
        .fetch_etf_enrichment("not-an-isin", None, NOW)
        .expect_err("malformed ISIN must error");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn page_isin_mismatch_is_rejected_even_without_expected_isin() {
    // The URL is keyed by the lookup ISIN, so a page whose header echoes a DIFFERENT
    // ISIN must be rejected even when the caller passed no expected_isin — otherwise
    // wrong-ETF data could be attached. The server returns a profile for a different
    // ISIN than requested.
    let profile = spawn(move |req| {
        let path = req.path.split('?').next().unwrap_or(&req.path);
        if req.method == "GET" && path == "/en/etf-profile.html" {
            // A valid-format ISIN, but a DIFFERENT fund than the one requested.
            httptiny::Response::html(200, synthetic_profile("IE00B5BMR087"))
        } else {
            httptiny::Response::not_found()
        }
    });
    let client = MarketClient::list_only(UNUSED_LIST_URL).with_etf_enrichment(
        &profile,
        EnrichmentHostAllowlist::from_allowed_hosts(["127.0.0.1"]),
    );
    let err = client
        .fetch_etf_enrichment("IE00B8GKDB10", None, NOW)
        .expect_err("page ISIN mismatch must be rejected without expected_isin");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn page_is_verified_against_lookup_isin_not_just_expected() {
    // The route is keyed by the lookup ISIN. A page for a DIFFERENT ISIN must be
    // rejected even if the caller's (stale/mismatched) expected_isin happens to
    // match that wrong page — verification is anchored to the lookup ISIN.
    let profile = spawn(|req| {
        let path = req.path.split('?').next().unwrap_or(&req.path);
        if req.method == "GET" && path == "/en/etf-profile.html" {
            httptiny::Response::html(200, synthetic_profile("IE00B5BMR087"))
        } else {
            httptiny::Response::not_found()
        }
    });
    let client = MarketClient::list_only(UNUSED_LIST_URL).with_etf_enrichment(
        &profile,
        EnrichmentHostAllowlist::from_allowed_hosts(["127.0.0.1"]),
    );
    // Lookup IE00B8GKDB10, but the caller passes the wrong page's ISIN as expected.
    let err = client
        .fetch_etf_enrichment("IE00B8GKDB10", Some("IE00B5BMR087"), NOW)
        .expect_err("must verify against the lookup ISIN, not just expected_isin");
    assert_eq!(err.code(), "invalid_request");
}
