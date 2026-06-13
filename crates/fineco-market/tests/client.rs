//! Integration tests: the market client fetches over a real socket against the
//! SYNTHETIC mock enrichment + mock Fineco servers. No real host is used; the
//! allowlist pins the loopback mock.

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use fineco_market::{EnrichmentHostAllowlist, MarketClient};

const NOW: &str = "2026-06-03T12:00:00Z";
const ETF_PATH: &str = "/common-pvt/js/json/etf-zero/etf_piu_scambiati.json";

/// Serve `handler` on an ephemeral port; return its base URL.
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

type Captured = Arc<Mutex<Vec<(String, String)>>>;

/// Serve `route` while capturing the headers of the last request received.
fn spawn_capturing<F>(route: F) -> (String, Captured)
where
    F: Fn(&httptiny::Request) -> httptiny::Response + Send + Sync + 'static,
{
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let base = spawn(move |req| {
        *sink.lock().expect("lock") = req.headers.clone();
        route(req)
    });
    (base, captured)
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

/// A client whose allowlist pins the loopback mock host.
fn client_for(enrichment_base: &str, etf_url: &str) -> MarketClient {
    MarketClient::new(
        enrichment_base,
        EnrichmentHostAllowlist::from_allowed_hosts(["127.0.0.1"]),
        etf_url,
    )
}

#[test]
fn fetches_and_parses_enrichment_over_http() {
    let enrichment = spawn(|req| {
        let path = req.path.split('?').next().unwrap_or(&req.path);
        if req.method == "GET" && path == "/stock/BIT/TIP" {
            mock_enrichment::route(&httptiny::Request {
                method: req.method.clone(),
                path: "/stocks/it/diversified-financials/syn-tip/synth-shares".to_string(),
                headers: req.headers.clone(),
            })
        } else {
            httptiny::Response::not_found()
        }
    });
    let etf = spawn(mock_fineco::route);
    let client = client_for(&enrichment, &format!("{etf}{ETF_PATH}"));

    let report = client
        .fetch_enrichment("BIT/TIP", Some("IT0003153621"), NOW)
        .expect("enrichment fetch should succeed");

    assert_eq!(
        report.company.name,
        "SYNTHETIC Tamburi Investment Partners SpA"
    );
    assert_eq!(report.company.ticker, "BIT:TIP");
    assert_eq!(report.company.isin, "IT0003153621");
    assert_eq!(report.metrics["value"]["pe"], serde_json::json!(12.3));
    assert_eq!(report.scores["total"], serde_json::json!(20));
    assert_eq!(report.source_url, format!("{enrichment}/stock/BIT/TIP"));
}

#[test]
fn qualified_identifier_fetches_singular_stock_page_path() {
    let enrichment = spawn(|req| {
        let path = req.path.split('?').next().unwrap_or(&req.path);
        if req.method == "GET" && path == "/stock/LSE/VHYL" {
            mock_enrichment::route(&httptiny::Request {
                method: req.method.clone(),
                path: "/stocks/it/diversified-financials/syn-tip/synth-shares".to_string(),
                headers: req.headers.clone(),
            })
        } else {
            httptiny::Response::not_found()
        }
    });
    let etf = spawn(mock_fineco::route);
    let client = client_for(&enrichment, &format!("{etf}{ETF_PATH}"));

    let report = client
        .fetch_enrichment("LSE/VHYL", Some("IT0003153621"), NOW)
        .expect("qualified ticker identifier should fetch /stock/");

    assert_eq!(report.source_url, format!("{enrichment}/stock/LSE/VHYL"));
    assert_eq!(report.company.ticker, "BIT:TIP");
}

#[test]
fn colon_qualified_identifier_is_normalized_to_slash_route() {
    let enrichment = spawn(|req| {
        let path = req.path.split('?').next().unwrap_or(&req.path);
        if req.method == "GET" && path == "/stock/LSE/VHYL" {
            mock_enrichment::route(&httptiny::Request {
                method: req.method.clone(),
                path: "/stocks/it/diversified-financials/syn-tip/synth-shares".to_string(),
                headers: req.headers.clone(),
            })
        } else {
            httptiny::Response::not_found()
        }
    });
    let etf = spawn(mock_fineco::route);
    let client = client_for(&enrichment, &format!("{etf}{ETF_PATH}"));

    let report = client
        .fetch_enrichment("lse:vhyl", Some("IT0003153621.AF"), NOW)
        .expect("colon-qualified ticker should normalize to slash route");

    assert_eq!(report.source_url, format!("{enrichment}/stock/LSE/VHYL"));
    assert_eq!(report.company.ticker, "BIT:TIP");
}

#[test]
fn bare_ticker_is_rejected_before_fetching() {
    let client = client_for("http://127.0.0.1:9", "http://127.0.0.1:9/etf");
    let err = client
        .fetch_enrichment("VHYL", None, NOW)
        .expect_err("bare ticker should not be routed or guessed");

    assert_eq!(err.code(), "invalid_request");
    assert!(err.safe_message().contains("bare tickers"));
}

#[test]
fn isin_shaped_identifier_is_rejected_before_fetching() {
    let client = client_for("http://127.0.0.1:9", "http://127.0.0.1:9/etf");

    for identifier in ["IE00B8GKDB10", "IE00B8GKDB10.AF"] {
        let err = client
            .fetch_enrichment(identifier, None, NOW)
            .expect_err("ISIN belongs in expected_isin, not identifier");
        assert_eq!(err.code(), "invalid_request", "{identifier}");
        assert!(err.safe_message().contains("expected_isin"));
    }
}

#[test]
fn malformed_expected_isin_is_rejected_before_fetching() {
    let requests = Arc::new(AtomicUsize::new(0));
    let request_counter = Arc::clone(&requests);
    let enrichment = spawn(move |_req| {
        request_counter.fetch_add(1, Ordering::SeqCst);
        httptiny::Response::not_found()
    });
    let client = client_for(&enrichment, "http://127.0.0.1:9/etf");

    let err = client
        .fetch_enrichment("LSE/VHYL", Some("not-an-isin"), NOW)
        .expect_err("malformed expected_isin should fail before fetch");

    assert_eq!(err.code(), "invalid_request");
    assert!(err.safe_message().contains("expected_isin"));
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

#[test]
fn rejects_unsafe_identifier_before_any_request() {
    // Pointed at a dead port: the identifier guard must fire before connecting.
    let client = client_for("http://127.0.0.1:9", "http://127.0.0.1:9/etf");
    for bad in [
        "",
        "/leading-slash",
        "trailing-slash/",
        "../secret",
        "a/../b",
        "double//slash",
        "https://evil/x",
        "a@b/c",
        "a b",
        "x?y",
        "x#y",
        // Percent-encoded traversal / separator must be rejected too.
        "%2e%2e/x",
        "a%2fb",
        "a\\b",
    ] {
        let err = client
            .fetch_enrichment(bad, None, NOW)
            .expect_err("unsafe identifier must be rejected");
        assert_eq!(err.code(), "invalid_request", "identifier {bad:?}");
    }
}

#[test]
fn refuses_cleartext_to_a_non_loopback_host() {
    // An https-less base to a real host must be rejected before any fetch, even
    // when that host is on the allowlist.
    let client = MarketClient::new(
        "http://stocks.example",
        EnrichmentHostAllowlist::from_allowed_hosts(["stocks.example"]),
        "http://127.0.0.1:9/etf",
    );
    let err = client
        .fetch_enrichment("LSE/VHYL", None, NOW)
        .expect_err("cleartext to a non-loopback host must be rejected");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn refuses_cleartext_etf_url() {
    // The public ETF fetch must enforce the same https-or-loopback transport
    // posture as enrichment.
    let client = MarketClient::new(
        "https://stocks.example",
        EnrichmentHostAllowlist::from_allowed_hosts(["stocks.example"]),
        "http://etf.example/list",
    );
    let err = client
        .fetch_zero_commission_etfs(NOW)
        .expect_err("cleartext ETF url to a non-loopback host must be rejected");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn rejects_off_allowlist_host() {
    // The mock host is real and reachable, but it is not on this allowlist, so
    // the built URL must be rejected before any fetch.
    let enrichment = spawn(mock_enrichment::route);
    let client = MarketClient::new(
        &enrichment,
        EnrichmentHostAllowlist::from_allowed_hosts(["stocks.example"]),
        "http://127.0.0.1:9/etf",
    );
    let err = client
        .fetch_enrichment("LSE/VHYL", None, NOW)
        .expect_err("off-allowlist host must be rejected");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn fetches_public_zero_commission_etfs() {
    let etf = spawn(mock_fineco::route);
    let client = client_for("http://127.0.0.1:9", &format!("{etf}{ETF_PATH}"));

    let etfs = client
        .fetch_zero_commission_etfs(NOW)
        .expect("etf fetch should succeed");
    assert_eq!(etfs.captured_at, NOW);
    assert_eq!(etfs.count, 2);
    assert_eq!(etfs.instruments[0].instr_id, "SYNTHETF0001");
    assert_eq!(etfs.instruments[0].venue_system, "SYNTHV");
    assert_eq!(etfs.instruments[0].issuer, "SYNTHETIC Asset Mgmt");
}

#[test]
fn enrichment_fetch_sends_browser_headers() {
    // The enrichment fetch must carry the reference's browser context (UA +
    // Accept-Language), or real pages may return bot-defense/locale responses.
    let (base, captured) = spawn_capturing(|req| {
        let path = req.path.split('?').next().unwrap_or(&req.path);
        if req.method == "GET" && path == "/stock/BIT/TIP" {
            mock_enrichment::route(&httptiny::Request {
                method: req.method.clone(),
                path: "/stocks/it/diversified-financials/syn-tip/synth-shares".to_string(),
                headers: req.headers.clone(),
            })
        } else {
            httptiny::Response::not_found()
        }
    });
    let client = client_for(&base, "http://127.0.0.1:9/etf");
    client
        .fetch_enrichment("BIT/TIP", None, NOW)
        .expect("enrichment fetch");

    let headers = captured.lock().expect("lock");
    assert!(has_header(&headers, "user-agent"), "missing User-Agent");
    assert!(
        has_header(&headers, "accept-language"),
        "missing Accept-Language"
    );
}

#[test]
fn etf_fetch_sends_browser_headers() {
    // The public ETF fetch must carry the Fineco page context (UA + Origin +
    // Referer), or the real endpoint may serve a browser-gated response.
    let (base, captured) = spawn_capturing(mock_fineco::route);
    let client = client_for("http://127.0.0.1:9", &format!("{base}{ETF_PATH}"));
    client.fetch_zero_commission_etfs(NOW).expect("etf fetch");

    let headers = captured.lock().expect("lock");
    assert!(has_header(&headers, "user-agent"), "missing User-Agent");
    assert!(has_header(&headers, "origin"), "missing Origin");
    assert!(has_header(&headers, "referer"), "missing Referer");
}
