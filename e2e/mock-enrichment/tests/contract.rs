//! Contract tests for the mock enrichment server. Red→green driver: fails
//! against the 404 stub, passes once routing serves the canned synthetic page.

use httptiny::Request;
use mock_enrichment::route;

fn get(path: &str) -> httptiny::Response {
    route(&Request {
        method: "GET".to_string(),
        path: path.to_string(),
        headers: Vec::new(),
        body: String::new(),
    })
}

#[test]
fn health_is_ok() {
    let r = get("/healthz");
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "ok");
}

#[test]
fn stock_page_is_canned_synthetic_html() {
    let r = get("/stocks/it/diversified-financials/syn-tip/synth-shares");
    assert_eq!(r.status, 200);
    assert!(r.content_type.starts_with("text/html"));
    assert!(
        r.body.contains("SYNTHETIC"),
        "fixture must be clearly synthetic"
    );
    // The page embeds the React-Query cache the enrichment parser extracts.
    assert!(r.body.contains("window.__REACT_QUERY_STATE__"));
}

#[test]
fn unknown_route_is_404() {
    assert_eq!(get("/not-a-stock").status, 404);
}

#[test]
fn stock_path_requires_a_non_empty_slug() {
    // Stock pages live under `/stocks/<slug…>`; the slug may be multi-segment
    // (as on the real host) but must be non-empty.
    assert_eq!(get("/stocks/").status, 404);
    assert_eq!(get("/stocks").status, 404);
    assert_eq!(
        get("/stocks/it/diversified-financials/syn-tip/x").status,
        200
    );
}
