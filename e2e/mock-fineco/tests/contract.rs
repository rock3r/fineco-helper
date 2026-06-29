//! Contract tests for the mock Fineco server. These model the real Fineco
//! endpoints the M3 credential worker calls: a login that issues a session
//! cookie, private reads gated behind that cookie, and the public
//! zero-commission ETF list. All fixtures are SYNTHETIC — never real account
//! data. Test infrastructure only.

use httptiny::{Request, Response};
use mock_fineco::{PREFLIGHT_COOKIE, SESSION_COOKIE, route, route_cookieless_home};

fn req(method: &str, path: &str, headers: Vec<(String, String)>) -> Response {
    route(&Request {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body: String::new(),
    })
}

fn get(path: &str) -> Response {
    req("GET", path, Vec::new())
}

/// An authenticated private read: the session cookie, the account selector, and
/// the calling-page Referer the private APIs require.
fn get_authed(path: &str) -> Response {
    req(
        "GET",
        path,
        vec![
            ("Cookie".to_string(), SESSION_COOKIE.to_string()),
            ("X-Account-Index".to_string(), "0".to_string()),
            (
                "Referer".to_string(),
                "https://finecobank.com/pvt/portfolio".to_string(),
            ),
        ],
    )
}

#[test]
fn health_is_ok() {
    let r = get("/healthz");
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "ok");
}

#[test]
fn home_preflight_issues_a_cookie() {
    let r = get("/");
    assert_eq!(r.status, 200);
    let set_cookie = r
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, value)| value.as_str())
        .expect("the home preflight must issue a Set-Cookie");
    assert!(set_cookie.contains(PREFLIGHT_COOKIE));
}

#[test]
fn login_issues_a_session_cookie() {
    // Login requires the preflight cookie the home page issued and the
    // public-site browser origin.
    let r = req(
        "POST",
        "/v1/public/authentications/web/login?sca=true",
        vec![
            ("Cookie".to_string(), PREFLIGHT_COOKIE.to_string()),
            (
                "Origin".to_string(),
                "https://it.finecobank.com".to_string(),
            ),
        ],
    );
    assert_eq!(r.status, 200);
    // The worker reads the session from Set-Cookie and replays it on reads.
    let set_cookie = r
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, value)| value.as_str())
        .expect("login must issue a Set-Cookie");
    assert!(
        set_cookie.contains(SESSION_COOKIE),
        "Set-Cookie {set_cookie:?} must carry the session cookie {SESSION_COOKIE:?}"
    );
}

#[test]
fn login_requires_the_preflight_cookie() {
    // A login POST without the preflight cookie is rejected — never mints a
    // session straight away.
    let r = req(
        "POST",
        "/v1/public/authentications/web/login?sca=true",
        Vec::new(),
    );
    assert_eq!(r.status, 401);
}

#[test]
fn login_requires_the_browser_origin() {
    // With the preflight cookie but no Origin, login is rejected (400).
    let r = req(
        "POST",
        "/v1/public/authentications/web/login?sca=true",
        vec![("Cookie".to_string(), PREFLIGHT_COOKIE.to_string())],
    );
    assert_eq!(r.status, 400);
}

#[test]
fn login_rejects_non_post() {
    // The login endpoint is POST-only; a GET hits the public ETF/home routing,
    // never the login (so it cannot mint a session).
    assert_ne!(
        get("/v1/public/authentications/web/login?sca=true").status,
        200
    );
}

#[test]
fn private_reads_require_the_session_cookie() {
    // Without the session cookie every private read is 401 — never leaks data.
    // Covers the cached-data reads AND the authenticated-market reads (search,
    // instrument snapshot, indices, ETF query, stock snapshot/reports); each GET
    // carries the fixture-matching query so it reaches the session gate.
    for path in [
        "/v1/private/tol/positions/summary?type=sintesi",
        "/v1/private/tol/transactions?type=equity&days=0",
        "/v1/private/tax-carry-forward/search?dateFrom=2026-01-01&dateTo=2026-01-31",
        "/v1/private/tax-carry-forward/minus",
        "/v1/private/tol/stocklists/search/global?term=VHYL",
        "/v1/private/tol/instruments/snapshot?instruments=IE00B8GKDB10.AFF",
        "/v1/private/tol/indicesbar/indices",
        "/v1/private/tol/etf/query?type=ETF&ids=IE00B8GKDB10.AFF&view=snapshot",
        "/v1/private/snapshot/NASDAQ/US0378331005",
        "/v1/private/snapshot/reports/NASDAQ/US0378331005",
    ] {
        let r = get(path);
        assert_eq!(
            r.status, 401,
            "{path} must be 401 without the session cookie"
        );
        // The body must be the session-gate rejection, not any fixture. This is
        // the load-bearing leak guard: every private route's 401 carries the
        // `unauthenticated` error and no fixture markers do (the market fixtures
        // would otherwise not trip a `SYNTHETIC`-substring check).
        assert!(
            r.body.contains("unauthenticated") && !r.body.contains("SYNTHETIC"),
            "{path} must return the session-gate rejection, not fixture data"
        );
    }

    // The static instrument search is POST + body-gated; a cookieless POST whose
    // body matches a fixture must still be 401 before any data is served.
    let static_search = route(&Request {
        method: "POST".to_string(),
        path: "/v1/private/tol/instruments/static/search".to_string(),
        headers: Vec::new(),
        body: r#"{"instruments":["IE00B8GKDB10.AFF"]}"#.to_string(),
    });
    assert_eq!(
        static_search.status, 401,
        "static instrument search must be 401 without the session cookie"
    );
    assert!(
        static_search.body.contains("unauthenticated") && !static_search.body.contains("SYNTHETIC")
    );
}

#[test]
fn private_reads_require_the_account_index() {
    // Authenticated but missing the account selector → 400, no fixture data.
    let r = req(
        "GET",
        "/v1/private/tol/positions/summary?type=sintesi",
        vec![("Cookie".to_string(), SESSION_COOKIE.to_string())],
    );
    assert_eq!(r.status, 400);
    assert!(!r.body.contains("SYNTHETIC"));
}

#[test]
fn private_reads_require_a_referer() {
    // Authenticated with the account index but no Referer → 400, no fixture data.
    let r = req(
        "GET",
        "/v1/private/tol/positions/summary?type=sintesi",
        vec![
            ("Cookie".to_string(), SESSION_COOKIE.to_string()),
            ("X-Account-Index".to_string(), "0".to_string()),
        ],
    );
    assert_eq!(r.status, 400);
    assert!(!r.body.contains("SYNTHETIC"));
}

#[test]
fn positions_summary_returns_synthetic_shape() {
    let r = get_authed("/v1/private/tol/positions/summary?type=sintesi");
    assert_eq!(r.status, 200);
    assert!(r.content_type.starts_with("application/json"));
    assert!(
        r.body.contains("SYNTHETIC"),
        "fixture must be clearly synthetic"
    );
    // Real Fineco positions-summary shape the worker parses.
    assert!(r.body.contains("\"summary\""));
    assert!(r.body.contains("\"positions\""));
    assert!(r.body.contains("\"instrId\""));
    assert!(r.body.contains("\"venueSystem\""));
}

#[test]
fn transactions_returns_synthetic_shape() {
    let r = get_authed("/v1/private/tol/transactions?type=equity&days=0");
    assert_eq!(r.status, 200);
    assert!(r.content_type.starts_with("application/json"));
    assert!(r.body.contains("SYNTHETIC"));
    assert!(r.body.contains("\"transactions\""));
    assert!(r.body.contains("\"transId\""));
}

#[test]
fn tax_carry_forward_returns_synthetic_shape() {
    let r =
        get_authed("/v1/private/tax-carry-forward/search?dateFrom=2026-01-01&dateTo=2026-01-31");
    assert_eq!(r.status, 200);
    assert!(r.content_type.starts_with("application/json"));
    assert!(r.body.contains("SYNTHETIC"));
    assert!(r.body.contains("\"total\""));
}

#[test]
fn tax_minus_returns_synthetic_shape() {
    let r = get_authed("/v1/private/tax-carry-forward/minus");
    assert_eq!(r.status, 200);
    assert!(r.content_type.starts_with("application/json"));
    assert!(r.body.contains("SYNTHETIC"));
    assert!(r.body.contains("\"minusResidue\""));
    assert!(r.body.contains("\"expirationDate\""));
}

/// An authenticated private POST (session cookie + account selector + Referer).
fn post_authed(path: &str, body: &str) -> Response {
    route(&Request {
        method: "POST".to_string(),
        path: path.to_string(),
        headers: vec![
            ("Cookie".to_string(), SESSION_COOKIE.to_string()),
            ("X-Account-Index".to_string(), "0".to_string()),
            (
                "Referer".to_string(),
                "https://finecobank.com/pvt/banking".to_string(),
            ),
        ],
        body: body.to_string(),
    })
}

const MONEYMAP_PATH: &str = "/conto-e-carte/bilancio-familiare/widget-home/preload-data";

#[test]
fn moneymap_categories_returns_synthetic_taxonomy() {
    // The web MoneyMap taxonomy endpoint: a private POST (empty `{}` body) gated
    // behind the session cookie, returning a map keyed by category id with the
    // snake_case shape the worker flattens.
    let r = post_authed(MONEYMAP_PATH, "{}");
    assert_eq!(r.status, 200);
    assert!(r.content_type.starts_with("application/json"));
    assert!(r.body.contains("\"id_categoria\""));
    assert!(r.body.contains("\"categoria\""));
    assert!(r.body.contains("\"sottocategorie\""));
    assert!(r.body.contains("\"id_sottocategoria\""));
    assert!(r.body.contains("\"sottocategoria\""));
}

#[test]
fn moneymap_categories_requires_the_session_cookie() {
    // Like every other private read, it 401s without the session cookie.
    let r = route(&Request {
        method: "POST".to_string(),
        path: MONEYMAP_PATH.to_string(),
        headers: Vec::new(),
        body: "{}".to_string(),
    });
    assert_eq!(r.status, 401);
}

#[test]
fn zero_commission_etfs_is_a_public_list() {
    // The public ETF list needs no session cookie.
    let r = get("/common-pvt/js/json/etf-zero/etf_piu_scambiati.json");
    assert_eq!(r.status, 200);
    assert!(r.content_type.starts_with("application/json"));
    assert!(r.body.contains("SYNTHETIC"));
    assert!(r.body.contains("\"instruments\""));
}

#[test]
fn unknown_route_is_404() {
    assert_eq!(get("/api/does-not-exist").status, 404);
}

// --- route_cookieless_home: models real Fineco's cookie-less public home ---

fn cookieless(method: &str, path: &str, headers: Vec<(String, String)>) -> Response {
    route_cookieless_home(&Request {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body: String::new(),
    })
}

#[test]
fn cookieless_home_issues_no_cookie() {
    // Real Fineco's public home page sets no cookie, so the worker has none to
    // replay and must mint synthetic ones instead.
    let r = cookieless("GET", "/", Vec::new());
    assert_eq!(r.status, 200);
    assert!(
        !r.headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("set-cookie")),
        "the cookie-less home must NOT issue a Set-Cookie"
    );
}

#[test]
fn cookieless_login_rejects_without_synthetic_cookies() {
    // A login POST carrying no synthetic public cookies is answered with Fineco's
    // generic 403 auth.invalid.credentials shape — exactly the production symptom.
    let r = cookieless(
        "POST",
        "/v1/public/authentications/web/login?sca=true",
        vec![(
            "Origin".to_string(),
            "https://it.finecobank.com".to_string(),
        )],
    );
    assert_eq!(r.status, 403);
    assert!(r.body.contains("auth.invalid.credentials"));
}

#[test]
fn cookieless_login_succeeds_with_synthetic_cookies() {
    // With ALL seven synthetic public cookies present (names; the five non-fixed
    // values are random per login), login issues the session cookie the reads
    // then replay.
    let r = cookieless(
        "POST",
        "/v1/public/authentications/web/login?sca=true",
        vec![
            (
                "Cookie".to_string(),
                "finecostat=abc.def; XID=1.2; LBM=pubsapipr03; PORTALSESSIONID=12345678; \
                 gdate=1; store-sessionid=s; finecoLogin=f"
                    .to_string(),
            ),
            (
                "Origin".to_string(),
                "https://it.finecobank.com".to_string(),
            ),
        ],
    );
    assert_eq!(r.status, 200);
    let set_cookie = r
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, value)| value.as_str())
        .expect("login must issue a Set-Cookie");
    assert!(set_cookie.contains(SESSION_COOKIE));
}
