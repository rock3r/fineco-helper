//! Mock Fineco server for the E2E harness. Models the real Fineco endpoints the
//! M3 credential worker calls — a POST login that issues a session cookie,
//! private reads gated behind that cookie, and the public zero-commission ETF
//! list. Serves canned, SYNTHETIC fixtures only — never real account data. Test
//! infrastructure only.

use httptiny::{Request, Response};

/// The session cookie the mock issues on login and requires on private reads.
/// Fixed (not random) so tests are deterministic and the worker must faithfully
/// round-trip the `Set-Cookie` value it received.
pub const SESSION_COOKIE: &str = "FINECOSESSION=synthetic-session-token";

/// The cookie the home-page preflight issues, which login then requires — the
/// worker must fetch the home page and replay this cookie on the login POST.
pub const PREFLIGHT_COOKIE: &str = "FINECOPREFLIGHT=synthetic-preflight-token";

/// Canned synthetic positions-summary fixture (real Fineco shape).
const PORTFOLIO: &str = include_str!("../../fixtures/fineco/portfolio.json");
/// Canned synthetic order-monitor transactions fixture.
const TRANSACTIONS: &str = include_str!("../../fixtures/fineco/transactions.json");
/// Canned synthetic tax carry-forward search fixture.
const TAX_CARRY_FORWARD: &str = include_str!("../../fixtures/fineco/tax-carry-forward.json");
/// Canned synthetic tax minus-by-year fixture.
const TAX_MINUS: &str = include_str!("../../fixtures/fineco/tax-minus.json");
/// Canned synthetic MoneyMap (bilancio familiare) taxonomy fixture — the web
/// `widget-home/preload-data` shape: a map keyed by category id.
const MONEYMAP_CATEGORIES: &str = include_str!("../../fixtures/fineco/moneymap-categories.json");
/// Canned synthetic zero-commission ETF list (public_market data class).
const ZERO_COMMISSION_ETFS: &str = include_str!("../../fixtures/fineco/zero-commission-etfs.json");
/// Canned synthetic global instrument-search fixture.
const GLOBAL_SEARCH_VHYL: &str = include_str!("../../fixtures/fineco/global-search-vhyl.json");
/// Canned synthetic stock global-search fixture.
const GLOBAL_SEARCH_AAPL: &str = include_str!("../../fixtures/fineco/global-search-aapl.json");
/// Canned synthetic bond global-search fixture (now a supported details type).
const GLOBAL_SEARCH_T56094: &str = include_str!("../../fixtures/fineco/global-search-t56094.json");
/// Canned synthetic CFD global-search fixture (an unsupported details type).
const GLOBAL_SEARCH_CFD: &str = include_str!("../../fixtures/fineco/global-search-cfd.json");
/// Canned synthetic static instrument fixture.
const STATIC_SEARCH_VHYL: &str = include_str!("../../fixtures/fineco/static-search-vhyl.json");
/// Canned synthetic stock static instrument fixture.
const STATIC_SEARCH_AAPL: &str = include_str!("../../fixtures/fineco/static-search-aapl.json");
/// Canned synthetic bond static instrument fixture.
const STATIC_SEARCH_BOND: &str = include_str!("../../fixtures/fineco/static-search-bond.json");
/// Canned synthetic instrument snapshot fixture.
const SNAPSHOT_VHYL: &str = include_str!("../../fixtures/fineco/snapshot-vhyl.json");
/// Canned synthetic stock instrument quote fixture.
const SNAPSHOT_AAPL: &str = include_str!("../../fixtures/fineco/snapshot-aapl.json");
/// Canned synthetic bond instrument quote/yield fixture.
const SNAPSHOT_BOND: &str = include_str!("../../fixtures/fineco/snapshot-bond.json");
/// Canned synthetic ETF snapshot fixture.
const ETF_SNAPSHOT_VHYL: &str = include_str!("../../fixtures/fineco/etf-snapshot-vhyl.json");
/// Canned synthetic ETF composition fixture.
const ETF_COMPOSITION_VHYL: &str = include_str!("../../fixtures/fineco/etf-composition-vhyl.json");
/// Canned synthetic ETF returns fixture.
const ETF_RETURNS_VHYL: &str = include_str!("../../fixtures/fineco/etf-returns-vhyl.json");
/// Canned synthetic stock profile/snapshot fixture.
const STOCK_SNAPSHOT_AAPL: &str = include_str!("../../fixtures/fineco/stock-snapshot-aapl.json");
/// Canned synthetic stock reports fixture.
const STOCK_REPORTS_AAPL: &str = include_str!("../../fixtures/fineco/stock-reports-aapl.json");
/// Canned synthetic Fineco indices-bar fixture, shaped from captured HARs with
/// no auth/session material.
const INDICES_BAR: &str = r#"{
  "nextToken": "redacted",
  "indices": [
    {"symbol":"^FTMIB.affIdx","url":"/pvt/trading/stocklist/ftsemib","label":"Ftse mib","var":1.97},
    {"symbol":"^GDAXI.XETRA","url":"/pvt/trading/stocklist/dax","label":"Dax","var":1.76},
    {"symbol":"^DJI.NYSE","url":"/pvt/trading/stocklist/usadj","label":"Dow Jones","var":0.7},
    {"symbol":"^NDX.nasdaq-nm","url":"/pvt/trading/stocklist/nasdaq100","label":"Nasdaq","var":0.644},
    {"symbol":"MBTM6CFD.CFDC","url":"/pvt/trading/crypto/home/showcase","label":"BITCOIN","value":63535,"var":-0.4162},
    {"symbol":"^N225.Tokyo","url":"/pvt/trading/indices?listname=indiciAsia&titolo=^N225.Tokyo","label":"Nikkei","var":2.81}
  ]
}"#;

/// Path of the public, no-auth zero-commission ETF list (mirrors the real
/// `images.finecobank.com` JSON path).
const ZERO_COMMISSION_ETFS_PATH: &str = "/common-pvt/js/json/etf-zero/etf_piu_scambiati.json";

/// True if the request carries the session cookie issued at login.
fn is_authenticated(req: &Request) -> bool {
    req.header("Cookie")
        .is_some_and(|cookie| cookie.contains(SESSION_COOKIE))
}

/// A private read: serve the fixture only when the request is authenticated AND
/// carries the account selector the real private APIs require. Otherwise 401/400
/// with no fixture data (private reads never leak account data without a valid
/// session + account context).
fn private(req: &Request, body: &str) -> Response {
    if !is_authenticated(req) {
        return Response::json(401, "{\"error\":\"unauthenticated\"}");
    }
    if req.header("X-Account-Index") != Some("0") {
        return Response::json(400, "{\"error\":\"missing account index\"}");
    }
    // The private APIs expect the calling-page Referer.
    if !req
        .header("Referer")
        .is_some_and(|referer| referer.contains("finecobank.com"))
    {
        return Response::json(400, "{\"error\":\"missing referer\"}");
    }
    Response::json(200, body)
}

/// Synthetic paginating movements endpoint. Honors the `offset`/`limit` in the
/// POST body and sets `lastPage` once the window is exhausted, so the worker's
/// pagination loop is exercised end to end against a multi-page result. There are
/// `TOTAL` synthetic movements; each carries a unique `progressivoMovimento` so a
/// test can prove every page was accumulated with no drops or duplicates.
fn movements_page(req: &Request) -> Response {
    if !is_authenticated(req) {
        return Response::json(401, "{\"error\":\"unauthenticated\"}");
    }
    const TOTAL: i64 = 23;
    let offset = json_int(&req.body, "offset").unwrap_or(0).max(0);
    let limit = json_int(&req.body, "limit").unwrap_or(15).max(1);
    let end = (offset + limit).min(TOTAL);
    let items: Vec<String> = (offset..end)
        .map(|i| {
            format!(
                "{{\"progressivoMovimento\":\"MOV-{i}\",\"importo\":1.0,\
                 \"descrizione\":\"synthetic\",\"tipoMovimento\":\"MOVIMENTO_CONTO\"}}"
            )
        })
        .collect();
    let last_page = end >= TOTAL;
    // The account-level summary sits at the response top level and is carried on the
    // first page only (offset 0), mirroring the live endpoint; the worker reads it
    // there and ignores it on later pages.
    let summary = if offset == 0 {
        ",\"balanceAccountAtMovement\":1234.56,\"balanceAccountAtSearchDate\":1200.0,\
         \"currentMonthCreditSpending\":500.0,\"currentMonthDebtSpending\":-321.0"
    } else {
        ""
    };
    let body = format!(
        "{{\"movimenti\":[{}],\"lastPage\":{last_page},\
         \"limitedResult\":false,\"missingData\":[]{summary}}}",
        items.join(",")
    );
    Response::json(200, body)
}

/// Extract a JSON integer value for `key` from a flat request body (synthetic
/// helper — not a general JSON parser; the worker's bodies are flat objects).
fn json_int(body: &str, key: &str) -> Option<i64> {
    let pat = format!("\"{key}\":");
    let start = body.find(&pat)? + pat.len();
    let rest = body[start..].trim_start();
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    digits.parse().ok()
}

/// Route a request to a canned response. Unknown routes return 404. The session
/// cookie is minted by `POST /…/login` and required on every private read.
#[must_use]
pub fn route(req: &Request) -> Response {
    // The request target includes the query string; route on the path only.
    let path = req.path.split('?').next().unwrap_or(&req.path);

    match (req.method.as_str(), path) {
        ("GET", "/healthz") => Response::text(200, "ok"),

        // Login preflight: the public home page issues a bootstrap cookie that
        // login then requires (models Fineco's cookie-jar handshake).
        ("GET", "/") => Response::html(200, "<!-- SYNTHETIC home -->")
            .with_header("Set-Cookie", &format!("{PREFLIGHT_COOKIE}; Path=/")),

        // Login is POST-only; it requires the preflight cookie and issues the
        // session cookie the worker replays.
        ("POST", "/v1/public/authentications/web/login") => {
            if !req
                .header("Cookie")
                .is_some_and(|cookie| cookie.contains(PREFLIGHT_COOKIE))
            {
                return Response::json(401, "{\"error\":\"missing preflight cookie\"}");
            }
            // The login POST is expected to carry the public-site browser origin.
            if !req
                .header("Origin")
                .is_some_and(|origin| origin.contains("finecobank.com"))
            {
                return Response::json(400, "{\"error\":\"missing origin\"}");
            }
            Response::json(200, "{\"_fixture\":\"SYNTHETIC login ok\"}").with_header(
                "Set-Cookie",
                &format!("{SESSION_COOKIE}; Path=/; HttpOnly; Max-Age=3600"),
            )
        }

        // Private reads — gated behind the session cookie.
        ("GET", "/v1/private/tol/positions/summary") => private(req, PORTFOLIO),
        ("GET", "/v1/private/tol/transactions") => private(req, TRANSACTIONS),
        ("GET", "/v1/private/tol/stocklists/search/global") => {
            if req.path.contains("term=VHYL") {
                return private(req, GLOBAL_SEARCH_VHYL);
            }
            if req.path.contains("term=AAPL") {
                return private(req, GLOBAL_SEARCH_AAPL);
            }
            if req.path.contains("term=T56094") {
                return private(req, GLOBAL_SEARCH_T56094);
            }
            // The same synthetic bond is also discoverable by its ISIN, so a
            // `<venue>/<ISIN>` identifier resolves it.
            if req.path.contains("term=IT0005560948") {
                return private(req, GLOBAL_SEARCH_T56094);
            }
            if req.path.contains("term=SYNTHCFD") {
                return private(req, GLOBAL_SEARCH_CFD);
            }
            Response::json(400, "{\"error\":\"unexpected search term\"}")
        }
        ("POST", "/v1/private/tol/instruments/static/search") => {
            if req.body.contains("IE00B8GKDB10.AFF") {
                return private(req, STATIC_SEARCH_VHYL);
            }
            if req.body.contains("US0378331005.NASDAQ") {
                return private(req, STATIC_SEARCH_AAPL);
            }
            if req.body.contains("IT0005560948.MOT") {
                return private(req, STATIC_SEARCH_BOND);
            }
            Response::json(400, "{\"error\":\"unexpected static search body\"}")
        }
        ("GET", "/v1/private/tol/instruments/snapshot") => {
            if req.path.contains("instruments=IE00B8GKDB10.AFF") {
                return private(req, SNAPSHOT_VHYL);
            }
            if req.path.contains("instruments=US0378331005.NASDAQ") {
                return private(req, SNAPSHOT_AAPL);
            }
            if req.path.contains("instruments=IT0005560948.MOT") {
                return private(req, SNAPSHOT_BOND);
            }
            Response::json(400, "{\"error\":\"unexpected snapshot instrument\"}")
        }
        ("GET", "/v1/private/tol/indicesbar/indices") => private(req, INDICES_BAR),
        ("GET", "/v1/private/tol/etf/query") => {
            if !req.path.contains("ids=IE00B8GKDB10.AFF") {
                return Response::json(400, "{\"error\":\"unexpected etf id\"}");
            }
            if req.path.contains("view=snapshot") {
                return private(req, ETF_SNAPSHOT_VHYL);
            }
            if req.path.contains("view=composition") {
                return private(req, ETF_COMPOSITION_VHYL);
            }
            if req.path.contains("view=returns") {
                return private(req, ETF_RETURNS_VHYL);
            }
            Response::json(400, "{\"error\":\"unexpected etf view\"}")
        }
        ("GET", "/v1/private/snapshot/NASDAQ/US0378331005") => private(req, STOCK_SNAPSHOT_AAPL),
        ("GET", "/v1/private/snapshot/reports/NASDAQ/US0378331005") => {
            private(req, STOCK_REPORTS_AAPL)
        }
        ("GET", "/v1/private/tax-carry-forward/search") => private(req, TAX_CARRY_FORWARD),
        ("GET", "/v1/private/tax-carry-forward/minus") => private(req, TAX_MINUS),
        ("POST", "/v2/private/accounts-and-cards/movements") => movements_page(req),
        ("POST", "/conto-e-carte/bilancio-familiare/widget-home/preload-data") => {
            private(req, MONEYMAP_CATEGORIES)
        }

        // Public — no auth.
        ("GET", ZERO_COMMISSION_ETFS_PATH) => Response::json(200, ZERO_COMMISSION_ETFS),

        _ => Response::not_found(),
    }
}

/// The names of all seven synthetic public cookies the worker must mint when the
/// home preflight issues none. We key on the names (the five non-fixed values are
/// random per login), so a worker that drops or misnames any one of them fails
/// the login here — letting the integration test catch an incomplete cookie set.
const SYNTHETIC_COOKIE_MARKERS: [&str; 7] = [
    "finecostat=",
    "XID=",
    "LBM=pubsapipr03",
    "PORTALSESSIONID=",
    "gdate=",
    "store-sessionid=",
    "finecoLogin=",
];

/// True only if the login POST carries ALL seven synthetic public cookies.
fn carries_synthetic_cookies(req: &Request) -> bool {
    req.header("Cookie").is_some_and(|cookie| {
        SYNTHETIC_COOKIE_MARKERS
            .iter()
            .all(|marker| cookie.contains(marker))
    })
}

/// Like [`route`], but models the REAL Fineco public home page, which sets **no**
/// cookie. With no preflight cookie to replay, the worker must mint the synthetic
/// public cookies and send them on the login POST; login here fails (403, the
/// real `auth.invalid.credentials` shape) without them. Used to prove the worker
/// ports the reference's `syntheticPublicCookies()` step. Non-login/non-home
/// requests delegate to [`route`] (same session-cookie gating).
#[must_use]
pub fn route_cookieless_home(req: &Request) -> Response {
    let path = req.path.split('?').next().unwrap_or(&req.path);
    match (req.method.as_str(), path) {
        // Home preflight sets NO cookie (mirrors real Fineco).
        ("GET", "/") => Response::html(200, "<!-- SYNTHETIC home, no cookie -->"),

        ("POST", "/v1/public/authentications/web/login") => {
            if !carries_synthetic_cookies(req) {
                return Response::json(
                    403,
                    "{\"code\":403,\"issues\":[{\"severity\":\"error\",\
                     \"code\":\"auth.invalid.credentials\"}]}",
                );
            }
            if !req
                .header("Origin")
                .is_some_and(|origin| origin.contains("finecobank.com"))
            {
                return Response::json(400, "{\"error\":\"missing origin\"}");
            }
            Response::json(200, "{\"_fixture\":\"SYNTHETIC login ok\"}").with_header(
                "Set-Cookie",
                &format!("{SESSION_COOKIE}; Path=/; HttpOnly; Max-Age=3600"),
            )
        }

        // Everything else (private reads, public ETF list) is identical.
        _ => route(req),
    }
}
