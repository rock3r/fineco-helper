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
/// Canned synthetic zero-commission ETF list (public_market data class).
const ZERO_COMMISSION_ETFS: &str = include_str!("../../fixtures/fineco/zero-commission-etfs.json");

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
            Response::json(200, "{\"_fixture\":\"SYNTHETIC login ok\"}")
                .with_header("Set-Cookie", &format!("{SESSION_COOKIE}; Path=/; HttpOnly"))
        }

        // Private reads — gated behind the session cookie.
        ("GET", "/v1/private/tol/positions/summary") => private(req, PORTFOLIO),
        ("GET", "/v1/private/tol/transactions") => private(req, TRANSACTIONS),
        ("GET", "/v1/private/tax-carry-forward/search") => private(req, TAX_CARRY_FORWARD),
        ("GET", "/v1/private/tax-carry-forward/minus") => private(req, TAX_MINUS),

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
            Response::json(200, "{\"_fixture\":\"SYNTHETIC login ok\"}")
                .with_header("Set-Cookie", &format!("{SESSION_COOKIE}; Path=/; HttpOnly"))
        }

        // Everything else (private reads, public ETF list) is identical.
        _ => route(req),
    }
}
