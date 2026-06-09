//! Mock third-party stock enrichment server for the E2E harness. Serves a
//! canned, synthetic stock page under the real `/stocks/<slug…>` path. The page
//! embeds `window.__REACT_QUERY_STATE__` (plus a never-run script) so the
//! enrichment path can prove it parses HTML as data and never executes it. Test
//! infra only.

use httptiny::{Request, Response};

/// Canned synthetic stock page (embeds a parseable `__REACT_QUERY_STATE__`).
const STOCK_PAGE: &str = include_str!("../../fixtures/enrichment/stock.html");

/// Route a request to a canned response. Stock pages live under
/// `/stocks/<slug…>` (a multi-segment slug, as on the real host). Unknown routes
/// return 404.
#[must_use]
pub fn route(req: &Request) -> Response {
    if req.method != "GET" {
        return Response::not_found();
    }
    let path = req.path.split('?').next().unwrap_or(&req.path);
    if path == "/healthz" {
        return Response::text(200, "ok");
    }
    // A stock page: `/stocks/` followed by a non-empty slug.
    if let Some(slug) = path.strip_prefix("/stocks/")
        && !slug.is_empty()
    {
        return Response::html(200, STOCK_PAGE);
    }
    Response::not_found()
}
