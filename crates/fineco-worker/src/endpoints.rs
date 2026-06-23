//! Allowlisted Fineco endpoint URLs.
//!
//! The worker builds every request URL from this fixed set — there is no
//! client-supplied URL or path. [`FinecoEndpoints::production`] holds the real
//! private Fineco API hosts (ported from the TS reference);
//! [`FinecoEndpoints::for_base`] collapses them onto a single base URL so tests
//! can point the worker at the mock server.
//!
//! Only authenticated reads live here: the credential worker is outbound to
//! Fineco-login-gated endpoints only. The public zero-commission ETF list and
//! third-party enrichment are handled by the credential-free market path, never
//! this worker (security plan §"Stock enrichment must not run inside
//! private-fineco-worker").

/// The read-only, authenticated Fineco endpoints the worker may call.
pub struct FinecoEndpoints {
    /// Public home page, fetched as a login preflight to bootstrap cookies.
    pub(crate) home: String,
    pub(crate) login: String,
    pub(crate) positions_summary: String,
    pub(crate) transactions: String,
    pub(crate) global_search: String,
    pub(crate) static_search: String,
    pub(crate) instruments_snapshot: String,
    pub(crate) indicesbar: String,
    pub(crate) etf_query: String,
    pub(crate) stock_snapshot: String,
    pub(crate) stock_reports: String,
    pub(crate) tax_carry_forward: String,
    pub(crate) tax_minus: String,
    pub(crate) movements: String,
}

impl FinecoEndpoints {
    /// The real Fineco private-API endpoints (ported from `fineco-portfolio.ts`).
    #[must_use]
    pub fn production() -> Self {
        Self {
            home: "https://it.finecobank.com/".to_string(),
            login: "https://public-api.finecobank.com/v1/public/authentications/web/login?sca=true"
                .to_string(),
            positions_summary:
                "https://private-api.finecobank.com/v1/private/tol/positions/summary?type=sintesi"
                    .to_string(),
            transactions: "https://private-api.finecobank.com/v1/private/tol/transactions"
                .to_string(),
            global_search:
                "https://private-api.finecobank.com/v1/private/tol/stocklists/search/global"
                    .to_string(),
            static_search:
                "https://private-api.finecobank.com/v1/private/tol/instruments/static/search"
                    .to_string(),
            instruments_snapshot:
                "https://private-api.finecobank.com/v1/private/tol/instruments/snapshot".to_string(),
            indicesbar: "https://private-api.finecobank.com/v1/private/tol/indicesbar/indices"
                .to_string(),
            etf_query: "https://private-api.finecobank.com/v1/private/tol/etf/query".to_string(),
            stock_snapshot: "https://private-api.finecobank.com/v1/private/snapshot".to_string(),
            stock_reports: "https://private-api.finecobank.com/v1/private/snapshot/reports"
                .to_string(),
            tax_carry_forward:
                "https://private-api.finecobank.com/v1/private/tax-carry-forward/search".to_string(),
            tax_minus: "https://private-api.finecobank.com/v1/private/tax-carry-forward/minus"
                .to_string(),
            movements: "https://private-api.finecobank.com/v2/private/accounts-and-cards/movements"
                .to_string(),
        }
    }

    /// Point every endpoint at a single `base` URL (e.g. the mock server). The
    /// paths mirror the real Fineco paths so the mock and production agree.
    #[must_use]
    pub fn for_base(base: &str) -> Self {
        let base = base.trim_end_matches('/');
        Self {
            home: format!("{base}/"),
            login: format!("{base}/v1/public/authentications/web/login?sca=true"),
            positions_summary: format!("{base}/v1/private/tol/positions/summary?type=sintesi"),
            transactions: format!("{base}/v1/private/tol/transactions"),
            global_search: format!("{base}/v1/private/tol/stocklists/search/global"),
            static_search: format!("{base}/v1/private/tol/instruments/static/search"),
            instruments_snapshot: format!("{base}/v1/private/tol/instruments/snapshot"),
            indicesbar: format!("{base}/v1/private/tol/indicesbar/indices"),
            etf_query: format!("{base}/v1/private/tol/etf/query"),
            stock_snapshot: format!("{base}/v1/private/snapshot"),
            stock_reports: format!("{base}/v1/private/snapshot/reports"),
            tax_carry_forward: format!("{base}/v1/private/tax-carry-forward/search"),
            tax_minus: format!("{base}/v1/private/tax-carry-forward/minus"),
            movements: format!("{base}/v2/private/accounts-and-cards/movements"),
        }
    }
}
