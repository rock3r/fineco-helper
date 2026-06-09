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
    pub(crate) tax_carry_forward: String,
    pub(crate) tax_minus: String,
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
            tax_carry_forward:
                "https://private-api.finecobank.com/v1/private/tax-carry-forward/search".to_string(),
            tax_minus: "https://private-api.finecobank.com/v1/private/tax-carry-forward/minus"
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
            tax_carry_forward: format!("{base}/v1/private/tax-carry-forward/search"),
            tax_minus: format!("{base}/v1/private/tax-carry-forward/minus"),
        }
    }
}
