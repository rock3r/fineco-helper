//! `fineco-market` — credential-free market data (stock enrichment + the public
//! zero-commission ETF list).
//!
//! This path holds **no Fineco credentials** and reaches no authenticated
//! Fineco endpoint. Stock enrichment is *parse-not-execute*: fetched HTML/JS is
//! extracted and parsed strictly as data (`serde_json`) — there is no `eval`,
//! `Function`, or JS engine anywhere here. Source URLs are restricted to an
//! allowlisted, SHA-256-pinned host with a `/stocks/` path; there is no
//! client-supplied URL and no `validateSource`/`userAgent` knob.

mod client;
mod report;
mod source;
mod state;

pub use client::{
    DEFAULT_ZERO_COMMISSION_ETFS_URL, MarketClient, ZeroCommissionEtf, ZeroCommissionEtfs,
};
pub use report::{CompanyOverview, EnrichmentMatch, EnrichmentReport};
pub use source::{EnrichmentHostAllowlist, validate_source_url};

use fineco_core::SafeError;

/// Build a bounded enrichment report from already-fetched page `html`.
///
/// `source_url` is the (already validated) page URL recorded on the report;
/// `captured_at` is the caller's timestamp; `fineco_title`, when present, adds a
/// title-match score. Parsing is data-only — the HTML is never executed.
///
/// # Errors
/// Returns [`SafeError::invalid_request`] if the embedded query cache is
/// missing/oversized/not an object, or lacks company data.
pub fn build_enrichment_report(
    html: &str,
    source_url: &str,
    captured_at: &str,
    fineco_title: Option<&str>,
) -> Result<EnrichmentReport, SafeError> {
    let state = state::parse_enrichment_state(html)?;
    report::build_report(&state, source_url, captured_at, fineco_title)
}
