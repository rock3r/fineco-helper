//! The credential-free market HTTP client.
//!
//! Fetches stock-enrichment pages (server-built URL, host-pinned stock-page
//! route, redirects disabled) and the public zero-commission ETF list. Holds no
//! credentials and never reaches an authenticated Fineco endpoint. Nothing here
//! logs URLs, bodies, or responses; failures map to a [`SafeError`] envelope.

use fineco_core::SafeError;
use serde::{Deserialize, Serialize};
use ureq::Agent;

use crate::build_enrichment_report;
use crate::report::{EnrichmentReport, sanitize_text};
use crate::source::{EnrichmentHostAllowlist, validate_fetch_target};

/// Cap the enrichment page read at the network layer (matches the parser's page
/// cap), so an oversized response is bounded as it is read, not after.
const MAX_ENRICHMENT_BYTES: u64 = 4 * 1024 * 1024;
/// Cap on a JSON response body (the public ETF list), bounding memory against an
/// oversized/hostile response.
const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;

/// Upper bound on a single market fetch (connect + transfer). A stalled or
/// hostile CDN/upstream that accepts the connection but never responds must not
/// pin the `spawn_blocking` worker thread the gateway runs the fetch on; mirrors
/// the JWKS fetch timeout.
const MARKET_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// User-Agent the reference sends when fetching enrichment pages (a desktop
/// browser UA, distinct from the Fineco mobile one). Static, non-sensitive.
const ENRICHMENT_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36";

/// Browser/page context the reference sends when fetching the public ETF list
/// (ported verbatim). Static, non-sensitive.
const ETF_HEADERS: &[(&str, &str)] = &[
    (
        "User-Agent",
        "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36",
    ),
    ("Accept-Language", "it,en;q=0.9"),
    ("Cache-Control", "no-cache"),
    ("Pragma", "no-cache"),
    ("Origin", "https://finecobank.com"),
    (
        "Referer",
        "https://finecobank.com/pvt/trading/stocklist/etf/zero",
    ),
    ("Sec-Fetch-Dest", "empty"),
    ("Sec-Fetch-Mode", "cors"),
    ("Sec-Fetch-Site", "same-site"),
    (
        "sec-ch-ua",
        "\"Google Chrome\";v=\"147\", \"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"147\"",
    ),
    ("sec-ch-ua-mobile", "?1"),
    ("sec-ch-ua-platform", "\"Android\""),
    ("sec-gpc", "1"),
];

/// Fineco's public zero-commission ETF list — a static JSON on the CDN host
/// (`images.finecobank.com`), served without authentication or cookies. This is
/// a fixed Fineco endpoint, not per-deployment config, so it is the default for
/// `FINECO_ETF_URL`; a deployment only overrides it to point at a mock or a moved
/// list.
pub const DEFAULT_ZERO_COMMISSION_ETFS_URL: &str =
    "https://images.finecobank.com/common-pvt/js/json/etf-zero/etf_piu_scambiati.json";

/// A single zero-commission ETF instrument (public_market data class).
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ZeroCommissionEtf {
    pub instr_id: String,
    pub venue_system: String,
    pub description: String,
    pub issuer: String,
}

/// The captured zero-commission ETF list.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ZeroCommissionEtfs {
    pub captured_at: String,
    pub source_url: String,
    pub count: usize,
    pub instruments: Vec<ZeroCommissionEtf>,
}

/// Config + agent for the market reads. Construct with the enrichment base URL
/// and host allowlist, plus the public ETF list URL. The enrichment base must be
/// HTTPS in production; only the local mock uses plain HTTP.
pub struct MarketClient {
    agent: Agent,
    enrichment_base: String,
    allowlist: EnrichmentHostAllowlist,
    zero_commission_etfs_url: String,
}

impl MarketClient {
    /// Build a client. `enrichment_base` is the scheme+host the server prepends
    /// to a fixed stock-page route; `allowlist` pins the acceptable host(s);
    /// `zero_commission_etfs_url` is the public ETF list endpoint.
    #[must_use]
    pub fn new(
        enrichment_base: impl Into<String>,
        allowlist: EnrichmentHostAllowlist,
        zero_commission_etfs_url: impl Into<String>,
    ) -> Self {
        Self::new_with_timeout(
            enrichment_base,
            allowlist,
            zero_commission_etfs_url,
            MARKET_FETCH_TIMEOUT,
        )
    }

    /// Like [`MarketClient::new`] but with an explicit global fetch timeout.
    /// Production uses [`MarketClient::new`] (which applies [`MARKET_FETCH_TIMEOUT`]);
    /// this lets tests exercise the stalled-upstream path with a short bound.
    #[must_use]
    pub fn new_with_timeout(
        enrichment_base: impl Into<String>,
        allowlist: EnrichmentHostAllowlist,
        zero_commission_etfs_url: impl Into<String>,
        fetch_timeout: std::time::Duration,
    ) -> Self {
        // Handle non-2xx ourselves and never follow redirects: a stock page is
        // fetched at its canonical URL, and we do not chase untrusted hops. Bound
        // the whole fetch so a CDN/upstream that accepts the connection but stalls
        // cannot pin a gateway worker thread forever (mirrors the JWKS posture).
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            // Ignore proxy env vars (ureq honors them by default): the market path
            // is egress-pinned to its allowlisted hosts and must not be rerouted
            // through an env-injected proxy.
            .proxy(None)
            .timeout_global(Some(fetch_timeout))
            .build();
        Self {
            agent: Agent::new_with_config(config),
            enrichment_base: enrichment_base.into(),
            allowlist,
            zero_commission_etfs_url: zero_commission_etfs_url.into(),
        }
    }

    /// The configured zero-commission ETF list URL (the default Fineco endpoint
    /// unless overridden). Exposed for config tests.
    #[must_use]
    pub fn zero_commission_etfs_url(&self) -> &str {
        &self.zero_commission_etfs_url
    }

    /// Fetch and parse the enrichment report for a stock-page `identifier`.
    /// Slugs use `/stocks/<identifier>`; market-code-like two-segment
    /// venue/symbol identifiers use `/stock/<venue>/<symbol>`. `fineco_title`,
    /// when present, adds a title match. `now_iso` stamps `captured_at`.
    ///
    /// # Errors
    /// - [`SafeError::invalid_request`] for an unsafe identifier, a non-pinned
    ///   host, or an unparseable page.
    /// - Upstream/internal envelopes on transport failure.
    pub fn fetch_enrichment(
        &self,
        identifier: &str,
        fineco_title: Option<&str>,
        now_iso: &str,
    ) -> Result<EnrichmentReport, SafeError> {
        validate_identifier(identifier)?;
        let url = format!(
            "{}{}",
            self.enrichment_base.trim_end_matches('/'),
            enrichment_path(identifier)
        );
        // Defense in depth: even though the base is trusted config, confirm the
        // built URL still hits a pinned host and a stock-page path.
        validate_fetch_target(&url, &self.allowlist)?;

        let html = self.get_text(&url)?;
        build_enrichment_report(&html, &url, now_iso, fineco_title)
    }

    /// Fetch and parse the public zero-commission ETF list. `now_iso` stamps
    /// `captured_at`.
    ///
    /// # Errors
    /// Upstream/internal envelopes on transport or parse failure.
    pub fn fetch_zero_commission_etfs(
        &self,
        now_iso: &str,
    ) -> Result<ZeroCommissionEtfs, SafeError> {
        let url = self.zero_commission_etfs_url.clone();
        let parsed: EtfListResponse = self.get_json(&url)?;
        let instruments: Vec<ZeroCommissionEtf> = parsed
            .instruments
            .into_iter()
            .map(EtfEntry::into_instrument)
            .collect();
        Ok(ZeroCommissionEtfs {
            captured_at: now_iso.to_string(),
            source_url: url,
            count: instruments.len(),
            instruments,
        })
    }

    /// GET `url` and return the body text, bounding status to 2xx.
    fn get_text(&self, url: &str) -> Result<String, SafeError> {
        ensure_secure_transport(url)?;
        let mut response = self
            .agent
            .get(url)
            .header("User-Agent", ENRICHMENT_USER_AGENT)
            .header("Accept-Language", "en")
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .call()
            .map_err(map_transport_error)?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(SafeError::from_upstream_status(status));
        }
        read_body_to_string_bounded(response.body_mut(), MAX_ENRICHMENT_BYTES)
    }

    /// GET `url` and parse the JSON body, bounding status to 2xx.
    fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, SafeError> {
        ensure_secure_transport(url)?;
        let mut response = with_headers(self.agent.get(url), ETF_HEADERS)
            .header("Accept", "*/*")
            .call()
            .map_err(map_transport_error)?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(SafeError::from_upstream_status(status));
        }
        // Read the body to a string FIRST, then parse — not `read_json`, which
        // wraps a body-read timeout inside a `serde_json` error that would be
        // misclassified as `internal`. The bounded read surfaces a stalled-body
        // timeout cleanly as `fineco_timeout` and caps the DECOMPRESSED size; the
        // JSON parse maps to `internal`.
        let body = read_body_to_string_bounded(response.body_mut(), MAX_JSON_BYTES)?;
        serde_json::from_str(&body).map_err(|_| SafeError::internal())
    }
}

/// Apply a fixed set of `(name, value)` headers to a request builder.
fn with_headers<B>(
    mut builder: ureq::RequestBuilder<B>,
    headers: &[(&str, &str)],
) -> ureq::RequestBuilder<B> {
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
}

#[derive(Deserialize)]
struct EtfListResponse {
    #[serde(default)]
    instruments: Vec<EtfEntry>,
}

#[derive(Deserialize)]
struct EtfEntry {
    #[serde(rename = "instrId", default)]
    instr_id: Option<String>,
    #[serde(rename = "venueSystem", default)]
    venue_system: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
}

impl EtfEntry {
    fn into_instrument(self) -> ZeroCommissionEtf {
        // The ETF list is untrusted third-party content returned to the model:
        // control-strip and length-bound every string field, like enrichment.
        ZeroCommissionEtf {
            instr_id: sanitize_text(&self.instr_id.unwrap_or_default()),
            venue_system: sanitize_text(&self.venue_system.unwrap_or_default()),
            description: sanitize_text(&self.description.unwrap_or_default()),
            issuer: sanitize_text(&self.issuer.unwrap_or_default()),
        }
    }
}

/// Validate a stock-page identifier. The identifier may be a slug or a
/// market-code-like venue/symbol pair, but each character is restricted to the
/// URL "unreserved" set plus `/`. This admits nothing that could escape the
/// server-built stock-page route downstream — no scheme, userinfo,
/// percent-encoding (`%`), backslash, query/fragment, whitespace, or control —
/// and no empty/`.`/`..` path segment.
fn validate_identifier(identifier: &str) -> Result<(), SafeError> {
    let charset_ok = !identifier.is_empty() && identifier.chars().all(is_slug_char);
    let segments_ok = identifier
        .split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
    if !charset_ok || !segments_ok {
        return Err(SafeError::invalid_request(
            "Enrichment identifier is not a valid stock-page slug.",
        ));
    }
    Ok(())
}

fn enrichment_path(identifier: &str) -> String {
    if is_two_segment_identifier(identifier) {
        format!("/stock/{identifier}")
    } else {
        format!("/stocks/{identifier}")
    }
}

fn is_two_segment_identifier(identifier: &str) -> bool {
    let mut segments = identifier.split('/');
    let (Some(venue), Some(symbol), None) = (segments.next(), segments.next(), segments.next())
    else {
        return false;
    };
    looks_like_market_code(venue) && looks_like_market_code(symbol)
}

fn looks_like_market_code(segment: &str) -> bool {
    segment
        .chars()
        .any(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        && segment
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
}

/// The characters allowed in a slug: ASCII alphanumerics, the URL "unreserved"
/// marks, and the segment separator `/`.
fn is_slug_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '/')
}

/// Refuse to fetch over cleartext to a non-loopback host. The scheme is fixed
/// by the trusted configured base (enrichment base / ETF URL), but a
/// misconfiguration must fail closed, not silently fetch over http. Applied to
/// every market request — enrichment and the public ETF list alike.
fn ensure_secure_transport(url: &str) -> Result<(), SafeError> {
    if fineco_core::is_secure_or_loopback(url) {
        Ok(())
    } else {
        Err(SafeError::invalid_request(
            "Market source URL must use https.",
        ))
    }
}

/// Read a response body to a `String`, bounding the **decompressed** size.
///
/// ureq's `.limit()` caps the *compressed* bytes read off the socket — the limit
/// reader sits beneath the gzip decoder — so a small gzip body that inflates to
/// gigabytes would slip past a compressed-size cap and be materialized whole. We
/// therefore read through the decoded reader under a `take` cap on the
/// *decompressed* output and reject anything larger, bounding memory against a
/// hostile/compromised upstream. A stalled body read is still surfaced as
/// `fineco_timeout`: the gzip decoder passes a wrapped ureq timeout through, and
/// `ureq::Error::from(io::Error)` round-trips it (see `map_read_error`).
fn read_body_to_string_bounded(body: &mut ureq::Body, max: u64) -> Result<String, SafeError> {
    use std::io::Read;
    // Keep the compressed-side cap too (bounds bytes pulled off the socket), then
    // bound the decoded output — the cap that actually stops a decompression bomb.
    let mut reader = body.with_config().limit(max).reader();
    let mut buf = Vec::new();
    (&mut reader)
        .take(max + 1)
        .read_to_end(&mut buf)
        .map_err(map_read_error)?;
    if buf.len() as u64 > max {
        return Err(SafeError::internal());
    }
    String::from_utf8(buf).map_err(|_| SafeError::internal())
}

/// Map an I/O error from the bounded body read to a safe envelope, preserving the
/// `fineco_timeout` classification a stalled body read produces (the decoder
/// passes a wrapped ureq error through, which `ureq::Error::from` recovers).
fn map_read_error(err: std::io::Error) -> SafeError {
    map_transport_error(ureq::Error::from(err))
}

/// Map a ureq transport error to a safe envelope. The error's `Display` may
/// reference the URL, so it is NEVER placed into the envelope message.
fn map_transport_error(err: ureq::Error) -> SafeError {
    match err {
        ureq::Error::Timeout(_) => SafeError::fineco_timeout(),
        ureq::Error::StatusCode(code) => SafeError::from_upstream_status(code),
        _ => SafeError::internal(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etf_entry_string_fields_are_sanitized_and_bounded() {
        // The public ETF list is untrusted third-party content too: its string
        // fields must be control-stripped and length-bounded before reaching the
        // model, exactly like the enrichment free-text fields.
        let entry = EtfEntry {
            instr_id: Some("IE00\u{1b}[31mB4L5Y983".to_string()),
            venue_system: Some("MOT\nMTA".to_string()),
            description: Some("d".repeat(crate::report::MAX_STR + 100)),
            issuer: Some("Issuer\u{0}Co".to_string()),
        };
        let etf = entry.into_instrument();
        for field in [
            &etf.instr_id,
            &etf.venue_system,
            &etf.description,
            &etf.issuer,
        ] {
            assert!(
                !field.chars().any(char::is_control),
                "ETF field still has a control char: {field:?}"
            );
            assert!(
                field.chars().count() <= crate::report::MAX_STR,
                "ETF field not length-bounded: {} chars",
                field.chars().count()
            );
        }
    }
}
