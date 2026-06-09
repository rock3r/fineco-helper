//! `fineco-worker` — the credential-holding Fineco fetch.
//!
//! This is the ONLY component that holds Fineco credentials, mints/holds a
//! session cookie, and reaches the live Fineco socket. It logs in, performs
//! allowlisted read-only requests against server-built URLs (never a
//! client-supplied URL), parses the JSON responses into the store's `New*`
//! types, and implements [`fineco_refresh::PortfolioFetcher`] so the
//! credential-free refresh orchestration can drive it.
//!
//! Security posture:
//! - The session cookie lives only on the stack for the duration of one fetch;
//!   each fetch logs in fresh and discards the session — nothing is retained.
//! - Nothing here logs request/response bodies, cookies, or credentials; every
//!   failure is mapped to a [`SafeError`] envelope with a developer-authored,
//!   payload-free message.
//! - Reads only. There is no write/trade path.

mod credentials;
mod endpoints;
mod parse;

pub use credentials::{
    CredentialSource, EnvCredentialSource, FinecoCredential, StaticCredentialSource,
};
pub use endpoints::FinecoEndpoints;

use fineco_core::{SafeError, validate_order_request, validate_tax_range};
use fineco_refresh::{PortfolioFetcher, RawOrdersFetcher, TaxFetcher};
use fineco_store::{NewPortfolioSnapshot, NewTaxCarryForward, NewTaxMinusByYear, RawOrder};
use serde::de::DeserializeOwned;
use ureq::Agent;

/// Cap on an authenticated JSON response body, so a hostile/buggy upstream
/// cannot drive unbounded memory in the sole credential-holding process.
const MAX_JSON_BYTES: u64 = 8 * 1024 * 1024;

/// Upper bound on a single Fineco request (connect + transfer). A bank endpoint
/// that accepts the connection but stalls must surface as `fineco_timeout` and
/// must not pin the refresh lock; the orchestrator's retry/circuit logic keys on
/// that. Generous because bank APIs can be slow under load.
const FINECO_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Fixed browser/request context sent on every Fineco request (ported verbatim
/// from the TS reference's `browserHeaders`). Static, non-sensitive — no secret
/// here; it is the anti-bot request fingerprint the Fineco endpoints expect.
const BROWSER_HEADERS: &[(&str, &str)] = &[
    (
        "User-Agent",
        "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36",
    ),
    ("Accept-Language", "it"),
    ("Cache-Control", "no-cache"),
    ("Pragma", "no-cache"),
    ("Connection", "keep-alive"),
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

/// Headers the private Fineco read APIs require on top of the session cookie:
/// the account/dossier selectors (the owner's defaults), the page origin, and
/// the content type the reference sends.
const PRIVATE_READ_HEADERS: &[(&str, &str)] = &[
    ("X-Account-Index", "0"),
    ("X-Dossier-Index", "0"),
    ("Origin", "https://finecobank.com"),
    ("Content-Type", "application/json"),
];

/// Per-endpoint `Referer` values the reference sends on private reads (the page
/// each API is called from), ported verbatim.
const PORTFOLIO_REFERER: &str = "https://finecobank.com/pvt/portfolio/trading-summary/home";
const ORDERS_REFERER: &str = "https://finecobank.com/pvt/portfolio/order-monitor/shares";
const TAX_REFERER: &str =
    "https://finecobank.com/pvt/portfolio/report/tax-carry-forward/current-month";

/// Origin/Referer the reference sends on the home preflight and the login POST
/// (the public site), distinct from the private reads' `finecobank.com` origin.
const LOGIN_ORIGIN: &str = "https://it.finecobank.com";
const LOGIN_REFERER: &str = "https://it.finecobank.com/";

/// The credential-holding Fineco fetch. Construct with the endpoint set and a
/// credential source; drive it via [`PortfolioFetcher`] or the typed fetch
/// methods.
pub struct FinecoWorker {
    agent: Agent,
    endpoints: FinecoEndpoints,
    credentials: Box<dyn CredentialSource>,
}

impl FinecoWorker {
    /// Build a worker for `endpoints`, sourcing credentials from `credentials`.
    #[must_use]
    pub fn new(endpoints: FinecoEndpoints, credentials: Box<dyn CredentialSource>) -> Self {
        Self::new_with_timeout(endpoints, credentials, FINECO_HTTP_TIMEOUT)
    }

    /// Like [`FinecoWorker::new`] but with an explicit per-request HTTP timeout.
    /// Production uses [`FinecoWorker::new`] (which applies [`FINECO_HTTP_TIMEOUT`]);
    /// this lets tests exercise the stalled-endpoint path with a short bound.
    #[must_use]
    pub fn new_with_timeout(
        endpoints: FinecoEndpoints,
        credentials: Box<dyn CredentialSource>,
        http_timeout: std::time::Duration,
    ) -> Self {
        // Handle non-2xx ourselves (map to a safe envelope) rather than letting
        // ureq raise a status error whose Display could echo the URL. Never
        // follow redirects: the credentialed worker talks only to its fixed
        // allowlisted endpoints and must not chase a response to another host.
        // Bound every request: a stalled Fineco endpoint must surface as
        // `fineco_timeout` and must not hold the refresh lock open forever.
        let config = Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .timeout_global(Some(http_timeout))
            .build();
        Self {
            agent: Agent::new_with_config(config),
            endpoints,
            credentials,
        }
    }

    /// Best-effort login preflight: fetch the public home page to bootstrap any
    /// cookies the login then needs (mirrors the TS reference). Returns the
    /// collected `Cookie` header value (possibly empty); a non-2xx home is not
    /// fatal — login still proceeds.
    fn preflight(&self) -> Result<String, SafeError> {
        ensure_secure_transport(&self.endpoints.home)?;
        let response = with_headers(self.agent.get(&self.endpoints.home), BROWSER_HEADERS)
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .header("Origin", LOGIN_ORIGIN)
            .header("Referer", LOGIN_REFERER)
            .call()
            .map_err(map_transport_error)?;
        Ok(cookie_header_from(response.headers()))
    }

    /// Log in and return the session `Cookie` header value (in memory only),
    /// merged with any preflight cookies the reads then replay.
    fn login(&self) -> Result<String, SafeError> {
        // Never send the credential over cleartext to a non-loopback host.
        ensure_secure_transport(&self.endpoints.login)?;
        let preflight_cookie = self.preflight()?;
        // Real Fineco's public home page sets no cookie. When the preflight
        // yields none, mint the synthetic public cookies the login POST requires
        // (Fineco's WAF answers a cookieless POST with a generic
        // `auth.invalid.credentials`) — mirrors the TS reference's
        // `synthetic_public_cookies()`. When the preflight DID set cookies, replay
        // those instead; the two are mutually exclusive (as in the reference).
        let login_cookie = if preflight_cookie.is_empty() {
            synthetic_public_cookies()
        } else {
            preflight_cookie
        };

        let credential = self.credentials.load()?;
        let body = serde_json::json!({
            "userId": credential.user_id,
            "password": credential.password,
        });
        let mut request = with_headers(self.agent.post(&self.endpoints.login), BROWSER_HEADERS)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Origin", LOGIN_ORIGIN)
            .header("Referer", LOGIN_REFERER);
        if !login_cookie.is_empty() {
            request = request.header("Cookie", &login_cookie);
        }
        let response = request.send_json(body).map_err(map_transport_error)?;

        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(SafeError::from_upstream_status(status));
        }

        let session_cookie = cookie_header_from(response.headers());
        if session_cookie.is_empty() {
            // A 200 with no session cookie is an auth failure, not a transport one.
            return Err(SafeError::auth_required());
        }
        // The reads replay the full jar the browser would carry: the login
        // context (preflight or synthetic) plus the freshly minted session.
        Ok(merge_cookies(&login_cookie, &session_cookie))
    }

    /// Authenticated GET returning parsed JSON. `cookie` is the session header,
    /// `referer` the calling page. Carries the fixed browser context plus
    /// `X-Account-Index`/`X-Dossier-Index` the private Fineco APIs require to
    /// select the owner's account/dossier.
    fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        cookie: &str,
        referer: &str,
    ) -> Result<T, SafeError> {
        // Never replay the session cookie over cleartext to a non-loopback host.
        ensure_secure_transport(url)?;
        let request = with_headers(
            with_headers(self.agent.get(url), BROWSER_HEADERS),
            PRIVATE_READ_HEADERS,
        )
        .header("Cookie", cookie)
        .header("Referer", referer)
        .header("Accept", "application/json, text/plain, */*");
        let mut response = request.call().map_err(map_transport_error)?;

        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(SafeError::from_upstream_status(status));
        }
        // Read the body to a string FIRST, then parse — do NOT use `read_json`,
        // which would collapse a stalled body-read **timeout** into a generic
        // parse error. Mapping the read through `map_transport_error` keeps a
        // body-read timeout as `fineco_timeout` (so the controller's retry +
        // circuit-breaker logic classifies it correctly); only a genuine parse
        // failure becomes `internal`. The raw body is never surfaced (it may carry
        // account data); the read is bounded so an oversized body cannot exhaust
        // memory. (Same fix as the M7 market client.)
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_JSON_BYTES)
            .read_to_string()
            .map_err(map_transport_error)?;
        serde_json::from_str::<T>(&body).map_err(|_| SafeError::internal())
    }
}

impl PortfolioFetcher for FinecoWorker {
    fn fetch_portfolio(&self, now_iso: &str) -> Result<NewPortfolioSnapshot, SafeError> {
        let cookie = self.login()?;
        let response: parse::PositionsSummaryResponse = self.get_json(
            &self.endpoints.positions_summary,
            &cookie,
            PORTFOLIO_REFERER,
        )?;
        Ok(parse::to_snapshot(response, now_iso))
    }
}

impl RawOrdersFetcher for FinecoWorker {
    /// Fetch order-monitor transactions for `instrument_kind` over the last
    /// `days` days, parsed to un-hashed [`RawOrder`]s. The worker holds no DB key;
    /// the controller hashes the raw `trans_id`s after they cross the socket.
    ///
    /// # Errors
    /// - [`SafeError::invalid_request`] if `days` exceeds the cap or
    ///   `instrument_kind` is not alphanumeric.
    /// - Auth/upstream/internal envelopes on login, fetch, or parse failure.
    fn fetch_raw_orders(
        &self,
        instrument_kind: &str,
        days: u32,
    ) -> Result<Vec<RawOrder>, SafeError> {
        // Defense in depth: the controller validates before taking the lock; the
        // worker re-validates with the SAME shared rules before any network call.
        validate_order_request(instrument_kind, days)?;

        let cookie = self.login()?;
        let url = format!(
            "{}?type={instrument_kind}&days={days}",
            self.endpoints.transactions
        );
        let response: parse::TransactionsResponse = self.get_json(&url, &cookie, ORDERS_REFERER)?;
        Ok(parse::to_raw_orders(response))
    }
}

impl TaxFetcher for FinecoWorker {
    /// Fetch the tax carry-forward total for an explicit `YYYY-MM-DD` range.
    ///
    /// # Errors
    /// - [`SafeError::invalid_request`] if a date is malformed or `date_from`
    ///   is after `date_to`.
    /// - Auth/upstream/internal envelopes on login, fetch, or parse failure.
    fn fetch_tax_carry_forward(
        &self,
        date_from: &str,
        date_to: &str,
    ) -> Result<NewTaxCarryForward, SafeError> {
        // Defense in depth: same shared validation the controller ran pre-lock.
        validate_tax_range(date_from, date_to)?;

        let cookie = self.login()?;
        let url = format!(
            "{}?dateFrom={date_from}&dateTo={date_to}",
            self.endpoints.tax_carry_forward
        );
        let response: parse::TaxCarryForwardResponse = self.get_json(&url, &cookie, TAX_REFERER)?;
        Ok(parse::to_tax_carry_forward(response, date_from, date_to))
    }

    /// Fetch the tax minus-by-year residues.
    ///
    /// # Errors
    /// Auth/upstream/internal envelopes on login, fetch, or parse failure.
    fn fetch_tax_minus_by_year(&self) -> Result<Vec<NewTaxMinusByYear>, SafeError> {
        let cookie = self.login()?;
        let response: parse::TaxMinusResponse =
            self.get_json(&self.endpoints.tax_minus, &cookie, TAX_REFERER)?;
        Ok(parse::to_tax_minus(response))
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

/// Merge two `Cookie` header values (preflight + session), deduplicating by
/// cookie name with the later value winning, preserving first-seen order.
fn merge_cookies(first: &str, second: &str) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for raw in first.split("; ").chain(second.split("; ")) {
        let pair = raw.trim();
        if pair.is_empty() {
            continue;
        }
        let name = pair.split('=').next().unwrap_or(pair).to_string();
        match pairs.iter_mut().find(|(existing, _)| *existing == name) {
            Some(slot) => slot.1 = pair.to_string(),
            None => pairs.push((name, pair.to_string())),
        }
    }
    pairs
        .iter()
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Refuse to send the credential or session cookie over cleartext to a
/// non-loopback host (a misconfigured endpoint must fail closed, not leak).
fn ensure_secure_transport(url: &str) -> Result<(), SafeError> {
    if fineco_core::is_secure_or_loopback(url) {
        Ok(())
    } else {
        Err(SafeError::invalid_request(
            "Fineco endpoint must use https.",
        ))
    }
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

/// Build a `Cookie` request-header value from a response's `Set-Cookie`
/// headers: take each cookie's `name=value` pair (before the first `;`) and
/// join with `; `.
fn cookie_header_from(headers: &ureq::http::HeaderMap) -> String {
    headers
        .get_all(ureq::http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|set_cookie| set_cookie.split(';').next())
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Mint the synthetic public cookies the real Fineco home page would otherwise
/// set, for replay on the login POST when the home preflight issues none. Ports
/// the TS reference's `syntheticPublicCookies()` verbatim in shape. The values
/// are random/timestamped so repeated logins don't reuse identical cookies (less
/// bot-like); Fineco keys on their presence/shape, not their contents. NOT a
/// secret — no credential material is involved.
fn synthetic_public_cookies() -> String {
    let now = unix_millis();
    [
        format!("finecostat={}.{}", random_uuid_v4(), random_base64url(33)),
        format!("XID={now}.{}", random_digits(4)),
        "LBM=pubsapipr03".to_string(),
        format!("PORTALSESSIONID={}", random_digits(8)),
        format!("gdate={}", now.saturating_add(random_below(60_000))),
        format!("store-sessionid={}", random_uuid_v4()),
        format!("finecoLogin={}", random_uuid_v4()),
    ]
    .join("; ")
}

/// Milliseconds since the Unix epoch (0 if the clock is before the epoch, which
/// cannot happen on a sane host — these cookies are cosmetic regardless).
fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Read `n` bytes from the OS RNG (`/dev/urandom`), dependency-free. Used ONLY
/// for the non-security synthetic cookie values; on the (Linux) worker host the
/// read cannot realistically fail, and a zeroed fallback would still yield
/// well-formed, present cookies.
fn random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read as _;
    let mut buf = vec![0u8; n];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        let _ = file.read_exact(&mut buf);
    }
    buf
}

/// A random UUID v4 (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`), mirroring the TS
/// reference's `randomUUID()`.
fn random_uuid_v4() -> String {
    let mut b = [0u8; 16];
    b.copy_from_slice(&random_bytes(16));
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
    let hex: String = b.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// `n` random URL-safe base64 characters, unpadded (mirrors the TS reference's
/// `randomBase64Url`: base64 of `n` random bytes with `+/=`→`-_`/stripped).
fn random_base64url(n: usize) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = random_bytes(n);
    let mut out = String::with_capacity(n.div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3f) as usize] as char);
        }
    }
    out
}

/// A string of `n` random decimal digits (mirrors the TS reference's
/// `randomDigits`). Rejection-samples bytes to `0..250` (= 25·10) so `% 10` is
/// unbiased — matching the reference's unbiased `Math.random()*10`. ~97.7% of
/// bytes are accepted, so one pass over `n` fresh bytes almost always suffices;
/// the `/dev/urandom` zero-fallback yields all-`0` bytes (still accepted), so the
/// loop always terminates.
fn random_digits(n: usize) -> String {
    let mut out = String::with_capacity(n);
    while out.len() < n {
        for byte in random_bytes(n) {
            if byte < 250 {
                out.push(char::from(b'0' + byte % 10));
                if out.len() == n {
                    break;
                }
            }
        }
    }
    out
}

/// A random `u64` in `0..bound` (`bound` must be non-zero). Used for the small
/// `gdate` jitter; the modulo bias is irrelevant for a cosmetic cookie.
fn random_below(bound: u64) -> u64 {
    let mut acc = 0u64;
    for byte in random_bytes(8) {
        acc = (acc << 8) | u64::from(byte);
    }
    acc % bound
}

#[cfg(test)]
mod tests {
    use super::synthetic_public_cookies;
    use std::collections::HashMap;

    /// Split a `name=value; name=value` cookie header into a name→value map.
    fn parse(header: &str) -> HashMap<String, String> {
        header
            .split("; ")
            .filter_map(|pair| pair.split_once('='))
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    /// True for a canonical UUID v4 string (`8-4-4-4-12` lowercase hex, with the
    /// version `4` and variant `8/9/a/b` nibbles in place).
    fn is_uuid_v4(value: &str) -> bool {
        let groups: Vec<&str> = value.split('-').collect();
        groups.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(&groups)
                .all(|(len, g)| g.len() == *len && g.bytes().all(|c| c.is_ascii_hexdigit()))
            && groups[2].starts_with('4')
            && matches!(groups[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b')
    }

    #[test]
    fn mints_all_seven_reference_cookies_with_the_right_shape() {
        let cookies = parse(&synthetic_public_cookies());

        // Exactly the seven cookies the TS reference's syntheticPublicCookies()
        // emits — no more, no fewer.
        let mut names: Vec<&String> = cookies.keys().collect();
        names.sort();
        assert_eq!(
            names,
            [
                "LBM",
                "PORTALSESSIONID",
                "XID",
                "finecoLogin",
                "finecostat",
                "gdate",
                "store-sessionid",
            ]
        );

        // LBM is the fixed marker the worker always sends.
        assert_eq!(cookies["LBM"], "pubsapipr03");

        // finecostat = <uuid v4>.<44 url-safe base64 chars (33 bytes, unpadded)>.
        let (uuid, b64) = cookies["finecostat"]
            .split_once('.')
            .expect("finecostat has a uuid.base64 shape");
        assert!(is_uuid_v4(uuid), "finecostat uuid: {uuid}");
        assert_eq!(b64.len(), 44, "33 bytes base64url unpadded = 44 chars");
        assert!(
            b64.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
            "finecostat base64 must be url-safe and unpadded: {b64}"
        );

        // XID = <epoch millis>.<4 digits>.
        let (millis, suffix) = cookies["XID"]
            .split_once('.')
            .expect("XID has a ts.digits shape");
        assert!(millis.bytes().all(|c| c.is_ascii_digit()) && !millis.is_empty());
        assert_eq!(suffix.len(), 4);
        assert!(suffix.bytes().all(|c| c.is_ascii_digit()));

        assert_eq!(cookies["PORTALSESSIONID"].len(), 8);
        assert!(
            cookies["PORTALSESSIONID"]
                .bytes()
                .all(|c| c.is_ascii_digit())
        );
        assert!(
            cookies["gdate"].bytes().all(|c| c.is_ascii_digit()) && !cookies["gdate"].is_empty()
        );
        assert!(is_uuid_v4(&cookies["store-sessionid"]));
        assert!(is_uuid_v4(&cookies["finecoLogin"]));
    }

    #[test]
    fn each_login_mints_fresh_cookie_values() {
        // Repeated logins must not reuse identical cookie values (less bot-like);
        // the random UUID/base64 parts make a collision astronomically unlikely.
        assert_ne!(synthetic_public_cookies(), synthetic_public_cookies());
    }
}
