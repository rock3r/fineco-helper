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
//! - Refresh and search/details fetches log in fresh and discard the session
//!   within the call. Authenticated **market** reads additionally hold one
//!   `Zeroizing` session for cross-call reuse within
//!   [`fineco_ipc::MARKET_SESSION_REUSE_TTL_SECS`] (plan D-22), so a basket of
//!   back-to-back instrument reads rides a single login instead of a login storm.
//!   The held cookie is zeroized on TTL expiry, a reused-session 401, replacement,
//!   any refresh login (which may rotate the server session), and shutdown. This
//!   longer in-memory credential window is the AC-22 accepted residual; the
//!   gateway still never sees a cookie or session handle.
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

use std::sync::{Arc, Mutex};

use fineco_core::{
    SafeError, normalize_expected_isin, parse_iso8601_utc, sanitize_text, validate_order_request,
    validate_tax_range,
};
use fineco_ipc::{
    MARKET_SESSION_REUSE_TTL_SECS, MAX_AMBIGUITY_SUGGESTIONS, MarketAssetDetailsLiveFetcher,
    MarketAssetDetailsLiveResult, MarketAssetDetailsResult, MarketAssetIdentity,
    MarketAssetSections, MarketAssetType, MarketDetailsParams, MarketDetailsSection, MarketField,
    MarketIndicesLiveFetcher, MarketIndicesLiveResult, MarketIndicesParams, MarketSearchCandidate,
    MarketSearchLiveFetcher, MarketSearchLiveResult, MarketSearchParams, MarketSessionStatus,
    MarketSource,
};
use fineco_refresh::{PortfolioFetcher, RawOrdersFetcher, TaxFetcher};
use fineco_store::{NewPortfolioSnapshot, NewTaxCarryForward, NewTaxMinusByYear, RawOrder};
use serde::Serialize;
use serde::de::DeserializeOwned;
use ureq::Agent;
use zeroize::Zeroizing;

/// Cap on an authenticated JSON response body, so a hostile/buggy upstream
/// cannot drive unbounded memory in the sole credential-holding process.
const MAX_JSON_BYTES: u64 = 8 * 1024 * 1024;

/// How often the background reaper checks the held market session for TTL expiry.
/// The held cookie is therefore zeroized within this much of its reuse window
/// lapsing, bounding the in-memory credential window (AC-22).
const SESSION_REAPER_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Total attempts for one authenticated market endpoint call after a single
/// Fineco login. Retries are local to the worker so they do not multiply logins.
const MARKET_RETRY_ATTEMPTS: u32 = 3;

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
const MARKET_SEARCH_REFERER: &str = "https://finecobank.com/pvt/home";
const MARKET_DETAILS_REFERER: &str = "https://finecobank.com/pvt/trading/etf/scheda";

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
    /// Cross-call market-session reuse window (plan D-22). `Some(ttl)`: hold the
    /// market session and reuse it for a follow-up read within `ttl` seconds;
    /// `None`: stateless per call (a fresh login every read). Defaults to
    /// [`fineco_ipc::MARKET_SESSION_REUSE_TTL_SECS`]; tests override it.
    reuse_ttl_secs: Option<u64>,
    /// The single worker-held market session, when reuse is enabled and one is
    /// live. The cookie is `Zeroizing`, so dropping/replacing it scrubs the
    /// session material from memory; the gateway never sees it. Behind a `Mutex`
    /// because the fetch methods take `&self` (the live serve loop is sequential,
    /// so there is no real contention); behind an `Arc` so the background reaper
    /// thread ([`FinecoWorker::spawn_session_reaper`]) can hold a `Weak` to it and
    /// zeroize the session at TTL expiry without keeping the worker alive.
    market_session: Arc<Mutex<Option<HeldMarketSession>>>,
}

struct FinecoSession {
    cookie: Zeroizing<String>,
    expires_in_secs: Option<u64>,
}

/// A market session the worker is holding for possible cross-call reuse.
struct HeldMarketSession {
    cookie: Zeroizing<String>,
    expires_in_secs: Option<u64>,
    /// Controller-clock epoch (seconds) after which this held session is treated
    /// as stale and must not be reused. Refreshed on every successful read (the
    /// server idle timer resets on activity), so a steady stream of reads keeps
    /// one login alive.
    valid_until_epoch: i64,
}

/// The session a market read runs on: either a reused held session or a fresh
/// login. Carries the `Cookie` value plus the status the worker reports back.
struct AcquiredMarketSession {
    cookie: Zeroizing<String>,
    expires_in_secs: Option<u64>,
    reused: bool,
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
            // Pin the crypto backend to aws-lc-rs (workspace-wide single backend;
            // ureq is built `rustls-no-provider` so this MUST be set or HTTPS panics).
            .tls_config(fineco_tls::tls_config())
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            // Ignore proxy environment variables (`HTTPS_PROXY`/`ALL_PROXY`/…):
            // ureq honors them by default, which would let an env-injection
            // mistake silently reroute the credentialed login through an
            // attacker-chosen proxy. The worker talks only to its fixed,
            // egress-pinned Fineco endpoints — no proxy, ever.
            .proxy(None)
            .timeout_global(Some(http_timeout))
            .build();
        Self {
            agent: Agent::new_with_config(config),
            endpoints,
            credentials,
            reuse_ttl_secs: MARKET_SESSION_REUSE_TTL_SECS,
            market_session: Arc::new(Mutex::new(None)),
        }
    }

    /// Override the cross-call market-session reuse window. `None` disables reuse
    /// (stateless per call). Used by tests; production keeps the
    /// [`fineco_ipc::MARKET_SESSION_REUSE_TTL_SECS`] default.
    #[must_use]
    pub fn with_market_reuse_ttl(mut self, reuse_ttl_secs: Option<u64>) -> Self {
        self.reuse_ttl_secs = reuse_ttl_secs;
        self
    }

    /// Best-effort login preflight: fetch the public home page to bootstrap any
    /// cookies the login then needs (mirrors the TS reference). Returns the
    /// collected `Cookie` header value (possibly empty); a non-2xx home is not
    /// fatal — login still proceeds.
    fn preflight(&self) -> Result<Zeroizing<String>, SafeError> {
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
    /// merged with any preflight cookies the reads then replay, plus status-only
    /// lifetime metadata from `Set-Cookie` attributes.
    fn login(&self) -> Result<FinecoSession, SafeError> {
        // Never send the credential over cleartext to a non-loopback host.
        ensure_secure_transport(&self.endpoints.login)?;
        let preflight_cookie = self.preflight()?;
        // Real Fineco's public home page sets no cookie. When the preflight
        // yields none, mint the synthetic public cookies the login POST requires
        // (Fineco's WAF answers a cookieless POST with a generic
        // `auth.invalid.credentials`) — mirrors the TS reference's
        // `synthetic_public_cookies()`. When the preflight DID set cookies, replay
        // those instead; the two are mutually exclusive (as in the reference).
        let login_cookie: Zeroizing<String> = if preflight_cookie.is_empty() {
            // Synthetic public cookies are not secret, but wrap them so both
            // branches share the zeroized type.
            Zeroizing::new(synthetic_public_cookies())
        } else {
            preflight_cookie
        };

        let credential = self.credentials.load()?;
        // Serialize from borrowed fields so no intermediate `serde_json::Value`
        // owns a second, un-zeroized copy of the password.
        #[derive(Serialize)]
        struct LoginBody<'a> {
            #[serde(rename = "userId")]
            user_id: &'a str,
            password: &'a str,
        }
        let body = LoginBody {
            user_id: &credential.user_id,
            password: credential.password.as_str(),
        };
        // Serialize into a ZEROIZED buffer and send raw JSON bytes — not
        // `send_json`, whose internal `Vec<u8>` would hold an un-zeroized copy of
        // the password. (ureq/rustls still buffer the bytes to write them to the
        // socket; that copy is outside our control and is the irreducible residual.)
        let json = Zeroizing::new(serde_json::to_vec(&body).map_err(|_| SafeError::internal())?);
        let mut request = with_headers(self.agent.post(&self.endpoints.login), BROWSER_HEADERS)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Origin", LOGIN_ORIGIN)
            .header("Referer", LOGIN_REFERER);
        if !login_cookie.is_empty() {
            request = request.header("Cookie", login_cookie.as_str());
        }
        let response = request.send(&json[..]).map_err(map_transport_error)?;

        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(SafeError::from_upstream_status(status));
        }

        let session_expires_in_secs = session_expires_in_secs_from(response.headers());
        let session_cookie = cookie_header_from(response.headers());
        if session_cookie.is_empty() {
            // A 200 with no session cookie is an auth failure, not a transport one.
            return Err(SafeError::auth_required());
        }
        // The reads replay the full jar the browser would carry: the login
        // context (preflight or synthetic) plus the freshly minted session.
        Ok(FinecoSession {
            cookie: merge_cookies(&login_cookie, &session_cookie),
            expires_in_secs: session_expires_in_secs,
        })
    }

    /// Run one authenticated market read under the held-session lifecycle (plan
    /// D-22): reuse a still-valid held session when reuse is enabled, otherwise
    /// log in fresh; a reused session the server has expired (a 401) is repaired
    /// by exactly one fresh-login retry. `read` receives the session `Cookie`
    /// header value and performs the (idempotent, read-only) Fineco calls; it may
    /// be invoked twice (once on the reused session, once after recovery), so it
    /// must not have side effects beyond the bounded Fineco reads. Returns the
    /// read's value plus the status-only session facts the controller audits.
    fn run_market_read<T>(
        &self,
        now_iso: &str,
        read: impl Fn(&str) -> Result<T, SafeError>,
    ) -> Result<(T, MarketSessionStatus), SafeError> {
        let now_epoch = parse_iso8601_utc(now_iso).ok_or_else(SafeError::internal)?;
        let acquired = self.acquire_market_session(now_epoch)?;
        match read(acquired.cookie.as_str()) {
            Ok(value) => {
                // The read proved the session good and reset the server idle timer:
                // re-store it (re-establishing it even if the reaper evicted it
                // mid-read) so the held session matches what we report.
                self.store_market_session_parts(
                    acquired.cookie.clone(),
                    acquired.expires_in_secs,
                    now_epoch,
                );
                let session = if acquired.reused {
                    MarketSessionStatus {
                        login_performed: false,
                        session_reused: true,
                        session_evicted: false,
                        reused_session_401_recovered: false,
                        session_expires_in_secs: acquired.expires_in_secs,
                    }
                } else {
                    MarketSessionStatus::fresh_login_with_expiry(acquired.expires_in_secs)
                };
                Ok((value, session))
            }
            // The session that served this read is unauthenticated, so evict and
            // zeroize it immediately — whether it was reused or freshly logged in —
            // so a known-bad jar is never held for reuse. A reused session then gets
            // exactly one fresh-login retry (`MARKET_REUSED_SESSION_401_RELOGIN_ATTEMPTS
            // = 1`); a fresh-login 401 stays `market_auth_required`. A 429 or any
            // non-auth error is NOT a session expiry and never triggers re-login.
            Err(error) if error.code() == "market_auth_required" => {
                self.evict_market_session();
                if !acquired.reused {
                    return Err(error);
                }
                let fresh = self.login().map_err(market_login_error)?;
                let cookie = fresh.cookie.clone();
                let expires = fresh.expires_in_secs;
                self.store_market_session(fresh, now_epoch);
                match read(cookie.as_str()) {
                    Ok(value) => {
                        self.store_market_session_parts(cookie.clone(), expires, now_epoch);
                        Ok((
                            value,
                            MarketSessionStatus {
                                login_performed: true,
                                session_reused: false,
                                session_evicted: true,
                                reused_session_401_recovered: true,
                                session_expires_in_secs: expires,
                            },
                        ))
                    }
                    // The fresh login's own session ALSO 401'd: drop it too and
                    // surface `market_auth_required` (a fresh-login 401, no retry). A
                    // non-auth retry error (e.g. 429) leaves the valid fresh session
                    // held — 429 never evicts/re-logs.
                    Err(error) => {
                        if error.code() == "market_auth_required" {
                            self.evict_market_session();
                        }
                        Err(error)
                    }
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Reuse a still-valid held market session, or log in fresh (holding the new
    /// session when reuse is enabled). With reuse disabled, always logs in fresh
    /// and holds nothing (the historic stateless-per-call behavior).
    fn acquire_market_session(&self, now_epoch: i64) -> Result<AcquiredMarketSession, SafeError> {
        if self.reuse_ttl_secs.is_some() {
            {
                let guard = self
                    .market_session
                    .lock()
                    .map_err(|_| SafeError::internal())?;
                if let Some(held) = guard.as_ref()
                    && now_epoch < held.valid_until_epoch
                {
                    return Ok(AcquiredMarketSession {
                        cookie: held.cookie.clone(),
                        expires_in_secs: held.expires_in_secs,
                        reused: true,
                    });
                }
            }
            // No valid held session: drop any stale one, then log in fresh and hold it.
            self.evict_market_session();
            let fresh = self.login().map_err(market_login_error)?;
            let cookie = fresh.cookie.clone();
            let expires = fresh.expires_in_secs;
            self.store_market_session(fresh, now_epoch);
            Ok(AcquiredMarketSession {
                cookie,
                expires_in_secs: expires,
                reused: false,
            })
        } else {
            let fresh = self.login().map_err(market_login_error)?;
            Ok(AcquiredMarketSession {
                cookie: fresh.cookie,
                expires_in_secs: fresh.expires_in_secs,
                reused: false,
            })
        }
    }

    /// Hold a market session (cookie + lifetime metadata) for reuse, valid for
    /// `reuse_ttl_secs` from `now_epoch`. A no-op when reuse is disabled. A
    /// successful read re-stores its own cookie through this, so the held session
    /// always reflects the last good read and the window resets on activity — even
    /// if the reaper happened to evict it mid-read.
    fn store_market_session_parts(
        &self,
        cookie: Zeroizing<String>,
        expires_in_secs: Option<u64>,
        now_epoch: i64,
    ) {
        let Some(ttl) = self.reuse_ttl_secs else {
            return;
        };
        let valid_until_epoch = now_epoch.saturating_add(i64::try_from(ttl).unwrap_or(i64::MAX));
        if let Ok(mut guard) = self.market_session.lock() {
            *guard = Some(HeldMarketSession {
                cookie,
                expires_in_secs,
                valid_until_epoch,
            });
        }
    }

    /// Hold `session` as the reusable market session, valid for `reuse_ttl_secs`
    /// from `now_epoch`. A no-op when reuse is disabled.
    fn store_market_session(&self, session: FinecoSession, now_epoch: i64) {
        self.store_market_session_parts(session.cookie, session.expires_in_secs, now_epoch);
    }

    /// Drop and zeroize any held market session. Called on TTL expiry, a
    /// reused-session 401, and before any refresh fresh login (D-22 G-2), so a
    /// later market read never reuses a session a refresh may have invalidated.
    fn evict_market_session(&self) {
        if let Ok(mut guard) = self.market_session.lock() {
            // Dropping the `Zeroizing` cookie scrubs the session material.
            *guard = None;
        }
    }

    /// Log in fresh for a refresh read, first evicting any held market session
    /// (D-22 G-2): a refresh login may rotate the account's single server
    /// session, so the worker must not afterwards reuse a market session that
    /// login could have invalidated.
    fn refresh_login(&self) -> Result<FinecoSession, SafeError> {
        self.evict_market_session();
        self.login()
    }

    /// Spawn the background reaper that zeroizes a held market session at its TTL
    /// expiry (AC-22), so an idle worker never retains a session past the reuse
    /// window — reuse-on-next-read would zeroize it lazily, but an idle worker
    /// would otherwise hold a dead cookie in memory indefinitely. The reaper holds
    /// only a `Weak` to the session, so it exits when the worker is dropped, and
    /// uses wall-clock time (which the controller's `now_iso` also is in
    /// production). No-op when reuse is disabled. Call once, from the serving
    /// binary — not in tests, whose synthetic `now_iso` would not match wall clock.
    pub fn spawn_session_reaper(&self) {
        if self.reuse_ttl_secs.is_none() {
            return;
        }
        let session = Arc::downgrade(&self.market_session);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(SESSION_REAPER_POLL_INTERVAL);
                let Some(session) = session.upgrade() else {
                    return; // the worker was dropped — stop reaping.
                };
                reap_expired_market_session(&session, now_unix_secs());
            }
        });
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
        self.get_json_mapped(url, cookie, referer, SafeError::from_upstream_status)
    }

    /// Authenticated GET returning parsed JSON, with caller-provided safe status
    /// mapping. Authenticated market reads need market-specific error codes while
    /// refresh reads keep the historic live-refresh codes.
    fn get_json_mapped<T: DeserializeOwned>(
        &self,
        url: &str,
        cookie: &str,
        referer: &str,
        map_status: fn(u16) -> SafeError,
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
            return Err(map_status(status));
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

    fn get_market_json<T: DeserializeOwned>(
        &self,
        url: &str,
        cookie: &str,
        referer: &str,
    ) -> Result<T, SafeError> {
        with_market_retry(|| self.get_json_mapped(url, cookie, referer, market_status_error))
    }

    /// Authenticated POST returning parsed JSON, with caller-provided safe
    /// status mapping. Used for Fineco static instrument search, whose request
    /// body is server-built from a fixed field allowlist.
    fn post_json_mapped<B: Serialize, T: DeserializeOwned>(
        &self,
        url: &str,
        body: &B,
        cookie: &str,
        referer: &str,
        map_status: fn(u16) -> SafeError,
    ) -> Result<T, SafeError> {
        ensure_secure_transport(url)?;
        let request = with_headers(
            with_headers(self.agent.post(url), BROWSER_HEADERS),
            PRIVATE_READ_HEADERS,
        )
        .header("Cookie", cookie)
        .header("Referer", referer)
        .header("Accept", "application/json, text/plain, */*");
        let json = serde_json::to_string(body).map_err(|_| SafeError::internal())?;
        let mut response = request.send(&json).map_err(map_transport_error)?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(map_status(status));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_JSON_BYTES)
            .read_to_string()
            .map_err(map_transport_error)?;
        serde_json::from_str::<T>(&body).map_err(|_| SafeError::internal())
    }

    fn post_market_json<B: Serialize, T: DeserializeOwned>(
        &self,
        url: &str,
        body: &B,
        cookie: &str,
        referer: &str,
    ) -> Result<T, SafeError> {
        with_market_retry(|| self.post_json_mapped(url, body, cookie, referer, market_status_error))
    }
}

impl PortfolioFetcher for FinecoWorker {
    fn fetch_portfolio(&self, now_iso: &str) -> Result<NewPortfolioSnapshot, SafeError> {
        let session = self.refresh_login()?;
        let response: parse::PositionsSummaryResponse = self.get_json(
            &self.endpoints.positions_summary,
            &session.cookie,
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

        let session = self.refresh_login()?;
        let url = format!(
            "{}?type={instrument_kind}&days={days}",
            self.endpoints.transactions
        );
        let response: parse::TransactionsResponse =
            self.get_json(&url, &session.cookie, ORDERS_REFERER)?;
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

        let session = self.refresh_login()?;
        let url = format!(
            "{}?dateFrom={date_from}&dateTo={date_to}",
            self.endpoints.tax_carry_forward
        );
        let response: parse::TaxCarryForwardResponse =
            self.get_json(&url, &session.cookie, TAX_REFERER)?;
        Ok(parse::to_tax_carry_forward(response, date_from, date_to))
    }

    /// Fetch the tax minus-by-year residues.
    ///
    /// # Errors
    /// Auth/upstream/internal envelopes on login, fetch, or parse failure.
    fn fetch_tax_minus_by_year(&self) -> Result<Vec<NewTaxMinusByYear>, SafeError> {
        let session = self.refresh_login()?;
        let response: parse::TaxMinusResponse =
            self.get_json(&self.endpoints.tax_minus, &session.cookie, TAX_REFERER)?;
        Ok(parse::to_tax_minus(response))
    }
}

impl MarketSearchLiveFetcher for FinecoWorker {
    /// Search Fineco's authenticated global instrument list by ticker, ISIN, or
    /// name, returning normalized candidates only.
    ///
    /// # Errors
    /// Auth/upstream/internal envelopes on login, fetch, or parse failure; or
    /// [`SafeError::invalid_request`] if params are out of bounds.
    fn fetch_market_search(
        &self,
        params: &MarketSearchParams,
        now_iso: &str,
    ) -> Result<MarketSearchLiveResult, SafeError> {
        params.validate()?;
        let url = format!(
            "{}?term={}",
            self.endpoints.global_search,
            percent_encode_query_component(&params.query)
        );
        let (result, session) = self.run_market_read(now_iso, |cookie| {
            let response: parse::MarketSearchResponse =
                self.get_market_json(&url, cookie, MARKET_SEARCH_REFERER)?;
            Ok(parse::to_market_search(response, params, now_iso))
        })?;
        Ok(MarketSearchLiveResult { result, session })
    }
}

impl MarketAssetDetailsLiveFetcher for FinecoWorker {
    /// Resolve a venue-qualified Fineco identifier and return normalized ETF
    /// details. M-3 supports ETFs; stocks are added by the stock slice.
    ///
    /// # Errors
    /// Market safe errors on validation/auth/resolution/upstream failures.
    fn fetch_market_asset_details(
        &self,
        params: &MarketDetailsParams,
        now_iso: &str,
    ) -> Result<MarketAssetDetailsLiveResult, SafeError> {
        params.validate()?;
        let parsed = ParsedMarketIdentifier::parse(&params.identifier)?;
        // The whole resolve-and-fetch fan-out runs on one session under
        // `run_market_read`: it shares a single login across every endpoint, and a
        // reused session the server has expired (a 401 on any call) re-runs this
        // idempotent, read-only closure once on a fresh login.
        let (result, session) = self.run_market_read(now_iso, |cookie| {
            let mut candidate = None;
            for query in details_search_terms(&parsed.symbol) {
                let search_params = MarketSearchParams {
                    query,
                    asset_type: None,
                    limit: Some(fineco_ipc::MAX_TOTAL_CANDIDATES),
                };
                let search_url = format!(
                    "{}?term={}",
                    self.endpoints.global_search,
                    percent_encode_query_component(&search_params.query)
                );
                let search_response: parse::MarketSearchResponse =
                    self.get_market_json(&search_url, cookie, MARKET_SEARCH_REFERER)?;
                let search = parse::to_market_search_for_resolution(
                    search_response,
                    &search_params,
                    now_iso,
                );
                match resolve_market_candidate(&search, &parsed, params) {
                    Ok(resolved) => {
                        candidate = Some(resolved);
                        break;
                    }
                    Err(error) if error.code() == "market_not_found" => {}
                    Err(error) => return Err(error),
                }
            }
            let candidate = candidate.ok_or_else(SafeError::market_not_found)?;
            if !matches!(
                candidate.asset_type,
                MarketAssetType::Etf | MarketAssetType::Stock | MarketAssetType::Bond
            ) {
                return Err(SafeError::market_unsupported_asset_type_for(
                    candidate.asset_type.as_str(),
                    &candidate.identifier,
                ));
            }
            if wants_only_identity(params) {
                let result = identity_only_details(params, &candidate, now_iso);
                result.validate_response_size()?;
                return Ok(result);
            }

            let static_body = StaticSearchRequest::for_instrument(&candidate.fineco_key);
            let static_response: parse::StaticSearchResponse = self.post_market_json(
                &self.endpoints.static_search,
                &static_body,
                cookie,
                MARKET_DETAILS_REFERER,
            )?;
            verify_static_identity(
                &static_response,
                &candidate,
                params.expected_isin.as_deref(),
            )?;
            // The bond section's yield-to-maturity comes from the quote snapshot, so
            // fetch the snapshot when the bond section is wanted even if `quote` was
            // not explicitly requested.
            let snapshot_response = if wants_default_or_section(params, MarketDetailsSection::Quote)
                || (matches!(candidate.asset_type, MarketAssetType::Bond)
                    && wants_default_or_section(params, MarketDetailsSection::Bond))
            {
                let snapshot_url = format!(
                    "{}?instruments={}",
                    self.endpoints.instruments_snapshot,
                    percent_encode_query_component(&candidate.fineco_key)
                );
                Some(self.get_market_json(&snapshot_url, cookie, MARKET_DETAILS_REFERER)?)
            } else {
                None
            };

            let result = match candidate.asset_type {
                MarketAssetType::Etf => {
                    let etf_snapshot = if wants_default_or_any_section(
                        params,
                        &[
                            MarketDetailsSection::Profile,
                            MarketDetailsSection::Etf,
                            MarketDetailsSection::Risk,
                        ],
                    ) {
                        let etf_snapshot_url = etf_query_url(
                            &self.endpoints.etf_query,
                            &candidate.fineco_key,
                            "snapshot",
                        );
                        Some(self.get_market_json(
                            &etf_snapshot_url,
                            cookie,
                            MARKET_DETAILS_REFERER,
                        )?)
                    } else {
                        None
                    };

                    let etf_composition = if wants_any_section(
                        params,
                        &[
                            MarketDetailsSection::Holdings,
                            MarketDetailsSection::Exposures,
                        ],
                    ) {
                        let url = etf_query_url(
                            &self.endpoints.etf_query,
                            &candidate.fineco_key,
                            "composition",
                        );
                        Some(self.get_market_json(&url, cookie, MARKET_DETAILS_REFERER)?)
                    } else {
                        None
                    };

                    let etf_returns = if wants_section(params, MarketDetailsSection::Returns) {
                        let url = etf_query_url(
                            &self.endpoints.etf_query,
                            &candidate.fineco_key,
                            "returns",
                        );
                        Some(self.get_market_json(&url, cookie, MARKET_DETAILS_REFERER)?)
                    } else {
                        None
                    };

                    parse::to_market_asset_details(
                        params,
                        &candidate,
                        parse::MarketDetailsInputs {
                            static_response,
                            snapshot_response,
                            etf_snapshot,
                            etf_composition,
                            etf_returns,
                        },
                        now_iso,
                    )?
                }
                MarketAssetType::Stock => {
                    let (instr_id, venue) = fineco_key_parts(&candidate.fineco_key)?;
                    let stock_snapshot = if wants_default_or_any_section(
                        params,
                        &[MarketDetailsSection::Profile, MarketDetailsSection::Stock],
                    ) {
                        let stock_snapshot_url =
                            stock_details_url(&self.endpoints.stock_snapshot, venue, instr_id);
                        Some(self.get_market_json(
                            &stock_snapshot_url,
                            cookie,
                            MARKET_DETAILS_REFERER,
                        )?)
                    } else {
                        None
                    };
                    let stock_reports = if wants_section(params, MarketDetailsSection::Ratios) {
                        let url = stock_details_url(&self.endpoints.stock_reports, venue, instr_id);
                        Some(self.get_market_json(&url, cookie, MARKET_DETAILS_REFERER)?)
                    } else {
                        None
                    };
                    parse::to_stock_asset_details(
                        params,
                        &candidate,
                        parse::StockDetailsInputs {
                            static_response,
                            snapshot_response,
                            stock_snapshot,
                            stock_reports,
                        },
                        now_iso,
                    )?
                }
                MarketAssetType::Bond => parse::to_bond_asset_details(
                    params,
                    &candidate,
                    parse::BondDetailsInputs {
                        static_response,
                        snapshot_response,
                    },
                    now_iso,
                )?,
                _ => {
                    return Err(SafeError::market_unsupported_asset_type_for(
                        candidate.asset_type.as_str(),
                        &candidate.identifier,
                    ));
                }
            };
            result.validate_response_size()?;
            Ok(result)
        })?;
        Ok(MarketAssetDetailsLiveResult { result, session })
    }
}

impl MarketIndicesLiveFetcher for FinecoWorker {
    fn fetch_market_indices(
        &self,
        params: &MarketIndicesParams,
        now_iso: &str,
    ) -> Result<MarketIndicesLiveResult, SafeError> {
        params.validate()?;
        let (result, session) = self.run_market_read(now_iso, |cookie| {
            let response: parse::MarketIndicesResponse =
                self.get_market_json(&self.endpoints.indicesbar, cookie, MARKET_SEARCH_REFERER)?;
            Ok(parse::to_market_indices(response, params, now_iso))
        })?;
        Ok(MarketIndicesLiveResult { result, session })
    }
}

#[derive(Debug)]
struct ParsedMarketIdentifier {
    venue: String,
    symbol: String,
}

impl ParsedMarketIdentifier {
    fn parse(identifier: &str) -> Result<Self, SafeError> {
        let (venue, symbol) = identifier
            .split_once('/')
            .or_else(|| identifier.split_once(':'))
            .ok_or_else(|| SafeError::invalid_request("identifier must be venue-qualified."))?;
        Ok(Self {
            venue: venue.to_ascii_uppercase(),
            symbol: symbol.to_ascii_uppercase(),
        })
    }
}

fn resolve_market_candidate(
    search: &fineco_ipc::MarketSearchResult,
    parsed: &ParsedMarketIdentifier,
    params: &MarketDetailsParams,
) -> Result<MarketSearchCandidate, SafeError> {
    let expected_isin = params
        .expected_isin
        .as_deref()
        .map(normalize_expected_isin)
        .transpose()?;
    let mut survivors = Vec::new();
    for group in &search.groups {
        for candidate in &group.candidates {
            if candidate.venue.eq_ignore_ascii_case(&parsed.venue)
                && identifier_symbol_matches(candidate, &parsed.symbol)
                && expected_isin.as_ref().is_none_or(|expected| {
                    candidate
                        .isin
                        .as_ref()
                        .is_some_and(|isin| isin.eq_ignore_ascii_case(expected))
                })
            {
                survivors.push(candidate.clone());
            }
        }
    }
    match survivors.len() {
        0 => Err(SafeError::market_not_found()),
        1 => Ok(survivors.remove(0)),
        _ => Err(SafeError::market_ambiguous_identifier_with_suggestions(
            &ambiguity_suggestions(&survivors),
        )),
    }
}

fn ambiguity_suggestions(candidates: &[MarketSearchCandidate]) -> Vec<String> {
    candidates
        .iter()
        .take(MAX_AMBIGUITY_SUGGESTIONS)
        .map(|candidate| {
            let isin = candidate.isin.as_deref().unwrap_or("no_isin");
            sanitize_text(&format!(
                "{} ({}, {isin})",
                candidate.identifier,
                candidate.asset_type.as_str()
            ))
        })
        .collect()
}

fn verify_static_identity(
    static_response: &parse::StaticSearchResponse,
    candidate: &MarketSearchCandidate,
    expected_isin: Option<&str>,
) -> Result<(), SafeError> {
    let Some(expected_isin) = expected_isin.or(candidate.isin.as_deref()) else {
        return Ok(());
    };
    let expected_isin = normalize_expected_isin(expected_isin)?;
    let Some(static_instr_id) = parse::static_instrument_id(static_response, &candidate.fineco_key)
    else {
        return Err(SafeError::market_unexpected_response());
    };
    if static_instr_id.eq_ignore_ascii_case(&expected_isin) {
        Ok(())
    } else {
        Err(SafeError::market_unexpected_response())
    }
}

fn symbols_equivalent(candidate: &str, requested: &str) -> bool {
    normalize_symbol(candidate) == normalize_symbol(requested)
}

/// Whether the requested symbol portion of a `<venue>/<symbol>` identifier matches
/// this candidate. Stocks/ETFs match on their (share-class-normalized) symbol per
/// D-1. Bonds additionally match on their ISIN, because the owner-approved bond
/// input is `<venue>/<ISIN>` (the Fineco search symbol for a bond is an opaque
/// short ticker the caller would not know). The venue filter plus the
/// exactly-one-survivor rule keep this unambiguous.
fn identifier_symbol_matches(candidate: &MarketSearchCandidate, requested_symbol: &str) -> bool {
    if symbols_equivalent(&candidate.symbol, requested_symbol) {
        return true;
    }
    candidate.asset_type == MarketAssetType::Bond
        && candidate
            .isin
            .as_deref()
            .is_some_and(|isin| isin.eq_ignore_ascii_case(requested_symbol))
}

fn details_search_terms(symbol: &str) -> Vec<String> {
    let mut terms = Vec::new();
    push_unique_search_term(&mut terms, symbol);
    let spaced = symbol
        .chars()
        .map(|ch| {
            if matches!(ch, '.' | '/' | '-' | '_') {
                ' '
            } else {
                ch
            }
        })
        .collect::<String>();
    push_unique_search_term(&mut terms, &spaced);
    if let Some((root, _)) = symbol.split_once(['.', '/', '-', '_']) {
        push_unique_search_term(&mut terms, root);
    }
    let compact = normalize_symbol(symbol);
    push_unique_search_term(&mut terms, &compact);
    terms
}

fn push_unique_search_term(terms: &mut Vec<String>, value: &str) {
    let term = sanitize_text(value).to_ascii_uppercase();
    if !term.is_empty() && !terms.iter().any(|existing| existing == &term) {
        terms.push(term);
    }
}

fn normalize_symbol(symbol: &str) -> String {
    symbol
        .chars()
        .filter(|ch| !matches!(ch, '.' | '/' | '-' | '_' | ' '))
        .flat_map(char::to_uppercase)
        .collect()
}

#[derive(Serialize)]
struct StaticSearchRequest<'a> {
    instruments: [&'a str; 1],
    fields: &'static [&'static str],
    #[serde(rename = "withWarnings")]
    with_warnings: bool,
}

impl<'a> StaticSearchRequest<'a> {
    fn for_instrument(instrument: &'a str) -> Self {
        Self {
            instruments: [instrument],
            fields: &[
                "instrId",
                "venueSystem",
                "description",
                "symbol",
                "instrTyp",
                "newType",
                "ricReuters",
                "currencyCd",
                "issueDate",
                "issuer",
                "preferredVenue",
                "kidIt",
                "kidEn",
                "esgTaxonomy",
                "topQuality",
                "categoryId",
                // Bond-only static fields; harmless (returned null) for stocks/ETFs.
                "bondCouponRate",
                "bondCouponTyp",
                "bondFrequency",
                "bondExpiryDate",
                "bondMaturityDate",
                "bondAccruedInterestRate",
                "bondSubordinate",
                "bondParValue",
                "bondIssueDate",
                "bondIssuePrice",
                "minQty",
                "rating",
                "issuerRating",
                "bailin",
                "flagPriips",
                "valueAtRisk",
            ],
            with_warnings: true,
        }
    }
}

fn wants_section(params: &MarketDetailsParams, section: MarketDetailsSection) -> bool {
    params
        .sections
        .as_ref()
        .is_some_and(|sections| sections.contains(&section))
}

fn wants_default_or_section(params: &MarketDetailsParams, section: MarketDetailsSection) -> bool {
    params
        .sections
        .as_ref()
        .is_none_or(|sections| sections.contains(&section))
}

fn wants_default_or_any_section(
    params: &MarketDetailsParams,
    sections: &[MarketDetailsSection],
) -> bool {
    params.sections.as_ref().is_none_or(|requested| {
        sections
            .iter()
            .copied()
            .any(|section| requested.contains(&section))
    })
}

fn wants_only_identity(params: &MarketDetailsParams) -> bool {
    params.sections.as_ref().is_some_and(|sections| {
        !sections.is_empty()
            && sections
                .iter()
                .all(|section| *section == MarketDetailsSection::Identity)
    })
}

fn wants_any_section(params: &MarketDetailsParams, sections: &[MarketDetailsSection]) -> bool {
    sections
        .iter()
        .copied()
        .any(|section| wants_section(params, section))
}

fn identity_only_details(
    params: &MarketDetailsParams,
    candidate: &MarketSearchCandidate,
    captured_at: &str,
) -> MarketAssetDetailsResult {
    MarketAssetDetailsResult {
        schema_version: 1,
        data_class: "authenticated_market".to_string(),
        captured_at: captured_at.to_string(),
        asset: MarketAssetIdentity {
            identifier: params.identifier.clone(),
            fineco_key: MarketField::high_string(
                &candidate.fineco_key,
                "fineco",
                "authenticated_market",
                "search.global",
                captured_at,
            ),
            asset_type: MarketField::high(
                candidate.asset_type,
                None,
                "fineco",
                "authenticated_market",
                "search.global",
                None,
                captured_at,
            ),
            name: Some(MarketField::high_string(
                &candidate.name,
                "fineco",
                "authenticated_market",
                "search.global",
                captured_at,
            )),
            isin: candidate.isin.as_ref().map(|isin| {
                MarketField::high_string(
                    isin,
                    "fineco",
                    "authenticated_market",
                    "search.global",
                    captured_at,
                )
            }),
            venue: MarketField::high_string(
                &candidate.venue,
                "fineco",
                "authenticated_market",
                "search.global",
                captured_at,
            ),
            symbol: MarketField::medium_string(
                &candidate.symbol,
                "fineco",
                "authenticated_market",
                "search.global",
                captured_at,
            ),
            display_symbol: Some(MarketField::medium_string(
                &candidate.display_symbol,
                "fineco",
                "authenticated_market",
                "search.global",
                captured_at,
            )),
            currency: candidate.currency.as_ref().map(|currency| {
                MarketField::high_string(
                    currency,
                    "fineco",
                    "authenticated_market",
                    "search.global",
                    captured_at,
                )
            }),
        },
        sections: MarketAssetSections::default(),
        sources: vec![MarketSource {
            source: "fineco".to_string(),
            data_class: "authenticated_market".to_string(),
            source_ref: "search.global".to_string(),
            captured_at: captured_at.to_string(),
        }],
        warnings: vec![],
    }
}

fn etf_query_url(base: &str, fineco_key: &str, view: &str) -> String {
    format!(
        "{base}?type=ETF&ids={}&view={view}",
        percent_encode_query_component(fineco_key)
    )
}

fn fineco_key_parts(fineco_key: &str) -> Result<(&str, &str), SafeError> {
    fineco_key
        .rsplit_once('.')
        .ok_or_else(SafeError::market_unexpected_response)
}

fn stock_details_url(base: &str, venue: &str, instr_id: &str) -> String {
    format!(
        "{base}/{}/{}",
        percent_encode_query_component(venue),
        percent_encode_query_component(instr_id)
    )
}

fn with_market_retry<T>(mut op: impl FnMut() -> Result<T, SafeError>) -> Result<T, SafeError> {
    let mut attempt = 1u32;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(error) if is_market_retryable(&error) && attempt < MARKET_RETRY_ATTEMPTS => {
                attempt += 1;
            }
            Err(error) => return Err(market_login_error(error)),
        }
    }
}

fn is_market_retryable(error: &SafeError) -> bool {
    matches!(
        error.code(),
        "market_upstream_failure" | "fineco_timeout" | "fineco_upstream_error"
    ) && error.retryable()
}

fn market_login_error(error: SafeError) -> SafeError {
    match error.code() {
        "auth_required" => SafeError::market_auth_required(),
        "rate_limited" => SafeError::market_rate_limited(),
        "fineco_timeout" => SafeError::market_upstream_failure(),
        "fineco_upstream_error" if error.retryable() => SafeError::market_upstream_failure(),
        "fineco_upstream_error" => SafeError::market_unexpected_response(),
        "not_found" => SafeError::market_unexpected_response(),
        _ => error,
    }
}

fn market_status_error(status: u16) -> SafeError {
    match status {
        401 | 403 => SafeError::market_auth_required(),
        429 => SafeError::market_rate_limited(),
        500..=599 => SafeError::market_upstream_failure(),
        _ => SafeError::market_unexpected_response(),
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
fn merge_cookies(first: &str, second: &str) -> Zeroizing<String> {
    // The cookie *values* carry session material, so each owned fragment is held
    // in a `Zeroizing<String>` (the name, used only for dedup, is not secret).
    let mut pairs: Vec<(String, Zeroizing<String>)> = Vec::new();
    for raw in first.split("; ").chain(second.split("; ")) {
        let pair = raw.trim();
        if pair.is_empty() {
            continue;
        }
        let name = pair.split('=').next().unwrap_or(pair).to_string();
        match pairs.iter_mut().find(|(existing, _)| *existing == name) {
            Some(slot) => slot.1 = Zeroizing::new(pair.to_string()),
            None => pairs.push((name, Zeroizing::new(pair.to_string()))),
        }
    }
    Zeroizing::new(
        pairs
            .iter()
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
            .join("; "),
    )
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

fn percent_encode_query_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(&mut out, "%{byte:02X}");
            }
        }
    }
    out
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
fn cookie_header_from(headers: &ureq::http::HeaderMap) -> Zeroizing<String> {
    Zeroizing::new(
        headers
            .get_all(ureq::http::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|set_cookie| set_cookie.split(';').next())
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// Extract a conservative, status-only session TTL from the **session** cookies'
/// `Set-Cookie` lifetime attributes (`Max-Age`/`Expires`) — never their values.
///
/// Only cookies whose NAME marks them as session cookies are considered, so a
/// long-lived tracking/analytics cookie (a stats or logging id that outlives the
/// login by days) can never masquerade as the session lifetime. Fineco's real
/// session cookies are typically `Session`-scoped (no declared lifetime), so this
/// is usually `None`: the authoritative idle timeout is server-enforced, not
/// client-derivable. This metadata is informational only — the cross-call reuse
/// window is the fixed [`fineco_ipc::MARKET_SESSION_REUSE_TTL_SECS`], not derived
/// from it. If several session cookies declare a lifetime, the shortest is used.
fn session_expires_in_secs_from(headers: &ureq::http::HeaderMap) -> Option<u64> {
    let now = now_unix_secs();
    headers
        .get_all(ureq::http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|set_cookie| is_session_cookie(set_cookie))
        .filter_map(|set_cookie| ttl_secs_from_set_cookie_at(set_cookie, now))
        .min()
}

/// Whether a `Set-Cookie` is a session cookie by name (case-insensitive
/// `session`) — used to keep tracking-cookie lifetimes out of the session TTL.
fn is_session_cookie(set_cookie: &str) -> bool {
    set_cookie
        .split(['=', ';'])
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .contains("session")
}

fn max_age_secs_from_set_cookie(set_cookie: &str) -> Option<u64> {
    set_cookie.split(';').skip(1).find_map(|attribute| {
        let (name, value) = attribute.trim().split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("Max-Age") {
            return None;
        }
        let seconds = value.trim().parse::<i64>().ok()?;
        Some(u64::try_from(seconds).unwrap_or(0))
    })
}

fn ttl_secs_from_set_cookie_at(set_cookie: &str, now_unix_secs: u64) -> Option<u64> {
    max_age_secs_from_set_cookie(set_cookie)
        .or_else(|| expires_secs_from_set_cookie_at(set_cookie, now_unix_secs))
}

fn expires_secs_from_set_cookie_at(set_cookie: &str, now_unix_secs: u64) -> Option<u64> {
    set_cookie.split(';').skip(1).find_map(|attribute| {
        let (name, value) = attribute.trim().split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("Expires") {
            return None;
        }
        let expires = parse_imf_fixdate_unix_secs(value.trim())?;
        Some(expires.saturating_sub(now_unix_secs))
    })
}

fn parse_imf_fixdate_unix_secs(value: &str) -> Option<u64> {
    let (_weekday, rest) = value.split_once(',')?;
    let mut parts = rest.split_whitespace();
    let date = parts.next()?;
    let (day, month, year) = if let Some((day, month, year)) = parse_hyphenated_cookie_date(date) {
        (day, month, year)
    } else {
        let day = date.parse::<u32>().ok()?;
        let month = month_number(parts.next()?)?;
        let year = parts.next()?.parse::<i32>().ok()?;
        (day, month, year)
    };
    let (hour, minute, second) = parse_hms(parts.next()?)?;
    if !parts.next()?.eq_ignore_ascii_case("GMT") || parts.next().is_some() {
        return None;
    }
    unix_secs_from_ymdhms(year, month, day, hour, minute, second)
}

fn parse_hyphenated_cookie_date(date: &str) -> Option<(u32, u32, i32)> {
    let mut parts = date.split('-');
    let day = parts.next()?.parse::<u32>().ok()?;
    let month = month_number(parts.next()?)?;
    let year = parts.next()?.parse::<i32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((day, month, year))
}

fn month_number(month: &str) -> Option<u32> {
    if month.eq_ignore_ascii_case("Jan") {
        Some(1)
    } else if month.eq_ignore_ascii_case("Feb") {
        Some(2)
    } else if month.eq_ignore_ascii_case("Mar") {
        Some(3)
    } else if month.eq_ignore_ascii_case("Apr") {
        Some(4)
    } else if month.eq_ignore_ascii_case("May") {
        Some(5)
    } else if month.eq_ignore_ascii_case("Jun") {
        Some(6)
    } else if month.eq_ignore_ascii_case("Jul") {
        Some(7)
    } else if month.eq_ignore_ascii_case("Aug") {
        Some(8)
    } else if month.eq_ignore_ascii_case("Sep") {
        Some(9)
    } else if month.eq_ignore_ascii_case("Oct") {
        Some(10)
    } else if month.eq_ignore_ascii_case("Nov") {
        Some(11)
    } else if month.eq_ignore_ascii_case("Dec") {
        Some(12)
    } else {
        None
    }
}

fn parse_hms(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.split(':');
    let hour = parts.next()?.parse::<u32>().ok()?;
    let minute = parts.next()?.parse::<u32>().ok()?;
    let second = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some((hour, minute, second))
}

fn unix_secs_from_ymdhms(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<u64> {
    if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    let max_day = days_in_month(year, month)?;
    if day == 0 || day > max_day {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))?;
    u64::try_from(seconds).ok()
}

fn days_in_month(year: i32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let year = i64::from(year) - if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Zeroize the held market session if its reuse window has lapsed (the reaper's
/// per-tick action; a free function so it can be unit-tested with a controlled
/// clock). `now_unix_secs` and the stored `valid_until_epoch` are both UTC epoch
/// seconds, which is what the controller's `now_iso` resolves to in production.
fn reap_expired_market_session(session: &Mutex<Option<HeldMarketSession>>, now_unix_secs: u64) {
    let now = i64::try_from(now_unix_secs).unwrap_or(i64::MAX);
    if let Ok(mut guard) = session.lock()
        && guard
            .as_ref()
            .is_some_and(|held| now >= held.valid_until_epoch)
    {
        // Dropping the `Zeroizing` cookie scrubs the session material.
        *guard = None;
    }
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
    use super::{
        FinecoEndpoints, FinecoWorker, HeldMarketSession, MARKET_RETRY_ATTEMPTS,
        ParsedMarketIdentifier, StaticCredentialSource, details_search_terms, market_status_error,
        max_age_secs_from_set_cookie, reap_expired_market_session, resolve_market_candidate,
        session_expires_in_secs_from, ttl_secs_from_set_cookie_at, with_market_retry,
    };
    use super::{market_login_error, synthetic_public_cookies};
    use fineco_core::SafeError;
    use fineco_ipc::{
        MarketAssetType, MarketDetailsParams, MarketSearchCandidate, MarketSearchGroup,
        MarketSearchParams, MarketSearchResult,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    /// The credentialed worker must NEVER honor a proxy from the environment:
    /// ureq honors `HTTPS_PROXY`/`ALL_PROXY`/… by default, which would let an
    /// env-injection mistake reroute the credentialed login through an
    /// attacker-chosen proxy. We pin `proxy(None)`, so the built agent's config
    /// carries no proxy. (The adversarial env-hijack scenario isn't unit-testable
    /// here: `std::env::set_var` is `unsafe` on edition 2024 and the workspace
    /// lint forbids `unsafe`; this asserts the resulting config invariant.)
    #[test]
    fn the_worker_agent_does_not_honor_proxy_env_vars() {
        let worker = FinecoWorker::new_with_timeout(
            FinecoEndpoints::for_base("https://example.invalid"),
            Box::new(StaticCredentialSource::new("u", "p")),
            std::time::Duration::from_secs(1),
        );
        assert!(
            worker.agent.config().proxy().is_none(),
            "the credentialed worker must not honor a proxy from the environment"
        );
    }

    #[test]
    fn max_age_metadata_is_parsed_without_cookie_values() {
        assert_eq!(
            max_age_secs_from_set_cookie(
                "FINECOSESSION=secret-session-value; Path=/; HttpOnly; Max-Age=3600"
            ),
            Some(3600)
        );
        assert_eq!(
            max_age_secs_from_set_cookie("FINECOSESSION=secret; max-age=42; HttpOnly"),
            Some(42)
        );
        assert_eq!(
            max_age_secs_from_set_cookie("FINECOSESSION=secret; Path=/; HttpOnly"),
            None
        );
        assert_eq!(
            max_age_secs_from_set_cookie("FINECOSESSION=secret; Max-Age=-1"),
            Some(0)
        );
        assert_eq!(
            max_age_secs_from_set_cookie("FINECOSESSION=secret; Max-Age=not-a-number"),
            None
        );
    }

    #[test]
    fn expires_metadata_is_parsed_without_cookie_values() {
        const NOW: u64 = 1_781_524_800; // Mon, 15 Jun 2026 12:00:00 GMT

        assert_eq!(
            ttl_secs_from_set_cookie_at(
                "FINECOSESSION=secret; Path=/; HttpOnly; Expires=Mon, 15 Jun 2026 12:30:00 GMT",
                NOW
            ),
            Some(1_800)
        );
        assert_eq!(
            ttl_secs_from_set_cookie_at(
                "FINECOSESSION=secret; Path=/; HttpOnly; Expires=Mon, 15-Jun-2026 12:30:00 GMT",
                NOW
            ),
            Some(1_800)
        );
        assert_eq!(
            ttl_secs_from_set_cookie_at(
                "FINECOSESSION=secret; Path=/; HttpOnly; Expires=Mon, 15 jun 2026 12:30:00 gmt",
                NOW
            ),
            Some(1_800)
        );
        assert_eq!(
            ttl_secs_from_set_cookie_at(
                "FINECOSESSION=secret; Path=/; Expires=Mon, 15 Jun 2026 11:59:59 GMT",
                NOW
            ),
            Some(0)
        );
        assert_eq!(
            ttl_secs_from_set_cookie_at("FINECOSESSION=secret; Expires=not-a-date", NOW),
            None
        );
        assert_eq!(
            ttl_secs_from_set_cookie_at(
                "FINECOSESSION=secret; Expires=Mon, 15 Jun 2026 12:30:00 GMT; Max-Age=60",
                NOW
            ),
            Some(60)
        );
    }

    #[test]
    fn session_expiry_metadata_uses_only_session_cookie_lifetimes() {
        let mut headers = ureq::http::HeaderMap::new();
        // A short-lived TRACKING cookie: must NOT be read as the session TTL.
        headers.append(
            ureq::http::header::SET_COOKIE,
            "loggerUid=secret; Path=/; Max-Age=60"
                .parse()
                .expect("header"),
        );
        // A non-session preflight cookie with a longer lifetime: also excluded.
        headers.append(
            ureq::http::header::SET_COOKIE,
            "PREFLIGHT=secret; Path=/; Max-Age=3600"
                .parse()
                .expect("header"),
        );
        // The actual session cookie: this is the lifetime we report.
        headers.append(
            ureq::http::header::SET_COOKIE,
            "FINECOSESSION=secret; Path=/; HttpOnly; Max-Age=600"
                .parse()
                .expect("header"),
        );

        // The 60s tracker is ignored; only the session cookie's lifetime counts.
        assert_eq!(session_expires_in_secs_from(&headers), Some(600));
    }

    #[test]
    fn session_expiry_metadata_is_none_when_session_cookies_are_session_scoped() {
        // Real Fineco session cookies carry no Max-Age/Expires (they are
        // `Session`-scoped); only trackers declare a lifetime. The session TTL is
        // then unknown from cookies (server-enforced), so this is `None`.
        let mut headers = ureq::http::HeaderMap::new();
        headers.append(
            ureq::http::header::SET_COOKIE,
            "gsessionid=secret; Path=/; HttpOnly"
                .parse()
                .expect("header"),
        );
        headers.append(
            ureq::http::header::SET_COOKIE,
            "finecostat=secret; Path=/; Max-Age=31536000"
                .parse()
                .expect("header"),
        );

        assert_eq!(session_expires_in_secs_from(&headers), None);
    }

    #[test]
    fn the_reaper_zeroizes_only_an_expired_held_session() {
        let held = |valid_until_epoch: i64| {
            Mutex::new(Some(HeldMarketSession {
                cookie: Zeroizing::new("FINECOSESSION=secret".to_string()),
                expires_in_secs: None,
                valid_until_epoch,
            }))
        };

        // Before the window lapses: the reaper leaves the session in place.
        let session = held(1_000);
        reap_expired_market_session(&session, 999);
        assert!(session.lock().expect("lock").is_some());

        // At/after expiry: the reaper zeroizes the held session.
        reap_expired_market_session(&session, 1_000);
        assert!(session.lock().expect("lock").is_none());

        // An empty slot is a no-op (idle worker, nothing held).
        let empty: Mutex<Option<HeldMarketSession>> = Mutex::new(None);
        reap_expired_market_session(&empty, u64::MAX);
        assert!(empty.lock().expect("lock").is_none());
    }

    #[test]
    fn resolver_accepts_dotted_expected_isin_suffixes() {
        let search = search_result(vec![candidate(
            "AFF/VHYL",
            "VHYL",
            "IE00B8GKDB10",
            MarketAssetType::Etf,
        )]);
        let parsed = ParsedMarketIdentifier {
            venue: "AFF".to_string(),
            symbol: "VHYL".to_string(),
        };
        let resolved = resolve_market_candidate(
            &search,
            &parsed,
            &MarketDetailsParams {
                identifier: "AFF/VHYL".to_string(),
                expected_isin: Some("IE00B8GKDB10.AFF".to_string()),
                sections: None,
            },
        )
        .expect("dotted expected_isin should compare by normalized ISIN");

        assert_eq!(resolved.identifier, "AFF/VHYL");
    }

    #[test]
    fn ambiguous_resolver_error_includes_bounded_candidate_suggestions() {
        let search = search_result(vec![
            candidate("AFF/VHYL", "VHYL", "IE00B8GKDB10", MarketAssetType::Etf),
            candidate("AFF/VHYL", "VHYL", "IE00B8GKDB11", MarketAssetType::Etf),
        ]);
        let parsed = ParsedMarketIdentifier {
            venue: "AFF".to_string(),
            symbol: "VHYL".to_string(),
        };

        let err = resolve_market_candidate(
            &search,
            &parsed,
            &MarketDetailsParams {
                identifier: "AFF/VHYL".to_string(),
                expected_isin: None,
                sections: None,
            },
        )
        .expect_err("two hard-filter survivors must fail closed");

        assert_eq!(err.code(), "market_ambiguous_identifier");
        assert!(err.safe_message().contains("AFF/VHYL"));
        assert!(err.safe_message().contains("IE00B8GKDB10"));
        assert!(!err.safe_message().contains('\n'));
    }

    #[test]
    fn resolver_matrix_covers_common_symbols_and_share_classes() {
        for (identifier, candidate_symbol, isin, asset_type) in [
            (
                "NASDAQ/AAPL",
                "AAPL",
                "US0378331005",
                MarketAssetType::Stock,
            ),
            ("AFF/VHYL", "VHYL", "IE00B8GKDB10", MarketAssetType::Etf),
            ("AFF/ENEL", "ENEL", "IT0003128367", MarketAssetType::Stock),
            ("AFF/ISP", "ISP", "IT0000072618", MarketAssetType::Stock),
            (
                "NYSE/BRK.B",
                "BRK/B",
                "US0846707026",
                MarketAssetType::Stock,
            ),
            ("XETRA/BMW3", "BMW3", "DE0005190037", MarketAssetType::Stock),
            ("XETRA/VUAA", "VUAA", "IE00BFMXXD54", MarketAssetType::Etf),
            (
                "MOT/T56094",
                "T56094",
                "IT0005560948",
                MarketAssetType::Bond,
            ),
        ] {
            let (venue, symbol) = identifier.split_once('/').expect("qualified");
            let search = search_result(vec![candidate(
                identifier,
                candidate_symbol,
                isin,
                asset_type,
            )]);
            let parsed = ParsedMarketIdentifier {
                venue: venue.to_string(),
                symbol: symbol.to_string(),
            };
            let resolved = resolve_market_candidate(
                &search,
                &parsed,
                &MarketDetailsParams {
                    identifier: identifier.to_string(),
                    expected_isin: Some(format!("{isin}.{venue}")),
                    sections: None,
                },
            )
            .expect("one hard-filter survivor should resolve");

            assert_eq!(resolved.identifier, identifier);
            assert_eq!(resolved.isin.as_deref(), Some(isin));
        }
    }

    #[test]
    fn resolver_accepts_venue_plus_isin_for_bonds_only() {
        // A bond resolves by venue + ISIN even though its Fineco search symbol is
        // an opaque short ticker the caller would not know.
        let bond_search = search_result(vec![candidate(
            "MOT/T56094",
            "T56094",
            "IT0005560948",
            MarketAssetType::Bond,
        )]);
        let parsed = ParsedMarketIdentifier {
            venue: "MOT".to_string(),
            symbol: "IT0005560948".to_string(),
        };
        let resolved = resolve_market_candidate(
            &bond_search,
            &parsed,
            &MarketDetailsParams {
                identifier: "MOT/IT0005560948".to_string(),
                expected_isin: None,
                sections: None,
            },
        )
        .expect("bond resolves by venue + ISIN");
        assert_eq!(resolved.isin.as_deref(), Some("IT0005560948"));

        // The ISIN-as-symbol path is bond-only: a stock keeps the venue/ticker
        // contract and is not resolvable by its ISIN.
        let stock_search = search_result(vec![candidate(
            "NASDAQ/AAPL",
            "AAPL",
            "US0378331005",
            MarketAssetType::Stock,
        )]);
        let parsed_stock = ParsedMarketIdentifier {
            venue: "NASDAQ".to_string(),
            symbol: "US0378331005".to_string(),
        };
        let err = resolve_market_candidate(
            &stock_search,
            &parsed_stock,
            &MarketDetailsParams {
                identifier: "NASDAQ/US0378331005".to_string(),
                expected_isin: None,
                sections: None,
            },
        )
        .expect_err("a stock must not resolve by ISIN-as-symbol");
        assert_eq!(err.code(), "market_not_found");
    }

    #[test]
    fn details_search_terms_cover_share_class_aliases() {
        assert_eq!(
            details_search_terms("BRK.B"),
            vec!["BRK.B", "BRK B", "BRK", "BRKB"]
        );
        assert_eq!(
            details_search_terms("BRK/B"),
            vec!["BRK/B", "BRK B", "BRK", "BRKB"]
        );
    }

    #[test]
    fn details_resolution_uses_uncapped_search_candidates() {
        let mut etfs = Vec::new();
        for idx in 0..fineco_ipc::MAX_CANDIDATES_PER_GROUP {
            etfs.push(format!(
                r#"{{"d":"Distractor {idx}","m":"AFF","s":"D{idx}.MI","i":"IE00DIST{idx:04}","c":"EUR"}}"#
            ));
        }
        etfs.push(
            r#"{"d":"Target ETF","m":"AFF","s":"VHYL.MI","i":"IE00B8GKDB10","c":"EUR"}"#
                .to_string(),
        );
        let raw = format!(r#"{{"ETF":[{}]}}"#, etfs.join(","));
        let response: super::parse::MarketSearchResponse =
            serde_json::from_str(&raw).expect("search fixture");
        let params = MarketSearchParams {
            query: "VHYL".to_string(),
            asset_type: None,
            limit: Some(fineco_ipc::MAX_TOTAL_CANDIDATES),
        };
        let search = super::parse::to_market_search_for_resolution(
            response,
            &params,
            "2026-06-14T09:30:00Z",
        );
        let parsed = ParsedMarketIdentifier {
            venue: "AFF".to_string(),
            symbol: "VHYL".to_string(),
        };

        let resolved = resolve_market_candidate(
            &search,
            &parsed,
            &MarketDetailsParams {
                identifier: "AFF/VHYL".to_string(),
                expected_isin: Some("IE00B8GKDB10".to_string()),
                sections: None,
            },
        )
        .expect("details resolution must see candidates beyond display caps");

        assert_eq!(resolved.identifier, "AFF/VHYL");
    }

    #[test]
    fn static_identity_mismatch_fails_closed() {
        let static_response = serde_json::from_str(
            r#"{"IE00B8GKDB10.AFF":{"instrId":"IE00B8GKDB11","venueSystem":"AFF"}}"#,
        )
        .expect("static response");
        let candidate = candidate("AFF/VHYL", "VHYL", "IE00B8GKDB10", MarketAssetType::Etf);

        let err =
            super::verify_static_identity(&static_response, &candidate, Some("IE00B8GKDB10.AFF"))
                .expect_err("static identity mismatch must fail closed");

        assert_eq!(err.code(), "market_unexpected_response");
    }

    #[test]
    fn static_identity_uses_candidate_isin_without_expected_isin() {
        let static_response = serde_json::from_str(
            r#"{"IE00B8GKDB10.AFF":{"instrId":"IE00B8GKDB11","venueSystem":"AFF"}}"#,
        )
        .expect("static response");
        let candidate = candidate("AFF/VHYL", "VHYL", "IE00B8GKDB10", MarketAssetType::Etf);

        let err = super::verify_static_identity(&static_response, &candidate, None)
            .expect_err("candidate ISIN mismatch must fail closed");

        assert_eq!(err.code(), "market_unexpected_response");
    }

    fn search_result(candidates: Vec<MarketSearchCandidate>) -> MarketSearchResult {
        MarketSearchResult {
            query: "VHYL".to_string(),
            data_class: "authenticated_market".to_string(),
            source: "fineco.search.global".to_string(),
            captured_at: "2026-06-14T09:30:00Z".to_string(),
            groups: vec![MarketSearchGroup {
                asset_type: MarketAssetType::Etf,
                result_count: candidates.len(),
                candidates,
            }],
        }
    }

    fn candidate(
        identifier: &str,
        symbol: &str,
        isin: &str,
        asset_type: MarketAssetType,
    ) -> MarketSearchCandidate {
        let venue = identifier.split_once('/').expect("qualified").0;
        MarketSearchCandidate {
            fineco_key: format!("{isin}.{venue}"),
            identifier: identifier.to_string(),
            name: "Synthetic candidate".to_string(),
            venue: venue.to_string(),
            symbol: symbol.to_string(),
            display_symbol: format!("{symbol}.MI"),
            isin: Some(isin.to_string()),
            currency: Some("EUR".to_string()),
            asset_type,
            preferred: false,
        }
    }

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

    #[test]
    fn authenticated_market_statuses_map_to_market_error_codes() {
        assert_eq!(market_status_error(401).code(), "market_auth_required");
        assert_eq!(market_status_error(403).code(), "market_auth_required");
        assert_eq!(market_status_error(429).code(), "market_rate_limited");
        assert_eq!(market_status_error(500).code(), "market_upstream_failure");
        assert!(market_status_error(500).retryable());
        assert_eq!(
            market_status_error(418).code(),
            "market_unexpected_response"
        );
        assert!(!market_status_error(418).retryable());
    }

    #[test]
    fn authenticated_market_login_failures_map_to_market_error_codes() {
        assert_eq!(
            market_login_error(SafeError::auth_required()).code(),
            "market_auth_required"
        );
        assert_eq!(
            market_login_error(SafeError::rate_limited()).code(),
            "market_rate_limited"
        );
        assert_eq!(
            market_login_error(SafeError::fineco_timeout()).code(),
            "market_upstream_failure"
        );
        assert_eq!(
            market_login_error(SafeError::from_upstream_status(500)).code(),
            "market_upstream_failure"
        );
        assert_eq!(
            market_login_error(SafeError::from_upstream_status(418)).code(),
            "market_unexpected_response"
        );
        assert_eq!(
            market_login_error(SafeError::not_found()).code(),
            "market_unexpected_response"
        );
    }

    #[test]
    fn market_retry_retries_only_retryable_market_upstream_failures() {
        let attempts = std::cell::Cell::new(0u32);
        let out = with_market_retry(|| {
            attempts.set(attempts.get() + 1);
            if attempts.get() < MARKET_RETRY_ATTEMPTS {
                Err(SafeError::market_upstream_failure())
            } else {
                Ok("ok")
            }
        })
        .expect("retry succeeds");

        assert_eq!(out, "ok");
        assert_eq!(attempts.get(), MARKET_RETRY_ATTEMPTS);
    }

    #[test]
    fn market_retry_maps_timeout_after_exhaustion() {
        let attempts = std::cell::Cell::new(0u32);
        let err: SafeError = with_market_retry(|| -> Result<(), SafeError> {
            attempts.set(attempts.get() + 1);
            Err(SafeError::fineco_timeout())
        })
        .expect_err("timeout exhausts");

        assert_eq!(attempts.get(), MARKET_RETRY_ATTEMPTS);
        assert_eq!(err.code(), "market_upstream_failure");
    }

    #[test]
    fn market_retry_does_not_retry_auth_or_rate_limit() {
        for error in [
            SafeError::market_auth_required(),
            SafeError::market_rate_limited(),
        ] {
            let attempts = std::cell::Cell::new(0u32);
            let err: SafeError = with_market_retry(|| -> Result<(), SafeError> {
                attempts.set(attempts.get() + 1);
                Err(error.clone())
            })
            .expect_err("non-upstream error propagates");

            assert_eq!(attempts.get(), 1);
            assert_eq!(err.code(), error.code());
        }
    }
}
