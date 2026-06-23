//! `fineco-core` — shared, leaf domain types for `fineco-helper`.
//!
//! No credential, DB, or network dependencies (the architecture's leaf crate).
//! Provides the **safe error envelope**: every error returned across a boundary
//! is mapped to a [`SafeError`] carrying only allowlisted, non-sensitive fields
//! (`code` / `class` / `retryable` / `safe_message`) — never raw upstream
//! payloads, bodies, headers, or stack traces. (See the design spec, "Logging
//! And Audit".)

mod freshness;
mod text;
mod transport;
pub use freshness::{
    FreshnessState, epoch_to_iso8601_utc, freshness_from_age, now_epoch_seconds, now_iso8601_utc,
    parse_iso8601_utc,
};
pub use text::{MAX_TEXT_FIELD_CHARS, sanitize_text, truncate_text};
pub use transport::is_secure_or_loopback;

/// Coarse classification of an error, used for logging and client handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// A failure from an upstream service (e.g. Fineco / enrichment host).
    Upstream,
    /// Authentication/session failure.
    Auth,
    /// The request failed validation (bad/oversized input, forbidden field).
    Validation,
    /// A rate limit / budget was exceeded.
    RateLimit,
    /// A conflict with current state (e.g. a refresh already running).
    Conflict,
    /// The requested resource does not exist.
    NotFound,
    /// An unexpected internal error.
    Internal,
}

impl ErrorClass {
    /// Stable lowercase wire string for this class.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorClass::Upstream => "upstream",
            ErrorClass::Auth => "auth",
            ErrorClass::Validation => "validation",
            ErrorClass::RateLimit => "rate_limit",
            ErrorClass::Conflict => "conflict",
            ErrorClass::NotFound => "not_found",
            ErrorClass::Internal => "internal",
        }
    }
}

/// The safe error envelope. Every error crossing a boundary is mapped to one of
/// these. It holds ONLY safe fields; there is no field for, and no constructor
/// that accepts, a raw upstream body / payload / header / stack trace. Raw
/// detail belongs in local debug logs, never here.
#[derive(Debug, Clone)]
pub struct SafeError {
    code: String,
    class: ErrorClass,
    retryable: bool,
    safe_message: String,
}

impl SafeError {
    /// Construct an envelope from explicit, already-safe parts. **Private**: the
    /// envelope can only be built through the named constructors (or
    /// [`SafeError::invalid_request`] with a developer-authored message), so
    /// arbitrary runtime text — e.g. a raw upstream body — cannot enter it.
    fn new(
        code: impl Into<String>,
        class: ErrorClass,
        retryable: bool,
        safe_message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            class,
            retryable,
            safe_message: safe_message.into(),
        }
    }

    /// Stable machine-readable code (e.g. `"fineco_timeout"`).
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Error class.
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        self.class
    }

    /// Whether the caller may retry.
    #[must_use]
    pub fn retryable(&self) -> bool {
        self.retryable
    }

    /// Human-readable, payload-free message safe to return to the client.
    #[must_use]
    pub fn safe_message(&self) -> &str {
        &self.safe_message
    }

    /// Fineco authentication/session expired; not retried automatically.
    #[must_use]
    pub fn auth_required() -> Self {
        Self::new(
            "auth_required",
            ErrorClass::Auth,
            false,
            "Fineco authentication expired. Request a new refresh after credentials/session are available.",
        )
    }

    /// An upstream request timed out; retryable.
    #[must_use]
    pub fn fineco_timeout() -> Self {
        Self::new(
            "fineco_timeout",
            ErrorClass::Upstream,
            true,
            "Fineco request timed out.",
        )
    }

    /// A refresh for this data area is already running; retry later.
    #[must_use]
    pub fn already_refreshing() -> Self {
        Self::new(
            "already_refreshing",
            ErrorClass::Conflict,
            true,
            "A refresh for this data area is already running.",
        )
    }

    /// A rate limit or budget was exceeded.
    #[must_use]
    pub fn rate_limited() -> Self {
        Self::new(
            "rate_limited",
            ErrorClass::RateLimit,
            true,
            "Rate limit exceeded. Try again later.",
        )
    }

    /// An authenticated market live read would exceed the controller-governed
    /// Fineco login budget/cooldown/concurrency policy.
    #[must_use]
    pub fn market_rate_limited() -> Self {
        Self::new(
            "market_rate_limited",
            ErrorClass::RateLimit,
            true,
            "Fineco live-session reads are temporarily rate limited. Try again later.",
        )
    }

    /// Fineco authentication/session failed on an authenticated market read.
    #[must_use]
    pub fn market_auth_required() -> Self {
        Self::new(
            "market_auth_required",
            ErrorClass::Auth,
            false,
            "Fineco authentication is required for this market read.",
        )
    }

    /// The authenticated market resolver found no matching Fineco instrument.
    #[must_use]
    pub fn market_not_found() -> Self {
        Self::new(
            "market_not_found",
            ErrorClass::NotFound,
            false,
            "No matching Fineco market instrument was found.",
        )
    }

    /// The authenticated market resolver found multiple plausible instruments.
    #[must_use]
    pub fn market_ambiguous_identifier() -> Self {
        Self::new(
            "market_ambiguous_identifier",
            ErrorClass::Validation,
            false,
            "The market identifier is ambiguous; use a more specific Fineco venue-qualified identifier.",
        )
    }

    /// The authenticated market resolver found multiple plausible instruments,
    /// with bounded, already-normalized suggestions safe to show to the client.
    #[must_use]
    pub fn market_ambiguous_identifier_with_suggestions(suggestions: &[String]) -> Self {
        if suggestions.is_empty() {
            return Self::market_ambiguous_identifier();
        }
        let context = suggestions
            .iter()
            .map(|suggestion| truncate_text(&sanitize_text(suggestion), 120))
            .collect::<Vec<_>>()
            .join(", ");
        Self::market_ambiguous_identifier_from_safe_message(format!(
            "The market identifier is ambiguous; use a more specific Fineco venue-qualified identifier. Candidates: {context}."
        ))
    }

    /// Rebuild a contextual ambiguity error from an already-safe boundary DTO.
    /// The text is sanitized and bounded again before it re-enters the envelope.
    #[must_use]
    pub fn market_ambiguous_identifier_from_safe_message(safe_message: impl AsRef<str>) -> Self {
        let message = truncate_text(&sanitize_text(safe_message.as_ref()), 2_000);
        if message.is_empty() {
            return Self::market_ambiguous_identifier();
        }
        Self::new(
            "market_ambiguous_identifier",
            ErrorClass::Validation,
            false,
            message,
        )
    }

    /// The requested asset type is searchable but not supported by details v0.
    #[must_use]
    pub fn market_unsupported_asset_type() -> Self {
        Self::new(
            "market_unsupported_asset_type",
            ErrorClass::Validation,
            false,
            "This asset type is not supported by market details yet.",
        )
    }

    /// The requested asset type is searchable but not supported by details v0,
    /// with the resolved identity echoed in a bounded, safe form.
    #[must_use]
    pub fn market_unsupported_asset_type_for(asset_type: &str, identifier: &str) -> Self {
        let asset_type = truncate_text(&sanitize_text(asset_type), 80);
        let identifier = truncate_text(&sanitize_text(identifier), 120);
        Self::market_unsupported_asset_type_from_safe_message(format!(
            "Market details v0 does not support asset type {asset_type} for {identifier}."
        ))
    }

    /// Rebuild a contextual unsupported-type error from an already-safe boundary
    /// DTO. The text is sanitized and bounded again before it re-enters the
    /// envelope.
    #[must_use]
    pub fn market_unsupported_asset_type_from_safe_message(safe_message: impl AsRef<str>) -> Self {
        let message = truncate_text(&sanitize_text(safe_message.as_ref()), 2_000);
        if message.is_empty() {
            return Self::market_unsupported_asset_type();
        }
        Self::new(
            "market_unsupported_asset_type",
            ErrorClass::Validation,
            false,
            message,
        )
    }

    /// Fineco returned a retryable upstream failure on an authenticated market read.
    #[must_use]
    pub fn market_upstream_failure() -> Self {
        Self::new(
            "market_upstream_failure",
            ErrorClass::Upstream,
            true,
            "Authenticated market read failed upstream.",
        )
    }

    /// Authenticated market reads are temporarily disabled after repeated
    /// upstream failures.
    #[must_use]
    pub fn market_circuit_open() -> Self {
        Self::new(
            "market_circuit_open",
            ErrorClass::Upstream,
            true,
            "Authenticated market reads are temporarily unavailable after repeated upstream failures. Try again later.",
        )
    }

    /// Fineco returned an unexpected non-retryable authenticated-market response.
    #[must_use]
    pub fn market_unexpected_response() -> Self {
        Self::new(
            "market_unexpected_response",
            ErrorClass::Upstream,
            false,
            "Authenticated market read returned an unexpected response.",
        )
    }

    /// A live refresh was requested again before this data area's cooldown
    /// elapsed; retryable once the cooldown passes.
    #[must_use]
    pub fn refresh_cooldown() -> Self {
        Self::new(
            "refresh_cooldown",
            ErrorClass::RateLimit,
            true,
            "Refresh is cooling down for this data area. Try again later.",
        )
    }

    /// This data area's daily live-refresh budget is exhausted; not retryable
    /// until the budget resets (the next UTC day).
    #[must_use]
    pub fn refresh_budget_exhausted() -> Self {
        Self::new(
            "refresh_budget_exhausted",
            ErrorClass::RateLimit,
            false,
            "The daily refresh budget for this data area is exhausted.",
        )
    }

    /// Live refresh for this data area is temporarily disabled after repeated
    /// upstream failures (circuit breaker open); retryable once it half-opens.
    #[must_use]
    pub fn refresh_circuit_open() -> Self {
        Self::new(
            "refresh_circuit_open",
            ErrorClass::Upstream,
            true,
            "Live refresh is temporarily unavailable after repeated upstream failures. Try again later.",
        )
    }

    /// The requested resource was not found.
    #[must_use]
    pub fn not_found() -> Self {
        Self::new(
            "not_found",
            ErrorClass::NotFound,
            false,
            "The requested resource was not found.",
        )
    }

    /// An unexpected internal error. The underlying cause is logged locally only.
    #[must_use]
    pub fn internal() -> Self {
        Self::new(
            "internal",
            ErrorClass::Internal,
            false,
            "An internal error occurred.",
        )
    }

    /// The local controller-to-worker socket failed before a live worker result
    /// could be observed. This does not prove a Fineco login happened.
    #[must_use]
    pub fn live_transport_failure() -> Self {
        Self::new(
            "live_transport_failure",
            ErrorClass::Internal,
            false,
            "The live worker transport failed.",
        )
    }

    /// A validation failure. `safe_message` must be developer-authored and free
    /// of payloads (e.g. `"days must be <= 30"`).
    #[must_use]
    pub fn invalid_request(safe_message: impl Into<String>) -> Self {
        Self::new(
            "invalid_request",
            ErrorClass::Validation,
            false,
            safe_message,
        )
    }

    /// Map an upstream HTTP status to a safe envelope.
    ///
    /// The upstream response *body* is intentionally NOT a parameter: it may
    /// contain secrets/account data and must never enter the envelope (log it to
    /// local debug only). 4xx auth failures are not retried; 5xx are retryable.
    #[must_use]
    pub fn from_upstream_status(status: u16) -> Self {
        match status {
            401 | 403 => Self::auth_required(),
            404 => Self::not_found(),
            429 => Self::rate_limited(),
            500..=599 => Self::new(
                "fineco_upstream_error",
                ErrorClass::Upstream,
                true,
                "Fineco returned a server error.",
            ),
            _ => Self::new(
                "fineco_upstream_error",
                ErrorClass::Upstream,
                false,
                "Fineco returned an unexpected response.",
            ),
        }
    }
}

/// Normalize an expected ISIN verifier. Accepts a plain ISIN or a dotted
/// Fineco/provider suffix (`IE00B8GKDB10.AFF`), returning the uppercase ISIN.
///
/// # Errors
/// [`SafeError::invalid_request`] if the value is not ISIN-shaped after suffix
/// removal.
pub fn normalize_expected_isin(expected_isin: &str) -> Result<String, SafeError> {
    let trimmed = expected_isin.trim();
    let isin = trimmed.split_once('.').map_or(trimmed, |(isin, _)| isin);
    let isin = isin.to_ascii_uppercase();
    if is_isin(&isin) {
        Ok(isin)
    } else {
        Err(SafeError::invalid_request(
            "expected_isin must be an ISIN, optionally followed by a suffix.",
        ))
    }
}

fn is_isin(value: &str) -> bool {
    value.len() == 12
        && value
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
        && value.chars().take(2).all(|ch| ch.is_ascii_uppercase())
        && value.chars().last().is_some_and(|ch| ch.is_ascii_digit())
}

impl std::fmt::Display for SafeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}/{}] {}",
            self.class.as_str(),
            self.code,
            self.safe_message
        )
    }
}

impl std::error::Error for SafeError {}

/// Maximum order-monitor day window a refresh may request (plan rate-limit bound).
pub const MAX_ORDER_DAYS: u32 = 30;

/// Maximum movements day window a refresh may request. This is the **PSD2 SCA
/// boundary**, not an arbitrary rate-limit: Fineco serves up to 90 days of
/// account history on a plain session, but a window reaching further back returns
/// HTTP 451 "Unavailable For Legal Reason" / "Sca di sessione non valida" (Strong
/// Customer Authentication required), which a headless worker cannot satisfy.
/// Confirmed live (2026-06-23): a 90-day window returns 200; a 1-year window 451.
pub const MAX_MOVEMENTS_DAYS: u32 = 90;

/// Maximum length of a live-order `instrument_kind`. The cached snapshot-query IPC
/// path caps every client string at 256 chars; the live-refresh path validates
/// only through [`validate_order_request`], so it must bound the kind too — else a
/// multi-megabyte (still-alphanumeric) value would pass, be serialized across the
/// refresh/live sockets, and be interpolated into the worker-built Fineco URL.
pub const MAX_INSTRUMENT_KIND_LEN: usize = 256;

/// Validate an order-monitor refresh request's bounded parameters. Enforced by
/// the controller **before** acquiring the refresh lock — so an invalid request
/// never creates a `job_runs` row or burns budget — and again by the worker
/// (defense in depth).
///
/// # Errors
/// [`SafeError::invalid_request`] if `days` exceeds the cap or `instrument_kind`
/// is empty, longer than [`MAX_INSTRUMENT_KIND_LEN`], or not ASCII-alphanumeric.
pub fn validate_order_request(instrument_kind: &str, days: u32) -> Result<(), SafeError> {
    if days > MAX_ORDER_DAYS {
        return Err(SafeError::invalid_request("days must be <= 30."));
    }
    if instrument_kind.is_empty()
        || instrument_kind.chars().count() > MAX_INSTRUMENT_KIND_LEN
        || !instrument_kind.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return Err(SafeError::invalid_request(
            "instrument type must be 1-256 alphanumeric characters.",
        ));
    }
    Ok(())
}

/// Validate a movements refresh request's `days` bound. Enforced by the controller
/// before the lock and again by the worker (defense in depth).
///
/// # Errors
/// [`SafeError::invalid_request`] if `days` exceeds [`MAX_MOVEMENTS_DAYS`].
pub fn validate_movements_request(days: u32) -> Result<(), SafeError> {
    if days > MAX_MOVEMENTS_DAYS {
        return Err(SafeError::invalid_request("days must be <= 90."));
    }
    Ok(())
}

/// Validate a tax refresh request's date range (`YYYY-MM-DD`, `from <= to`).
/// Enforced by the controller before the lock and again by the worker.
///
/// # Errors
/// [`SafeError::invalid_request`] if a date is malformed or `date_from` is after
/// `date_to`.
pub fn validate_tax_range(date_from: &str, date_to: &str) -> Result<(), SafeError> {
    let from = parse_iso_date(date_from)?;
    let to = parse_iso_date(date_to)?;
    if from > to {
        return Err(SafeError::invalid_request(
            "date_from must be on or before date_to.",
        ));
    }
    Ok(())
}

/// Parse a strict `YYYY-MM-DD` date to a UTC epoch (midnight).
fn parse_iso_date(date: &str) -> Result<i64, SafeError> {
    // Bound the shape BEFORE allocating/parsing: a valid date is exactly 10 bytes
    // (`YYYY-MM-DD`), so a multi-megabyte client string (the live tax-refresh path
    // takes `date_from`/`date_to` straight from the request) is rejected cheaply
    // rather than being `format!`-expanded into a huge string and scanned.
    if date.len() != 10 {
        return Err(SafeError::invalid_request(
            "dates must be valid YYYY-MM-DD.",
        ));
    }
    parse_iso8601_utc(&format!("{date}T00:00:00Z"))
        .ok_or_else(|| SafeError::invalid_request("dates must be valid YYYY-MM-DD."))
}
