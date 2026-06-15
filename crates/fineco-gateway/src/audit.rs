//! Per-request audit log (plan §"Logging And Audit").
//!
//! **Allowlist by construction.** [`AuditRecord`] holds ONLY safe metadata
//! fields — timestamp, the owner auth id, the tool name, the coarse data class,
//! the outcome, a safe error code, the duration, and a result *count*. It carries
//! no DTO, no payload, no value/price/tax/account field, and no token/cookie, so
//! it is structurally impossible for an audit line to leak forbidden data. One
//! compact JSON line is emitted per tool call to stdout, which systemd routes to
//! the journal.

use serde::Serialize;

/// One audited tool call. Every field is on the plan's logging allowlist; there
/// is deliberately no field that could hold a payload, value, or secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    /// RFC 3339 UTC timestamp of the call.
    pub ts: String,
    /// The verified caller identity (the single owner).
    pub auth_id: &'static str,
    /// The MCP tool name.
    pub tool: &'static str,
    /// Canonical data class read (`public_market` / `authenticated_market` /
    /// `external_enrichment` / `shareable_private` / `sensitive_private_cached` /
    /// `credentialed_live`), per the plan's Data Classes.
    pub data_class: &'static str,
    /// `"ok"` or `"error"`.
    pub outcome: &'static str,
    /// Safe error code on failure (e.g. `fineco_timeout`) — never a message or
    /// payload. Omitted on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Wall-clock duration of the call in milliseconds.
    pub duration_ms: u64,
    /// Result row count where meaningful — a count only, never the values.
    /// Omitted for scalar/per-area reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_count: Option<usize>,
    /// Whether the credentialed worker performed a Fineco login during this
    /// call. Status-only; no cookie/session material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_performed: Option<bool>,
    /// Whether the credentialed worker reused an existing Fineco session.
    /// Status-only; no cookie/session material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_reused: Option<bool>,
    /// Whether the credentialed worker evicted a held Fineco session.
    /// Status-only; no cookie/session material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_evicted: Option<bool>,
    /// Whether a stale reused session was repaired by the single allowed
    /// fresh-login retry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reused_session_401_recovered: Option<bool>,
}

impl AuditRecord {
    /// Serialize to a single-line JSON audit record. The record has only metadata
    /// fields, so serialization cannot fail; on the impossible error we fall back
    /// to a minimal safe line rather than panic in the request path.
    #[must_use]
    pub fn to_log_line(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|_| String::from(r#"{"audit":"serialize_failed"}"#))
    }
}

/// Emit one audit line to stdout (captured by journald under systemd).
pub fn emit(record: &AuditRecord) {
    println!("{}", record.to_log_line());
}
