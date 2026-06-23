//! Safe error envelope contract. M2 red→green. Every error crossing a boundary
//! becomes a SafeError carrying only safe fields — never raw upstream detail.

use fineco_core::{ErrorClass, SafeError};

#[test]
fn error_class_strings_are_stable() {
    assert_eq!(ErrorClass::Upstream.as_str(), "upstream");
    assert_eq!(ErrorClass::Auth.as_str(), "auth");
    assert_eq!(ErrorClass::Validation.as_str(), "validation");
    assert_eq!(ErrorClass::RateLimit.as_str(), "rate_limit");
    assert_eq!(ErrorClass::Conflict.as_str(), "conflict");
    assert_eq!(ErrorClass::NotFound.as_str(), "not_found");
    assert_eq!(ErrorClass::Internal.as_str(), "internal");
}

#[test]
fn named_constructors_are_stable() {
    let a = SafeError::auth_required();
    assert_eq!(a.code(), "auth_required");
    assert_eq!(a.class(), ErrorClass::Auth);
    assert!(!a.retryable());
    assert!(!a.safe_message().is_empty());

    let t = SafeError::fineco_timeout();
    assert_eq!(t.code(), "fineco_timeout");
    assert_eq!(t.class(), ErrorClass::Upstream);
    assert!(t.retryable());

    let r = SafeError::already_refreshing();
    assert_eq!(r.code(), "already_refreshing");
    assert_eq!(r.class(), ErrorClass::Conflict);
    assert!(r.retryable());

    let m = SafeError::market_circuit_open();
    assert_eq!(m.code(), "market_circuit_open");
    assert_eq!(m.class(), ErrorClass::Upstream);
    assert!(m.retryable());

    let not_found = SafeError::market_not_found();
    assert_eq!(not_found.code(), "market_not_found");
    assert_eq!(not_found.class(), ErrorClass::NotFound);
    assert!(!not_found.retryable());

    let ambiguous = SafeError::market_ambiguous_identifier();
    assert_eq!(ambiguous.code(), "market_ambiguous_identifier");
    assert_eq!(ambiguous.class(), ErrorClass::Validation);
    assert!(!ambiguous.retryable());
    let contextual_ambiguous = SafeError::market_ambiguous_identifier_with_suggestions(&[
        "AFF/VHYL (IE00B8GKDB10)".to_string(),
    ]);
    assert_eq!(contextual_ambiguous.code(), "market_ambiguous_identifier");
    assert!(
        contextual_ambiguous
            .safe_message()
            .contains("AFF/VHYL (IE00B8GKDB10)")
    );

    let unsupported = SafeError::market_unsupported_asset_type();
    assert_eq!(unsupported.code(), "market_unsupported_asset_type");
    assert_eq!(unsupported.class(), ErrorClass::Validation);
    assert!(!unsupported.retryable());
    let contextual_unsupported =
        SafeError::market_unsupported_asset_type_for("stock", "NASDAQ/AAPL");
    assert_eq!(
        contextual_unsupported.code(),
        "market_unsupported_asset_type"
    );
    assert!(
        contextual_unsupported
            .safe_message()
            .contains("NASDAQ/AAPL")
    );
}

#[test]
fn step_up_required_is_a_distinct_non_retryable_auth_error() {
    // Tier 1: Fineco demands strong customer authentication. Distinct from
    // auth_required (a re-login won't clear it), Auth class, never retried, and
    // the message carries no payload.
    let s = SafeError::step_up_required();
    assert_eq!(s.code(), "step_up_required");
    assert_eq!(s.class(), ErrorClass::Auth);
    assert!(!s.retryable());
    assert!(!s.safe_message().is_empty());
    assert_ne!(s.code(), SafeError::auth_required().code());

    let m = SafeError::market_step_up_required();
    assert_eq!(m.code(), "market_step_up_required");
    assert_eq!(m.class(), ErrorClass::Auth);
    assert!(!m.retryable());
    assert!(!m.safe_message().is_empty());
}

#[test]
fn expected_isin_normalization_accepts_plain_and_dotted_suffixes() {
    assert_eq!(
        fineco_core::normalize_expected_isin("IE00B8GKDB10").expect("plain isin"),
        "IE00B8GKDB10"
    );
    assert_eq!(
        fineco_core::normalize_expected_isin("ie00b8gkdb10.aff").expect("dotted isin"),
        "IE00B8GKDB10"
    );
    assert!(fineco_core::normalize_expected_isin("Vanguard").is_err());
}

#[test]
fn expected_isin_normalization_rejects_non_numeric_check_digit() {
    assert!(fineco_core::normalize_expected_isin("IE00B8GKDB1A").is_err());
    assert!(fineco_core::normalize_expected_isin("IE00B8GKDB1A.AFF").is_err());
}

#[test]
fn upstream_status_maps_to_safe_class_and_retryability() {
    assert_eq!(
        SafeError::from_upstream_status(401).class(),
        ErrorClass::Auth
    );
    assert!(!SafeError::from_upstream_status(401).retryable());
    assert_eq!(
        SafeError::from_upstream_status(403).class(),
        ErrorClass::Auth
    );
    assert_eq!(
        SafeError::from_upstream_status(404).class(),
        ErrorClass::NotFound
    );
    assert_eq!(
        SafeError::from_upstream_status(429).class(),
        ErrorClass::RateLimit
    );
    // 5xx is a retryable upstream failure.
    let e = SafeError::from_upstream_status(503);
    assert_eq!(e.class(), ErrorClass::Upstream);
    assert!(e.retryable());
}

#[test]
fn envelope_exposes_only_safe_fields() {
    // By construction the envelope holds only code/class/retryable/safe_message,
    // and Display renders only those — no raw payloads can be embedded.
    let e = SafeError::auth_required();
    let shown = format!("{e}");
    assert!(shown.contains("auth_required"));
    assert!(shown.contains(e.safe_message()));

    // Validation messages are developer-authored and safe (not payloads).
    let v = SafeError::invalid_request("days must be <= 30");
    assert_eq!(v.class(), ErrorClass::Validation);
    assert!(format!("{v}").contains("days must be <= 30"));
}
