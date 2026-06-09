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
