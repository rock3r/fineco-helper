//! Freshness model contract. M2 red→green. Pure, dependency-free: an exact
//! ISO-8601-UTC→epoch parse plus age-based state classification.

use fineco_core::{FreshnessState, freshness_from_age, parse_iso8601_utc};

#[test]
fn parses_known_utc_timestamps_to_epoch() {
    assert_eq!(parse_iso8601_utc("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(parse_iso8601_utc("2000-01-01T00:00:00Z"), Some(946_684_800));
    assert_eq!(parse_iso8601_utc("2001-01-01T00:00:00Z"), Some(978_307_200));
    // Fractional seconds are accepted and truncated to whole seconds.
    assert_eq!(
        parse_iso8601_utc("2000-01-01T00:00:00.500Z"),
        Some(946_684_800)
    );
    // A known leap day.
    assert_eq!(parse_iso8601_utc("2000-02-29T00:00:00Z"), Some(951_782_400));
}

#[test]
fn rejects_malformed_timestamps() {
    for bad in [
        "not-a-date",
        "2026-13-01T00:00:00Z", // month 13
        "2026-01-32T00:00:00Z", // day 32
        "2026-01-01T24:00:00Z", // hour 24
        "2026-01-01 00:00:00Z", // space instead of T
        "2026-01-01T00:00:00",  // missing Z
        "2026-01-01T00:00Z",    // missing seconds
        "",
    ] {
        assert_eq!(parse_iso8601_utc(bad), None, "should reject {bad:?}");
    }
}

#[test]
fn freshness_state_strings_are_stable() {
    assert_eq!(FreshnessState::Fresh.as_str(), "fresh");
    assert_eq!(FreshnessState::Stale.as_str(), "stale");
    assert_eq!(FreshnessState::Refreshing.as_str(), "refreshing");
    assert_eq!(FreshnessState::RefreshFailed.as_str(), "refresh_failed");
    assert_eq!(FreshnessState::AuthRequired.as_str(), "auth_required");
    assert_eq!(FreshnessState::Missing.as_str(), "missing");
}

#[test]
fn freshness_from_age_classifies_fresh_stale_missing() {
    let now = 1_000_000_i64;
    assert_eq!(freshness_from_age(None, now, 3600), FreshnessState::Missing);
    // Captured 10s ago, max age 1h -> fresh.
    assert_eq!(
        freshness_from_age(Some(now - 10), now, 3600),
        FreshnessState::Fresh
    );
    // Captured 2h ago, max age 1h -> stale.
    assert_eq!(
        freshness_from_age(Some(now - 7200), now, 3600),
        FreshnessState::Stale
    );
    // Exactly at the boundary is still fresh.
    assert_eq!(
        freshness_from_age(Some(now - 3600), now, 3600),
        FreshnessState::Fresh
    );
}
