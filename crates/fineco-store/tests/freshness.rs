//! Integrated freshness contract: combine latest-snapshot age with job state
//! into a per-data-area state. M2 red→green.

use fineco_store::{FreshnessState, JobOutcome, NewPortfolioSnapshot, Store};

/// Epoch seconds of `2026-01-01T00:00:00Z`.
const T_2026: i64 = 1_767_225_600;

fn empty_snapshot(captured_at: &str) -> NewPortfolioSnapshot {
    NewPortfolioSnapshot {
        captured_at: captured_at.to_string(),
        source: "test".to_string(),
        market_value: None,
        book_value: None,
        profit_loss: None,
        profit_loss_perc: None,
        positions: vec![],
        fx_rates: vec![],
    }
}

#[test]
fn missing_when_no_data_or_jobs() {
    let store = Store::open_in_memory().expect("open");
    let f = store
        .freshness_for("portfolio", T_2026, 3600)
        .expect("freshness");
    assert_eq!(f.state, FreshnessState::Missing);
    assert_eq!(f.captured_at, None);
}

#[test]
fn unparseable_captured_at_is_stale_not_missing() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_portfolio_snapshot(&empty_snapshot("not-a-valid-timestamp"))
        .expect("cap");
    let f = store
        .freshness_for("portfolio", T_2026, 3600)
        .expect("freshness");
    // Data exists, so not Missing; its age is indeterminate, so conservatively
    // Stale — and captured_at stays present (no Missing+Some contradiction).
    assert_eq!(f.state, FreshnessState::Stale);
    assert_eq!(f.captured_at.as_deref(), Some("not-a-valid-timestamp"));
}

#[test]
fn fresh_then_stale_by_age() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_portfolio_snapshot(&empty_snapshot("2026-01-01T00:00:00Z"))
        .expect("cap");

    let fresh = store
        .freshness_for("portfolio", T_2026 + 10, 3600)
        .expect("freshness");
    assert_eq!(fresh.state, FreshnessState::Fresh);
    assert_eq!(fresh.captured_at.as_deref(), Some("2026-01-01T00:00:00Z"));

    let stale = store
        .freshness_for("portfolio", T_2026 + 7200, 3600)
        .expect("freshness");
    assert_eq!(stale.state, FreshnessState::Stale);
    assert_eq!(stale.captured_at.as_deref(), Some("2026-01-01T00:00:00Z"));
}

#[test]
fn refreshing_overrides_when_job_running() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .record_job_start("owner", "portfolio", "2026-01-01T00:00:00Z")
        .expect("start");
    let f = store
        .freshness_for("portfolio", T_2026 + 100, 3600)
        .expect("freshness");
    assert_eq!(f.state, FreshnessState::Refreshing);
}

#[test]
fn auth_required_when_last_job_failed_auth_and_no_data() {
    let mut store = Store::open_in_memory().expect("open");
    let id = store
        .record_job_start("owner", "orders", "2026-01-01T00:00:00Z")
        .expect("start");
    store
        .record_job_finish(
            id,
            "2026-01-01T00:00:05Z",
            JobOutcome::Failed,
            Some("auth_required"),
        )
        .expect("finish");
    let f = store
        .freshness_for("orders", T_2026 + 100, 3600)
        .expect("freshness");
    assert_eq!(f.state, FreshnessState::AuthRequired);
    assert_eq!(f.captured_at, None);
}

#[test]
fn refresh_failed_when_last_job_failed_other_and_no_data() {
    let mut store = Store::open_in_memory().expect("open");
    let id = store
        .record_job_start("owner", "orders", "2026-01-01T00:00:00Z")
        .expect("start");
    store
        .record_job_finish(
            id,
            "2026-01-01T00:00:05Z",
            JobOutcome::Failed,
            Some("fineco_upstream_error"),
        )
        .expect("finish");
    let f = store
        .freshness_for("orders", T_2026 + 100, 3600)
        .expect("freshness");
    assert_eq!(f.state, FreshnessState::RefreshFailed);
}
