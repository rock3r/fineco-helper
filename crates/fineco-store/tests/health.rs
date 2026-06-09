//! Health/readiness primitives. M2 red→green. DB readiness + operational job
//! counts back the future `/readyz` and `system_get_status` surfaces (wired at
//! M4); here they are pure store queries.

use fineco_store::{JobOutcome, Store};

#[test]
fn fresh_store_is_ready_with_no_jobs() {
    let store = Store::open_in_memory().expect("open");
    assert!(store.is_ready().expect("ready"));
    let c = store.job_counts().expect("counts");
    assert_eq!(c.running, 0);
    assert_eq!(c.completed, 0);
    assert_eq!(c.failed, 0);
}

#[test]
fn job_counts_track_outcomes() {
    let mut store = Store::open_in_memory().expect("open");
    let a = store
        .record_job_start("owner", "portfolio", "2026-01-01T00:00:00Z")
        .expect("a");
    store
        .record_job_finish(a, "2026-01-01T00:00:01Z", JobOutcome::Completed, None)
        .expect("a fin");
    let b = store
        .record_job_start("owner", "orders", "2026-01-01T00:00:00Z")
        .expect("b");
    store
        .record_job_finish(
            b,
            "2026-01-01T00:00:01Z",
            JobOutcome::Failed,
            Some("auth_required"),
        )
        .expect("b fin");
    // One still running.
    store
        .record_job_start("owner", "tax", "2026-01-01T00:00:00Z")
        .expect("c");

    let c = store.job_counts().expect("counts");
    assert_eq!(c.completed, 1);
    assert_eq!(c.failed, 1);
    assert_eq!(c.running, 1);
}
