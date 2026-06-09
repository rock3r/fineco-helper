//! job_runs recording + lock query contract. M2 red→green. Underpins refresh
//! locks (`already_refreshing`) and the integrated freshness model.

use fineco_store::{JobOutcome, Store};

#[test]
fn records_and_queries_job_runs() {
    let mut store = Store::open_in_memory().expect("open");
    assert!(store.latest_job_run("portfolio").expect("q").is_none());
    assert_eq!(store.running_job_for("portfolio").expect("q"), None);

    let id = store
        .record_job_start("owner", "portfolio", "2026-01-01T00:00:00Z")
        .expect("start");
    assert!(id > 0);

    // While running it is the latest job and reported as running.
    let latest = store
        .latest_job_run("portfolio")
        .expect("q")
        .expect("a job");
    assert_eq!(latest.id, id);
    assert_eq!(latest.auth_id, "owner");
    assert_eq!(latest.data_area, "portfolio");
    assert_eq!(latest.status, "running");
    assert_eq!(latest.finished_at, None);
    assert_eq!(latest.safe_error_code, None);
    assert_eq!(store.running_job_for("portfolio").expect("q"), Some(id));

    // Finishing clears the running lock and records the outcome.
    store
        .record_job_finish(id, "2026-01-01T00:01:00Z", JobOutcome::Completed, None)
        .expect("finish");
    let done = store
        .latest_job_run("portfolio")
        .expect("q")
        .expect("a job");
    assert_eq!(done.status, "completed");
    assert_eq!(done.finished_at.as_deref(), Some("2026-01-01T00:01:00Z"));
    assert_eq!(store.running_job_for("portfolio").expect("q"), None);
}

#[test]
fn finish_records_safe_error_code() {
    let mut store = Store::open_in_memory().expect("open");
    let id = store
        .record_job_start("owner", "tax", "2026-01-01T00:00:00Z")
        .expect("start");
    store
        .record_job_finish(
            id,
            "2026-01-01T00:00:05Z",
            JobOutcome::Failed,
            Some("auth_required"),
        )
        .expect("finish");
    let row = store.latest_job_run("tax").expect("q").expect("a job");
    assert_eq!(row.status, "failed");
    assert_eq!(row.safe_error_code.as_deref(), Some("auth_required"));
}

#[test]
fn running_lock_is_per_data_area() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .record_job_start("owner", "portfolio", "2026-01-01T00:00:00Z")
        .expect("start");
    assert!(store.running_job_for("portfolio").expect("q").is_some());
    assert_eq!(store.running_job_for("orders").expect("q"), None);
}

#[test]
fn try_begin_job_is_an_atomic_lock() {
    let mut store = Store::open_in_memory().expect("open");
    let first = store
        .try_begin_job("owner", "portfolio", "2026-01-01T00:00:00Z", 3600)
        .expect("q");
    let first_id = first.expect("first begins");

    // A second begin while the first is running is rejected by the unique index —
    // atomically, with no check-then-insert window. (Not stale: 1s < 3600s.)
    assert_eq!(
        store
            .try_begin_job("owner", "portfolio", "2026-01-01T00:00:01Z", 3600)
            .expect("q"),
        None
    );
    // A different data area is independent.
    assert!(
        store
            .try_begin_job("owner", "orders", "2026-01-01T00:00:01Z", 3600)
            .expect("q")
            .is_some()
    );

    // Finishing releases the lock; a new portfolio refresh can then begin.
    store
        .record_job_finish(
            first_id,
            "2026-01-01T00:00:02Z",
            JobOutcome::Completed,
            None,
        )
        .expect("finish");
    assert!(
        store
            .try_begin_job("owner", "portfolio", "2026-01-01T00:00:03Z", 3600)
            .expect("q")
            .is_some()
    );
}

#[test]
fn try_begin_job_reclaims_a_stale_running_job() {
    let mut store = Store::open_in_memory().expect("open");
    // A running job that never finished (e.g. its finish write failed).
    store
        .try_begin_job("owner", "portfolio", "2026-01-01T00:00:00Z", 900)
        .expect("q")
        .expect("begins");

    // An hour later (> 900s stale threshold) the dead job is reclaimed and a new
    // refresh can begin — the lock is self-healing, not stuck forever.
    let reclaimed = store
        .try_begin_job("owner", "portfolio", "2026-01-01T01:00:00Z", 900)
        .expect("q");
    assert!(reclaimed.is_some(), "stale running job should be reclaimed");

    let counts = store.job_counts().expect("counts");
    assert_eq!(counts.running, 1, "exactly the new job is running");
    assert_eq!(counts.failed, 1, "the stale job was marked failed");
    // A fresh attempt within the threshold is still locked out.
    assert_eq!(
        store
            .try_begin_job("owner", "portfolio", "2026-01-01T01:00:01Z", 900)
            .expect("q"),
        None
    );
}

#[test]
fn finish_reports_whether_a_running_job_was_updated() {
    let mut store = Store::open_in_memory().expect("open");
    let id = store
        .record_job_start("owner", "portfolio", "2026-01-01T00:00:00Z")
        .expect("start");
    // Finishing a running job updates it and reports true.
    assert!(
        store
            .record_job_finish(id, "2026-01-01T00:00:01Z", JobOutcome::Completed, None)
            .expect("finish")
    );
    // A second finish (now terminal) updates nothing and reports false — the
    // no-op is observable, not silent.
    assert!(
        !store
            .record_job_finish(id, "2026-01-01T00:00:02Z", JobOutcome::Completed, None)
            .expect("finish")
    );
}
