//! Tax capture + freshness contract (non-credentialed store layer). M3 red→green.
//! Tax has two tables (carry-forward + minus-by-year) captured together.

use fineco_store::{FreshnessState, NewTaxCarryForward, NewTaxMinusByYear, Store};

#[test]
fn capture_and_read_back_tax() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_tax(
            "2026-01-01T10:00:00Z",
            &[NewTaxCarryForward {
                date_from: "2025-01-01".to_string(),
                date_to: "2025-12-31".to_string(),
                total: Some(1234.5),
            }],
            &[NewTaxMinusByYear {
                year: 2024,
                minus_residue: Some(500.0),
                expiration_date: Some("2028-12-31".to_string()),
            }],
        )
        .expect("capture");

    let cf = store.latest_tax_carry_forward().expect("cf");
    assert_eq!(cf.len(), 1);
    assert_eq!(cf[0].captured_at, "2026-01-01T10:00:00Z");
    assert_eq!(cf[0].date_from, "2025-01-01");
    assert_eq!(cf[0].date_to, "2025-12-31");
    assert_eq!(cf[0].total, Some(1234.5));

    let my = store.latest_tax_minus_by_year().expect("my");
    assert_eq!(my.len(), 1);
    assert_eq!(my[0].year, 2024);
    assert_eq!(my[0].minus_residue, Some(500.0));
    assert_eq!(my[0].expiration_date.as_deref(), Some("2028-12-31"));
}

#[test]
fn latest_tax_returns_only_the_most_recent_capture() {
    let mut store = Store::open_in_memory().expect("open");
    let cf = |total: f64| NewTaxCarryForward {
        date_from: "2025-01-01".to_string(),
        date_to: "2025-12-31".to_string(),
        total: Some(total),
    };
    store
        .capture_tax("2026-01-01T00:00:00Z", &[cf(100.0)], &[])
        .expect("c1");
    store
        .capture_tax("2026-02-01T00:00:00Z", &[cf(200.0)], &[])
        .expect("c2");
    let rows = store.latest_tax_carry_forward().expect("cf");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].captured_at, "2026-02-01T00:00:00Z");
    assert_eq!(rows[0].total, Some(200.0));
}

#[test]
fn empty_minus_in_latest_capture_supersedes_old_residues() {
    let mut store = Store::open_in_memory().expect("open");
    let cf = |total: f64| NewTaxCarryForward {
        date_from: "2025-01-01".to_string(),
        date_to: "2025-12-31".to_string(),
        total: Some(total),
    };
    // First capture carries a minus-by-year residue.
    store
        .capture_tax(
            "2026-01-01T00:00:00Z",
            &[cf(100.0)],
            &[NewTaxMinusByYear {
                year: 2024,
                minus_residue: Some(500.0),
                expiration_date: Some("2028-12-31".to_string()),
            }],
        )
        .expect("c1");
    // A later capture has carry-forward but NO minus rows (losses cleared).
    store
        .capture_tax("2026-02-01T00:00:00Z", &[cf(200.0)], &[])
        .expect("c2");

    // Carry-forward reflects the new capture...
    let cf_rows = store.latest_tax_carry_forward().expect("cf");
    assert_eq!(cf_rows.len(), 1);
    assert_eq!(cf_rows[0].captured_at, "2026-02-01T00:00:00Z");
    assert_eq!(cf_rows[0].total, Some(200.0));

    // ...and minus-by-year is now empty — the stale 2024 residue must not
    // re-surface just because the latest capture inserted no minus rows.
    assert!(
        store.latest_tax_minus_by_year().expect("my").is_empty(),
        "an empty minus list in the latest capture must not re-surface old residues"
    );
}

#[test]
fn tax_freshness_tracks_latest_capture() {
    let mut store = Store::open_in_memory().expect("open");
    assert_eq!(
        store
            .freshness_for("tax", 1_767_225_700, 3600)
            .expect("f")
            .state,
        FreshnessState::Missing
    );
    store
        .capture_tax(
            "2026-01-01T00:00:00Z",
            &[NewTaxCarryForward {
                date_from: "2025-01-01".to_string(),
                date_to: "2025-12-31".to_string(),
                total: None,
            }],
            &[],
        )
        .expect("capture");
    let f = store.freshness_for("tax", 1_767_225_610, 3600).expect("f");
    assert_eq!(f.state, FreshnessState::Fresh);
    assert_eq!(f.captured_at.as_deref(), Some("2026-01-01T00:00:00Z"));
}
