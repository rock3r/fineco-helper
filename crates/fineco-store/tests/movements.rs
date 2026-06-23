//! Movements capture + freshness contract (non-credentialed store layer). The
//! Fineco fetch that produces these is the credentialed worker (gated); this is
//! the store side, tested with synthetic data. Mirrors the orders contract.

use fineco_store::{FreshnessState, NewMovement, Store};

fn movement(id_hash: &str, importo: f64) -> NewMovement {
    NewMovement {
        movement_id_hash: id_hash.to_string(),
        causale: Some("BONIFICO".to_string()),
        descrizione: Some("synthetic line".to_string()),
        importo: Some(importo),
        tipo_movimento: Some("MOVIMENTO_CONTO".to_string()),
        data_operazione: Some("2026-01-01".to_string()),
        data_registrazione: Some("2026-01-01".to_string()),
        data_valuta: Some("2026-01-02".to_string()),
        causale_movimento: Some("48".to_string()),
    }
}

#[test]
fn capture_and_read_back_movements() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_movements(
            "2026-01-01T10:00:00Z",
            &[movement("H1", -25.0), movement("H2", 1000.0)],
        )
        .expect("capture");

    let mut rows = store.latest_movements().expect("movements");
    rows.sort_by(|a, b| a.movement_id_hash.cmp(&b.movement_id_hash));
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].captured_at, "2026-01-01T10:00:00Z");
    assert_eq!(rows[0].movement_id_hash, "H1");
    assert_eq!(rows[0].importo, Some(-25.0));
    assert_eq!(rows[0].causale.as_deref(), Some("BONIFICO"));
    assert_eq!(rows[0].tipo_movimento.as_deref(), Some("MOVIMENTO_CONTO"));
    assert_eq!(rows[0].data_valuta.as_deref(), Some("2026-01-02"));
    assert_eq!(rows[1].movement_id_hash, "H2");
    assert_eq!(rows[1].importo, Some(1000.0));
}

#[test]
fn latest_movements_returns_only_the_most_recent_capture() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_movements("2026-01-01T10:00:00Z", &[movement("H1", -25.0)])
        .expect("c1");
    store
        .capture_movements(
            "2026-01-02T10:00:00Z",
            &[movement("H1", -25.0), movement("H9", 9.0)],
        )
        .expect("c2");
    let rows = store.latest_movements().expect("movements");
    assert_eq!(rows.len(), 2, "only the 2026-01-02 capture");
    assert!(rows.iter().all(|r| r.captured_at == "2026-01-02T10:00:00Z"));
}

#[test]
fn empty_capture_supersedes_previous_movements() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_movements("2026-01-01T10:00:00Z", &[movement("H1", -25.0)])
        .expect("c1");
    // A later, legitimately empty capture (e.g. the window has no movements).
    store
        .capture_movements("2026-01-02T10:00:00Z", &[])
        .expect("empty c2");

    // Latest must reflect the empty capture — not re-surface the old movements.
    assert!(
        store.latest_movements().expect("movements").is_empty(),
        "an empty capture must supersede the previous non-empty one"
    );

    // Freshness reflects the empty capture's timestamp, not the old one.
    // 2026-01-02T10:00:00Z = 1767348000.
    let f = store
        .freshness_for("movements", 1_767_348_060, 3600)
        .expect("f");
    assert_eq!(f.state, FreshnessState::Fresh);
    assert_eq!(f.captured_at.as_deref(), Some("2026-01-02T10:00:00Z"));
}

#[test]
fn movements_freshness_tracks_latest_capture() {
    let mut store = Store::open_in_memory().expect("open");
    // T_2026 = 1767225600 (2026-01-01T00:00:00Z).
    assert_eq!(
        store
            .freshness_for("movements", 1_767_225_700, 3600)
            .expect("f")
            .state,
        FreshnessState::Missing
    );
    store
        .capture_movements("2026-01-01T00:00:00Z", &[movement("H1", -25.0)])
        .expect("capture");
    let f = store
        .freshness_for("movements", 1_767_225_610, 3600)
        .expect("f");
    assert_eq!(f.state, FreshnessState::Fresh);
    assert_eq!(f.captured_at.as_deref(), Some("2026-01-01T00:00:00Z"));
}
