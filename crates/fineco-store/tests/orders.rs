//! Orders capture + freshness contract (non-credentialed store layer). M3
//! red→green. The Fineco fetch that produces these is the credentialed M3 worker
//! (gated); this is the store side, tested with synthetic data.

use fineco_store::{FreshnessState, NewAsset, NewOrder, Store};

fn order(trans: &str, instr: &str) -> NewOrder {
    NewOrder {
        trans_id_hash: trans.to_string(),
        asset: NewAsset {
            instr_id: instr.to_string(),
            venue_system: "MOT".to_string(),
            symbol: Some(instr.to_string()),
            description: None,
            kind: None,
            currency: Some("EUR".to_string()),
        },
        status: Some("filled".to_string()),
        sign: Some("BUY".to_string()),
        order_size: Some(10.0),
        size_filled: Some(10.0),
        avg_price: Some(100.0),
        submit_time: Some("2026-01-01T09:00:00Z".to_string()),
    }
}

#[test]
fn capture_and_read_back_orders() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_orders(
            "2026-01-01T10:00:00Z",
            &[order("TX1", "AAA"), order("TX2", "BBB")],
        )
        .expect("capture");

    let mut rows = store.latest_orders().expect("orders");
    rows.sort_by(|a, b| a.trans_id_hash.cmp(&b.trans_id_hash));
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].captured_at, "2026-01-01T10:00:00Z");
    assert_eq!(rows[0].trans_id_hash, "TX1");
    assert_eq!(rows[0].asset_instr_id, "AAA");
    assert_eq!(rows[0].status.as_deref(), Some("filled"));
    assert_eq!(rows[0].sign.as_deref(), Some("BUY"));
    assert_eq!(rows[0].avg_price, Some(100.0));
}

#[test]
fn latest_orders_returns_only_the_most_recent_capture() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_orders("2026-01-01T10:00:00Z", &[order("TX1", "AAA")])
        .expect("c1");
    store
        .capture_orders(
            "2026-01-02T10:00:00Z",
            &[order("TX1", "AAA"), order("TX9", "ZZZ")],
        )
        .expect("c2");
    let rows = store.latest_orders().expect("orders");
    assert_eq!(rows.len(), 2, "only the 2026-01-02 capture");
    assert!(rows.iter().all(|r| r.captured_at == "2026-01-02T10:00:00Z"));
}

#[test]
fn empty_capture_supersedes_previous_orders() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_orders("2026-01-01T10:00:00Z", &[order("TX1", "AAA")])
        .expect("c1");
    // A later, legitimately empty capture (e.g. every order settled/cancelled).
    store
        .capture_orders("2026-01-02T10:00:00Z", &[])
        .expect("empty c2");

    // Latest must reflect the empty capture — not re-surface the old orders.
    assert!(
        store.latest_orders().expect("orders").is_empty(),
        "an empty capture must supersede the previous non-empty one"
    );

    // Freshness reflects the empty capture's timestamp, not the old one.
    // 2026-01-02T10:00:00Z = 1767348000.
    let f = store
        .freshness_for("orders", 1_767_348_060, 3600)
        .expect("f");
    assert_eq!(f.state, FreshnessState::Fresh);
    assert_eq!(f.captured_at.as_deref(), Some("2026-01-02T10:00:00Z"));
}

#[test]
fn orders_freshness_tracks_latest_capture() {
    let mut store = Store::open_in_memory().expect("open");
    // T_2026 = 1767225600 (2026-01-01T00:00:00Z).
    assert_eq!(
        store
            .freshness_for("orders", 1_767_225_700, 3600)
            .expect("f")
            .state,
        FreshnessState::Missing
    );
    store
        .capture_orders("2026-01-01T00:00:00Z", &[order("TX1", "AAA")])
        .expect("capture");
    let f = store
        .freshness_for("orders", 1_767_225_610, 3600)
        .expect("f");
    assert_eq!(f.state, FreshnessState::Fresh);
    assert_eq!(f.captured_at.as_deref(), Some("2026-01-01T00:00:00Z"));
}
