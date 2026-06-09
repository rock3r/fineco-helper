//! History query contract: portfolio time series, allocation history, and
//! per-position history. M1 red→green.

use fineco_store::{MAX_HISTORY_SNAPSHOTS, NewAsset, NewPortfolioSnapshot, NewPosition, Store};

fn one_position_snapshot(
    captured_at: &str,
    instr: &str,
    weight: f64,
    pl_perc: f64,
) -> NewPortfolioSnapshot {
    NewPortfolioSnapshot {
        captured_at: captured_at.to_string(),
        source: "test".to_string(),
        market_value: Some(1000.0),
        book_value: None,
        profit_loss: None,
        profit_loss_perc: None,
        positions: vec![NewPosition {
            asset: NewAsset {
                instr_id: instr.to_string(),
                venue_system: "MOT".to_string(),
                symbol: Some(instr.to_string()),
                description: None,
                kind: None,
                currency: Some("EUR".to_string()),
            },
            position_key_hash: None,
            qty: Some(1.0),
            avg_price: None,
            market_price: None,
            book_value: None,
            market_value: Some(1000.0),
            profit_loss: None,
            profit_loss_perc: Some(pl_perc),
            weight_perc: Some(weight),
        }],
        fx_rates: vec![],
    }
}

#[test]
fn portfolio_history_is_chronological_regardless_of_insert_order() {
    let mut store = Store::open_in_memory().expect("open");
    // Insert out of order on purpose; history must order by captured_at.
    for ts in [
        "2026-01-03T00:00:00Z",
        "2026-01-01T00:00:00Z",
        "2026-01-02T00:00:00Z",
    ] {
        store
            .capture_portfolio_snapshot(&one_position_snapshot(ts, "X", 100.0, 1.0))
            .expect("cap");
    }
    let times: Vec<String> = store
        .portfolio_history(10)
        .expect("hist")
        .into_iter()
        .map(|s| s.captured_at)
        .collect();
    assert_eq!(
        times,
        [
            "2026-01-01T00:00:00Z",
            "2026-01-02T00:00:00Z",
            "2026-01-03T00:00:00Z"
        ]
    );
}

#[test]
fn portfolio_history_honors_limit_returning_most_recent() {
    let mut store = Store::open_in_memory().expect("open");
    for ts in [
        "2026-01-01T00:00:00Z",
        "2026-01-02T00:00:00Z",
        "2026-01-03T00:00:00Z",
    ] {
        store
            .capture_portfolio_snapshot(&one_position_snapshot(ts, "X", 100.0, 1.0))
            .expect("cap");
    }
    let times: Vec<String> = store
        .portfolio_history(2)
        .expect("hist")
        .into_iter()
        .map(|s| s.captured_at)
        .collect();
    // The two most recent, in chronological order.
    assert_eq!(times, ["2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"]);
}

#[test]
fn allocation_and_position_history_track_changes() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_portfolio_snapshot(&one_position_snapshot(
            "2026-01-01T00:00:00Z",
            "X",
            70.0,
            5.0,
        ))
        .expect("cap1");
    store
        .capture_portfolio_snapshot(&one_position_snapshot(
            "2026-01-02T00:00:00Z",
            "X",
            80.0,
            7.0,
        ))
        .expect("cap2");

    let alloc = store
        .allocation_history(MAX_HISTORY_SNAPSHOTS)
        .expect("alloc");
    assert_eq!(alloc.len(), 2);
    assert_eq!(alloc[0].captured_at, "2026-01-01T00:00:00Z");
    assert_eq!(alloc[0].instr_id, "X");
    assert_eq!(alloc[0].venue_system, "MOT");
    assert_eq!(alloc[0].weight_perc, Some(70.0));

    let ph = store
        .position_history("X", "MOT", MAX_HISTORY_SNAPSHOTS)
        .expect("pos hist");
    assert_eq!(ph.len(), 2);
    assert_eq!(ph[0].weight_perc, Some(70.0));
    assert_eq!(ph[1].weight_perc, Some(80.0));
    assert_eq!(ph[1].profit_loss_perc, Some(7.0));
}

#[test]
fn position_history_is_venue_specific() {
    let mut store = Store::open_in_memory().expect("open");
    // Same instrument id "X" on two venues within each snapshot.
    let snap = |ts: &str, mot_weight: f64, xetra_weight: f64| NewPortfolioSnapshot {
        captured_at: ts.to_string(),
        source: "test".to_string(),
        market_value: None,
        book_value: None,
        profit_loss: None,
        profit_loss_perc: None,
        positions: vec![
            position_at("X", "MOT", mot_weight),
            position_at("X", "XETRA", xetra_weight),
        ],
        fx_rates: vec![],
    };
    store
        .capture_portfolio_snapshot(&snap("2026-01-01T00:00:00Z", 70.0, 30.0))
        .expect("cap1");
    store
        .capture_portfolio_snapshot(&snap("2026-01-02T00:00:00Z", 80.0, 20.0))
        .expect("cap2");

    // Only the MOT series — not merged with XETRA.
    let mot = store
        .position_history("X", "MOT", MAX_HISTORY_SNAPSHOTS)
        .expect("mot");
    assert_eq!(mot.len(), 2);
    assert_eq!(mot[0].weight_perc, Some(70.0));
    assert_eq!(mot[1].weight_perc, Some(80.0));
}

#[test]
fn history_orders_same_timestamp_by_capture_sequence() {
    let mut store = Store::open_in_memory().expect("open");
    let ts = "2026-01-01T00:00:00Z";
    // Two snapshots at the SAME timestamp — order must follow capture sequence
    // (snapshot id), not be left to SQLite's unspecified default.
    store
        .capture_portfolio_snapshot(&one_position_snapshot(ts, "X", 70.0, 5.0))
        .expect("c1");
    store
        .capture_portfolio_snapshot(&one_position_snapshot(ts, "X", 80.0, 7.0))
        .expect("c2");

    let ph = store
        .position_history("X", "MOT", MAX_HISTORY_SNAPSHOTS)
        .expect("ph");
    assert_eq!(ph.len(), 2);
    assert_eq!(
        ph[0].weight_perc,
        Some(70.0),
        "first-captured must come first"
    );
    assert_eq!(ph[1].weight_perc, Some(80.0));

    let alloc = store
        .allocation_history(MAX_HISTORY_SNAPSHOTS)
        .expect("alloc");
    assert_eq!(alloc.len(), 2);
    assert_eq!(alloc[0].weight_perc, Some(70.0));
    assert_eq!(alloc[1].weight_perc, Some(80.0));
}

#[test]
fn history_caps_to_the_most_recent_snapshots() {
    // The defensive bound: with a cap of 2 over 4 snapshots, only the two MOST RECENT
    // come back (still oldest-first), for both allocation and position history — so the
    // response can't grow without limit as captured history accumulates.
    let mut store = Store::open_in_memory().expect("open");
    for ts in [
        "2026-01-01T00:00:00Z",
        "2026-01-02T00:00:00Z",
        "2026-01-03T00:00:00Z",
        "2026-01-04T00:00:00Z",
    ] {
        store
            .capture_portfolio_snapshot(&one_position_snapshot(ts, "X", 50.0, 1.0))
            .expect("cap");
    }

    let alloc = store.allocation_history(2).expect("alloc");
    assert_eq!(alloc.len(), 2, "allocation history must cap to the limit");
    assert_eq!(alloc[0].captured_at, "2026-01-03T00:00:00Z");
    assert_eq!(alloc[1].captured_at, "2026-01-04T00:00:00Z");

    let ph = store.position_history("X", "MOT", 2).expect("ph");
    assert_eq!(ph.len(), 2, "position history must cap to the limit");
    assert_eq!(ph[0].captured_at, "2026-01-03T00:00:00Z");
    assert_eq!(ph[1].captured_at, "2026-01-04T00:00:00Z");
}

#[test]
fn allocation_cap_keeps_whole_snapshots_not_partial_rows() {
    // The cap must bound by SNAPSHOTS (each complete), NOT by joined allocation rows —
    // so with multi-position snapshots and a cap of 2, ALL positions of the two newest
    // snapshots come back and NONE from the capped-out oldest (no partial bleed-through).
    let mut store = Store::open_in_memory().expect("open");
    let snap = |ts: &str| NewPortfolioSnapshot {
        captured_at: ts.to_string(),
        source: "test".to_string(),
        market_value: None,
        book_value: None,
        profit_loss: None,
        profit_loss_perc: None,
        positions: vec![
            position_at("A", "MOT", 40.0),
            position_at("B", "MOT", 35.0),
            position_at("C", "MOT", 25.0),
        ],
        fx_rates: vec![],
    };
    for ts in [
        "2026-01-01T00:00:00Z",
        "2026-01-02T00:00:00Z",
        "2026-01-03T00:00:00Z",
    ] {
        store.capture_portfolio_snapshot(&snap(ts)).expect("cap");
    }

    let alloc = store.allocation_history(2).expect("alloc");
    // 2 whole snapshots × 3 positions = 6 rows, none from the capped-out oldest.
    assert_eq!(alloc.len(), 6, "two WHOLE snapshots, all positions each");
    assert!(
        alloc
            .iter()
            .all(|p| p.captured_at != "2026-01-01T00:00:00Z"),
        "the capped-out oldest snapshot must contribute no rows"
    );
    let dates: std::collections::BTreeSet<_> =
        alloc.iter().map(|p| p.captured_at.as_str()).collect();
    assert_eq!(
        dates,
        ["2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"]
            .into_iter()
            .collect()
    );
}

fn position_at(instr: &str, venue: &str, weight: f64) -> NewPosition {
    NewPosition {
        asset: NewAsset {
            instr_id: instr.to_string(),
            venue_system: venue.to_string(),
            symbol: Some(instr.to_string()),
            description: None,
            kind: None,
            currency: Some("EUR".to_string()),
        },
        position_key_hash: None,
        qty: Some(1.0),
        avg_price: None,
        market_price: None,
        book_value: None,
        market_value: Some(1000.0),
        profit_loss: None,
        profit_loss_perc: None,
        weight_perc: Some(weight),
    }
}
