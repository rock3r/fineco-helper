//! Snapshot capture round-trip contract. M1 red→green: drives the typed capture
//! API (insert a portfolio snapshot + positions + assets + fx, read it back).

use fineco_store::{NewAsset, NewFxRate, NewPortfolioSnapshot, NewPosition, Store};

fn asset(instr: &str, symbol: Option<&str>) -> NewAsset {
    NewAsset {
        instr_id: instr.to_string(),
        venue_system: "MOT".to_string(),
        symbol: symbol.map(str::to_string),
        description: None,
        kind: None,
        currency: Some("EUR".to_string()),
    }
}

fn position(instr: &str, symbol: Option<&str>, market_value: f64, weight: f64) -> NewPosition {
    NewPosition {
        asset: asset(instr, symbol),
        position_key_hash: None,
        qty: Some(10.0),
        avg_price: Some(50.0),
        market_price: Some(60.0),
        book_value: Some(500.0),
        market_value: Some(market_value),
        profit_loss: Some(100.0),
        profit_loss_perc: Some(20.0),
        weight_perc: Some(weight),
    }
}

#[test]
fn capture_and_read_back_portfolio_snapshot() {
    let mut store = Store::open_in_memory().expect("open");
    let snap = NewPortfolioSnapshot {
        captured_at: "2026-01-01T00:00:00Z".to_string(),
        source: "test".to_string(),
        market_value: Some(1000.0),
        book_value: Some(900.0),
        profit_loss: Some(100.0),
        profit_loss_perc: Some(11.11),
        positions: vec![
            position("SYNTH0000001", Some("SYNTH-A"), 600.0, 60.0),
            position("SYNTH0000002", Some("SYNTH-B"), 400.0, 40.0),
        ],
        fx_rates: vec![NewFxRate {
            currency: "USD".to_string(),
            rate_to_eur: 0.92,
        }],
    };

    let id = store.capture_portfolio_snapshot(&snap).expect("capture");
    assert!(id > 0);

    let latest = store
        .latest_portfolio_snapshot()
        .expect("query")
        .expect("a snapshot");
    assert_eq!(latest.id, id);
    assert_eq!(latest.captured_at, "2026-01-01T00:00:00Z");
    assert_eq!(latest.market_value, Some(1000.0));
    assert_eq!(latest.profit_loss_perc, Some(11.11));

    let mut positions = store.positions_for_snapshot(id).expect("positions");
    positions.sort_by(|a, b| a.asset_instr_id.cmp(&b.asset_instr_id));
    assert_eq!(positions.len(), 2);
    assert_eq!(positions[0].asset_instr_id, "SYNTH0000001");
    assert_eq!(positions[0].symbol, Some("SYNTH-A".to_string()));
    assert_eq!(positions[0].market_value, Some(600.0));
    assert_eq!(positions[0].weight_perc, Some(60.0));
}

#[test]
fn sparse_recapture_preserves_asset_metadata() {
    let mut store = Store::open_in_memory().expect("open");
    let snap = |captured: &str, a: NewAsset| NewPortfolioSnapshot {
        captured_at: captured.to_string(),
        source: "test".to_string(),
        market_value: None,
        book_value: None,
        profit_loss: None,
        profit_loss_perc: None,
        positions: vec![NewPosition {
            asset: a,
            position_key_hash: None,
            qty: Some(1.0),
            avg_price: None,
            market_price: None,
            book_value: None,
            market_value: Some(1.0),
            profit_loss: None,
            profit_loss_perc: None,
            weight_perc: Some(100.0),
        }],
        fx_rates: vec![],
    };
    let full = NewAsset {
        instr_id: "X".to_string(),
        venue_system: "MOT".to_string(),
        symbol: Some("ABC".to_string()),
        description: Some("Alpha Corp".to_string()),
        kind: Some("STOCK".to_string()),
        currency: Some("EUR".to_string()),
    };
    let sparse = NewAsset {
        instr_id: "X".to_string(),
        venue_system: "MOT".to_string(),
        symbol: None,
        description: None,
        kind: None,
        currency: None,
    };
    store
        .capture_portfolio_snapshot(&snap("2026-01-01T00:00:00Z", full))
        .expect("first");
    let id2 = store
        .capture_portfolio_snapshot(&snap("2026-01-02T00:00:00Z", sparse))
        .expect("second");

    // A sparse recapture must not erase metadata stored from the first capture
    // (all history/reports join to the single asset row).
    let positions = store.positions_for_snapshot(id2).expect("positions");
    assert_eq!(positions.len(), 1);
    assert_eq!(positions[0].symbol, Some("ABC".to_string()));
}

#[test]
fn fx_capture_is_robust_to_repeated_timestamp() {
    let mut store = Store::open_in_memory().expect("open");
    let snap = |ts: &str| NewPortfolioSnapshot {
        captured_at: ts.to_string(),
        source: "test".to_string(),
        market_value: None,
        book_value: None,
        profit_loss: None,
        profit_loss_perc: None,
        positions: vec![position("X", Some("X"), 1.0, 100.0)],
        fx_rates: vec![NewFxRate {
            currency: "USD".to_string(),
            rate_to_eur: 0.92,
        }],
    };
    let ts = "2026-01-01T00:00:00Z";
    store
        .capture_portfolio_snapshot(&snap(ts))
        .expect("first capture");
    // A second capture at the same timestamp carrying FX must NOT collide on the
    // fx_rates key and roll back the whole snapshot.
    store
        .capture_portfolio_snapshot(&snap(ts))
        .expect("second capture at same timestamp");
}

#[test]
fn assets_are_deduplicated_across_snapshots() {
    let mut store = Store::open_in_memory().expect("open");
    let snap = |captured: &str| NewPortfolioSnapshot {
        captured_at: captured.to_string(),
        source: "test".to_string(),
        market_value: None,
        book_value: None,
        profit_loss: None,
        profit_loss_perc: None,
        positions: vec![position("X", Some("X"), 1.0, 100.0)],
        fx_rates: vec![],
    };
    store
        .capture_portfolio_snapshot(&snap("2026-01-01T00:00:00Z"))
        .expect("first");
    store
        .capture_portfolio_snapshot(&snap("2026-01-02T00:00:00Z"))
        .expect("second");

    // Same instrument across two snapshots → one asset row, two position rows.
    assert_eq!(store.asset_count().expect("assets"), 1);
    assert_eq!(
        store
            .latest_portfolio_snapshot()
            .expect("q")
            .expect("snap")
            .captured_at,
        "2026-01-02T00:00:00Z"
    );
}
