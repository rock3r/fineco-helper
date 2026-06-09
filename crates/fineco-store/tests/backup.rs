//! The online-backup contract: `Store::backup_to` writes a consistent, standalone
//! SQLite copy that re-opens with the same data and schema version — the basis of
//! the encrypted backup + restore drill (plan "Backup And Restore").

use fineco_store::{NewPortfolioSnapshot, Store};

fn snapshot(captured_at: &str) -> NewPortfolioSnapshot {
    NewPortfolioSnapshot {
        captured_at: captured_at.to_string(),
        source: "test".to_string(),
        market_value: Some(1234.5),
        book_value: Some(1000.0),
        profit_loss: Some(234.5),
        profit_loss_perc: Some(23.45),
        positions: Vec::new(),
        fx_rates: Vec::new(),
    }
}

#[test]
fn backup_to_produces_a_readable_standalone_copy() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let src = dir.join(format!("fineco-store-backup-src-{pid}.sqlite"));
    let dest = dir.join(format!("fineco-store-backup-dst-{pid}.sqlite"));
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dest);

    {
        let mut store = Store::open(&src).expect("open source");
        store
            .capture_portfolio_snapshot(&snapshot("2026-06-05T10:00:00Z"))
            .expect("capture");
        store.backup_to(&dest).expect("backup");
    }

    // The backup is a standalone DB: re-open it and read the data back. It must be
    // at the current schema version (so re-opening does not try to re-migrate).
    let restored = Store::open(&dest).expect("open backup");
    assert_eq!(
        restored.schema_version().expect("version"),
        fineco_store::SCHEMA_VERSION,
        "the backup must preserve the schema version"
    );
    let snap = restored
        .latest_portfolio_snapshot()
        .expect("query")
        .expect("a snapshot");
    assert_eq!(snap.captured_at, "2026-06-05T10:00:00Z");
    assert_eq!(snap.market_value, Some(1234.5));

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dest);
}

#[test]
fn backup_to_refuses_to_overwrite_an_existing_file() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let dest = dir.join(format!("fineco-store-backup-exists-{pid}.sqlite"));
    std::fs::write(&dest, b"precious").expect("seed");

    let store = Store::open_in_memory().expect("open");
    // VACUUM INTO will not clobber an existing target — it must error, leaving the
    // file intact (a backup must never destroy data).
    assert!(store.backup_to(&dest).is_err(), "must not overwrite");
    assert_eq!(std::fs::read(&dest).expect("read"), b"precious");

    let _ = std::fs::remove_file(&dest);
}
