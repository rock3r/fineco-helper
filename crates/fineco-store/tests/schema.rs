//! Schema/migration contract for the store. Drives the full schema (v1 data
//! tables + v3 `store_meta`) applied on open.

use fineco_store::{SCHEMA_VERSION, Store};

/// All tables a fully-migrated store has, sorted (8 plan data tables + the v3
/// `store_meta` + the v4 `data_captures` + the v5 `movements` + the v6
/// `movements_summary`). Exact set so an accidental table addition is caught.
const ALL_TABLES: &[&str] = &[
    "assets",
    "data_captures",
    "fx_rates",
    "job_runs",
    "movements",
    "movements_summary",
    "orders",
    "portfolio_snapshots",
    "position_snapshots",
    "store_meta",
    "tax_carry_forward",
    "tax_minus_by_year",
];

#[test]
fn open_applies_the_full_schema() {
    let store = Store::open_in_memory().expect("open store");
    let names = store.table_names().expect("table names");
    assert_eq!(
        names,
        ALL_TABLES
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn open_records_schema_version() {
    let store = Store::open_in_memory().expect("open store");
    assert_eq!(
        store.schema_version().expect("schema version"),
        SCHEMA_VERSION
    );
}

#[test]
fn reopen_is_idempotent() {
    let mut path = std::env::temp_dir();
    path.push(format!("fineco-store-idem-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&path);

    {
        let store = Store::open(&path).expect("first open");
        assert_eq!(store.schema_version().expect("version"), SCHEMA_VERSION);
    }
    // Reopening must not re-run CREATE TABLE (which would error) — migration is
    // a no-op once the database is at the current version.
    {
        let store = Store::open(&path).expect("second open");
        assert_eq!(store.schema_version().expect("version"), SCHEMA_VERSION);
        assert_eq!(store.table_names().expect("tables").len(), ALL_TABLES.len());
    }
    std::fs::remove_file(&path).expect("cleanup temp db");
}
