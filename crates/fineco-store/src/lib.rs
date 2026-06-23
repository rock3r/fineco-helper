//! `fineco-store` — the local SQLite history store for `fineco-helper`.
//!
//! Owns the snapshot database (statically-linked SQLite via `rusqlite` with the
//! `bundled` feature). In the minimum deployment topology this store lives inside
//! the credential-holding worker; the internet-facing gateway never opens these
//! files directly. This crate is local-only and holds no credentials. (See the
//! design spec, "Storage".)
//!
//! The `rusqlite` driver is an implementation detail: it is never exposed
//! through the public API, so callers (and the eventual gateway boundary) cannot
//! depend on it or issue raw SQL.

use std::path::Path;

use rusqlite::Connection;

mod backup;
mod capture;
mod categories;
mod freshness;
mod hashing;
mod health;
mod history;
mod jobs;
mod movements;
mod orders;
mod report;
mod tax;
pub use capture::{
    NewAsset, NewFxRate, NewPortfolioSnapshot, NewPosition, PortfolioSnapshotRow, PositionRow,
};
pub use categories::{CategoryLookup, MoneyMapCategory};
pub use fineco_core::FreshnessState;
pub use freshness::DataAreaFreshness;
pub use health::JobCounts;
pub use history::{AllocationPoint, MAX_HISTORY_SNAPSHOTS, PositionHistoryPoint};
pub use jobs::{JobOutcome, JobRunRow};
pub use movements::{MovementRow, MovementsSummary, NewMovement, RawMovement, RawMovementsBundle};
pub use orders::{NewOrder, OrderRow, RawOrder};
pub use report::{ShareableRow, shareable_rows_to_csv};
pub use tax::{NewTaxCarryForward, NewTaxMinusByYear, TaxCarryForwardRow, TaxMinusByYearRow};

/// Current schema version applied when a store is opened.
pub const SCHEMA_VERSION: i64 = 7;

const SCHEMA_V1: &str = include_str!("schema_v1.sql");
const SCHEMA_V2: &str = include_str!("schema_v2.sql");
const SCHEMA_V3: &str = include_str!("schema_v3.sql");
const SCHEMA_V4: &str = include_str!("schema_v4.sql");
const SCHEMA_V5: &str = include_str!("schema_v5.sql");
const SCHEMA_V6: &str = include_str!("schema_v6.sql");
const SCHEMA_V7: &str = include_str!("schema_v7.sql");

/// An error from the store. Opaque by design: the underlying SQLite driver type
/// is never exposed through the public API, so callers cannot couple to
/// `rusqlite` or pattern-match raw driver errors.
#[derive(Debug)]
pub struct StoreError(ErrorKind);

#[derive(Debug)]
enum ErrorKind {
    Sqlite(rusqlite::Error),
    Io(std::io::Error),
    SchemaTooNew { found: i64, supported: i64 },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            ErrorKind::Sqlite(e) => write!(f, "sqlite error: {e}"),
            ErrorKind::Io(e) => write!(f, "io error: {e}"),
            ErrorKind::SchemaTooNew { found, supported } => write!(
                f,
                "database schema version {found} is newer than this binary supports ({supported})"
            ),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            ErrorKind::Sqlite(e) => Some(e),
            ErrorKind::Io(e) => Some(e),
            ErrorKind::SchemaTooNew { .. } => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError(ErrorKind::Sqlite(e))
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError(ErrorKind::Io(e))
    }
}

/// Result alias for store operations.
pub type Result<T> = std::result::Result<T, StoreError>;

/// The local SQLite history store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (or create) the store at `path` and bring its schema up to date.
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or migrated.
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_connection(Connection::open(path)?)
    }

    /// Open an in-memory store (for tests) with the schema applied.
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or migrated.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self> {
        // Enforce foreign keys for the connection. These pragmas are connection-
        // level and must be set outside any transaction. `busy_timeout` lets the
        // store-server's two connections (the snapshot-query reader and the
        // refresh controller's writer, both on the same DB file) wait briefly for
        // each other instead of failing immediately with `SQLITE_BUSY` on a short
        // lock overlap.
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Bring the database schema up to [`SCHEMA_VERSION`], applying each missing
    /// version in a single transaction. A store already at the current version
    /// is left untouched (idempotent). A store at a **newer** version fails
    /// closed (`SchemaTooNew`) rather than being operated on blindly.
    fn migrate(&mut self) -> Result<()> {
        let current: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if current == SCHEMA_VERSION {
            return Ok(());
        }
        if current > SCHEMA_VERSION {
            return Err(StoreError(ErrorKind::SchemaTooNew {
                found: current,
                supported: SCHEMA_VERSION,
            }));
        }
        // `current < SCHEMA_VERSION`: apply each missing version's step in order,
        // all in one transaction.
        let tx = self.conn.transaction()?;
        if current < 1 {
            tx.execute_batch(SCHEMA_V1)?;
        }
        if current < 2 {
            tx.execute_batch(SCHEMA_V2)?;
        }
        if current < 3 {
            tx.execute_batch(SCHEMA_V3)?;
        }
        if current < 4 {
            tx.execute_batch(SCHEMA_V4)?;
        }
        if current < 5 {
            tx.execute_batch(SCHEMA_V5)?;
        }
        if current < 6 {
            tx.execute_batch(SCHEMA_V6)?;
        }
        if current < 7 {
            tx.execute_batch(SCHEMA_V7)?;
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }

    /// The schema version currently recorded in the database.
    ///
    /// # Errors
    /// Returns an error if the version cannot be read.
    pub fn schema_version(&self) -> Result<i64> {
        let v = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        Ok(v)
    }

    /// The user table names in the database (excludes internal `sqlite_*`
    /// tables), sorted. Read-only introspection used by tests and readiness.
    ///
    /// # Errors
    /// Returns an error if the catalog cannot be queried.
    pub fn table_names(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT name FROM sqlite_master \
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' \
             ORDER BY name",
        )?;
        let names = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::Store;

    #[test]
    fn rejects_database_newer_than_supported() {
        // A database written by a newer binary must fail closed, not be silently
        // opened and operated on by this (older-schema) binary.
        let conn = rusqlite::Connection::open_in_memory().expect("open");
        conn.pragma_update(None, "user_version", 99_i64)
            .expect("bump version");
        let err = match Store::from_connection(conn) {
            Ok(_) => panic!("newer schema must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("newer"), "unexpected error: {err}");
    }

    #[test]
    fn v4_migration_backfills_existing_capture_markers() {
        // A populated pre-v4 store (orders/tax rows, no `data_captures`) must
        // keep its history visible after the v4 upgrade backfills the markers.
        let conn = rusqlite::Connection::open_in_memory().expect("open");
        conn.execute_batch(super::SCHEMA_V1).expect("v1");
        conn.execute_batch(super::SCHEMA_V2).expect("v2");
        conn.execute_batch(super::SCHEMA_V3).expect("v3");
        conn.execute(
            "INSERT INTO tax_carry_forward (captured_at, date_from, date_to, total) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["2026-01-01T00:00:00Z", "2025-01-01", "2025-12-31", 100.0],
        )
        .expect("seed pre-v4 tax row");
        conn.pragma_update(None, "user_version", 3_i64)
            .expect("set v3");

        // Opening runs the v4+v5 migrations, which backfill the capture marker
        // and create the movements table.
        let store = Store::from_connection(conn).expect("migrate to v5");
        let rows = store.latest_tax_carry_forward().expect("cf");
        assert_eq!(rows.len(), 1, "pre-v4 tax history must remain visible");
        assert_eq!(rows[0].captured_at, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn v5_migration_creates_movements_table() {
        let conn = rusqlite::Connection::open_in_memory().expect("open");
        conn.execute_batch(super::SCHEMA_V1).expect("v1");
        conn.execute_batch(super::SCHEMA_V2).expect("v2");
        conn.execute_batch(super::SCHEMA_V3).expect("v3");
        conn.execute_batch(super::SCHEMA_V4).expect("v4");
        conn.pragma_update(None, "user_version", 4_i64)
            .expect("set v4");

        let store = Store::from_connection(conn).expect("migrate to v6");
        let tables = store.table_names().expect("tables");
        assert!(
            tables.contains(&"movements".to_string()),
            "movements table must exist after v5"
        );
    }

    #[test]
    fn v6_migration_creates_movements_summary_table() {
        // A store at v5 (movements rows, no per-capture summary) gains the
        // movements_summary table on the v6 upgrade, without losing the movements
        // table or its data.
        let conn = rusqlite::Connection::open_in_memory().expect("open");
        conn.execute_batch(super::SCHEMA_V1).expect("v1");
        conn.execute_batch(super::SCHEMA_V2).expect("v2");
        conn.execute_batch(super::SCHEMA_V3).expect("v3");
        conn.execute_batch(super::SCHEMA_V4).expect("v4");
        conn.execute_batch(super::SCHEMA_V5).expect("v5");
        conn.pragma_update(None, "user_version", 5_i64)
            .expect("set v5");

        let store = Store::from_connection(conn).expect("migrate to v6");
        let tables = store.table_names().expect("tables");
        assert!(
            tables.contains(&"movements".to_string()),
            "movements table must survive the v6 upgrade"
        );
        assert!(
            tables.contains(&"movements_summary".to_string()),
            "movements_summary table must exist after v6"
        );
    }
}
