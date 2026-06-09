//! Typed snapshot capture and read-back for the store.
//!
//! Capture takes owned domain structs (never raw SQL) and writes a portfolio
//! snapshot, its positions, the referenced assets (deduplicated by
//! `(instr_id, venue_system)`), and any FX rates in a single transaction.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{Result, Store};

/// An instrument referenced by a position. Deduplicated on
/// `(instr_id, venue_system)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAsset {
    pub instr_id: String,
    pub venue_system: String,
    pub symbol: Option<String>,
    pub description: Option<String>,
    /// Maps to the `assets.type` column (`type` is a Rust keyword).
    pub kind: Option<String>,
    pub currency: Option<String>,
}

/// A single position to capture, with its instrument.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewPosition {
    pub asset: NewAsset,
    pub position_key_hash: Option<String>,
    pub qty: Option<f64>,
    pub avg_price: Option<f64>,
    pub market_price: Option<f64>,
    pub book_value: Option<f64>,
    pub market_value: Option<f64>,
    pub profit_loss: Option<f64>,
    pub profit_loss_perc: Option<f64>,
    pub weight_perc: Option<f64>,
}

/// An FX rate to EUR captured alongside a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewFxRate {
    pub currency: String,
    pub rate_to_eur: f64,
}

/// A portfolio snapshot to capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewPortfolioSnapshot {
    /// ISO-8601 UTC timestamp.
    pub captured_at: String,
    /// Provenance label (e.g. `"scheduled"`, `"manual"`, `"test"`).
    pub source: String,
    pub market_value: Option<f64>,
    pub book_value: Option<f64>,
    pub profit_loss: Option<f64>,
    pub profit_loss_perc: Option<f64>,
    pub positions: Vec<NewPosition>,
    pub fx_rates: Vec<NewFxRate>,
}

/// A portfolio snapshot read back from the store.
#[derive(Debug, Clone)]
pub struct PortfolioSnapshotRow {
    pub id: i64,
    pub captured_at: String,
    pub source: String,
    pub market_value: Option<f64>,
    pub book_value: Option<f64>,
    pub profit_loss: Option<f64>,
    pub profit_loss_perc: Option<f64>,
}

/// A position read back from the store (joined to its instrument).
#[derive(Debug, Clone)]
pub struct PositionRow {
    pub asset_instr_id: String,
    pub asset_venue_system: String,
    pub symbol: Option<String>,
    pub qty: Option<f64>,
    pub avg_price: Option<f64>,
    pub market_price: Option<f64>,
    pub book_value: Option<f64>,
    pub market_value: Option<f64>,
    pub profit_loss: Option<f64>,
    pub profit_loss_perc: Option<f64>,
    pub weight_perc: Option<f64>,
    pub position_key_hash: Option<String>,
}

impl Store {
    /// Capture a portfolio snapshot with its positions, assets, and FX rates.
    /// Returns the new `portfolio_snapshots.id`. Atomic: all-or-nothing.
    ///
    /// # Errors
    /// Returns an error if any insert fails (e.g. a duplicate snapshot key).
    pub fn capture_portfolio_snapshot(&mut self, snapshot: &NewPortfolioSnapshot) -> Result<i64> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO portfolio_snapshots \
               (captured_at, source, portfolio_market_value, portfolio_book_value, \
                portfolio_profit_loss, portfolio_profit_loss_perc) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                snapshot.captured_at,
                snapshot.source,
                snapshot.market_value,
                snapshot.book_value,
                snapshot.profit_loss,
                snapshot.profit_loss_perc,
            ],
        )?;
        let snapshot_id = tx.last_insert_rowid();

        for pos in &snapshot.positions {
            let asset_id = upsert_asset(&tx, &pos.asset)?;
            tx.execute(
                "INSERT INTO position_snapshots \
                   (snapshot_id, asset_id, position_key_hash, qty, avg_price, market_price, \
                    book_value, market_value, profit_loss, profit_loss_perc, weight_perc) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    snapshot_id,
                    asset_id,
                    pos.position_key_hash,
                    pos.qty,
                    pos.avg_price,
                    pos.market_price,
                    pos.book_value,
                    pos.market_value,
                    pos.profit_loss,
                    pos.profit_loss_perc,
                    pos.weight_perc,
                ],
            )?;
        }

        for fx in &snapshot.fx_rates {
            // fx_rates is a per-time rate series keyed by (captured_at, currency).
            // Two snapshots can share a captured_at, so upsert rather than letting
            // a duplicate key roll back the whole snapshot.
            tx.execute(
                "INSERT INTO fx_rates (captured_at, currency, rate_to_eur) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(captured_at, currency) DO UPDATE SET rate_to_eur = excluded.rate_to_eur",
                params![snapshot.captured_at, fx.currency, fx.rate_to_eur],
            )?;
        }

        tx.commit()?;
        Ok(snapshot_id)
    }

    /// The most recent portfolio snapshot, or `None` if the store is empty.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn latest_portfolio_snapshot(&self) -> Result<Option<PortfolioSnapshotRow>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, captured_at, source, portfolio_market_value, portfolio_book_value, \
                        portfolio_profit_loss, portfolio_profit_loss_perc \
                 FROM portfolio_snapshots ORDER BY captured_at DESC, id DESC LIMIT 1",
                [],
                |r| {
                    Ok(PortfolioSnapshotRow {
                        id: r.get(0)?,
                        captured_at: r.get(1)?,
                        source: r.get(2)?,
                        market_value: r.get(3)?,
                        book_value: r.get(4)?,
                        profit_loss: r.get(5)?,
                        profit_loss_perc: r.get(6)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// The positions belonging to a snapshot, ordered by instrument id.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn positions_for_snapshot(&self, snapshot_id: i64) -> Result<Vec<PositionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT a.instr_id, a.venue_system, a.symbol, p.qty, p.avg_price, p.market_price, \
                    p.book_value, p.market_value, p.profit_loss, p.profit_loss_perc, \
                    p.weight_perc, p.position_key_hash \
             FROM position_snapshots p JOIN assets a ON a.id = p.asset_id \
             WHERE p.snapshot_id = ?1 \
             ORDER BY a.instr_id, a.venue_system",
        )?;
        let rows = stmt
            .query_map([snapshot_id], |r| {
                Ok(PositionRow {
                    asset_instr_id: r.get(0)?,
                    asset_venue_system: r.get(1)?,
                    symbol: r.get(2)?,
                    qty: r.get(3)?,
                    avg_price: r.get(4)?,
                    market_price: r.get(5)?,
                    book_value: r.get(6)?,
                    market_value: r.get(7)?,
                    profit_loss: r.get(8)?,
                    profit_loss_perc: r.get(9)?,
                    weight_perc: r.get(10)?,
                    position_key_hash: r.get(11)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Total number of distinct instruments stored. Read-only.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn asset_count(&self) -> Result<i64> {
        let n = self
            .conn
            .query_row("SELECT COUNT(*) FROM assets", [], |r| r.get(0))?;
        Ok(n)
    }
}

/// Upsert an instrument and return its `assets.id`, within a transaction.
///
/// Preserves existing non-null metadata when a later capture omits it (COALESCE
/// keeps the stored value if the new one is NULL) — a sparse recapture must not
/// erase names/symbols, since every historical/report query joins back to this
/// single asset row. Shared by portfolio-snapshot and orders capture.
pub(crate) fn upsert_asset(tx: &rusqlite::Transaction, asset: &NewAsset) -> rusqlite::Result<i64> {
    tx.query_row(
        "INSERT INTO assets (instr_id, venue_system, symbol, description, \"type\", currency) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(instr_id, venue_system) DO UPDATE SET \
           symbol = COALESCE(excluded.symbol, symbol), \
           description = COALESCE(excluded.description, description), \
           \"type\" = COALESCE(excluded.\"type\", \"type\"), \
           currency = COALESCE(excluded.currency, currency) \
         RETURNING id",
        params![
            asset.instr_id,
            asset.venue_system,
            asset.symbol,
            asset.description,
            asset.kind,
            asset.currency,
        ],
        |row| row.get(0),
    )
}
