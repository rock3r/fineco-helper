//! Orders capture + read-back. The orders table is a time series keyed by
//! `(captured_at, trans_id_hash)`; each capture records the order monitor state
//! at a point in time. `trans_id_hash` is an opaque caller-supplied hash (the
//! hashing strategy lives at the M3 fetch source).

use rusqlite::params;

use crate::capture::upsert_asset;
use crate::{NewAsset, Result, Store};

/// An order to capture, with its instrument.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewOrder {
    pub trans_id_hash: String,
    pub asset: NewAsset,
    pub status: Option<String>,
    pub sign: Option<String>,
    pub order_size: Option<f64>,
    pub size_filled: Option<f64>,
    pub avg_price: Option<f64>,
    pub submit_time: Option<String>,
}

/// An order as fetched from Fineco but **not yet hashed**: it carries the raw
/// broker `trans_id`. The credential-holding worker has no DB key, so it parses
/// Fineco's response into `RawOrder`s and returns them over the fineco-live
/// socket; the controller (which owns the DB and its per-DB HMAC key) turns each
/// into a [`NewOrder`] via [`Store::hash_raw_order`] before capture. The raw
/// `trans_id` therefore never needs the worker to hold the key, and is never
/// logged.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RawOrder {
    pub trans_id: String,
    pub asset: NewAsset,
    pub status: Option<String>,
    pub sign: Option<String>,
    pub order_size: Option<f64>,
    pub size_filled: Option<f64>,
    pub avg_price: Option<f64>,
    pub submit_time: Option<String>,
}

/// An order read back from the store (joined to its instrument).
#[derive(Debug, Clone)]
pub struct OrderRow {
    pub captured_at: String,
    pub trans_id_hash: String,
    pub asset_instr_id: String,
    pub asset_venue_system: String,
    pub status: Option<String>,
    pub sign: Option<String>,
    pub order_size: Option<f64>,
    pub size_filled: Option<f64>,
    pub avg_price: Option<f64>,
    pub submit_time: Option<String>,
}

impl Store {
    /// Capture the order monitor state at `captured_at`. Atomic.
    ///
    /// # Errors
    /// Returns an error if any insert fails (e.g. a duplicate trans id at the
    /// same capture time).
    pub fn capture_orders(&mut self, captured_at: &str, orders: &[NewOrder]) -> Result<()> {
        let tx = self.conn.transaction()?;
        for order in orders {
            let asset_id = upsert_asset(&tx, &order.asset)?;
            tx.execute(
                "INSERT INTO orders \
                   (captured_at, trans_id_hash, asset_id, status, sign, order_size, \
                    size_filled, avg_price, submit_time) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    captured_at,
                    order.trans_id_hash,
                    asset_id,
                    order.status,
                    order.sign,
                    order.order_size,
                    order.size_filled,
                    order.avg_price,
                    order.submit_time,
                ],
            )?;
        }
        // Mark the capture even when `orders` is empty, so a legitimately empty
        // refresh is observable (latest = empty, freshness = this timestamp)
        // rather than re-surfacing the previous non-empty capture.
        tx.execute(
            "INSERT OR IGNORE INTO data_captures (data_area, captured_at) VALUES ('orders', ?1)",
            params![captured_at],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The orders from the most recent capture, ordered by transaction hash.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn latest_orders(&self) -> Result<Vec<OrderRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT o.captured_at, o.trans_id_hash, a.instr_id, a.venue_system, o.status, \
                    o.sign, o.order_size, o.size_filled, o.avg_price, o.submit_time \
             FROM orders o JOIN assets a ON a.id = o.asset_id \
             WHERE o.captured_at = \
                   (SELECT MAX(captured_at) FROM data_captures WHERE data_area = 'orders') \
             ORDER BY o.trans_id_hash",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(OrderRow {
                    captured_at: r.get(0)?,
                    trans_id_hash: r.get(1)?,
                    asset_instr_id: r.get(2)?,
                    asset_venue_system: r.get(3)?,
                    status: r.get(4)?,
                    sign: r.get(5)?,
                    order_size: r.get(6)?,
                    size_filled: r.get(7)?,
                    avg_price: r.get(8)?,
                    submit_time: r.get(9)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}
