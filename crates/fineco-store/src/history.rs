//! History queries over stored snapshots: portfolio time series, allocation
//! history (per-asset weight over time), and per-position history. Allocation
//! and weight/percentage series are shareable-safe by nature; absolute fields
//! (e.g. `market_value`) are owner-only and filtered at the report/MCP layer.

use crate::{PortfolioSnapshotRow, Result, Store};

/// Defensive upper bound on how many recent snapshots a single history query may
/// return, so an authenticated caller cannot force an ever-growing full-history
/// scan/serialize as captured data accumulates (allocation history is positions ×
/// snapshots). The most recent snapshots are kept. The server passes this for the
/// no-`limit` history tools; the value is generous (≈ 3 years of daily snapshots).
pub const MAX_HISTORY_SNAPSHOTS: u32 = 1000;

/// One point in the allocation history: an asset's weight at a capture time.
/// An instrument is identified by `(instr_id, venue_system)`, so both are
/// carried — the same `instr_id` can exist on different venues.
#[derive(Debug, Clone)]
pub struct AllocationPoint {
    pub captured_at: String,
    pub instr_id: String,
    pub venue_system: String,
    pub symbol: Option<String>,
    pub weight_perc: Option<f64>,
}

/// One point in a single instrument's history.
#[derive(Debug, Clone)]
pub struct PositionHistoryPoint {
    pub captured_at: String,
    pub weight_perc: Option<f64>,
    pub profit_loss_perc: Option<f64>,
    /// Owner-only absolute; callers building shareable output must drop this.
    pub market_value: Option<f64>,
}

impl Store {
    /// The most recent `limit` portfolio snapshots, in chronological order.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn portfolio_history(&self, limit: u32) -> Result<Vec<PortfolioSnapshotRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, captured_at, source, portfolio_market_value, portfolio_book_value, \
                    portfolio_profit_loss, portfolio_profit_loss_perc \
             FROM portfolio_snapshots ORDER BY captured_at DESC, id DESC LIMIT ?1",
        )?;
        let mut rows = stmt
            .query_map([limit], |r| {
                Ok(PortfolioSnapshotRow {
                    id: r.get(0)?,
                    captured_at: r.get(1)?,
                    source: r.get(2)?,
                    market_value: r.get(3)?,
                    book_value: r.get(4)?,
                    profit_loss: r.get(5)?,
                    profit_loss_perc: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // Query returns most-recent-first; present chronologically.
        rows.reverse();
        Ok(rows)
    }

    /// Per-asset weight over time, oldest first, restricted to the most recent
    /// `max_snapshots` snapshots (a defensive bound — see [`MAX_HISTORY_SNAPSHOTS`]).
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn allocation_history(&self, max_snapshots: u32) -> Result<Vec<AllocationPoint>> {
        // Bound to the most recent `max_snapshots` snapshots (each with all its
        // positions), then present oldest-first — so the cap never returns a partial
        // snapshot, and the response can't grow without limit as history accumulates.
        let mut stmt = self.conn.prepare(
            "SELECT ps.captured_at, a.instr_id, a.venue_system, a.symbol, p.weight_perc \
             FROM position_snapshots p \
             JOIN portfolio_snapshots ps ON ps.id = p.snapshot_id \
             JOIN assets a ON a.id = p.asset_id \
             WHERE ps.id IN ( \
                 SELECT id FROM portfolio_snapshots ORDER BY captured_at DESC, id DESC LIMIT ?1 \
             ) \
             ORDER BY ps.captured_at ASC, ps.id ASC, a.instr_id ASC, a.venue_system ASC",
        )?;
        let rows = stmt
            .query_map([max_snapshots], |r| {
                Ok(AllocationPoint {
                    captured_at: r.get(0)?,
                    instr_id: r.get(1)?,
                    venue_system: r.get(2)?,
                    symbol: r.get(3)?,
                    weight_perc: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// One instrument's history across snapshots, oldest first. An instrument is
    /// `(instr_id, venue_system)`; both are required so the same ISIN on
    /// different venues is not merged into one series.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn position_history(
        &self,
        instr_id: &str,
        venue_system: &str,
        max_points: u32,
    ) -> Result<Vec<PositionHistoryPoint>> {
        // Most recent `max_points` points (one per snapshot for this instrument),
        // presented oldest-first — bounds the response as history accumulates.
        let mut stmt = self.conn.prepare(
            "SELECT ps.captured_at, p.weight_perc, p.profit_loss_perc, p.market_value \
             FROM position_snapshots p \
             JOIN portfolio_snapshots ps ON ps.id = p.snapshot_id \
             JOIN assets a ON a.id = p.asset_id \
             WHERE a.instr_id = ?1 AND a.venue_system = ?2 \
             ORDER BY ps.captured_at DESC, ps.id DESC LIMIT ?3",
        )?;
        let mut rows = stmt
            .query_map(rusqlite::params![instr_id, venue_system, max_points], |r| {
                Ok(PositionHistoryPoint {
                    captured_at: r.get(0)?,
                    weight_perc: r.get(1)?,
                    profit_loss_perc: r.get(2)?,
                    market_value: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.reverse();
        Ok(rows)
    }
}
