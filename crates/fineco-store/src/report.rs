//! Report generation over stored snapshots.
//!
//! Two report shapes, mirroring the TS reference:
//! - **full** — owner-only; carries every position field including absolute
//!   values, quantities, and prices.
//! - **shareable** — safe to share outside the owner-only system; carries ONLY
//!   names/symbols/ISINs, asset weights, and percentage performance. It must
//!   never include absolute values, quantities, prices, book/market values,
//!   absolute profit/loss, tax, order, or account data, nor the position key
//!   hash (plan "Shareable Contract"). The shareable projection is enforced
//!   structurally by [`ShareableRow`] (it has no field for any forbidden datum).

use crate::{Result, Store};

/// One row of a shareable report. By construction it can hold only the
/// allowed-to-share fields — there is no field for any value/quantity/price.
#[derive(Debug, Clone)]
pub struct ShareableRow {
    pub description: String,
    pub symbol: String,
    pub instr_id: String,
    pub venue_system: String,
    /// The `assets.type` column.
    pub kind: String,
    pub currency: String,
    /// Percentage weight of the position in the portfolio.
    pub weight_perc: Option<f64>,
    /// Percentage profit/loss of the position.
    pub profit_loss_perc: Option<f64>,
}

/// CSV header for the shareable report (matches the TS reference column names).
const SHAREABLE_HEADER: &str =
    "description,symbol,instrId,venueSystem,type,currencyCd,weightPerc,profitLossPerc";

/// CSV header for the full (owner-only) report.
const FULL_HEADER: &str = "instrId,venueSystem,symbol,qty,avgPrice,marketPrice,bookValue,\
    marketValue,profitLoss,profitLossPerc,weightPerc,positionKeyHash";

impl Store {
    /// The shareable rows for a snapshot, ordered by weight descending.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn shareable_report_rows(&self, snapshot_id: i64) -> Result<Vec<ShareableRow>> {
        // NULL weights sort last under SQLite's DESC ordering.
        let mut stmt = self.conn.prepare(
            "SELECT a.description, a.symbol, a.instr_id, a.venue_system, a.\"type\", a.currency, \
                    p.weight_perc, p.profit_loss_perc \
             FROM position_snapshots p JOIN assets a ON a.id = p.asset_id \
             WHERE p.snapshot_id = ?1 \
             ORDER BY p.weight_perc DESC, a.instr_id ASC, a.venue_system ASC",
        )?;
        let rows = stmt
            .query_map([snapshot_id], |r| {
                Ok(ShareableRow {
                    description: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    symbol: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    instr_id: r.get(2)?,
                    venue_system: r.get(3)?,
                    kind: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    currency: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    weight_perc: r.get(6)?,
                    profit_loss_perc: r.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The full (owner-only) report for a snapshot as CSV, including absolute
    /// values. Ordered by instrument id.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn full_report_csv(&self, snapshot_id: i64) -> Result<String> {
        let positions = self.positions_for_snapshot(snapshot_id)?;
        let mut out = String::from(FULL_HEADER);
        for p in &positions {
            let cells = [
                csv_text_cell(&p.asset_instr_id),
                csv_text_cell(&p.asset_venue_system),
                csv_text_cell(&opt_str(p.symbol.as_deref())),
                fmt_f64(p.qty),
                fmt_f64(p.avg_price),
                fmt_f64(p.market_price),
                fmt_f64(p.book_value),
                fmt_f64(p.market_value),
                fmt_f64(p.profit_loss),
                fmt_f64(p.profit_loss_perc),
                fmt_f64(p.weight_perc),
                csv_text_cell(&opt_str(p.position_key_hash.as_deref())),
            ];
            out.push('\n');
            out.push_str(&cells.join(","));
        }
        Ok(out)
    }
}

/// Serialize shareable rows to CSV.
#[must_use]
pub fn shareable_rows_to_csv(rows: &[ShareableRow]) -> String {
    let mut out = String::from(SHAREABLE_HEADER);
    for row in rows {
        let cells = [
            csv_text_cell(&row.description),
            csv_text_cell(&row.symbol),
            csv_text_cell(&row.instr_id),
            csv_text_cell(&row.venue_system),
            csv_text_cell(&row.kind),
            csv_text_cell(&row.currency),
            fmt_f64(row.weight_perc),
            fmt_f64(row.profit_loss_perc),
        ];
        out.push('\n');
        out.push_str(&cells.join(","));
    }
    out
}

fn opt_str(s: Option<&str>) -> String {
    s.unwrap_or_default().to_string()
}

fn fmt_f64(v: Option<f64>) -> String {
    match v {
        Some(x) if x.is_finite() => format!("{x}"),
        _ => String::new(),
    }
}

/// Encode a free-text cell: neutralize spreadsheet-formula triggers, then quote.
///
/// Identity text fields (names/symbols/ISINs) are allowed in shareable output by
/// the plan's Shareable Contract, but text a spreadsheet could interpret as a
/// formula is a real output-safety risk (a CSV parser strips the surrounding
/// quotes, so quoting alone does not stop `=`/`+`/`-`/`@`-led formulas from
/// executing). We prefix such cells with `'` so they are treated as literal text.
fn csv_text_cell(value: &str) -> String {
    csv_quote(&neutralize_formula(value))
}

/// Prefix a `'` if the cell begins with a spreadsheet-formula trigger (`= + - @`)
/// or any ASCII whitespace (space / tab / CR / LF / FF) — a parser may strip
/// leading whitespace and then evaluate a formula. Numeric cells are
/// machine-formatted (digits / `-` / `.` / `e`) and routed around this.
fn neutralize_formula(value: &str) -> String {
    let needs_prefix = value
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '=' | '+' | '-' | '@') || c.is_ascii_whitespace());
    if needs_prefix {
        let mut out = String::with_capacity(value.len() + 1);
        out.push('\'');
        out.push_str(value);
        out
    } else {
        value.to_string()
    }
}

/// Quote a CSV cell if it contains a delimiter/quote/newline (RFC-4180 style).
fn csv_quote(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
