//! Tax capture + read-back: carry-forward and minus-by-year, captured together
//! at one `captured_at`. Both are time series; reads return the most recent
//! capture.

use rusqlite::params;

use crate::{Result, Store};

/// A tax carry-forward entry to capture.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewTaxCarryForward {
    pub date_from: String,
    pub date_to: String,
    pub total: Option<f64>,
}

/// A tax minus-by-year entry to capture.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewTaxMinusByYear {
    pub year: i64,
    pub minus_residue: Option<f64>,
    pub expiration_date: Option<String>,
}

/// A tax carry-forward row read back from the store.
#[derive(Debug, Clone)]
pub struct TaxCarryForwardRow {
    pub captured_at: String,
    pub date_from: String,
    pub date_to: String,
    pub total: Option<f64>,
}

/// A tax minus-by-year row read back from the store.
#[derive(Debug, Clone)]
pub struct TaxMinusByYearRow {
    pub captured_at: String,
    pub year: i64,
    pub minus_residue: Option<f64>,
    pub expiration_date: Option<String>,
}

impl Store {
    /// Capture tax state (carry-forward + minus-by-year) at `captured_at`. Atomic.
    ///
    /// # Errors
    /// Returns an error if any insert fails.
    pub fn capture_tax(
        &mut self,
        captured_at: &str,
        carry_forward: &[NewTaxCarryForward],
        minus_by_year: &[NewTaxMinusByYear],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        for cf in carry_forward {
            tx.execute(
                "INSERT INTO tax_carry_forward (captured_at, date_from, date_to, total) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![captured_at, cf.date_from, cf.date_to, cf.total],
            )?;
        }
        for my in minus_by_year {
            tx.execute(
                "INSERT INTO tax_minus_by_year (captured_at, year, minus_residue, expiration_date) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![captured_at, my.year, my.minus_residue, my.expiration_date],
            )?;
        }
        // Mark the capture even when a sub-list is empty (e.g. no carried losses),
        // so the latest carry-forward and minus-by-year both derive from the same
        // tax-capture timestamp instead of each table's own MAX — an empty
        // minus-by-year then returns empty rather than stale residues.
        tx.execute(
            "INSERT OR IGNORE INTO data_captures (data_area, captured_at) VALUES ('tax', ?1)",
            params![captured_at],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Carry-forward entries from the most recent tax capture.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn latest_tax_carry_forward(&self) -> Result<Vec<TaxCarryForwardRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT captured_at, date_from, date_to, total FROM tax_carry_forward \
             WHERE captured_at = \
                   (SELECT MAX(captured_at) FROM data_captures WHERE data_area = 'tax') \
             ORDER BY date_from, date_to",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(TaxCarryForwardRow {
                    captured_at: r.get(0)?,
                    date_from: r.get(1)?,
                    date_to: r.get(2)?,
                    total: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Minus-by-year entries from the most recent tax capture.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn latest_tax_minus_by_year(&self) -> Result<Vec<TaxMinusByYearRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT captured_at, year, minus_residue, expiration_date FROM tax_minus_by_year \
             WHERE captured_at = \
                   (SELECT MAX(captured_at) FROM data_captures WHERE data_area = 'tax') \
             ORDER BY year",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(TaxMinusByYearRow {
                    captured_at: r.get(0)?,
                    year: r.get(1)?,
                    minus_residue: r.get(2)?,
                    expiration_date: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}
