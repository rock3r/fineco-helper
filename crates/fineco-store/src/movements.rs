//! Movements capture + read-back. The movements table is a time series keyed by
//! `(captured_at, movement_id_hash)`; each capture records the bank statement
//! lines at a point in time. `movement_id_hash` is the HMAC-SHA256 of the raw
//! `progressivoMovimento` id (hashed by the controller; the worker never sees the key).

use rusqlite::params;

use crate::{Result, Store};

/// A movement to capture, with its hashed id.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewMovement {
    pub movement_id_hash: String,
    pub causale: Option<String>,
    pub descrizione: Option<String>,
    pub importo: Option<f64>,
    pub tipo_movimento: Option<String>,
    pub data_operazione: Option<String>,
    pub data_registrazione: Option<String>,
    pub data_valuta: Option<String>,
    pub causale_movimento: Option<String>,
}

/// A movement as fetched from Fineco but **not yet hashed**: it carries the raw
/// `movement_id` (`progressivoMovimento`). The credential-holding worker has no DB
/// key, so it parses Fineco's response into `RawMovement`s and returns them over
/// the fineco-live socket; the controller turns each into a [`NewMovement`] via
/// [`Store::hash_raw_movement`] before capture.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RawMovement {
    pub movement_id: String,
    pub causale: Option<String>,
    pub descrizione: Option<String>,
    pub importo: Option<f64>,
    pub tipo_movimento: Option<String>,
    pub data_operazione: Option<String>,
    pub data_registrazione: Option<String>,
    pub data_valuta: Option<String>,
    pub causale_movimento: Option<String>,
}

/// A movement read back from the store.
#[derive(Debug, Clone)]
pub struct MovementRow {
    pub captured_at: String,
    pub movement_id_hash: String,
    pub causale: Option<String>,
    pub descrizione: Option<String>,
    pub importo: Option<f64>,
    pub tipo_movimento: Option<String>,
    pub data_operazione: Option<String>,
    pub data_registrazione: Option<String>,
    pub data_valuta: Option<String>,
    pub causale_movimento: Option<String>,
}

impl Store {
    /// Capture movements at `captured_at`. Atomic: inserts all movement rows then
    /// stamps the capture marker, even when the list is empty.
    ///
    /// # Errors
    /// Returns an error if any insert fails.
    pub fn capture_movements(
        &mut self,
        captured_at: &str,
        movements: &[NewMovement],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        for m in movements {
            tx.execute(
                "INSERT INTO movements \
                   (captured_at, movement_id_hash, causale, descrizione, importo, \
                    tipo_movimento, data_operazione, data_registrazione, data_valuta, \
                    causale_movimento) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    captured_at,
                    m.movement_id_hash,
                    m.causale,
                    m.descrizione,
                    m.importo,
                    m.tipo_movimento,
                    m.data_operazione,
                    m.data_registrazione,
                    m.data_valuta,
                    m.causale_movimento,
                ],
            )?;
        }
        // Mark the capture even when `movements` is empty, so a legitimately empty
        // refresh is observable (latest = empty, freshness = this timestamp).
        tx.execute(
            "INSERT OR IGNORE INTO data_captures (data_area, captured_at) \
             VALUES ('movements', ?1)",
            params![captured_at],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The movements from the most recent capture, ordered by movement_id_hash.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn latest_movements(&self) -> Result<Vec<MovementRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT captured_at, movement_id_hash, causale, descrizione, importo, \
                    tipo_movimento, data_operazione, data_registrazione, data_valuta, \
                    causale_movimento \
             FROM movements \
             WHERE captured_at = \
                   (SELECT MAX(captured_at) FROM data_captures WHERE data_area = 'movements') \
             ORDER BY movement_id_hash",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(MovementRow {
                    captured_at: r.get(0)?,
                    movement_id_hash: r.get(1)?,
                    causale: r.get(2)?,
                    descrizione: r.get(3)?,
                    importo: r.get(4)?,
                    tipo_movimento: r.get(5)?,
                    data_operazione: r.get(6)?,
                    data_registrazione: r.get(7)?,
                    data_valuta: r.get(8)?,
                    causale_movimento: r.get(9)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}
