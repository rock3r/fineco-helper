//! Movements capture + read-back. The movements table is a time series keyed by
//! `(captured_at, movement_id_hash)`; each capture records the bank statement
//! lines at a point in time. `movement_id_hash` is the HMAC-SHA256 of the raw
//! `progressivoMovimento` id (hashed by the controller; the worker never sees the key).

use rusqlite::{OptionalExtension, params};

use crate::{MoneyMapCategory, Result, Store};

/// What a single credentialed movements refresh yields from the worker: the bank
/// statement lines, the per-capture account `summary` (from the response envelope),
/// and the account's MoneyMap taxonomy, fetched best-effort in the same login
/// session to resolve the lines' raw category ids to names.
///
/// `categories` is `None` when the best-effort taxonomy fetch failed — the
/// movements are still authoritative, and the previously-cached taxonomy is left
/// untouched (a transient failure must not wipe resolved names). `Some` means the
/// taxonomy was fetched (and should replace the cache, even if legitimately empty).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RawMovementsBundle {
    pub movements: Vec<RawMovement>,
    pub summary: MovementsSummary,
    pub categories: Option<Vec<MoneyMapCategory>>,
}

/// A movement to capture, with its hashed id.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewMovement {
    pub movement_id_hash: String,
    pub causale: Option<String>,
    pub descrizione: Option<String>,
    pub descrizione_breve: Option<String>,
    pub importo: Option<f64>,
    pub tipo_movimento: Option<String>,
    pub data_operazione: Option<String>,
    pub data_registrazione: Option<String>,
    pub data_valuta: Option<String>,
    pub causale_movimento: Option<String>,
    pub categoria_id: Option<String>,
    pub sottocategoria_id: Option<String>,
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
    pub descrizione_breve: Option<String>,
    pub importo: Option<f64>,
    pub tipo_movimento: Option<String>,
    pub data_operazione: Option<String>,
    pub data_registrazione: Option<String>,
    pub data_valuta: Option<String>,
    pub causale_movimento: Option<String>,
    pub categoria_id: Option<String>,
    pub sottocategoria_id: Option<String>,
}

/// Account-level summary for one movements capture. These are fields the movements
/// endpoint returns at the response **top level** (one set per fetch, not per
/// movement): the account balance at the latest movement and as of the search date,
/// and the current month's credit/debit spending totals. All optional — a capture may
/// omit any of them. Numeric (€ amounts), so unlike [`RawMovement`] there is no id to
/// hash; the same struct crosses the worker socket and is stored verbatim.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MovementsSummary {
    pub balance_at_movement: Option<f64>,
    pub balance_at_search_date: Option<f64>,
    pub current_month_credit_spending: Option<f64>,
    pub current_month_debit_spending: Option<f64>,
}

impl MovementsSummary {
    /// `true` when no account-level field was present (all `None`) — i.e. the fetch
    /// carried no summary. The orchestrator does not persist such a summary, so
    /// `movements_get_latest` omits `account_summary` entirely rather than emitting an
    /// empty `{}` object that callers couldn't distinguish from "no summary returned".
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.balance_at_movement.is_none()
            && self.balance_at_search_date.is_none()
            && self.current_month_credit_spending.is_none()
            && self.current_month_debit_spending.is_none()
    }
}

/// A movement read back from the store.
#[derive(Debug, Clone)]
pub struct MovementRow {
    pub captured_at: String,
    pub movement_id_hash: String,
    pub causale: Option<String>,
    pub descrizione: Option<String>,
    pub descrizione_breve: Option<String>,
    pub importo: Option<f64>,
    pub tipo_movimento: Option<String>,
    pub data_operazione: Option<String>,
    pub data_registrazione: Option<String>,
    pub data_valuta: Option<String>,
    pub causale_movimento: Option<String>,
    pub categoria_id: Option<String>,
    pub sottocategoria_id: Option<String>,
}

impl Store {
    /// Capture movements at `captured_at`. Atomic: inserts all movement rows, the
    /// optional per-capture account summary, then stamps the capture marker — even
    /// when the list is empty. `summary` is `None` when the fetch carried no
    /// account-level fields; passing `Some` always writes a summary row (so the four
    /// fields are observable together with the capture).
    ///
    /// # Errors
    /// Returns an error if any insert fails.
    pub fn capture_movements(
        &mut self,
        captured_at: &str,
        movements: &[NewMovement],
        summary: Option<&MovementsSummary>,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        for m in movements {
            tx.execute(
                "INSERT INTO movements \
                   (captured_at, movement_id_hash, causale, descrizione, descrizione_breve, \
                    importo, tipo_movimento, data_operazione, data_registrazione, data_valuta, \
                    causale_movimento, categoria_id, sottocategoria_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    captured_at,
                    m.movement_id_hash,
                    m.causale,
                    m.descrizione,
                    m.descrizione_breve,
                    m.importo,
                    m.tipo_movimento,
                    m.data_operazione,
                    m.data_registrazione,
                    m.data_valuta,
                    m.causale_movimento,
                    m.categoria_id,
                    m.sottocategoria_id,
                ],
            )?;
        }
        if let Some(s) = summary {
            tx.execute(
                "INSERT OR REPLACE INTO movements_summary \
                   (captured_at, balance_at_movement, balance_at_search_date, \
                    current_month_credit_spending, current_month_debit_spending) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    captured_at,
                    s.balance_at_movement,
                    s.balance_at_search_date,
                    s.current_month_credit_spending,
                    s.current_month_debit_spending,
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
            "SELECT captured_at, movement_id_hash, causale, descrizione, descrizione_breve, \
                    importo, tipo_movimento, data_operazione, data_registrazione, data_valuta, \
                    causale_movimento, categoria_id, sottocategoria_id \
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
                    descrizione_breve: r.get(4)?,
                    importo: r.get(5)?,
                    tipo_movimento: r.get(6)?,
                    data_operazione: r.get(7)?,
                    data_registrazione: r.get(8)?,
                    data_valuta: r.get(9)?,
                    causale_movimento: r.get(10)?,
                    categoria_id: r.get(11)?,
                    sottocategoria_id: r.get(12)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The account-level summary captured with the most recent movements capture, or
    /// `None` if that capture stored no summary row (e.g. pre-v6 history, or a fetch
    /// that carried no account-level fields).
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn latest_movements_summary(&self) -> Result<Option<MovementsSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT balance_at_movement, balance_at_search_date, \
                    current_month_credit_spending, current_month_debit_spending \
             FROM movements_summary \
             WHERE captured_at = \
                   (SELECT MAX(captured_at) FROM data_captures WHERE data_area = 'movements')",
        )?;
        let summary = stmt
            .query_row([], |r| {
                Ok(MovementsSummary {
                    balance_at_movement: r.get(0)?,
                    balance_at_search_date: r.get(1)?,
                    current_month_credit_spending: r.get(2)?,
                    current_month_debit_spending: r.get(3)?,
                })
            })
            .optional()?;
        Ok(summary)
    }
}
