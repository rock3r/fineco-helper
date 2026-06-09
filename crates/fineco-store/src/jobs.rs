//! `job_runs` recording and the running-job lock query. Underpins refresh locks
//! (`already_refreshing`) and the integrated freshness model. Timestamps are
//! supplied by the caller (ISO-8601 UTC), keeping the store clock-free/testable.

use fineco_core::parse_iso8601_utc;
use rusqlite::{ErrorCode, OptionalExtension, params};

use crate::{Result, Store};

/// Terminal outcome of a job. A typed value (not a free string) so a caller
/// cannot record a mistyped status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobOutcome {
    Completed,
    Failed,
}

impl JobOutcome {
    fn as_str(self) -> &'static str {
        match self {
            JobOutcome::Completed => "completed",
            JobOutcome::Failed => "failed",
        }
    }
}

/// A row from `job_runs`.
#[derive(Debug, Clone)]
pub struct JobRunRow {
    pub id: i64,
    pub auth_id: String,
    pub data_area: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    /// `"running"` until finished, then e.g. `"completed"` / `"failed"`.
    pub status: String,
    pub safe_error_code: Option<String>,
}

impl Store {
    /// Record the start of a refresh job (status `"running"`); returns its id.
    /// Errors if a running job already exists for the data area (the unique index
    /// enforces the lock) — prefer [`Store::try_begin_job`] for the lock-aware path.
    ///
    /// # Errors
    /// Returns an error if the insert fails.
    pub fn record_job_start(
        &mut self,
        auth_id: &str,
        data_area: &str,
        started_at: &str,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO job_runs (auth_id, data_area, started_at, status) \
             VALUES (?1, ?2, ?3, 'running')",
            params![auth_id, data_area, started_at],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Atomically acquire the per-data-area refresh lock by inserting a running
    /// job. Returns `Some(job_id)` on success, or `None` if a refresh is already
    /// running (the partial unique index rejects the insert) — i.e. the caller
    /// should return `already_refreshing`. There is no check-then-insert window.
    ///
    /// Self-healing: if the existing running job started more than
    /// `stale_after_secs` before `started_at`, it is presumed dead (e.g. a finish
    /// write failed) and reclaimed (marked `failed`/`stale`) so the lock cannot
    /// block forever.
    ///
    /// # Errors
    /// Returns an error on any failure other than the lock conflict.
    pub fn try_begin_job(
        &mut self,
        auth_id: &str,
        data_area: &str,
        started_at: &str,
        stale_after_secs: i64,
    ) -> Result<Option<i64>> {
        if let Some(id) = self.insert_running_job(auth_id, data_area, started_at)? {
            return Ok(Some(id));
        }
        // Conflict: reclaim a stale running job and retry once.
        if self.reclaim_stale_running(data_area, started_at, stale_after_secs)? {
            return self.insert_running_job(auth_id, data_area, started_at);
        }
        Ok(None)
    }

    /// Insert a running job; `Ok(None)` if the unique lock rejects it.
    fn insert_running_job(
        &self,
        auth_id: &str,
        data_area: &str,
        started_at: &str,
    ) -> Result<Option<i64>> {
        match self.conn.execute(
            "INSERT INTO job_runs (auth_id, data_area, started_at, status) \
             VALUES (?1, ?2, ?3, 'running')",
            params![auth_id, data_area, started_at],
        ) {
            Ok(_) => Ok(Some(self.conn.last_insert_rowid())),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == ErrorCode::ConstraintViolation =>
            {
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Reclaim a running job for `data_area` that started more than
    /// `stale_after_secs` before `now_iso`. Returns whether one was reclaimed.
    fn reclaim_stale_running(
        &self,
        data_area: &str,
        now_iso: &str,
        stale_after_secs: i64,
    ) -> Result<bool> {
        let running: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT id, started_at FROM job_runs WHERE data_area = ?1 AND status = 'running' \
                 ORDER BY id DESC LIMIT 1",
                [data_area],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((job_id, started)) = running else {
            return Ok(false);
        };
        let (Some(now), Some(then)) = (parse_iso8601_utc(now_iso), parse_iso8601_utc(&started))
        else {
            return Ok(false);
        };
        if now.saturating_sub(then) <= stale_after_secs {
            return Ok(false);
        }
        // Reclaim ONLY the specific stale row inspected above (matched by id), not
        // every running row — so a concurrently-started job cannot be dropped.
        // Report whether it was actually reclaimed (it may already be terminal).
        let updated = self.conn.execute(
            "UPDATE job_runs SET status = 'failed', finished_at = ?2, safe_error_code = 'stale' \
             WHERE id = ?1 AND status = 'running'",
            params![job_id, now_iso],
        )?;
        Ok(updated > 0)
    }

    /// Record the outcome of a running job, clearing its lock. Only a job that is
    /// currently `running` is updated. Returns `true` if a running job was
    /// updated, or `false` if it was already terminal (e.g. reclaimed as stale or
    /// superseded) — so the no-op is observable to the caller, never silent.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn record_job_finish(
        &mut self,
        job_id: i64,
        finished_at: &str,
        outcome: JobOutcome,
        safe_error_code: Option<&str>,
    ) -> Result<bool> {
        let updated = self.conn.execute(
            "UPDATE job_runs SET finished_at = ?2, status = ?3, safe_error_code = ?4 \
             WHERE id = ?1 AND status = 'running'",
            params![job_id, finished_at, outcome.as_str(), safe_error_code],
        )?;
        Ok(updated > 0)
    }

    /// The most recent job for a data area, or `None` if there are none.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn latest_job_run(&self, data_area: &str) -> Result<Option<JobRunRow>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, auth_id, data_area, started_at, finished_at, status, safe_error_code \
                 FROM job_runs WHERE data_area = ?1 ORDER BY started_at DESC, id DESC LIMIT 1",
                [data_area],
                map_job_row,
            )
            .optional()?;
        Ok(row)
    }

    /// The id of a currently-running job for a data area, if any (the lock used
    /// to return `already_refreshing`).
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn running_job_for(&self, data_area: &str) -> Result<Option<i64>> {
        let id = self
            .conn
            .query_row(
                "SELECT id FROM job_runs WHERE data_area = ?1 AND status = 'running' \
                 ORDER BY id DESC LIMIT 1",
                [data_area],
                |r| r.get(0),
            )
            .optional()?;
        Ok(id)
    }

    /// Count the `job_runs` rows for `data_area` whose `started_at` falls on the
    /// given `utc_date` (`YYYY-MM-DD`). Every row is a lock-acquired, Fineco-
    /// reaching attempt, so this is the per-area daily refresh budget tally
    /// (including auth/upstream failures; excluding pre-flight denials, which
    /// never create a row). `started_at` is stored UTC ISO-8601.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn count_jobs_on_utc_date(&self, data_area: &str, utc_date: &str) -> Result<i64> {
        let count = self.conn.query_row(
            "SELECT COUNT(*) FROM job_runs \
             WHERE data_area = ?1 AND substr(started_at, 1, 10) = ?2",
            params![data_area, utc_date],
            |r| r.get(0),
        )?;
        Ok(count)
    }

    /// The most recent terminal (`completed`/`failed`) `(started_at, status,
    /// safe_error_code)` rows for `data_area`, newest first, up to `limit`.
    /// Running rows are excluded so an in-flight attempt cannot skew the
    /// circuit-breaker derivation; `started_at` lets the breaker half-open after a
    /// cooldown.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn recent_job_outcomes(
        &self,
        data_area: &str,
        limit: u32,
    ) -> Result<Vec<(String, String, Option<String>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT started_at, status, safe_error_code FROM job_runs \
             WHERE data_area = ?1 AND status IN ('completed', 'failed') \
             ORDER BY started_at DESC, id DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![data_area, limit], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

fn map_job_row(r: &rusqlite::Row) -> rusqlite::Result<JobRunRow> {
    Ok(JobRunRow {
        id: r.get(0)?,
        auth_id: r.get(1)?,
        data_area: r.get(2)?,
        started_at: r.get(3)?,
        finished_at: r.get(4)?,
        status: r.get(5)?,
        safe_error_code: r.get(6)?,
    })
}
