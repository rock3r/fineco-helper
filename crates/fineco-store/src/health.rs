//! Health / readiness primitives over the store: DB readiness and operational
//! job counts. These back the future `/readyz` and `system_get_status` surfaces
//! (wired at the gateway in M4); here they are plain store queries.

use crate::{Result, SCHEMA_VERSION, Store};

/// Operational job counts by status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobCounts {
    pub running: i64,
    pub completed: i64,
    pub failed: i64,
}

impl Store {
    /// Readiness: the database is open and at the current schema version.
    ///
    /// # Errors
    /// Returns an error if the schema version cannot be read.
    pub fn is_ready(&self) -> Result<bool> {
        Ok(self.schema_version()? == SCHEMA_VERSION)
    }

    /// Counts of `job_runs` by status (running / completed / failed). Other
    /// statuses are ignored.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn job_counts(&self) -> Result<JobCounts> {
        let mut counts = JobCounts::default();
        let mut stmt = self
            .conn
            .prepare("SELECT status, COUNT(*) FROM job_runs GROUP BY status")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows {
            let (status, n) = row?;
            match status.as_str() {
                "running" => counts.running = n,
                "completed" => counts.completed = n,
                "failed" => counts.failed = n,
                _ => {}
            }
        }
        Ok(counts)
    }
}
