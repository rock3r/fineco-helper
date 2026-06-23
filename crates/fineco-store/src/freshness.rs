//! Integrated freshness: combine the latest snapshot's age with the latest job
//! state into a per-data-area [`FreshnessState`].

use fineco_core::{FreshnessState, freshness_from_age, parse_iso8601_utc};

use crate::{Result, Store};

/// Freshness for one data area: the computed state plus the latest snapshot's
/// captured-at timestamp, if any.
#[derive(Debug, Clone)]
pub struct DataAreaFreshness {
    pub state: FreshnessState,
    pub captured_at: Option<String>,
}

impl Store {
    /// Compute freshness for `data_area` at `now_epoch`, treating data older than
    /// `max_age_seconds` as stale.
    ///
    /// Precedence: a running job → `Refreshing`; else usable cached data →
    /// `Fresh`/`Stale` by age; else the last refresh outcome → `AuthRequired`
    /// (last job failed with `auth_required`) / `RefreshFailed` (any other
    /// failure); else `Missing`.
    ///
    /// # Errors
    /// Returns an error if a query fails.
    pub fn freshness_for(
        &self,
        data_area: &str,
        now_epoch: i64,
        max_age_seconds: i64,
    ) -> Result<DataAreaFreshness> {
        let captured_at = self.latest_capture_at(data_area)?;

        if self.running_job_for(data_area)?.is_some() {
            return Ok(DataAreaFreshness {
                state: FreshnessState::Refreshing,
                captured_at,
            });
        }

        if let Some(ts) = &captured_at {
            let state = match parse_iso8601_utc(ts) {
                Some(epoch) => freshness_from_age(Some(epoch), now_epoch, max_age_seconds),
                // Data exists but its timestamp is unparseable: treat as stale
                // (age indeterminate) rather than missing — `captured_at` is still
                // present, so reporting `missing` would contradict it.
                None => FreshnessState::Stale,
            };
            return Ok(DataAreaFreshness { state, captured_at });
        }

        // No cached data: reflect the last refresh attempt's outcome.
        let state = match self.latest_job_run(data_area)? {
            Some(job) if job.status == "failed" => {
                if job.safe_error_code.as_deref() == Some("auth_required") {
                    FreshnessState::AuthRequired
                } else {
                    FreshnessState::RefreshFailed
                }
            }
            _ => FreshnessState::Missing,
        };
        Ok(DataAreaFreshness {
            state,
            captured_at: None,
        })
    }

    /// Latest captured-at for a data area: the most recent portfolio snapshot, or
    /// the most recent orders/tax capture marker (`data_captures`). Returns the
    /// marker timestamp even when that latest capture is legitimately empty, so a
    /// fresh empty monitor reports its own time rather than `None`.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn latest_capture_at(&self, data_area: &str) -> Result<Option<String>> {
        match data_area {
            "portfolio" => Ok(self.latest_portfolio_snapshot()?.map(|s| s.captured_at)),
            // Orders/tax derive their latest capture from the per-area capture
            // marker (`data_captures`), not the data tables — so a legitimately
            // empty capture is the current one (instead of re-surfacing the
            // previous non-empty capture). MAX over no rows yields NULL → None.
            "orders" | "tax" | "movements" => {
                let ts: Option<String> = self.conn.query_row(
                    "SELECT MAX(captured_at) FROM data_captures WHERE data_area = ?1",
                    [data_area],
                    |r| r.get(0),
                )?;
                Ok(ts)
            }
            _ => Ok(None),
        }
    }
}
