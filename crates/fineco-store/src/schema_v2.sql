-- fineco-store schema v2 (M2).
--
-- Enforce the refresh lock at the database level: at most one running job per
-- data area. The INSERT of a 'running' row becomes the atomic lock acquisition,
-- so a check-then-insert race cannot produce two concurrent refreshes for the
-- same data area (see Store::try_begin_job).

-- Defensive: before enforcing one running job per area, resolve any pre-existing
-- duplicate running rows so index creation cannot fail and brick the database.
-- (A real v1 DB has no job_runs rows — recording is new in M2 — so this is a
-- no-op there; it guards against any out-of-band state.)
UPDATE job_runs SET status = 'failed', safe_error_code = 'superseded'
WHERE status = 'running'
  AND id NOT IN (
      SELECT MAX(id) FROM job_runs WHERE status = 'running' GROUP BY data_area
  );

CREATE UNIQUE INDEX one_running_job_per_data_area
    ON job_runs (data_area)
    WHERE status = 'running';
