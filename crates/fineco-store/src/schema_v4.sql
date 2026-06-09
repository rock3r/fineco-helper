-- fineco-store schema v4 (M3).
--
-- Per-area capture markers. Orders and tax are flat tables keyed by
-- `captured_at`; a legitimately EMPTY capture (no open orders, or no carried
-- losses) inserts no data row. A `MAX(captured_at)` over the data table would
-- then silently keep showing the previous non-empty capture as current. A marker
-- row per capture makes empty captures observable: "latest" and freshness derive
-- from the marker, so an empty latest capture correctly returns empty / reports
-- the new capture's timestamp. (Portfolio already gets this from its per-snapshot
-- header row in `portfolio_snapshots`.)

CREATE TABLE data_captures (
    data_area   TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    PRIMARY KEY (data_area, captured_at)
);

-- Backfill markers from any pre-existing order/tax history, so upgrading a
-- populated v1–v3 store keeps that history visible (the new latest/freshness
-- paths read the marker, not the data tables).
INSERT OR IGNORE INTO data_captures (data_area, captured_at)
    SELECT DISTINCT 'orders', captured_at FROM orders;
INSERT OR IGNORE INTO data_captures (data_area, captured_at)
    SELECT DISTINCT 'tax', captured_at FROM tax_carry_forward
    UNION
    SELECT DISTINCT 'tax', captured_at FROM tax_minus_by_year;
