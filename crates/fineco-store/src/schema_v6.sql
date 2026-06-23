-- Schema v6: per-capture bank-account summary for movements.
-- One row per movements capture, keyed by captured_at (the same timestamp used by
-- the movements rows and the data_captures marker). These are account-level fields
-- the movements endpoint returns at the response top level (not per movement):
-- balances and current-month spending totals. All nullable — a capture may omit them.

CREATE TABLE movements_summary (
    captured_at                   TEXT PRIMARY KEY,
    balance_at_movement           REAL,
    balance_at_search_date        REAL,
    current_month_credit_spending REAL,
    current_month_debit_spending  REAL
);
