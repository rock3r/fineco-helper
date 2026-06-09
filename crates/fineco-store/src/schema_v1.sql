-- fineco-store schema v1.
--
-- Tables and columns follow the design spec's "Storage" section. Column *types*,
-- primary keys, and foreign keys are implementation detail chosen here (the spec
-- lists columns,
-- not SQLite types): timestamps are ISO-8601 UTC TEXT; monetary values and
-- quantities are REAL. The plan shows some identifiers hashed
-- (position_key_hash, trans_id_hash): these columns store an opaque TEXT hash
-- supplied by the caller — the hashing strategy/key is decided at the capture
-- source (M3), not in the store.

CREATE TABLE job_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    auth_id         TEXT NOT NULL,
    data_area       TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    status          TEXT NOT NULL,
    safe_error_code TEXT
);

CREATE TABLE assets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    instr_id     TEXT NOT NULL,
    venue_system TEXT NOT NULL,
    symbol       TEXT,
    description  TEXT,
    type         TEXT,
    currency     TEXT,
    UNIQUE (instr_id, venue_system)
);

CREATE TABLE portfolio_snapshots (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at                TEXT NOT NULL,
    source                     TEXT NOT NULL,
    portfolio_market_value     REAL,
    portfolio_book_value       REAL,
    portfolio_profit_loss      REAL,
    portfolio_profit_loss_perc REAL
);

CREATE TABLE position_snapshots (
    snapshot_id       INTEGER NOT NULL REFERENCES portfolio_snapshots(id) ON DELETE CASCADE,
    asset_id          INTEGER NOT NULL REFERENCES assets(id),
    position_key_hash TEXT,
    qty               REAL,
    avg_price         REAL,
    market_price      REAL,
    book_value        REAL,
    market_value      REAL,
    profit_loss       REAL,
    profit_loss_perc  REAL,
    weight_perc       REAL,
    -- One position per (snapshot, instrument), matching the TS reference which
    -- keys holdings by instr_id.venue_system. Whether multiple lots of the same
    -- instrument (distinguished by position_key_hash) must be stored separately
    -- is part of the M3 hashing-strategy decision; making the nullable
    -- position_key_hash part of this key would be unsound today (NULLs compare
    -- distinct, defeating dedup). Revisit the key with that decision.
    PRIMARY KEY (snapshot_id, asset_id)
);

CREATE TABLE fx_rates (
    captured_at TEXT NOT NULL,
    currency    TEXT NOT NULL,
    rate_to_eur REAL NOT NULL,
    PRIMARY KEY (captured_at, currency)
);

CREATE TABLE orders (
    captured_at   TEXT NOT NULL,
    trans_id_hash TEXT NOT NULL,
    asset_id      INTEGER REFERENCES assets(id),
    status        TEXT,
    sign          TEXT,
    order_size    REAL,
    size_filled   REAL,
    avg_price     REAL,
    submit_time   TEXT,
    PRIMARY KEY (captured_at, trans_id_hash)
);

CREATE TABLE tax_carry_forward (
    captured_at TEXT NOT NULL,
    date_from   TEXT NOT NULL,
    date_to     TEXT NOT NULL,
    total       REAL,
    PRIMARY KEY (captured_at, date_from, date_to)
);

CREATE TABLE tax_minus_by_year (
    captured_at     TEXT NOT NULL,
    year            INTEGER NOT NULL,
    minus_residue   REAL,
    expiration_date TEXT,
    PRIMARY KEY (captured_at, year)
);
