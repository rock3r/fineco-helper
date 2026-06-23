-- Schema v5: bank account movements table.
-- Keyed by (captured_at, movement_id_hash) — a time-series of captures.
-- movement_id_hash is the HMAC-SHA256 of progressivoMovimento (hashed by the
-- controller; the worker returns the raw id and never touches the DB key).

CREATE TABLE movements (
    captured_at         TEXT NOT NULL,
    movement_id_hash    TEXT NOT NULL,
    causale             TEXT,
    descrizione         TEXT,
    descrizione_breve   TEXT,
    importo             REAL,
    tipo_movimento      TEXT,
    data_operazione     TEXT,
    data_registrazione  TEXT,
    data_valuta         TEXT,
    causale_movimento   TEXT,
    categoria_id        TEXT,
    sottocategoria_id   TEXT,
    PRIMARY KEY (captured_at, movement_id_hash)
);
