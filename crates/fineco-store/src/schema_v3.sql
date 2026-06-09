-- fineco-store schema v3 (M3).
--
-- Per-database metadata, including the random HMAC key used to hash broker
-- transaction/position ids (so the DB never stores raw identifiers). The key is
-- generated once here via SQLite's randomblob(), seeded from the OS, and stays
-- inside the database. Hashing provides stable joins, not the primary
-- confidentiality control — DB-at-rest encryption is (see the plan).

CREATE TABLE store_meta (
    meta_key   TEXT PRIMARY KEY,
    meta_value BLOB NOT NULL
);

INSERT INTO store_meta (meta_key, meta_value) VALUES ('hmac_key', randomblob(32));
