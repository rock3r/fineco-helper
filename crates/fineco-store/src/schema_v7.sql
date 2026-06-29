-- Schema v7: MoneyMap category taxonomy cache.
-- Resolves the raw `categoria_id`/`sottocategoria_id` on `movements` to names.
-- A time-series of captures, keyed by (captured_at, category_id, subcategory_id).
-- A category-level row uses '' as the `subcategory_id` sentinel (NOT NULL, so the
-- key stays well-defined); a subcategory row carries its parent in `category_id`.
-- Subcategory ids are unique only WITHIN a parent category, hence the composite key.
-- Names are sanitized plain text (the join key for movements; never hashed — they
-- must match the unhashed ids stored on movements, and carry no amounts).

CREATE TABLE moneymap_categories (
    captured_at        TEXT NOT NULL,
    category_id        TEXT NOT NULL,
    subcategory_id     TEXT NOT NULL,
    name               TEXT,
    flag_spesa_ricavo  TEXT,
    PRIMARY KEY (captured_at, category_id, subcategory_id)
);
