//! MoneyMap category taxonomy capture + lookup. The taxonomy resolves the raw
//! `categoria_id`/`sottocategoria_id` ids stored on `movements` to human-readable
//! names. It is captured (best-effort) alongside each movements refresh; the read
//! path joins names in at query time.
//!
//! Names are **not hashed**: they are the join key for the unhashed ids already on
//! movements, and they are a generic taxonomy (sanitized text, no amounts/PII).

use std::collections::HashMap;

use rusqlite::params;

use crate::{Result, Store};

/// A single MoneyMap taxonomy entry to capture. A category-level entry has
/// `subcategory_id == None`; a subcategory entry carries its parent in
/// `category_id` and its own id in `subcategory_id`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MoneyMapCategory {
    pub category_id: String,
    pub subcategory_id: Option<String>,
    pub name: Option<String>,
    pub flag_spesa_ricavo: Option<String>,
}

/// Resolved name lookups from the latest taxonomy capture. Only entries with a
/// non-empty id and a name are indexed (an unresolved id yields `None`, leaving
/// the raw id to surface on the movement).
#[derive(Debug, Default, Clone)]
pub struct CategoryLookup {
    categories: HashMap<String, String>,
    subcategories: HashMap<(String, String), String>,
}

impl CategoryLookup {
    /// The name for a category id, if known.
    #[must_use]
    pub fn category_name(&self, category_id: &str) -> Option<&str> {
        self.categories.get(category_id).map(String::as_str)
    }

    /// The name for a subcategory, scoped to its parent category id (subcategory
    /// ids are unique only within a parent). An empty `subcategory_id` never
    /// matches (the category-level sentinel row is not a subcategory).
    #[must_use]
    pub fn subcategory_name(&self, category_id: &str, subcategory_id: &str) -> Option<&str> {
        if subcategory_id.is_empty() {
            return None;
        }
        self.subcategories
            .get(&(category_id.to_string(), subcategory_id.to_string()))
            .map(String::as_str)
    }
}

impl Store {
    /// Capture the MoneyMap taxonomy at `captured_at`. Atomic: inserts all rows
    /// then stamps the capture marker, even when the list is empty (so a later
    /// empty capture supersedes a previous taxonomy). The category-level row uses
    /// `''` as the subcategory sentinel.
    ///
    /// # Errors
    /// Returns an error if any insert fails.
    pub fn capture_categories(
        &mut self,
        captured_at: &str,
        categories: &[MoneyMapCategory],
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        for c in categories {
            let subcategory_id = c.subcategory_id.as_deref().unwrap_or("");
            tx.execute(
                "INSERT OR REPLACE INTO moneymap_categories \
                   (captured_at, category_id, subcategory_id, name, flag_spesa_ricavo) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    captured_at,
                    c.category_id,
                    subcategory_id,
                    c.name,
                    c.flag_spesa_ricavo,
                ],
            )?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO data_captures (data_area, captured_at) \
             VALUES ('moneymap_categories', ?1)",
            params![captured_at],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Build name lookups from the most recent taxonomy capture. Rows without a
    /// name are skipped (they cannot resolve to anything). Category rows (empty
    /// `subcategory_id`) index the category map; subcategory rows index the
    /// `(category_id, subcategory_id)` map.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn latest_categories(&self) -> Result<CategoryLookup> {
        let mut stmt = self.conn.prepare(
            "SELECT category_id, subcategory_id, name \
             FROM moneymap_categories \
             WHERE captured_at = \
                   (SELECT MAX(captured_at) FROM data_captures \
                    WHERE data_area = 'moneymap_categories')",
        )?;
        let mut lookup = CategoryLookup::default();
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        for row in rows {
            let (category_id, subcategory_id, name) = row?;
            let Some(name) = name else { continue };
            if name.trim().is_empty() {
                continue;
            }
            if subcategory_id.is_empty() {
                lookup.categories.insert(category_id, name);
            } else {
                lookup
                    .subcategories
                    .insert((category_id, subcategory_id), name);
            }
        }
        Ok(lookup)
    }
}
