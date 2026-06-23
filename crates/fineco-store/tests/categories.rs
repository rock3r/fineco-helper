//! MoneyMap category taxonomy capture + lookup contract (non-credentialed store
//! layer). The Fineco fetch that produces this is the credentialed worker
//! (piggybacked on the movements refresh); this is the store side, tested with
//! synthetic data. Category names are NOT hashed — they are the join key for the
//! raw `categoria_id`/`sottocategoria_id` stored on movements.

use fineco_store::{MoneyMapCategory, Store};

fn category(id: &str, name: &str, flag: &str) -> MoneyMapCategory {
    MoneyMapCategory {
        category_id: id.to_string(),
        subcategory_id: None,
        name: Some(name.to_string()),
        flag_spesa_ricavo: Some(flag.to_string()),
    }
}

fn subcategory(category_id: &str, sub_id: &str, name: &str) -> MoneyMapCategory {
    MoneyMapCategory {
        category_id: category_id.to_string(),
        subcategory_id: Some(sub_id.to_string()),
        name: Some(name.to_string()),
        flag_spesa_ricavo: None,
    }
}

#[test]
fn capture_and_resolve_names() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_categories(
            "2026-01-01T10:00:00Z",
            &[
                category("12", "Shopping", "S"),
                subcategory("12", "34", "Clothes"),
                category("99", "Income", "R"),
            ],
        )
        .expect("capture");

    let lookup = store.latest_categories().expect("lookup");
    assert_eq!(lookup.category_name("12"), Some("Shopping"));
    assert_eq!(lookup.category_name("99"), Some("Income"));
    assert_eq!(lookup.subcategory_name("12", "34"), Some("Clothes"));
    // Unknown ids resolve to nothing (the raw id still surfaces on the movement).
    assert_eq!(lookup.category_name("404"), None);
    assert_eq!(lookup.subcategory_name("12", "404"), None);
}

#[test]
fn subcategory_lookup_does_not_match_the_category_row() {
    // A category-level row is stored with an empty-string subcategory sentinel.
    // A movement with an empty `sottocategoria_id` must not false-match it.
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_categories("2026-01-01T10:00:00Z", &[category("12", "Shopping", "S")])
        .expect("capture");
    let lookup = store.latest_categories().expect("lookup");
    assert_eq!(lookup.subcategory_name("12", ""), None);
}

#[test]
fn latest_categories_returns_only_the_most_recent_capture() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_categories("2026-01-01T10:00:00Z", &[category("12", "Old name", "S")])
        .expect("c1");
    store
        .capture_categories("2026-01-02T10:00:00Z", &[category("12", "New name", "S")])
        .expect("c2");
    let lookup = store.latest_categories().expect("lookup");
    assert_eq!(lookup.category_name("12"), Some("New name"));
}

#[test]
fn empty_capture_supersedes_previous_taxonomy() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_categories("2026-01-01T10:00:00Z", &[category("12", "Shopping", "S")])
        .expect("c1");
    // A later, empty taxonomy capture must clear the resolved names.
    store
        .capture_categories("2026-01-02T10:00:00Z", &[])
        .expect("empty c2");
    let lookup = store.latest_categories().expect("lookup");
    assert_eq!(lookup.category_name("12"), None);
}

#[test]
fn rows_without_a_name_do_not_resolve() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_categories(
            "2026-01-01T10:00:00Z",
            &[MoneyMapCategory {
                category_id: "12".to_string(),
                subcategory_id: None,
                name: None,
                flag_spesa_ricavo: None,
            }],
        )
        .expect("capture");
    let lookup = store.latest_categories().expect("lookup");
    assert_eq!(lookup.category_name("12"), None);
}
