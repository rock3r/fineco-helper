//! Per-DB HMAC hashing contract (M3). The store holds a per-database random HMAC
//! key (in store_meta) and hashes raw broker ids so the DB never stores the raw
//! transaction/position identifiers. Hashing is for stable joins, not the primary
//! confidentiality control (DB-at-rest encryption is — see the plan).

use fineco_store::{NewAsset, RawMovement, RawOrder, Store};

#[test]
fn hash_raw_order_hashes_the_trans_id_and_preserves_the_rest() {
    // The credential-holding worker has no DB key, so it returns a RawOrder with
    // the raw broker trans_id; the controller (which owns the DB/key) hashes it
    // into a NewOrder before capture. This proves that controller-side conversion:
    // the trans_id is HMAC'd exactly like `hash_id`, and every other field crosses
    // unchanged.
    let store = Store::open_in_memory().expect("open");
    let raw = RawOrder {
        trans_id: "SYNTH-TX-0001".to_string(),
        asset: NewAsset {
            instr_id: "A".to_string(),
            venue_system: "V".to_string(),
            symbol: Some("SYM".to_string()),
            description: Some("desc".to_string()),
            kind: Some("equity".to_string()),
            currency: Some("EUR".to_string()),
        },
        status: Some("filled".to_string()),
        sign: Some("B".to_string()),
        order_size: Some(10.0),
        size_filled: Some(10.0),
        avg_price: Some(1.5),
        submit_time: Some("2026-01-01T09:00:00Z".to_string()),
    };

    let order = store.hash_raw_order(&raw).expect("hash");

    assert_eq!(
        order.trans_id_hash,
        store.hash_id("SYNTH-TX-0001").expect("h")
    );
    // The raw id is not recoverable from the produced order.
    assert!(!order.trans_id_hash.contains("SYNTH-TX-0001"));
    assert_eq!(order.asset.instr_id, "A");
    assert_eq!(order.asset.venue_system, "V");
    assert_eq!(order.asset.symbol.as_deref(), Some("SYM"));
    assert_eq!(order.status.as_deref(), Some("filled"));
    assert_eq!(order.order_size, Some(10.0));
    assert_eq!(order.avg_price, Some(1.5));
    assert_eq!(order.submit_time.as_deref(), Some("2026-01-01T09:00:00Z"));
}

#[test]
fn hash_raw_movement_hashes_the_movement_id_and_preserves_the_rest() {
    // Same controller-side conversion contract as orders: the worker returns a
    // RawMovement with the raw `progressivoMovimento`; the controller HMAC's it
    // into a NewMovement before capture, leaving every other field unchanged.
    let store = Store::open_in_memory().expect("open");
    let raw = RawMovement {
        movement_id: "SYNTH-MOV-0001".to_string(),
        causale: Some("BONIFICO".to_string()),
        descrizione: Some("synthetic line".to_string()),
        importo: Some(-25.0),
        tipo_movimento: Some("MOVIMENTO_CONTO".to_string()),
        data_operazione: Some("2026-01-01".to_string()),
        data_registrazione: Some("2026-01-01".to_string()),
        data_valuta: Some("2026-01-02".to_string()),
        causale_movimento: Some("48".to_string()),
    };

    let movement = store.hash_raw_movement(&raw).expect("hash");

    assert_eq!(
        movement.movement_id_hash,
        store.hash_id("SYNTH-MOV-0001").expect("h")
    );
    // The raw id is not recoverable from the produced movement.
    assert!(!movement.movement_id_hash.contains("SYNTH-MOV-0001"));
    assert_eq!(movement.causale.as_deref(), Some("BONIFICO"));
    assert_eq!(movement.descrizione.as_deref(), Some("synthetic line"));
    assert_eq!(movement.importo, Some(-25.0));
    assert_eq!(movement.tipo_movimento.as_deref(), Some("MOVIMENTO_CONTO"));
    assert_eq!(movement.data_operazione.as_deref(), Some("2026-01-01"));
    assert_eq!(movement.data_registrazione.as_deref(), Some("2026-01-01"));
    assert_eq!(movement.data_valuta.as_deref(), Some("2026-01-02"));
    assert_eq!(movement.causale_movimento.as_deref(), Some("48"));
}

#[test]
fn hash_id_is_stable_and_hides_the_raw_id() {
    let store = Store::open_in_memory().expect("open");
    let h1 = store.hash_id("TX-12345").expect("hash");
    let h2 = store.hash_id("TX-12345").expect("hash");
    assert_eq!(h1, h2, "same input hashes the same within a DB");
    assert_eq!(h1.len(), 64, "SHA-256 hex");
    assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
    // Different input → different hash.
    assert_ne!(store.hash_id("TX-99999").expect("hash"), h1);
    // The raw id is not recoverable from the hash.
    assert!(!h1.contains("12345"));
}

#[test]
fn hash_id_differs_across_databases() {
    // Independent databases get independent random keys, so the same raw id
    // hashes differently (an attacker can't precompute hashes without the key).
    let a = Store::open_in_memory().expect("open a");
    let b = Store::open_in_memory().expect("open b");
    assert_ne!(
        a.hash_id("TX-1").expect("hash"),
        b.hash_id("TX-1").expect("hash")
    );
}
