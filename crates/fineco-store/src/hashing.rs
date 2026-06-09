//! Per-database HMAC-SHA256 hashing of broker ids. The key is the random
//! `hmac_key` row created in `store_meta` (schema v3); it stays inside the DB.
//! Used so the store keeps opaque hashes (`position_key_hash`, `trans_id_hash`)
//! instead of raw broker identifiers. Hashing gives stable joins, not the primary
//! confidentiality control (DB-at-rest encryption is — see the plan).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::{NewOrder, RawOrder, Result, Store};

type HmacSha256 = Hmac<Sha256>;

impl Store {
    /// Convert a [`RawOrder`] (carrying the raw broker `trans_id`) into a
    /// store-ready [`NewOrder`] by HMAC-hashing its `trans_id` with this
    /// database's key. This is the controller-side hashing step: the
    /// credential-holding worker returns `RawOrder`s and never touches the key.
    /// Every other field crosses unchanged.
    ///
    /// # Errors
    /// Returns an error if the per-DB key cannot be read.
    pub fn hash_raw_order(&self, raw: &RawOrder) -> Result<NewOrder> {
        Ok(NewOrder {
            trans_id_hash: self.hash_id(&raw.trans_id)?,
            asset: raw.asset.clone(),
            status: raw.status.clone(),
            sign: raw.sign.clone(),
            order_size: raw.order_size,
            size_filled: raw.size_filled,
            avg_price: raw.avg_price,
            submit_time: raw.submit_time.clone(),
        })
    }

    /// HMAC-SHA256 of `raw` with this database's key, hex-encoded (64 chars).
    /// Stable within a database; different across databases. The raw id is not
    /// recoverable from the result.
    ///
    /// # Errors
    /// Returns an error if the per-DB key cannot be read.
    pub fn hash_id(&self, raw: &str) -> Result<String> {
        let key: Vec<u8> = self.conn.query_row(
            "SELECT meta_value FROM store_meta WHERE meta_key = 'hmac_key'",
            [],
            |r| r.get(0),
        )?;
        // HMAC accepts a key of any length, so this construction never fails.
        let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
        mac.update(raw.as_bytes());
        Ok(hex_encode(mac.finalize().into_bytes().as_ref()))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(out, "{b:02x}");
    }
    out
}
