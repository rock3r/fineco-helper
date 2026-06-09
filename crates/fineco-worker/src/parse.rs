//! Parse Fineco JSON responses into the store's `New*` types.
//!
//! The response structs mirror the real Fineco shapes (camelCase fields,
//! everything optional/defensive — a missing field is `None`, never a parse
//! failure). Mapping is pure and unit-testable; the only impurity is order-id
//! hashing, which is injected as a closure so this module never touches the
//! store or its HMAC key.

use fineco_store::{
    NewAsset, NewPortfolioSnapshot, NewPosition, NewTaxCarryForward, NewTaxMinusByYear, RawOrder,
};
use serde::Deserialize;

/// Provenance label stamped on snapshots fetched by this worker.
const SOURCE: &str = "fineco";

// ---- Portfolio (positions summary) -----------------------------------------

#[derive(Deserialize)]
pub(crate) struct PositionsSummaryResponse {
    #[serde(default)]
    summary: Option<SummarySection>,
    #[serde(default)]
    positions: Option<PositionsSection>,
}

#[derive(Deserialize)]
struct SummarySection {
    #[serde(default)]
    show: Option<Totals>,
    #[serde(default)]
    total: Option<Totals>,
}

#[derive(Deserialize)]
struct Totals {
    #[serde(rename = "bookValue", default)]
    book_value: Option<f64>,
    #[serde(rename = "marketValue", default)]
    market_value: Option<f64>,
    #[serde(rename = "profitLoss", default)]
    profit_loss: Option<f64>,
    #[serde(rename = "profitLossPerc", default)]
    profit_loss_perc: Option<f64>,
}

/// True if a `Totals` carries at least one value (i.e. is not an empty object).
fn totals_have_data(totals: &Totals) -> bool {
    totals.book_value.is_some()
        || totals.market_value.is_some()
        || totals.profit_loss.is_some()
        || totals.profit_loss_perc.is_some()
}

#[derive(Deserialize)]
struct PositionsSection {
    #[serde(default)]
    show: Vec<RawPosition>,
}

#[derive(Deserialize)]
struct RawPosition {
    #[serde(rename = "instrId", default)]
    instr_id: Option<String>,
    #[serde(rename = "venueSystem", default)]
    venue_system: Option<String>,
    #[serde(default)]
    symbol: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(rename = "currencyCd", default)]
    currency_cd: Option<String>,
    #[serde(default)]
    qty: Option<f64>,
    #[serde(rename = "avgPrice", default)]
    avg_price: Option<f64>,
    #[serde(rename = "marketPrice", default)]
    market_price: Option<f64>,
    #[serde(rename = "bookValue", default)]
    book_value: Option<f64>,
    #[serde(rename = "marketValue", default)]
    market_value: Option<f64>,
    #[serde(rename = "profitLoss", default)]
    profit_loss: Option<f64>,
    #[serde(rename = "profitLossPerc", default)]
    profit_loss_perc: Option<f64>,
}

/// Map a positions-summary response to a snapshot stamped with `captured_at`.
/// Totals come from `summary.show`, falling back to `summary.total`.
pub(crate) fn to_snapshot(
    resp: PositionsSummaryResponse,
    captured_at: &str,
) -> NewPortfolioSnapshot {
    // Prefer `summary.show`, but only when it actually carries data — an empty
    // `show` object (present but all-null) must still fall back to `summary.total`
    // rather than blanking the headline values and derived weights.
    let totals = resp.summary.and_then(|s| match s.show {
        Some(show) if totals_have_data(&show) => Some(show),
        _ => s.total,
    });
    let (market_value, book_value, profit_loss, profit_loss_perc) = match totals {
        Some(t) => (
            t.market_value,
            t.book_value,
            t.profit_loss,
            t.profit_loss_perc,
        ),
        None => (None, None, None, None),
    };

    let mut positions: Vec<NewPosition> = resp
        .positions
        .map(|p| p.show)
        .unwrap_or_default()
        .into_iter()
        .filter_map(to_position)
        .collect();

    // Derive each position's allocation weight from the portfolio total (as the
    // TS reference does for shareable reports / weight ordering): a position's
    // market value as a percentage of total market value.
    if let Some(total_market_value) = market_value
        && total_market_value > 0.0
    {
        for position in &mut positions {
            if let Some(value) = position.market_value {
                position.weight_perc = Some(value / total_market_value * 100.0);
            }
        }
    }

    NewPortfolioSnapshot {
        captured_at: captured_at.to_string(),
        source: SOURCE.to_string(),
        market_value,
        book_value,
        profit_loss,
        profit_loss_perc,
        positions,
        fx_rates: Vec::new(),
    }
}

/// A position with no instrument identity can't be keyed, so it is skipped.
fn to_position(raw: RawPosition) -> Option<NewPosition> {
    let (Some(instr_id), Some(venue_system)) = (raw.instr_id, raw.venue_system) else {
        return None;
    };
    if instr_id.is_empty() || venue_system.is_empty() {
        return None;
    }
    Some(NewPosition {
        asset: NewAsset {
            instr_id,
            venue_system,
            symbol: raw.symbol,
            description: raw.description,
            kind: raw.kind,
            currency: raw.currency_cd,
        },
        // Positions are identified by their unhashed asset key; the hashed
        // position key is reserved for a later multi-lot revisit.
        position_key_hash: None,
        qty: raw.qty,
        avg_price: raw.avg_price,
        market_price: raw.market_price,
        book_value: raw.book_value,
        market_value: raw.market_value,
        profit_loss: raw.profit_loss,
        profit_loss_perc: raw.profit_loss_perc,
        weight_perc: None,
    })
}

// ---- Orders (transactions) -------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct TransactionsResponse {
    #[serde(default)]
    transactions: Vec<RawTransaction>,
}

#[derive(Deserialize)]
struct RawTransaction {
    #[serde(rename = "transId", default)]
    trans_id: Option<String>,
    #[serde(rename = "instrId", default)]
    instr_id: Option<String>,
    #[serde(rename = "venueSystem", default)]
    venue_system: Option<String>,
    #[serde(default)]
    symbol: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(rename = "currencyCd", default)]
    currency_cd: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    sign: Option<String>,
    #[serde(rename = "orderSize", default)]
    order_size: Option<f64>,
    #[serde(rename = "sizeFilled", default)]
    size_filled: Option<f64>,
    #[serde(rename = "avgPrice", default)]
    avg_price: Option<f64>,
    #[serde(rename = "submitTime", default)]
    submit_time: Option<String>,
}

/// Map a transactions response to **un-hashed** [`RawOrder`]s (raw broker
/// `trans_id`). The credential-holding worker holds no DB key, so hashing happens
/// controller-side via [`fineco_store::Store::hash_raw_order`] after these cross
/// the fineco-live socket. Transactions lacking an id or an instrument identity
/// are skipped (they can't be deduplicated).
pub(crate) fn to_raw_orders(resp: TransactionsResponse) -> Vec<RawOrder> {
    let mut orders = Vec::new();
    for raw in resp.transactions {
        let (Some(trans_id), Some(instr_id), Some(venue_system)) =
            (raw.trans_id, raw.instr_id, raw.venue_system)
        else {
            continue;
        };
        if trans_id.is_empty() || instr_id.is_empty() || venue_system.is_empty() {
            continue;
        }
        orders.push(RawOrder {
            trans_id,
            asset: NewAsset {
                instr_id,
                venue_system,
                symbol: raw.symbol,
                description: raw.description,
                kind: raw.kind,
                currency: raw.currency_cd,
            },
            status: raw.status,
            sign: raw.sign,
            order_size: raw.order_size,
            size_filled: raw.size_filled,
            avg_price: raw.avg_price,
            submit_time: raw.submit_time,
        });
    }
    orders
}

// ---- Tax -------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct TaxCarryForwardResponse {
    #[serde(default)]
    total: Option<f64>,
}

/// Map a tax carry-forward search response to a store-ready row. The requested
/// `date_from`/`date_to` define the period (echoed back, not parsed from JSON).
pub(crate) fn to_tax_carry_forward(
    resp: TaxCarryForwardResponse,
    date_from: &str,
    date_to: &str,
) -> NewTaxCarryForward {
    NewTaxCarryForward {
        date_from: date_from.to_string(),
        date_to: date_to.to_string(),
        total: resp.total,
    }
}

#[derive(Deserialize)]
pub(crate) struct TaxMinusResponse {
    #[serde(default)]
    list: Vec<RawMinus>,
}

#[derive(Deserialize)]
struct RawMinus {
    #[serde(default)]
    year: Option<i64>,
    #[serde(rename = "minusResidue", default)]
    minus_residue: Option<f64>,
    #[serde(rename = "expirationDate", default)]
    expiration_date: Option<String>,
}

/// Map a tax minus-by-year response to store-ready rows. Entries without a year
/// (the row key) are skipped.
pub(crate) fn to_tax_minus(resp: TaxMinusResponse) -> Vec<NewTaxMinusByYear> {
    resp.list
        .into_iter()
        .filter_map(|raw| {
            let year = raw.year?;
            Some(NewTaxMinusByYear {
                year,
                minus_residue: raw.minus_residue,
                expiration_date: raw.expiration_date,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_show_falls_back_to_total() {
        // `summary.show` is present but empty; `summary.total` carries the data.
        let json = r#"{
            "summary": { "show": {}, "total": { "marketValue": 1750.0, "bookValue": 1500.0 } },
            "positions": { "show": [
                { "instrId": "A", "venueSystem": "V", "marketValue": 1750.0 }
            ] }
        }"#;
        let resp: PositionsSummaryResponse = serde_json::from_str(json).expect("parse");
        let snapshot = to_snapshot(resp, "2026-06-03T12:00:00Z");

        // Headline values come from `total`, not the empty `show`.
        assert_eq!(snapshot.market_value, Some(1750.0));
        assert_eq!(snapshot.book_value, Some(1500.0));
        // ...and weights derive from those totals (1750 / 1750 * 100).
        assert_eq!(snapshot.positions.len(), 1);
        assert_eq!(snapshot.positions[0].weight_perc, Some(100.0));
    }
}
