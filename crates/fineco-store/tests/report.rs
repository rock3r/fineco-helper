//! Report generation contract, including the shareable-leakage guard. M1
//! red→green. The shareable report must carry only names/symbols/ISINs,
//! weights, and percentage performance — never absolute values, quantities,
//! prices, or hashes (plan "Shareable Contract").

use fineco_store::{NewAsset, NewPortfolioSnapshot, NewPosition, Store, shareable_rows_to_csv};

/// A snapshot whose absolute fields use distinctive 5-digit numbers and a
/// distinctive hash, so a leak is unambiguous if any appears in shareable output.
fn distinctive_snapshot() -> NewPortfolioSnapshot {
    NewPortfolioSnapshot {
        captured_at: "2026-01-01T00:00:00Z".to_string(),
        source: "test".to_string(),
        market_value: Some(99999.0),
        book_value: Some(88888.0),
        profit_loss: Some(11111.0),
        profit_loss_perc: Some(12.5),
        positions: vec![NewPosition {
            asset: NewAsset {
                instr_id: "ISIN000111".to_string(),
                venue_system: "MOT".to_string(),
                symbol: Some("ABC".to_string()),
                description: Some("Alpha Corp".to_string()),
                kind: Some("STOCK".to_string()),
                currency: Some("EUR".to_string()),
            },
            position_key_hash: Some("secrethash".to_string()),
            qty: Some(12345.0),
            avg_price: Some(54321.0),
            market_price: Some(67890.0),
            book_value: Some(88888.0),
            market_value: Some(99999.0),
            profit_loss: Some(11111.0),
            profit_loss_perc: Some(23.0),
            weight_perc: Some(100.0),
        }],
        fx_rates: vec![],
    }
}

const FORBIDDEN: &[&str] = &[
    "12345",
    "54321",
    "67890",
    "99999",
    "88888",
    "11111",
    "secrethash",
];

#[test]
fn shareable_csv_header_is_exactly_the_allowed_columns() {
    let mut store = Store::open_in_memory().expect("open");
    let id = store
        .capture_portfolio_snapshot(&distinctive_snapshot())
        .expect("capture");
    let csv = shareable_rows_to_csv(&store.shareable_report_rows(id).expect("rows"));
    let header = csv.lines().next().expect("header");
    assert_eq!(
        header,
        "description,symbol,instrId,venueSystem,type,currencyCd,weightPerc,profitLossPerc"
    );
}

#[test]
fn shareable_csv_omits_absolute_values_and_secrets() {
    let mut store = Store::open_in_memory().expect("open");
    let id = store
        .capture_portfolio_snapshot(&distinctive_snapshot())
        .expect("capture");
    let csv = shareable_rows_to_csv(&store.shareable_report_rows(id).expect("rows"));

    for forbidden in FORBIDDEN {
        assert!(
            !csv.contains(forbidden),
            "shareable CSV leaked {forbidden:?}:\n{csv}"
        );
    }
    // Allowed content is present.
    assert!(csv.contains("Alpha Corp"));
    assert!(csv.contains("ISIN000111"));
    assert!(csv.contains("23")); // profitLossPerc
    assert!(csv.contains("100")); // weightPerc
}

#[test]
fn shareable_csv_neutralizes_formula_injection() {
    let mut store = Store::open_in_memory().expect("open");
    let mut snap = distinctive_snapshot();
    // A spreadsheet-formula payload in an identity text field must be neutralized
    // so a CSV opened in a spreadsheet cannot execute it.
    snap.positions[0].asset.description = Some("=HYPERLINK(\"http://evil\")".to_string());
    let id = store.capture_portfolio_snapshot(&snap).expect("capture");
    let csv = shareable_rows_to_csv(&store.shareable_report_rows(id).expect("rows"));

    assert!(
        csv.contains("'=HYPERLINK"),
        "formula not neutralized:\n{csv}"
    );
    // The raw, un-neutralized leading '=' (quote-then-equals) must not survive.
    assert!(
        !csv.contains("\"=HYPERLINK"),
        "formula reached output un-neutralized:\n{csv}"
    );
}

#[test]
fn shareable_csv_neutralizes_leading_whitespace_formula() {
    let mut store = Store::open_in_memory().expect("open");
    let mut snap = distinctive_snapshot();
    // Leading newline (then a formula char) must still be neutralized — a parser
    // may strip the newline and then evaluate the formula.
    snap.positions[0].asset.description = Some("\n=cmd()".to_string());
    let id = store.capture_portfolio_snapshot(&snap).expect("capture");
    let csv = shareable_rows_to_csv(&store.shareable_report_rows(id).expect("rows"));
    assert!(
        csv.contains("'\n=cmd"),
        "leading-newline formula not neutralized:\n{csv:?}"
    );
}

#[test]
fn full_report_header_has_no_embedded_spaces() {
    let mut store = Store::open_in_memory().expect("open");
    let id = store
        .capture_portfolio_snapshot(&distinctive_snapshot())
        .expect("capture");
    let csv = store.full_report_csv(id).expect("full csv");
    let header = csv.lines().next().expect("header");
    assert_eq!(
        header,
        "instrId,venueSystem,symbol,qty,avgPrice,marketPrice,bookValue,marketValue,\
         profitLoss,profitLossPerc,weightPerc,positionKeyHash"
            .replace(' ', "")
    );
    assert!(
        !header.contains(' '),
        "full header has an embedded space: {header:?}"
    );
}

#[test]
fn full_report_csv_includes_absolute_values() {
    let mut store = Store::open_in_memory().expect("open");
    let id = store
        .capture_portfolio_snapshot(&distinctive_snapshot())
        .expect("capture");
    let csv = store.full_report_csv(id).expect("full csv");
    // The full (owner-only) report intentionally carries the absolutes.
    assert!(
        csv.contains("99999"),
        "full report should include market value"
    );
    assert!(csv.contains("12345"), "full report should include quantity");
}
