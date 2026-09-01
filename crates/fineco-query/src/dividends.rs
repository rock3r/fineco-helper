//! Dividend pairing over captured movements.
//!
//! Fineco posts a dividend as two separate account movements: the gross credit
//! and, usually the same day, the withholding debit. Each carries a
//! `causaleMovimento` code — `DII` gross, `DIR` Italian withholding, `DER`
//! foreign withholding, and the `DPR`/`RPR` pair for the remunerated portfolio —
//! and a description whose prefix is followed by the security label. Read one
//! movement at a time they say little; paired they are the income figure.
//!
//! This is pure post-processing over rows already in the store: no request
//! reaches Fineco, and no new capture is needed.

use std::collections::BTreeMap;

use fineco_store::MovementRow;

/// What a leg contributes to its event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Leg {
    Gross,
    Withholding,
}

/// The kind of payment a pair of legs describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DividendKind {
    /// An ordinary dividend on a held instrument (`DII` + `DIR`/`DER`).
    Dividend,
    /// Interest on the remunerated portfolio (`DPR` + `RPR`).
    RemuneratedPortfolio,
}

impl DividendKind {
    /// The wire spelling, matching the `snake_case` used across the DTOs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dividend => "dividend",
            Self::RemuneratedPortfolio => "remunerated_portfolio",
        }
    }
}

/// The leg an event is missing, when it is missing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnpairedLeg {
    /// A withholding with no gross: income is understated.
    Gross,
    /// A gross with no withholding: either an instrument that carries none, or a
    /// window that clipped the second leg. Nothing here can tell those apart.
    Withholding,
}

impl UnpairedLeg {
    /// The wire spelling. Names the leg that is MISSING, not the one present.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gross => "gross",
            Self::Withholding => "withholding",
        }
    }
}

/// A dividend event: one security, one operation date, both legs when both were
/// captured. Amounts are integer cents while they are summed, so a long run of
/// legs cannot drift the way repeated float addition would.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DividendEvent {
    pub pay_date: Option<String>,
    pub security: Option<String>,
    pub kind: DividendKind,
    pub gross_cents: Option<i64>,
    pub withholding_cents: Option<i64>,
    pub net_cents: Option<i64>,
    pub unpaired: Option<UnpairedLeg>,
}

/// The `causaleMovimento` codes that make up a dividend, and the description
/// prefix that precedes the security label on each.
const LEGS: &[(&str, Leg, DividendKind, &str)] = &[
    ("DII", Leg::Gross, DividendKind::Dividend, "Div.su "),
    (
        "DIR",
        Leg::Withholding,
        DividendKind::Dividend,
        "Rit.div.su ",
    ),
    // Foreign withholding arrives under its own code and the same prefix.
    (
        "DER",
        Leg::Withholding,
        DividendKind::Dividend,
        "Rit.div.su ",
    ),
    (
        "DPR",
        Leg::Gross,
        DividendKind::RemuneratedPortfolio,
        "Acc.div.Port.Rem. ",
    ),
    (
        "RPR",
        Leg::Withholding,
        DividendKind::RemuneratedPortfolio,
        "Add.rit.Port.Rem. ",
    ),
];

/// The security label carried after a known prefix, or `None`.
///
/// Never falls back to the whole description: that would drop every prefix-less
/// row into one bucket and merge unrelated securities. A description that is
/// nothing but the prefix yields `None` for the same reason — a blank label is
/// not a label, and two blank ones are not the same security.
fn security_label(description: Option<&str>, prefix: &str) -> Option<String> {
    let trimmed = description?.trim();
    // Case-insensitive: a casing change in the bank's descriptions would
    // otherwise silently demote every row to an unlabelled one, with nothing in
    // the output to say the labels had stopped resolving.
    if !trimmed.to_lowercase().starts_with(&prefix.to_lowercase()) {
        return None;
    }
    let label = trimmed[prefix.len()..].trim();
    if label.is_empty() {
        None
    } else {
        Some(label.to_string())
    }
}

/// Euros to cents. `None` in, `None` out: a leg the capture stored without an
/// amount leaves its side of the event absent rather than counted as zero, which
/// would post a dividend that reads as real and is worth nothing.
fn to_cents(amount: Option<f64>) -> Option<i64> {
    let amount = amount?;
    if !amount.is_finite() {
        return None;
    }
    // Float intermediate, safe at these magnitudes: 0.29 * 100.0 is
    // 28.999999999999996, which rounds to the right cent.
    let cents = (amount * 100.0).round();
    if cents.abs() > 9_007_199_254_740_991.0 {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded above; the value is a rounded, in-range integer"
    )]
    Some(cents as i64)
}

/// Accumulator for one event while its legs are being read.
#[derive(Debug, Default)]
struct Group {
    pay_date: Option<String>,
    security: Option<String>,
    gross_cents: Option<i64>,
    withholding_cents: Option<i64>,
    saw_gross: bool,
    saw_withholding: bool,
    /// A leg arrived with no readable amount, so that side cannot be totalled.
    gross_unreadable: bool,
    withholding_unreadable: bool,
}

/// Pair the dividend legs among `rows` into one event per security and date.
///
/// Rows that carry no dividend code are ignored. Events are returned sorted by
/// date, then kind, then security, so the output is stable across calls.
#[must_use]
pub fn pair_dividends(rows: &[MovementRow]) -> Vec<DividendEvent> {
    let mut groups: BTreeMap<(String, DividendKind, String), Group> = BTreeMap::new();

    for row in rows {
        let code = row.causale_movimento.as_deref().unwrap_or_default();
        let Some(&(_, leg, kind, prefix)) = LEGS.iter().find(|(c, ..)| *c == code) else {
            continue;
        };

        let label = security_label(row.descrizione.as_deref(), prefix);
        // The key only has to be unique and stable. An unlabelled leg falls back
        // to its own row id, which is unique by construction, so two unrelated
        // unlabelled rows never merge into one event.
        let key = label
            .clone()
            .unwrap_or_else(|| row.movement_id_hash.clone());
        let date = row.data_operazione.clone().unwrap_or_default();
        let group = groups.entry((date, kind, key)).or_default();

        if group.pay_date.is_none() {
            group.pay_date.clone_from(&row.data_operazione);
        }
        if group.security.is_none() {
            group.security.clone_from(&label);
        }

        let cents = to_cents(row.importo);
        match leg {
            Leg::Gross => {
                group.saw_gross = true;
                match cents {
                    // Signed on purpose: a reversal posts negative and stays negative.
                    Some(value) => {
                        group.gross_cents = Some(group.gross_cents.unwrap_or(0) + value);
                    }
                    None => group.gross_unreadable = true,
                }
            }
            Leg::Withholding => {
                group.saw_withholding = true;
                match cents {
                    // Negated, not made absolute: an ordinary withholding is a debit
                    // and becomes a positive charge, while a refund stays negative
                    // instead of flipping into one.
                    Some(value) => {
                        group.withholding_cents =
                            Some(group.withholding_cents.unwrap_or(0) - value);
                    }
                    None => group.withholding_unreadable = true,
                }
            }
        }
    }

    groups
        .into_iter()
        .map(|((_, kind, _), group)| {
            let gross = if group.gross_unreadable {
                None
            } else {
                group.gross_cents
            };
            let withholding = if group.withholding_unreadable {
                None
            } else {
                group.withholding_cents
            };
            // Net needs both sides. A missing withholding leg contributes zero —
            // the event is marked unpaired instead, so the reader can tell an
            // instrument that withholds nothing from one whose second leg fell
            // outside the captured window.
            let net = match (gross, group.saw_withholding) {
                (Some(gross), false) => Some(gross),
                (Some(gross), true) => withholding.map(|withholding| gross - withholding),
                (None, _) => None,
            };
            DividendEvent {
                pay_date: group.pay_date,
                security: group.security,
                kind,
                gross_cents: gross,
                withholding_cents: withholding,
                net_cents: net,
                // Both flags matter. An orphan withholding without its gross
                // understates income; an orphan gross is either an instrument with
                // no withholding or a clipped window, and nothing here can tell
                // those apart.
                unpaired: match (group.saw_gross, group.saw_withholding) {
                    (true, true) => None,
                    (true, false) => Some(UnpairedLeg::Withholding),
                    _ => Some(UnpairedLeg::Gross),
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{DividendKind, UnpairedLeg, pair_dividends};
    use fineco_store::MovementRow;

    /// A movement row carrying only the fields the pairing reads.
    fn row(
        id: &str,
        code: &str,
        date: &str,
        description: &str,
        amount: Option<f64>,
    ) -> MovementRow {
        MovementRow {
            captured_at: "2026-06-03T12:00:00Z".to_string(),
            movement_id_hash: id.to_string(),
            causale: None,
            descrizione: Some(description.to_string()),
            descrizione_breve: None,
            importo: amount,
            tipo_movimento: Some("MOVIMENTO_CONTO".to_string()),
            data_operazione: Some(date.to_string()),
            data_registrazione: None,
            data_valuta: None,
            causale_movimento: Some(code.to_string()),
            categoria_id: None,
            sottocategoria_id: None,
        }
    }

    #[test]
    fn pairs_a_gross_dividend_with_its_withholding() {
        // Amounts with real cents, not round numbers: they are what exercises the
        // rounding, where a float would drift.
        let events = pair_dividends(&[
            row(
                "a",
                "DII",
                "2026-02-10",
                "Div.su 100 EXAMPLE SPA",
                Some(147.73),
            ),
            row(
                "b",
                "DIR",
                "2026-02-10",
                "Rit.div.su 100 EXAMPLE SPA",
                Some(-38.41),
            ),
        ]);

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.security.as_deref(), Some("100 EXAMPLE SPA"));
        assert_eq!(event.kind, DividendKind::Dividend);
        assert_eq!(event.gross_cents, Some(14773));
        assert_eq!(event.withholding_cents, Some(3841));
        assert_eq!(event.net_cents, Some(10932));
        assert_eq!(event.unpaired, None);
    }

    #[test]
    fn pairs_a_foreign_withholding_which_arrives_under_der() {
        let events = pair_dividends(&[
            row("a", "DII", "2026-03-05", "Div.su 4 EXAMPLE CORP", Some(1.0)),
            row(
                "b",
                "DER",
                "2026-03-05",
                "Rit.div.su 4 EXAMPLE CORP",
                Some(-0.15),
            ),
        ]);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].gross_cents, Some(100));
        assert_eq!(events[0].withholding_cents, Some(15));
        assert_eq!(events[0].net_cents, Some(85));
    }

    #[test]
    fn pairs_the_remunerated_portfolio_codes() {
        let events = pair_dividends(&[
            row(
                "a",
                "DPR",
                "2026-04-01",
                "Acc.div.Port.Rem. EXAMPLE",
                Some(12.0),
            ),
            row(
                "b",
                "RPR",
                "2026-04-01",
                "Add.rit.Port.Rem. EXAMPLE",
                Some(-3.12),
            ),
        ]);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, DividendKind::RemuneratedPortfolio);
        assert_eq!(events[0].net_cents, Some(888));
    }

    #[test]
    fn keeps_a_reversal_negative_instead_of_counting_it_as_income() {
        // A cancelled dividend posts a negative gross. Made absolute it would read
        // as income twice over.
        let events = pair_dividends(&[row(
            "a",
            "DII",
            "2026-02-10",
            "Div.su 100 EXAMPLE SPA",
            Some(-147.73),
        )]);

        assert_eq!(events[0].gross_cents, Some(-14773));
        assert_eq!(events[0].net_cents, Some(-14773));
    }

    #[test]
    fn keeps_a_withholding_refund_negative_instead_of_counting_it_as_tax() {
        let events = pair_dividends(&[
            row(
                "a",
                "DII",
                "2026-02-10",
                "Div.su 100 EXAMPLE SPA",
                Some(10.0),
            ),
            // A refunded withholding posts positive; negating it keeps it a credit.
            row(
                "b",
                "DIR",
                "2026-02-10",
                "Rit.div.su 100 EXAMPLE SPA",
                Some(2.0),
            ),
        ]);

        assert_eq!(events[0].withholding_cents, Some(-200));
        assert_eq!(events[0].net_cents, Some(1200));
    }

    #[test]
    fn marks_the_missing_leg_not_the_present_one() {
        let events = pair_dividends(&[
            row("a", "DII", "2026-02-10", "Div.su AAA", Some(10.0)),
            row("b", "DIR", "2026-02-11", "Rit.div.su BBB", Some(-2.0)),
        ]);

        assert_eq!(events.len(), 2);
        let gross_only = events
            .iter()
            .find(|e| e.security.as_deref() == Some("AAA"))
            .expect("AAA event");
        let withholding_only = events
            .iter()
            .find(|e| e.security.as_deref() == Some("BBB"))
            .expect("BBB event");
        assert_eq!(gross_only.unpaired, Some(UnpairedLeg::Withholding));
        assert_eq!(withholding_only.unpaired, Some(UnpairedLeg::Gross));
        // A gross with no withholding still nets to the gross.
        assert_eq!(gross_only.net_cents, Some(1000));
    }

    #[test]
    fn reads_a_label_whose_prefix_arrives_in_a_different_case() {
        let events = pair_dividends(&[
            row(
                "a",
                "DII",
                "2026-02-10",
                "DIV.SU 100 EXAMPLE SPA",
                Some(10.0),
            ),
            row(
                "b",
                "DIR",
                "2026-02-10",
                "RIT.DIV.SU 100 EXAMPLE SPA",
                Some(-2.0),
            ),
        ]);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].security.as_deref(), Some("100 EXAMPLE SPA"));
    }

    #[test]
    fn keeps_unlabelled_legs_apart_instead_of_merging_them() {
        // Two rows whose description carries no known prefix: without the row-id
        // fallback they would share one key and merge into a single event whose
        // amounts belong to two different securities.
        let events = pair_dividends(&[
            row("a", "DII", "2026-02-10", "no prefix here", Some(10.0)),
            row("b", "DII", "2026-02-10", "no prefix either", Some(20.0)),
        ]);

        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.security.is_none()));
    }

    #[test]
    fn treats_a_prefix_only_description_as_unlabelled() {
        let events = pair_dividends(&[row("a", "DII", "2026-02-10", "Div.su ", Some(10.0))]);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].security, None);
    }

    #[test]
    fn leaves_a_side_absent_when_its_amount_was_not_captured() {
        // `importo` is nullable in the store. Counting a missing amount as zero
        // would post a dividend that reads as real and is worth nothing.
        let events = pair_dividends(&[
            row("a", "DII", "2026-02-10", "Div.su 100 EXAMPLE SPA", None),
            row(
                "b",
                "DIR",
                "2026-02-10",
                "Rit.div.su 100 EXAMPLE SPA",
                Some(-2.0),
            ),
        ]);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].gross_cents, None);
        assert_eq!(events[0].withholding_cents, Some(200));
        assert_eq!(events[0].net_cents, None);
    }

    #[test]
    fn ignores_movements_that_carry_no_dividend_code() {
        let events = pair_dividends(&[
            row("a", "48", "2026-02-10", "BONIFICO", Some(-25.0)),
            row("b", "DII", "2026-02-10", "Div.su AAA", Some(10.0)),
        ]);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].security.as_deref(), Some("AAA"));
    }

    #[test]
    fn merges_two_same_day_payments_of_one_security() {
        // The mirror of the split-day case, and the same key causes it: two real
        // payments of one security on one day cannot be told apart. The totals
        // stay right, the per-event split does not.
        let events = pair_dividends(&[
            row("a", "DII", "2026-02-10", "Div.su AAA", Some(10.0)),
            row("b", "DIR", "2026-02-10", "Rit.div.su AAA", Some(-2.0)),
            row("c", "DII", "2026-02-10", "Div.su AAA", Some(5.0)),
            row("d", "DIR", "2026-02-10", "Rit.div.su AAA", Some(-1.0)),
        ]);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].gross_cents, Some(1500));
        assert_eq!(events[0].withholding_cents, Some(300));
        assert_eq!(events[0].net_cents, Some(1200));
    }
}
