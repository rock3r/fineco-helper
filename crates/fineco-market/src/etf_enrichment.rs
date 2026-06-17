//! Parse-not-execute extraction of third-party ETF reference data.
//!
//! The enrichment page server-renders a fund "basics" table whose rows are keyed
//! by stable, locale-independent `data-testid` attributes
//! (`tl_etf-basics_value_<key>`), plus a header that echoes the page ISIN. We scan
//! that markup textually and read each value as **data** — there is no `eval`,
//! `Function`, or DOM/JS engine anywhere in this path. Every extracted string is
//! control-stripped and length-bounded before it leaves this module.

use fineco_core::{SafeError, sanitize_text};

/// Reject pages larger than this before doing any work (bounds memory/time);
/// mirrors the stock-enrichment page cap.
const MAX_HTML_BYTES: usize = 4 * 1024 * 1024;

/// A parsed money amount: a magnitude plus a `currency scale` unit string
/// (e.g. value `8622.0`, unit `"EUR million"`).
#[derive(Debug, Clone, PartialEq)]
pub struct EtfFundSize {
    pub value: f64,
    pub unit: String,
}

/// A bounded, structured ETF reference report (the `etf_external_enrichment`
/// payload, before it is wrapped into typed `MarketField`s by the gateway). Every
/// optional field is present only when the page exposed a non-empty value.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EtfEnrichmentReport {
    pub captured_at: String,
    pub source_url: String,
    /// The ISIN echoed by the page header (for the gateway's identity cross-check).
    pub isin: String,
    pub ter_percent: Option<f64>,
    pub fund_size: Option<EtfFundSize>,
    pub volatility_1y_percent: Option<f64>,
    pub replication: Option<String>,
    pub legal_structure: Option<String>,
    pub domicile: Option<String>,
    pub fund_provider: Option<String>,
    pub distribution_policy: Option<String>,
    pub distribution_frequency: Option<String>,
    pub fund_currency: Option<String>,
    pub currency_hedge: Option<String>,
    pub index_name: Option<String>,
    pub investment_focus: Option<String>,
    pub launch_date: Option<String>,
    pub strategy_risk: Option<String>,
    pub sustainable: Option<String>,
    pub securities_lending: Option<String>,
    pub warnings: Vec<String>,
}

/// Build a bounded ETF reference report from already-fetched page `html`.
///
/// `source_url` is the (already validated) page URL recorded on the report;
/// `captured_at` stamps it; `expected_isin`, when present, must match the ISIN the
/// page echoes (hard error on mismatch, like the stock path). Parsing is data-only.
///
/// # Errors
/// Returns [`SafeError::invalid_request`] if the page is too large, exposes no
/// basics fields, or its ISIN disagrees with a supplied `expected_isin`.
pub(crate) fn build_etf_report(
    html: &str,
    source_url: &str,
    captured_at: &str,
    expected_isin: Option<&str>,
) -> Result<EtfEnrichmentReport, SafeError> {
    if html.len() > MAX_HTML_BYTES {
        return Err(SafeError::invalid_request("Enrichment page is too large."));
    }

    let isin = field(html, "etf-profile-header_isin-value").unwrap_or_default();
    let ter_percent = field(html, "tl_etf-basics_value_ter").and_then(|raw| parse_percent(&raw));
    let fund_size = field(html, "tl_etf-basics_value_fund-size_indicator")
        .and_then(|raw| parse_fund_size(&raw));
    let volatility_1y_percent =
        field(html, "tl_etf-basics_value_volatility").and_then(|raw| parse_percent(&raw));

    let report = EtfEnrichmentReport {
        captured_at: captured_at.to_string(),
        source_url: source_url.to_string(),
        isin,
        ter_percent,
        fund_size,
        volatility_1y_percent,
        replication: field(html, "tl_etf-basics_value_replication"),
        legal_structure: field(html, "tl_etf-basics_value_legal-structure"),
        domicile: field(html, "tl_etf-basics_value_domicile-country"),
        fund_provider: field(html, "tl_etf-basics_value_fund-provider"),
        distribution_policy: field(html, "tl_etf-basics_value_distribution-policy"),
        distribution_frequency: field(html, "tl_etf-basics_value_distribution-interval"),
        fund_currency: field(html, "tl_etf-basics_value_fund-currency"),
        currency_hedge: field(html, "tl_etf-basics_value_currency-hedge"),
        index_name: field(html, "tl_etf-basics_value_index-name"),
        investment_focus: field(html, "tl_etf-basics_value_investment-focus"),
        launch_date: field(html, "tl_etf-basics_value_launch-date"),
        strategy_risk: field(html, "tl_etf-basics_value_strategy-risk"),
        sustainable: field(html, "tl_etf-basics_value_sustainable"),
        securities_lending: field(html, "tl_etf-basics_value_securities-lending"),
        warnings: Vec::new(),
    };

    if !report.has_any_field() {
        return Err(SafeError::invalid_request(
            "Enrichment page exposed no ETF basics fields.",
        ));
    }

    if let Some(expected) = expected_isin {
        let expected = comparable_isin(expected);
        if comparable_isin(&report.isin) != expected {
            return Err(SafeError::invalid_request(
                "Enrichment page ISIN did not match expected_isin.",
            ));
        }
    }

    Ok(report)
}

impl EtfEnrichmentReport {
    /// At least one substantive basics field was extracted (the header ISIN alone
    /// does not count — a bare ISIN with no fund data is not a usable report).
    fn has_any_field(&self) -> bool {
        self.ter_percent.is_some()
            || self.fund_size.is_some()
            || self.volatility_1y_percent.is_some()
            || self.replication.is_some()
            || self.legal_structure.is_some()
            || self.domicile.is_some()
            || self.fund_provider.is_some()
            || self.distribution_policy.is_some()
            || self.distribution_frequency.is_some()
            || self.fund_currency.is_some()
            || self.currency_hedge.is_some()
            || self.index_name.is_some()
            || self.investment_focus.is_some()
            || self.launch_date.is_some()
            || self.strategy_risk.is_some()
            || self.sustainable.is_some()
            || self.securities_lending.is_some()
    }
}

/// Extract the sanitized inner text of the element carrying `data-testid="<testid>"`.
/// Returns `None` when the anchor is absent or the value is empty / a bare "-"
/// placeholder (the source renders an absent attribute, e.g. an accumulating
/// fund's distribution interval, as "-").
fn field(html: &str, testid: &str) -> Option<String> {
    // The trailing quote in the needle prevents a prefix match (e.g. the
    // `_replication` anchor must not match `_replication-method`).
    let needle = format!("data-testid=\"{testid}\"");
    let pos = html.find(&needle)?;
    let after = &html[pos + needle.len()..];
    let gt = after.find('>')?;
    // Decode HTML entities BEFORE sanitizing: `&amp;`/`&reg;` become their real
    // characters and `&nbsp;` becomes a plain space (so numeric parsing works). The
    // sanitize pass runs after, so anything an entity decodes to — including a
    // control char from a hostile numeric entity — is still control-stripped.
    let cleaned = sanitize_text(&decode_entities(&inner_text(&after[gt + 1..])));
    let trimmed = cleaned.trim();
    if trimmed.is_empty() || trimmed == "-" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Collect the text content of an element, given the markup immediately after its
/// opening tag's `>`. Nested child tags are skipped (depth-tracked) and the scan
/// stops at the element's own closing tag. Tags are never interpreted — only
/// stripped — so this is pure data extraction, not execution.
fn inner_text(mut rest: &str) -> String {
    let mut out = String::new();
    let mut depth = 0i32;
    while let Some(lt) = rest.find('<') {
        out.push_str(&rest[..lt]);
        let tail = &rest[lt..];
        // An HTML comment never nests and may itself contain `>`, so skip to its
        // real `-->` end rather than the next `>`. (Replace it with a space too.)
        if let Some(after_open) = tail.strip_prefix("<!--") {
            out.push(' ');
            match after_open.find("-->") {
                Some(end) => {
                    rest = &after_open[end + "-->".len()..];
                    continue;
                }
                None => break,
            }
        }
        let Some(gt) = tail.find('>') else { break };
        let tag = &tail[..=gt];
        // Replace the tag with a space so text either side of it (e.g. a `<br>`)
        // never glues into one token; `sanitize_text` collapses the runs.
        out.push(' ');
        if tag.starts_with("</") {
            if depth == 0 {
                break;
            }
            depth -= 1;
        } else if !tag.ends_with("/>") && !is_void_tag(tag) {
            // A non-self-closing, non-void element opens a nested level. Void
            // elements (`<br>`, `<img>`, …) have no closing tag, so counting them
            // as nested would consume the cell's own `</td>` as their close and
            // bleed later rows into the value.
            depth += 1;
        }
        rest = &tail[gt + 1..];
    }
    out
}

/// Decode the HTML entities that appear in provider cells into their characters.
/// Covers the standard five (`&amp; &lt; &gt; &quot; &apos;`), `&nbsp;` (→ a plain
/// space, so numeric parsing works), a few common symbol entities, and numeric
/// references (`&#NNN;` / `&#xHHH;`). Unrecognized entities are left literal rather
/// than dropped, to avoid losing data. No external dependency — the set is bounded.
fn decode_entities(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp..];
        // Entities are short; only look for the ';' within a small window so a lone
        // '&' in free text doesn't scan the whole string.
        let window = after.len().min(12);
        if let Some(semi) = after[..window].find(';')
            && let Some(decoded) = decode_one_entity(&after[1..semi])
        {
            out.push_str(&decoded);
            rest = &after[semi + 1..];
            continue;
        }
        // Not a recognized entity: keep the '&' literal and move past it.
        out.push('&');
        rest = &after[1..];
    }
    out.push_str(rest);
    out
}

/// Decode the text between `&` and `;` (e.g. `"amp"`, `"#39"`, `"#x2014"`) into its
/// string, or `None` if it is not a recognized entity.
fn decode_one_entity(entity: &str) -> Option<String> {
    let named = match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        "reg" => Some('®'),
        "trade" => Some('™'),
        "copy" => Some('©'),
        "deg" => Some('°'),
        "mdash" => Some('—'),
        "ndash" => Some('–'),
        "hellip" => Some('…'),
        _ => None,
    };
    if let Some(ch) = named {
        return Some(ch.to_string());
    }
    // Numeric character reference: &#NNN; (decimal) or &#xHHH; (hex).
    let num = entity.strip_prefix('#')?;
    let code = match num.strip_prefix(['x', 'X']) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => num.parse::<u32>().ok()?,
    };
    char::from_u32(code).map(|ch| ch.to_string())
}

/// Whether `tag` (e.g. `"<br>"`, `"<img src=…>"`) is an HTML void element — one
/// with no closing tag. Such tags must not open a nesting level in [`inner_text`].
fn is_void_tag(tag: &str) -> bool {
    let name = tag
        .trim_start_matches('<')
        .split(|c: char| c.is_whitespace() || c == '>' || c == '/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

/// Parse a leading percentage like "0.29% p.a." or "8.22%" into a bare f64.
fn parse_percent(raw: &str) -> Option<f64> {
    let head = raw.split('%').next()?.trim();
    head.parse::<f64>().ok()
}

/// Parse a fund-size cell like "EUR 8,622 m" into a magnitude + "currency scale"
/// unit. Thousands separators are removed; a trailing magnitude word (m/bn) is
/// folded into the unit string. Returns `None` if no numeric magnitude is present.
fn parse_fund_size(raw: &str) -> Option<EtfFundSize> {
    let mut currency: Option<&str> = None;
    let mut magnitude: Option<f64> = None;
    let mut scale: Option<&str> = None;
    for token in raw.split_whitespace() {
        if magnitude.is_none() && token.chars().any(|c| c.is_ascii_digit()) {
            let digits: String = token.chars().filter(|c| *c != ',').collect();
            if let Ok(value) = digits.parse::<f64>() {
                magnitude = Some(value);
                continue;
            }
        }
        if currency.is_none() && token.len() == 3 && token.chars().all(|c| c.is_ascii_alphabetic())
        {
            currency = Some(token);
            continue;
        }
        if magnitude.is_some() && scale.is_none() {
            scale = match token.trim_end_matches('.').to_ascii_lowercase().as_str() {
                "m" | "mn" | "mln" => Some("million"),
                "bn" | "bln" | "b" => Some("billion"),
                "k" => Some("thousand"),
                _ => None,
            };
        }
    }
    let value = magnitude?;
    let unit = match (currency, scale) {
        (Some(currency), Some(scale)) => format!("{currency} {scale}"),
        (Some(currency), None) => currency.to_string(),
        (None, Some(scale)) => scale.to_string(),
        (None, None) => String::new(),
    };
    Some(EtfFundSize { value, unit })
}

/// Normalize an ISIN for identity comparison: drop a venue suffix, uppercase.
fn comparable_isin(value: &str) -> String {
    let trimmed = value.trim();
    let isin = trimmed.split_once('.').map_or(trimmed, |(isin, _)| isin);
    isin.to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "https://etf.example/etf-profile.html?isin=XX0000000001";

    /// A synthetic basics table mirroring the page's `data-testid` contract. No
    /// real provider/host is referenced; values are fictional but shaped like the
    /// real ones (currency-prefixed fund size, "% p.a." TER, "-" for an absent
    /// distribution interval, nested spans in the fund-size cell).
    fn page(isin: &str, distribution_policy: &str, interval: &str) -> String {
        format!(
            "<html><body>\
             <span data-testid=\"etf-profile-header_etf-name\">Synthetic World ETF</span>\
             <span data-testid=\"etf-profile-header_isin-value\">{isin}</span>\
             <table><tbody>\
             <tr><td class=\"vallabel\">Index</td>\
               <td class=\"val\" data-testid=\"tl_etf-basics_value_index-name\">Synthetic World Index</td></tr>\
             <tr><td>Investment focus</td>\
               <td data-testid=\"tl_etf-basics_value_investment-focus\">Equity, World</td></tr>\
             <tr><td>Fund size</td>\
               <td data-testid=\"tl_etf-basics_value_fund-size_indicator\"> <span> EUR 8,622 </span> m <span class=\"indicator-3\">x</span></td></tr>\
             <tr><td>TER</td>\
               <td data-testid=\"tl_etf-basics_value_ter\">0.29% p.a.</td></tr>\
             <tr><td>Replication</td>\
               <td data-testid=\"tl_etf-basics_value_replication\">Physical ( Optimized sampling )</td></tr>\
             <tr><td>Replication</td>\
               <td data-testid=\"tl_etf-basics_value_replication-method\">Optimized sampling</td></tr>\
             <tr><td>Legal structure</td>\
               <td data-testid=\"tl_etf-basics_value_legal-structure\">ETF</td></tr>\
             <tr><td>Strategy</td>\
               <td data-testid=\"tl_etf-basics_value_strategy-risk\">Long-only</td></tr>\
             <tr><td>Sustainability</td>\
               <td data-testid=\"tl_etf-basics_value_sustainable\">No</td></tr>\
             <tr><td>Fund currency</td>\
               <td data-testid=\"tl_etf-basics_value_fund-currency\">USD</td></tr>\
             <tr><td>Currency risk</td>\
               <td data-testid=\"tl_etf-basics_value_currency-hedge\">Currency unhedged</td></tr>\
             <tr><td>Volatility</td>\
               <td data-testid=\"tl_etf-basics_value_volatility\">8.22%</td></tr>\
             <tr><td>Launch</td>\
               <td data-testid=\"tl_etf-basics_value_launch-date\">21 May 2013</td></tr>\
             <tr><td>Distribution policy</td>\
               <td data-testid=\"tl_etf-basics_value_distribution-policy\">{distribution_policy}</td></tr>\
             <tr><td>Distribution frequency</td>\
               <td data-testid=\"tl_etf-basics_value_distribution-interval\">{interval}</td></tr>\
             <tr><td>Domicile</td>\
               <td data-testid=\"tl_etf-basics_value_domicile-country\">Ireland</td></tr>\
             <tr><td>Provider</td>\
               <td data-testid=\"tl_etf-basics_value_fund-provider\">Synthetic Asset Mgmt</td></tr>\
             </tbody></table></body></html>"
        )
    }

    #[test]
    fn parses_distributing_etf_basics() {
        let html = page("XX0000000001", "Distributing", "Quarterly");
        let report = build_etf_report(&html, HOST, "2026-06-17T09:00:00Z", None).expect("parse");

        assert_eq!(report.isin, "XX0000000001");
        assert_eq!(report.ter_percent, Some(0.29));
        assert_eq!(report.volatility_1y_percent, Some(8.22));
        let size = report.fund_size.expect("fund size");
        assert_eq!(size.value, 8622.0);
        assert_eq!(size.unit, "EUR million");
        assert_eq!(
            report.replication.as_deref(),
            Some("Physical ( Optimized sampling )")
        );
        assert_eq!(report.domicile.as_deref(), Some("Ireland"));
        assert_eq!(
            report.fund_provider.as_deref(),
            Some("Synthetic Asset Mgmt")
        );
        assert_eq!(report.distribution_policy.as_deref(), Some("Distributing"));
        assert_eq!(report.distribution_frequency.as_deref(), Some("Quarterly"));
        assert_eq!(report.fund_currency.as_deref(), Some("USD"));
        assert_eq!(report.currency_hedge.as_deref(), Some("Currency unhedged"));
        assert_eq!(report.index_name.as_deref(), Some("Synthetic World Index"));
        assert_eq!(report.investment_focus.as_deref(), Some("Equity, World"));
        assert_eq!(report.launch_date.as_deref(), Some("21 May 2013"));
        assert_eq!(report.strategy_risk.as_deref(), Some("Long-only"));
        assert_eq!(report.sustainable.as_deref(), Some("No"));
        assert_eq!(report.source_url, HOST);
        assert_eq!(report.captured_at, "2026-06-17T09:00:00Z");
    }

    #[test]
    fn accumulating_etf_has_no_distribution_frequency() {
        // An accumulating fund renders the interval cell as a bare "-": treat that
        // as absent, not as the literal value "-".
        let html = page("XX0000000002", "Accumulating", "-");
        let report = build_etf_report(&html, HOST, "2026-06-17T09:00:00Z", None).expect("parse");
        assert_eq!(report.distribution_policy.as_deref(), Some("Accumulating"));
        assert_eq!(report.distribution_frequency, None);
    }

    #[test]
    fn html_entities_in_cells_are_decoded() {
        // Provider cells use HTML entities: `&amp;`/`&reg;` in names, and `&nbsp;`
        // around numbers. Without decoding, the index name keeps the literal markup
        // and the `&nbsp;` breaks numeric parsing (silently dropping TER/fund size).
        let html = "<html><body>\
            <span data-testid=\"etf-profile-header_isin-value\">XX0000000001</span>\
            <td data-testid=\"tl_etf-basics_value_index-name\">S&amp;P 500&reg;</td>\
            <td data-testid=\"tl_etf-basics_value_ter\">0.29&nbsp;% p.a.</td>\
            <td data-testid=\"tl_etf-basics_value_fund-size_indicator\">EUR&nbsp;8,622 m</td>\
            <td data-testid=\"tl_etf-basics_value_fund-provider\">Acme &#39;Funds&#39;</td>\
            </body></html>";
        let report = build_etf_report(html, HOST, "t", None).expect("parse");
        assert_eq!(report.index_name.as_deref(), Some("S&P 500®"));
        assert_eq!(report.ter_percent, Some(0.29));
        assert_eq!(report.fund_provider.as_deref(), Some("Acme 'Funds'"));
        let size = report.fund_size.expect("fund size");
        assert_eq!(size.value, 8622.0);
    }

    #[test]
    fn numeric_entity_decoding_to_a_control_char_is_then_stripped() {
        // A hostile numeric entity that decodes to a control byte (e.g. ESC) must
        // not survive: decode happens before sanitize, which strips control chars.
        let html = "<html><body>\
            <span data-testid=\"etf-profile-header_isin-value\">XX0000000001</span>\
            <td data-testid=\"tl_etf-basics_value_domicile-country\">Ire&#27;land</td>\
            </body></html>";
        let report = build_etf_report(html, HOST, "t", None).expect("parse");
        let domicile = report.domicile.expect("domicile");
        assert!(
            !domicile.chars().any(char::is_control),
            "decoded control char survived: {domicile:?}"
        );
    }

    #[test]
    fn html_comments_in_a_cell_do_not_break_parsing() {
        // A React-rendered page can embed HTML comments inside a cell. A comment has
        // no closing tag, so counting it as a nested level would consume the cell's
        // `</td>` and bleed later rows — and a comment may even contain a `>`.
        let html = "<html><body>\
            <span data-testid=\"etf-profile-header_isin-value\">XX0000000001</span>\
            <td data-testid=\"tl_etf-basics_value_fund-size_indicator\">EUR<!-- a > b -->8,622 m</td>\
            <td data-testid=\"tl_etf-basics_value_domicile-country\">Ireland</td>\
            </body></html>";
        let report = build_etf_report(html, HOST, "t", None).expect("parse");
        let size = report.fund_size.expect("fund size");
        assert_eq!(size.value, 8622.0);
        // The comment did not bleed the next cell into this one or vice-versa.
        assert_eq!(report.domicile.as_deref(), Some("Ireland"));
    }

    #[test]
    fn void_tags_in_a_cell_do_not_bleed_into_the_value() {
        // A `<br>` (void, no closing tag) inside a value cell must not be counted as
        // a nested level — otherwise the cell's own `</td>` is consumed and the next
        // row's text bleeds into the value.
        let html = "<html><body>\
            <span data-testid=\"etf-profile-header_isin-value\">XX0000000001</span>\
            <td data-testid=\"tl_etf-basics_value_domicile-country\">Ireland<br>(Dublin)</td>\
            <td data-testid=\"tl_etf-basics_value_fund-provider\">Acme</td>\
            </body></html>";
        let report = build_etf_report(html, HOST, "t", None).expect("parse");
        // The br is stripped; both lines of the SAME cell are kept, collapsed.
        assert_eq!(report.domicile.as_deref(), Some("Ireland (Dublin)"));
        // The next cell did NOT bleed into domicile, and parses on its own.
        assert_eq!(report.fund_provider.as_deref(), Some("Acme"));
        assert!(
            !report.domicile.as_deref().unwrap().contains("Acme"),
            "next cell bled into the value"
        );
    }

    #[test]
    fn expected_isin_mismatch_is_rejected() {
        let html = page("XX0000000001", "Distributing", "Quarterly");
        let err = build_etf_report(&html, HOST, "2026-06-17T09:00:00Z", Some("XX0000000099"))
            .expect_err("mismatch must error");
        assert_eq!(err.code(), "invalid_request");
    }

    #[test]
    fn expected_isin_match_is_accepted() {
        let html = page("XX0000000001", "Distributing", "Quarterly");
        let report = build_etf_report(&html, HOST, "2026-06-17T09:00:00Z", Some("XX0000000001"))
            .expect("match");
        assert_eq!(report.isin, "XX0000000001");
    }

    #[test]
    fn page_without_basics_is_rejected() {
        let err = build_etf_report("<html><body>nothing</body></html>", HOST, "t", None)
            .expect_err("no basics must error");
        assert_eq!(err.code(), "invalid_request");
    }

    #[test]
    fn control_characters_in_values_are_stripped() {
        let html = "<html><body>\
            <span data-testid=\"etf-profile-header_isin-value\">XX0000000001</span>\
            <td data-testid=\"tl_etf-basics_value_domicile-country\">Ire\u{1b}[31mland\nXX</td>\
            </body></html>";
        let report = build_etf_report(html, HOST, "t", None).expect("parse");
        let domicile = report.domicile.expect("domicile");
        assert!(
            !domicile.chars().any(char::is_control),
            "control char survived: {domicile:?}"
        );
    }

    #[test]
    fn oversized_page_is_rejected() {
        let big = format!("<html>{}</html>", "x".repeat(MAX_HTML_BYTES));
        let err = build_etf_report(&big, HOST, "t", None).expect_err("oversized must error");
        assert_eq!(err.code(), "invalid_request");
    }
}
