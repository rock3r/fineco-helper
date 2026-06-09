//! Build a bounded, structured enrichment report from the parsed query cache.
//!
//! Navigates the React-Query cache to the `company` entry, extracts the company
//! overview, scores, and per-section metrics, and optionally scores a Fineco
//! title match. All external free text and raw score/metric output is
//! size-limited and reduced to primitives — never echoed unbounded.

use fineco_core::SafeError;
use serde::Serialize;
use serde_json::{Map, Value};

/// Max characters kept for any external free-text string.
const MAX_STR: usize = 4096;
/// Max entries kept from the scores object.
const MAX_SCORE_ENTRIES: usize = 64;
/// Max metric entries kept per analysis section (mirrors the TS `slice(0, 16)`).
const MAX_METRICS_PER_SECTION: usize = 16;
/// The analysis sections surfaced as metrics, in order.
const METRIC_SECTIONS: [&str; 6] = [
    "value",
    "future",
    "past",
    "health",
    "dividend",
    "management",
];

/// The company overview extracted from the enrichment page.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct CompanyOverview {
    pub name: String,
    pub ticker: String,
    pub exchange: String,
    pub isin: String,
    pub country: String,
    pub website: String,
    pub description: String,
}

/// The outcome of matching a Fineco instrument title against the page company.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct EnrichmentMatch {
    pub fineco_title: String,
    pub enrichment_title: String,
    pub score: f64,
    pub verdict: &'static str,
    pub reasons: Vec<String>,
}

/// A bounded, structured enrichment report (the `external_enrichment` payload).
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct EnrichmentReport {
    pub captured_at: String,
    pub source_url: String,
    pub company: CompanyOverview,
    pub scores: Value,
    pub metrics: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_match: Option<EnrichmentMatch>,
    pub warnings: Vec<String>,
}

/// Assemble a report from the parsed `state`, stamped with `captured_at` and the
/// validated `source_url`. If `fineco_title` is given, include a title match.
///
/// # Errors
/// Returns [`SafeError::invalid_request`] if the cache lacks a `company` entry.
pub(crate) fn build_report(
    state: &Value,
    source_url: &str,
    captured_at: &str,
    fineco_title: Option<&str>,
) -> Result<EnrichmentReport, SafeError> {
    let company_root = query(state, "company")
        .and_then(|data| data.get("data"))
        .ok_or_else(|| SafeError::invalid_request("Enrichment page has no company data."))?;

    let extended = company_root
        .pointer("/analysis/data/extended/data")
        .unwrap_or(&Value::Null);
    let raw = extended.pointer("/raw_data/data").unwrap_or(&Value::Null);
    let analysis = extended.get("analysis").unwrap_or(&Value::Null);
    let scores_src = extended
        .get("scores")
        .or_else(|| company_root.pointer("/score/data"))
        .unwrap_or(&Value::Null);

    let info = raw
        .get("company_info")
        .or_else(|| company_root.get("info"))
        .unwrap_or(&Value::Null);

    let company = CompanyOverview {
        name: pick_str(info, "name")
            .or_else(|| pick_str(company_root, "name"))
            .unwrap_or_default(),
        ticker: pick_str(info, "unique_symbol")
            .or_else(|| pick_str(company_root, "unique_symbol"))
            .unwrap_or_default(),
        exchange: pick_str(info, "exchange_symbol")
            .or_else(|| pick_str(company_root, "exchange_symbol"))
            .unwrap_or_default(),
        isin: pick_str(info, "isin_symbol")
            .or_else(|| pick_str(company_root, "isin_symbol"))
            .unwrap_or_default(),
        country: pick_str(info, "country").unwrap_or_default(),
        website: pick_str(info, "url").unwrap_or_default(),
        description: pick_str(info, "description").unwrap_or_default(),
    };

    let mut warnings = Vec::new();
    if company.name.is_empty() {
        warnings.push("Missing company name.".to_string());
    }
    if primitive_count(raw) == 0 {
        warnings.push("Missing raw company data.".to_string());
    }
    if analysis.as_object().is_none_or(serde_json::Map::is_empty) {
        warnings.push("Missing analysis metrics.".to_string());
    }

    let title_match = fineco_title.map(|title| match_title(title, &company));

    Ok(EnrichmentReport {
        captured_at: captured_at.to_string(),
        source_url: source_url.to_string(),
        scores: Value::Object(bounded_primitive_map(scores_src, MAX_SCORE_ENTRIES)),
        metrics: section_metrics(analysis),
        company,
        title_match,
        warnings,
    })
}

/// Find a React-Query cache entry by name and return its `state.data`.
fn query<'a>(state: &'a Value, name: &str) -> Option<&'a Value> {
    state
        .get("queries")?
        .as_array()?
        .iter()
        .find(|entry| entry.pointer("/queryKey/0").and_then(Value::as_str) == Some(name))?
        .pointer("/state/data")
}

/// Cleaned, length-bounded string for `object[key]`, or `None` if absent/empty.
fn pick_str(object: &Value, key: &str) -> Option<String> {
    let cleaned = clean_value(object.get(key)?);
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Whitespace-collapsed, trimmed, length-bounded rendering of a JSON value.
/// Objects/arrays render empty (only primitives carry display text).
fn clean_value(value: &Value) -> String {
    let raw = match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    };
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate(&collapsed, MAX_STR)
}

/// Truncate `s` to at most `max` characters (on a char boundary).
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

/// Count the primitive (non-object/array) fields of an object value.
fn primitive_count(value: &Value) -> usize {
    value
        .as_object()
        .map(|map| map.values().filter(|v| is_primitive(v)).count())
        .unwrap_or(0)
}

fn is_primitive(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    )
}

/// Keep up to `max` primitive entries of `value` (if it is an object), with
/// string values length-bounded. Drops nested objects/arrays.
fn bounded_primitive_map(value: &Value, max: usize) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(object) = value.as_object() else {
        return out;
    };
    for (key, val) in object {
        if out.len() >= max {
            break;
        }
        if !is_primitive(val) {
            continue;
        }
        let bounded = match val {
            Value::String(s) => Value::String(truncate(s, MAX_STR)),
            other => other.clone(),
        };
        out.insert(key.clone(), bounded);
    }
    out
}

/// Build the `{section: {metric: value}}` map from the analysis object.
fn section_metrics(analysis: &Value) -> Value {
    let mut sections = Map::new();
    for section in METRIC_SECTIONS {
        let entry = analysis.get(section).unwrap_or(&Value::Null);
        sections.insert(
            section.to_string(),
            Value::Object(bounded_primitive_map(entry, MAX_METRICS_PER_SECTION)),
        );
    }
    Value::Object(sections)
}

// ---- Title matching --------------------------------------------------------

/// Stopwords dropped from title tokens (corporate suffixes / filler).
const STOPWORDS: [&str; 25] = [
    "spa",
    "s",
    "p",
    "a",
    "sa",
    "ag",
    "nv",
    "plc",
    "ltd",
    "limited",
    "inc",
    "corp",
    "corporation",
    "company",
    "co",
    "ordinary",
    "shares",
    "stock",
    "adr",
    "the",
    "and",
    "di",
    "de",
    "del",
    "ord",
];

/// Score how well `fineco_title` matches the page `company`.
fn match_title(fineco_title: &str, company: &CompanyOverview) -> EnrichmentMatch {
    let enrichment_title = [&company.name, &company.ticker, &company.isin]
        .into_iter()
        .filter(|s| !s.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");

    let fineco_tokens = tokens(fineco_title);
    let source_tokens = tokens(&enrichment_title);
    let overlap: Vec<String> = fineco_tokens
        .iter()
        .filter(|t| source_tokens.contains(*t))
        .cloned()
        .collect();
    let ticker_short = company
        .ticker
        .rsplit(':')
        .next()
        .unwrap_or("")
        .to_lowercase();

    let mut score = 0.0_f64;
    let mut reasons = Vec::new();

    if !company.isin.is_empty()
        && fineco_title
            .to_lowercase()
            .contains(&company.isin.to_lowercase())
    {
        score += 0.55;
        reasons.push("ISIN match".to_string());
    }
    if !ticker_short.is_empty() && fineco_tokens.iter().any(|t| t == &ticker_short) {
        score += 0.35;
        reasons.push("ticker match".to_string());
    }
    if !fineco_tokens.is_empty() {
        let denominator = fineco_tokens.len().max(source_tokens.len()).max(1) as f64;
        let token_score = overlap.len() as f64 / denominator;
        score += token_score.min(0.55);
        if !overlap.is_empty() {
            reasons.push(format!("shared title tokens: {}", overlap.join(", ")));
        }
    }

    let bounded = (score * 1000.0).round() / 1000.0;
    let bounded = bounded.clamp(0.0, 1.0);
    let verdict = if bounded >= 0.7 {
        "strong"
    } else if bounded >= 0.35 {
        "possible"
    } else {
        "weak"
    };

    EnrichmentMatch {
        fineco_title: truncate(fineco_title, MAX_STR),
        enrichment_title: truncate(&enrichment_title, MAX_STR),
        score: bounded,
        verdict,
        reasons,
    }
}

/// Lowercase alphanumeric tokens, dropping single-character tokens and
/// stopwords. (No NFKD normalization — inputs here are ASCII tickers/ISINs and
/// largely-Latin company names.)
fn tokens(value: &str) -> Vec<String> {
    value
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .filter(|t| t.chars().count() > 1 && !STOPWORDS.contains(t))
        .map(str::to_string)
        .collect()
}
