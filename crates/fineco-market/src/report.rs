//! Build a bounded, structured enrichment report from the parsed query cache.
//!
//! Navigates the React-Query cache to a profile entry, extracts the company/fund
//! overview, scores, and per-section metrics, and optionally scores a Fineco
//! title match. All external free text and raw score/metric output is
//! size-limited and reduced to primitives — never echoed unbounded.

use fineco_core::SafeError;
use serde::Serialize;
use serde_json::{Map, Value};

/// Max characters kept for any external free-text string. Shared with the ETF
/// list path in `client.rs`, which sanitizes its untrusted string fields too.
pub(crate) const MAX_STR: usize = 4096;
/// Max entries kept from the scores object.
const MAX_SCORE_ENTRIES: usize = 64;
/// Max metric entries kept per analysis section (mirrors the TS `slice(0, 16)`).
const MAX_METRICS_PER_SECTION: usize = 16;
/// React-Query profile keys observed for enrichment pages. Equities use
/// `company`; ETF/fund pages can use fund-oriented keys with the same nested
/// analysis shape.
const PROFILE_QUERY_KEYS: [&str; 3] = ["company", "fund", "etf"];
/// Raw-info object keys observed under `raw_data.data`.
const RAW_INFO_KEYS: [&str; 3] = ["company_info", "fund_info", "asset_info"];
/// The analysis sections surfaced as metrics, in order.
const METRIC_SECTIONS: [&str; 6] = [
    "value",
    "future",
    "past",
    "health",
    "dividend",
    "management",
];

#[derive(Clone, Copy)]
struct ProfileCandidate<'a> {
    kind: &'a str,
    data: &'a Value,
}

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
/// Returns [`SafeError::invalid_request`] if the cache lacks a recognized
/// profile entry.
pub(crate) fn build_report(
    state: &Value,
    source_url: &str,
    captured_at: &str,
    fineco_title: Option<&str>,
) -> Result<EnrichmentReport, SafeError> {
    let profile = profile_query(state, fineco_title)
        .ok_or_else(|| SafeError::invalid_request("Enrichment page has no profile data."))?;
    let profile_root = profile
        .data
        .get("data")
        .ok_or_else(|| SafeError::invalid_request("Enrichment page has no profile data."))?;

    let extended = profile_root
        .pointer("/analysis/data/extended/data")
        .unwrap_or(&Value::Null);
    let raw = extended.pointer("/raw_data/data").unwrap_or(&Value::Null);
    let analysis = extended.get("analysis").unwrap_or(&Value::Null);
    let scores_src = extended
        .get("scores")
        .or_else(|| profile_root.pointer("/score/data"))
        .unwrap_or(&Value::Null);

    let company = company_overview(profile);

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

/// Find the best recognized company/fund profile cache entry and return its
/// `state.data`. If the caller supplied a Fineco title, prefer the profile whose
/// extracted display name/ticker/ISIN best matches it; otherwise keep the cache
/// source order.
fn profile_query<'a>(state: &'a Value, fineco_title: Option<&str>) -> Option<ProfileCandidate<'a>> {
    let candidates = profile_queries(state);
    let first_usable = candidates
        .iter()
        .copied()
        .find(|profile| profile_is_usable(*profile))
        .or_else(|| candidates.first().copied());
    let Some(title) = fineco_title.filter(|title| !tokens(title).is_empty()) else {
        return first_usable;
    };

    let mut best = None;
    let mut best_score = 0.0_f64;
    for candidate in candidates {
        let score = profile_match_score(candidate, title);
        if score > best_score {
            best = Some(candidate);
            best_score = score;
        }
    }
    best.or(first_usable)
}

fn profile_queries(state: &Value) -> Vec<ProfileCandidate<'_>> {
    state
        .get("queries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let kind = entry.pointer("/queryKey/0").and_then(Value::as_str)?;
            if !PROFILE_QUERY_KEYS.contains(&kind) {
                return None;
            }
            let data = entry.pointer("/state/data")?;
            Some(ProfileCandidate { kind, data })
        })
        .collect()
}

fn profile_is_usable(profile: ProfileCandidate<'_>) -> bool {
    profile.data.get("data").is_some_and(|root| {
        let raw = root
            .pointer("/analysis/data/extended/data/raw_data/data")
            .unwrap_or(&Value::Null);
        raw_info_values(raw, profile.kind).any(has_display_field)
            || root.get("info").is_some_and(has_display_field)
            || has_display_field(root)
    })
}

fn profile_match_score(profile: ProfileCandidate<'_>, fineco_title: &str) -> f64 {
    let company = company_overview(profile);
    match_title(fineco_title, &company).score
}

fn company_overview(profile: ProfileCandidate<'_>) -> CompanyOverview {
    let root = profile.data.get("data").unwrap_or(&Value::Null);
    let raw = root
        .pointer("/analysis/data/extended/data/raw_data/data")
        .unwrap_or(&Value::Null);
    CompanyOverview {
        name: pick_profile_str(raw, profile.kind, root, "name").unwrap_or_default(),
        ticker: pick_profile_str(raw, profile.kind, root, "unique_symbol").unwrap_or_default(),
        exchange: pick_profile_str(raw, profile.kind, root, "exchange_symbol").unwrap_or_default(),
        isin: pick_profile_str(raw, profile.kind, root, "isin_symbol").unwrap_or_default(),
        country: pick_profile_str(raw, profile.kind, root, "country").unwrap_or_default(),
        website: pick_profile_str(raw, profile.kind, root, "url").unwrap_or_default(),
        description: pick_profile_str(raw, profile.kind, root, "description").unwrap_or_default(),
    }
}

fn pick_profile_str(raw: &Value, profile_kind: &str, root: &Value, key: &str) -> Option<String> {
    pick_raw_str(raw, profile_kind, key)
        .or_else(|| root.get("info").and_then(|info| pick_str(info, key)))
        .or_else(|| pick_str(root, key))
}

fn pick_raw_str(raw: &Value, profile_kind: &str, key: &str) -> Option<String> {
    raw_info_values(raw, profile_kind).find_map(|value| pick_str(value, key))
}

fn raw_info_values<'a>(
    raw: &'a Value,
    profile_kind: &str,
) -> impl Iterator<Item = &'a Value> + use<'a> {
    raw_info_keys(profile_kind)
        .into_iter()
        .filter_map(|key| raw.get(key))
        .filter(|value| raw_info_score(value) > 0)
}

fn raw_info_keys(profile_kind: &str) -> [&'static str; 3] {
    match profile_kind {
        "fund" | "etf" => ["fund_info", "asset_info", "company_info"],
        _ => RAW_INFO_KEYS,
    }
}

fn raw_info_score(value: &Value) -> usize {
    let display_fields = ["name", "unique_symbol", "exchange_symbol", "isin_symbol"]
        .into_iter()
        .filter(|key| pick_str(value, key).is_some())
        .count();
    let non_empty_primitives = non_empty_primitive_count(value);
    display_fields * 100 + non_empty_primitives
}

fn non_empty_primitive_count(value: &Value) -> usize {
    value
        .as_object()
        .map(|map| {
            map.values()
                .filter(|value| is_primitive(value) && !clean_value(value).is_empty())
                .count()
        })
        .unwrap_or(0)
}

fn has_display_field(value: &Value) -> bool {
    ["name", "unique_symbol", "exchange_symbol", "isin_symbol"]
        .into_iter()
        .any(|key| pick_str(value, key).is_some())
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
    match value {
        Value::String(s) => sanitize_text(s),
        Value::Number(n) => truncate(&n.to_string(), MAX_STR),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

/// Sanitize an external free-text string before it reaches the model: replace
/// every control character (newline, tab, NUL, ANSI/ESC, DEL, C1) with a space,
/// collapse whitespace runs to single spaces, trim, and length-bound. Applied to
/// every untrusted free-text field — company overview, metric/score keys and
/// string values, and the public ETF list's string fields — so a hostile
/// provider cannot smuggle line breaks or escape sequences (a prompt-injection
/// channel) into a payload returned to the model.
pub(crate) fn sanitize_text(raw: &str) -> String {
    let stripped: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let collapsed = stripped.split_whitespace().collect::<Vec<_>>().join(" ");
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
        // Sanitize string values and keys the same way as company free text:
        // control-stripped, whitespace-collapsed, length-bounded. Non-string
        // primitives (numbers/bools) are preserved as their JSON type.
        let bounded = match val {
            Value::String(s) => Value::String(sanitize_text(s)),
            other => other.clone(),
        };
        out.insert(sanitize_text(key), bounded);
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
    let company_name_tokens = tokens(&company.name);
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

    if contains_token_sequence(&fineco_tokens, &company_name_tokens)
        || contains_token_sequence(&company_name_tokens, &fineco_tokens)
    {
        score += 0.4;
        reasons.push("name match".to_string());
    }
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

fn contains_token_sequence(haystack: &[String], needle: &[String]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Metric/score maps reach the model verbatim today: string values are only
    /// length-truncated (control chars kept) and keys are copied unbounded and
    /// unsanitized. Both must be control-stripped, whitespace-collapsed, and
    /// length-bounded like the company free-text fields, so a hostile provider
    /// cannot smuggle newlines/ANSI escapes (a prompt-injection channel) or an
    /// unbounded key into the report.
    #[test]
    fn metric_keys_and_string_values_are_sanitized_and_bounded() {
        let long_key = "k".repeat(MAX_STR + 50);
        let mut src = Map::new();
        src.insert("score".to_string(), json!(1.5));
        src.insert(
            "ev\u{1b}[31mil\nkey".to_string(),
            json!("line1\nline2\u{1b}[0m\ttabbed"),
        );
        src.insert(long_key.clone(), json!("v"));
        // A nested object must still be dropped (only primitives kept).
        src.insert("nested".to_string(), json!({"a": 1}));

        let out = bounded_primitive_map(&Value::Object(src), MAX_SCORE_ENTRIES);

        assert!(
            !out.contains_key("nested"),
            "nested objects must be dropped"
        );
        for (key, val) in &out {
            assert!(
                !key.chars().any(char::is_control),
                "key still has a control char: {key:?}"
            );
            assert!(
                key.chars().count() <= MAX_STR,
                "key not length-bounded: {} chars",
                key.chars().count()
            );
            if let Value::String(s) = val {
                assert!(
                    !s.chars().any(char::is_control),
                    "string value still has a control char: {s:?}"
                );
            }
        }
        // The numeric primitive is preserved as a number, not stringified.
        assert!(
            out.values().any(|v| v.as_f64() == Some(1.5)),
            "numeric score value should be preserved"
        );
    }

    /// Company free-text fields share the same sanitizer: the ESC byte of an ANSI
    /// sequence and an embedded newline/NUL are removed and whitespace collapsed.
    /// Only the control bytes are stripped — the inert printable remainder of the
    /// escape (`[31m`) is left as ordinary text rather than lossily mangled.
    #[test]
    fn clean_value_strips_control_characters() {
        let dirty = json!("Acme\u{1b}[31m Corp\nSpA\u{0}");
        let cleaned = clean_value(&dirty);
        assert!(
            !cleaned.chars().any(char::is_control),
            "clean_value left a control char: {cleaned:?}"
        );
        assert_eq!(cleaned, "Acme [31m Corp SpA");
    }
}
