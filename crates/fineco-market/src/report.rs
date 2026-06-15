//! Build a bounded, structured enrichment report from the parsed query cache.
//!
//! Navigates the React-Query cache to a profile entry, extracts the company/fund
//! overview, scores, and per-section metrics, and optionally verifies an
//! expected ISIN. All external free text and raw score/metric output is
//! size-limited and reduced to primitives — never echoed unbounded.

use fineco_core::{SafeError, sanitize_text, truncate_text};
use serde::Serialize;
use serde_json::{Map, Value};

/// Max characters kept for any external free-text string. Shared with the ETF
/// list path in `client.rs`, which sanitizes its untrusted string fields too.
pub(crate) const MAX_STR: usize = fineco_core::MAX_TEXT_FIELD_CHARS;
/// Max entries kept from the scores object.
const MAX_SCORE_ENTRIES: usize = 64;
/// Max metric entries kept per analysis section (mirrors the TS `slice(0, 16)`).
const MAX_METRICS_PER_SECTION: usize = 16;
/// React-Query profile keys observed for enrichment pages. Equities use
/// `company`; ETF/fund pages can use fund-oriented keys with the same nested
/// analysis shape.
const PROFILE_QUERY_KEYS: [&str; 3] = ["company", "fund", "etf"];
/// Raw-info object keys observed under `raw_data.data`.
const COMPANY_RAW_INFO_KEYS: &[&str] = &["company_info"];
const FUND_RAW_INFO_KEYS: &[&str] = &["fund_info", "asset_info"];
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

/// A bounded, structured enrichment report (the `external_enrichment` payload).
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct EnrichmentReport {
    pub captured_at: String,
    pub source_url: String,
    pub company: CompanyOverview,
    pub scores: Value,
    pub metrics: Value,
    pub warnings: Vec<String>,
}

/// Assemble a report from the parsed `state`, stamped with `captured_at` and the
/// validated `source_url`. If `expected_isin` is given, select and verify the
/// profile by exact ISIN match.
///
/// # Errors
/// Returns [`SafeError::invalid_request`] if the cache lacks a recognized
/// profile entry.
pub(crate) fn build_report(
    state: &Value,
    source_url: &str,
    captured_at: &str,
    expected_isin: Option<&str>,
) -> Result<EnrichmentReport, SafeError> {
    let expected_isin = normalize_expected_isin(expected_isin)?;
    let profile = profile_query(state, expected_isin.as_deref())
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
    if let Some(expected) = expected_isin.as_deref() {
        if company.isin.is_empty() {
            return Err(SafeError::invalid_request(
                "Enrichment page did not expose the expected ISIN.",
            ));
        }
        if page_isin_for_compare(&company.isin).as_deref() != Some(expected) {
            return Err(SafeError::invalid_request(
                "Enrichment page ISIN did not match expected_isin.",
            ));
        }
    }

    Ok(EnrichmentReport {
        captured_at: captured_at.to_string(),
        source_url: source_url.to_string(),
        scores: Value::Object(bounded_primitive_map(scores_src, MAX_SCORE_ENTRIES)),
        metrics: section_metrics(analysis),
        company,
        warnings,
    })
}

/// Find the best recognized company/fund profile cache entry and return its
/// `state.data`. If the caller supplied an expected ISIN, prefer the profile
/// whose extracted overview exposes that exact ISIN; otherwise keep the cache
/// source order.
fn profile_query<'a>(
    state: &'a Value,
    expected_isin: Option<&str>,
) -> Option<ProfileCandidate<'a>> {
    let candidates = profile_queries(state);
    if let Some(expected) = expected_isin {
        let matching_candidates = candidates
            .iter()
            .copied()
            .filter(|profile| {
                page_isin_for_compare(&company_overview(*profile).isin).as_deref() == Some(expected)
            })
            .collect::<Vec<_>>();
        if !matching_candidates.is_empty() {
            return select_preferred_profile(&matching_candidates);
        }
    }
    select_preferred_profile(&candidates)
}

fn select_preferred_profile<'a>(
    candidates: &[ProfileCandidate<'a>],
) -> Option<ProfileCandidate<'a>> {
    let analysis_candidates = candidates
        .iter()
        .copied()
        .filter(|profile| profile_has_extended_analysis(*profile))
        .collect::<Vec<_>>();
    let preferred_fallback_candidates = if analysis_candidates.is_empty() {
        candidates
    } else {
        &analysis_candidates
    };
    preferred_fallback_candidates
        .iter()
        .copied()
        .find(|profile| profile_is_usable(*profile))
        .or_else(|| {
            candidates
                .iter()
                .copied()
                .find(|profile| profile_is_usable(*profile))
        })
        .or_else(|| preferred_fallback_candidates.first().copied())
        .or_else(|| candidates.first().copied())
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

fn profile_has_extended_analysis(profile: ProfileCandidate<'_>) -> bool {
    profile
        .data
        .pointer("/data/analysis/data/extended/data")
        .is_some()
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
    let mut values = raw_info_keys(profile_kind)
        .iter()
        .filter_map(|key| raw.get(key))
        .filter(|value| raw_info_score(value) > 0)
        .collect::<Vec<_>>();
    values.sort_by_key(|value| std::cmp::Reverse(raw_info_score(value)));
    values.into_iter()
}

fn raw_info_keys(profile_kind: &str) -> &'static [&'static str] {
    match profile_kind {
        "fund" | "etf" => FUND_RAW_INFO_KEYS,
        _ => COMPANY_RAW_INFO_KEYS,
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
        Value::Number(n) => truncate_text(&n.to_string(), MAX_STR),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
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

// ---- ISIN verification -----------------------------------------------------

pub(crate) fn normalize_expected_isin(
    expected_isin: Option<&str>,
) -> Result<Option<String>, SafeError> {
    let Some(raw) = expected_isin else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    fineco_core::normalize_expected_isin(raw).map(Some)
}

fn page_isin_for_compare(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let isin = trimmed.split_once('.').map_or(trimmed, |(isin, _)| isin);
    let isin = isin.to_ascii_uppercase();
    is_isin(&isin).then_some(isin)
}

fn is_isin(value: &str) -> bool {
    let chars = value.chars().collect::<Vec<_>>();
    chars.len() == 12
        && chars[0].is_ascii_alphabetic()
        && chars[1].is_ascii_alphabetic()
        && chars[2..11].iter().all(|c| c.is_ascii_alphanumeric())
        && chars[11].is_ascii_digit()
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
