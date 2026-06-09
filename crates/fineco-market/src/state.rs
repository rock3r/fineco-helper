//! Parse-not-execute extraction of the embedded React-Query cache.
//!
//! The page embeds `window.__REACT_QUERY_STATE__ = {…}` in a `<script>`. We
//! extract that payload textually, normalize the only JS-ism that appears (bare
//! `undefined` → `null`, outside string literals), and parse it with
//! `serde_json`. The content is treated strictly as **data** — there is no
//! `eval`, `Function`, or JS engine anywhere in this path.

use fineco_core::SafeError;
use serde_json::Value;

/// Reject pages larger than this before doing any work (bounds memory/time).
const MAX_HTML_BYTES: usize = 4 * 1024 * 1024;

/// The assignment marker that precedes the embedded cache payload.
const MARKER: &str = "window.__REACT_QUERY_STATE__";

/// Extract and parse the embedded query-cache object from page `html`.
///
/// # Errors
/// Returns [`SafeError::invalid_request`] if the page is too large, the marker
/// is absent, or the payload is not a JSON object. The raw payload is never
/// echoed into the error.
pub(crate) fn parse_enrichment_state(html: &str) -> Result<Value, SafeError> {
    if html.len() > MAX_HTML_BYTES {
        return Err(SafeError::invalid_request("Enrichment page is too large."));
    }

    let payload = extract_payload(html).ok_or_else(|| {
        SafeError::invalid_request("Could not find the embedded query cache in the page.")
    })?;

    let normalized = normalize_json_like(payload.trim().trim_end_matches(';'));
    let value: Value = serde_json::from_str(&normalized)
        .map_err(|_| SafeError::invalid_request("Embedded query cache was not valid JSON data."))?;

    if !value.is_object() {
        return Err(SafeError::invalid_request(
            "Embedded query cache was not a JSON object.",
        ));
    }
    Ok(value)
}

/// Slice the payload text: everything after the first `=` following the marker,
/// up to the closing `</script>`.
fn extract_payload(html: &str) -> Option<&str> {
    let marker = html.find(MARKER)?;
    let after_marker = &html[marker + MARKER.len()..];
    let eq = after_marker.find('=')?;
    let after_eq = &after_marker[eq + 1..];
    let end = after_eq.find("</script>")?;
    Some(&after_eq[..end])
}

/// Replace bare `undefined` tokens (outside string literals, at identifier
/// boundaries) with `null`. Everything else is copied verbatim, so string
/// contents — including multibyte UTF-8 and the literal text `undefined` inside
/// a string — are preserved.
fn normalize_json_like(payload: &str) -> String {
    const UNDEFINED: &str = "undefined";
    let mut out = String::with_capacity(payload.len());
    let mut in_string = false;
    let mut escaped = false;
    // The source character immediately before the current position (TS uses
    // `payload[index - 1]` for the left identifier boundary).
    let mut prev_char: Option<char> = None;

    let mut iter = payload.char_indices().peekable();
    while let Some((idx, c)) = iter.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            prev_char = Some(c);
            continue;
        }

        if c == '"' {
            in_string = true;
            out.push(c);
            prev_char = Some(c);
            continue;
        }

        if c == 'u' && payload[idx..].starts_with(UNDEFINED) && !is_identifier_char(prev_char) {
            let after = idx + UNDEFINED.len();
            let next_is_ident = payload[after..]
                .chars()
                .next()
                .is_some_and(|next| is_identifier_char(Some(next)));
            if !next_is_ident {
                out.push_str("null");
                // Consume the remaining characters of `undefined`; the last one
                // ('d') becomes the previous-char for the next iteration.
                for _ in 1..UNDEFINED.len() {
                    iter.next();
                }
                prev_char = Some('d');
                continue;
            }
        }

        out.push(c);
        prev_char = Some(c);
    }

    out
}

/// True for the identifier characters JS allows around a token boundary.
fn is_identifier_char(c: Option<char>) -> bool {
    matches!(c, Some(ch) if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
}
