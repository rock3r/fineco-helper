/// Max characters kept for untrusted provider free text before it reaches an
/// MCP client. This is intentionally conservative: provider prose is data, not
/// instructions, and long text belongs in an explicit future section/cache.
pub const MAX_TEXT_FIELD_CHARS: usize = 2000;

/// Sanitize untrusted provider text before returning it to a model: replace
/// control characters with spaces, collapse whitespace, trim, and length-bound
/// on a char boundary.
#[must_use]
pub fn sanitize_text(raw: &str) -> String {
    let stripped: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let collapsed = stripped.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_text(&collapsed, MAX_TEXT_FIELD_CHARS)
}

/// Truncate `s` to at most `max` characters, preserving char boundaries.
#[must_use]
pub fn truncate_text(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_TEXT_FIELD_CHARS, sanitize_text, truncate_text};

    #[test]
    fn sanitize_text_strips_controls_collapses_whitespace_and_bounds() {
        let raw = format!(
            " first\n\t\0\x1b[31m second  {}",
            "x".repeat(MAX_TEXT_FIELD_CHARS + 20)
        );
        let cleaned = sanitize_text(&raw);

        assert!(!cleaned.contains('\n'));
        assert!(!cleaned.contains('\t'));
        assert!(!cleaned.contains('\0'));
        assert!(!cleaned.contains('\x1b'));
        assert!(cleaned.starts_with("first [31m second "));
        assert!(cleaned.chars().count() <= MAX_TEXT_FIELD_CHARS);
    }

    #[test]
    fn truncate_text_preserves_char_boundaries() {
        assert_eq!(truncate_text("åβc", 2), "åβ");
    }
}
