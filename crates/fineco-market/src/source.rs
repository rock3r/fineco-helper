//! Enrichment source-URL allowlisting.
//!
//! The server only ever fetches enrichment from a fixed, configured host. The
//! allowed host(s) are pinned by **SHA-256** so no plaintext host needs to live
//! in source — production supplies the hash (or a hashed-at-startup host from
//! config), and tests inject the mock host. Every fetched/redirect URL must be
//! HTTPS, carry no userinfo, hash into the allowlist, and have a stock-page path.
//! There is no client-supplied URL and no `validateSource` toggle.

use std::collections::HashSet;

use fineco_core::SafeError;
use sha2::{Digest, Sha256};

/// Locale path segments stripped before the stock-page route check.
const LOCALE_SEGMENTS: [&str; 10] = ["de", "en", "es", "fr", "it", "ja", "ko", "nl", "sv", "tr"];

/// The set of allowed enrichment hosts, pinned by SHA-256 of the normalized
/// host. Holds only hashes — never a plaintext host.
#[derive(Clone)]
pub struct EnrichmentHostAllowlist {
    host_hashes: HashSet<String>,
}

impl EnrichmentHostAllowlist {
    /// Build from pre-computed SHA-256 host hashes (hex). Production path: the
    /// hash comes from config, so the plaintext host never enters the binary.
    #[must_use]
    pub fn from_host_hashes<I: IntoIterator<Item = String>>(hashes: I) -> Self {
        Self {
            host_hashes: hashes.into_iter().map(|h| h.to_ascii_lowercase()).collect(),
        }
    }

    /// Build by hashing plaintext hosts at startup (e.g. a host read from an
    /// environment variable, or the mock host in tests). The plaintext is hashed
    /// immediately and not retained.
    #[must_use]
    pub fn from_allowed_hosts<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            host_hashes: hosts
                .into_iter()
                .map(|h| sha256_hex(&normalized_host(h.as_ref())))
                .collect(),
        }
    }

    fn allows(&self, normalized_host: &str) -> bool {
        self.host_hashes.contains(&sha256_hex(normalized_host))
    }
}

/// Validate that `url` is an acceptable enrichment source: HTTPS, no userinfo,
/// an allowlisted host, and a stock-page path.
///
/// # Errors
/// Returns [`SafeError::invalid_request`] with a payload-free message for any
/// violation. The URL is never echoed into the message.
pub fn validate_source_url(
    url: &str,
    allowlist: &EnrichmentHostAllowlist,
) -> Result<(), SafeError> {
    let (scheme, authority, path) = split_url(url)
        .ok_or_else(|| SafeError::invalid_request("Enrichment source URL is malformed."))?;

    if !scheme.eq_ignore_ascii_case("https") {
        return Err(SafeError::invalid_request(
            "Enrichment source URL must use https.",
        ));
    }
    check_authority_and_path(authority, path, allowlist)
}

/// Validates the host pin + stock-page path for a URL the server built from a
/// trusted, configured base. The transport requirement (https, or loopback http
/// only for the local mock) is enforced separately at the request layer so it
/// applies uniformly to every market fetch (see the client) — a misconfigured
/// base or crafted identifier cannot reach an off-allowlist host or non-stock
/// path, nor send over cleartext to a real host.
pub(crate) fn validate_fetch_target(
    url: &str,
    allowlist: &EnrichmentHostAllowlist,
) -> Result<(), SafeError> {
    let (_scheme, authority, path) = split_url(url)
        .ok_or_else(|| SafeError::invalid_request("Enrichment source URL is malformed."))?;
    check_authority_and_path(authority, path, allowlist)
}

/// Shared host/path checks: no userinfo, an allowlisted host, a stock-page path.
fn check_authority_and_path(
    authority: &str,
    path: &str,
    allowlist: &EnrichmentHostAllowlist,
) -> Result<(), SafeError> {
    if authority.contains('@') {
        return Err(SafeError::invalid_request(
            "Enrichment source URL must not include credentials.",
        ));
    }
    // A port, if present on a non-bracketed authority, must be numeric — a
    // malformed authority must not slip through host normalization.
    if !authority.starts_with('[')
        && let Some((_host, port)) = authority.rsplit_once(':')
        && (port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(SafeError::invalid_request(
            "Enrichment source URL has an invalid port.",
        ));
    }
    let host = normalized_host(authority);
    if host.is_empty() {
        return Err(SafeError::invalid_request(
            "Enrichment source URL has no host.",
        ));
    }
    if !allowlist.allows(&host) {
        return Err(SafeError::invalid_request(
            "Enrichment source host is not allowed.",
        ));
    }
    if !is_stock_page_path(&normalized_path(path)) {
        return Err(SafeError::invalid_request(
            "Enrichment source URL does not look like a stock page.",
        ));
    }
    Ok(())
}

/// Split `scheme://authority/path` into its parts, dropping query and fragment
/// from the path. Returns `None` if there is no `://`.
fn split_url(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let after = &rest[authority_end..];
    let path = if after.starts_with('/') {
        let path_end = after.find(['?', '#']).unwrap_or(after.len());
        &after[..path_end]
    } else {
        "/"
    };
    Some((scheme, authority, path))
}

/// Lowercase host without port or trailing dot. Handles bracketed IPv6
/// authorities (`[::1]:8080` → `::1`) as well as host[:port].
fn normalized_host(authority: &str) -> String {
    let host = if let Some(after_bracket) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal: `[addr]:port` → `addr`.
        after_bracket.split(']').next().unwrap_or(after_bracket)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Strip a leading locale segment (`/it`, `/en`, …) when it precedes a stock
/// page route.
fn normalized_path(path: &str) -> String {
    for locale in LOCALE_SEGMENTS {
        if let Some(rest) = path.strip_prefix(&format!("/{locale}"))
            && is_stock_page_path(rest)
        {
            return rest.to_string();
        }
    }
    path.to_string()
}

fn is_stock_page_path(path: &str) -> bool {
    path.starts_with("/stocks/") || path.starts_with("/stock/")
}

/// Lowercase hex SHA-256 of `input`.
fn sha256_hex(input: &str) -> String {
    Sha256::digest(input.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
