//! Transport-security helpers shared by the credentialed worker and the
//! credential-free market client.

/// True if `url` is safe to carry credentials, cookies, or private reads: it
/// uses `https`, or it uses `http` only against a **loopback** host (the local
/// mock). This refuses sending anything sensitive over cleartext to a
/// non-loopback host while keeping the loopback test mock usable.
#[must_use]
pub fn is_secure_or_loopback(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    if scheme.eq_ignore_ascii_case("https") {
        return true;
    }
    if !scheme.eq_ignore_ascii_case("http") {
        return false;
    }
    // Plain http is permitted only against a loopback host.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Drop any userinfo (`user@host`) — the host is what follows the last `@`.
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(after_bracket) = host_port.strip_prefix('[') {
        // Bracketed IPv6 literal: `[::1]:port`.
        after_bracket.split(']').next().unwrap_or(after_bracket)
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    // `localhost`, or an IP that actually parses as a loopback address. Parsing
    // via `std::net` bounds each octet (so `127.999.999.999` is rejected) and
    // covers `::1` for free.
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::is_secure_or_loopback;

    #[test]
    fn https_is_always_secure() {
        assert!(is_secure_or_loopback("https://example.com/x"));
        assert!(is_secure_or_loopback("HTTPS://example.com/x"));
    }

    #[test]
    fn http_is_allowed_only_for_loopback() {
        assert!(is_secure_or_loopback("http://127.0.0.1/x"));
        assert!(is_secure_or_loopback("http://127.0.0.1:8080/stocks/x"));
        assert!(is_secure_or_loopback("http://localhost:3000/x"));
        assert!(is_secure_or_loopback("http://[::1]:9/x"));
        assert!(!is_secure_or_loopback("http://example.com/x"));
        assert!(!is_secure_or_loopback("http://10.0.0.1/x"));
    }

    #[test]
    fn loopback_lookalikes_are_not_loopback() {
        // A non-loopback host that merely starts with or contains 127.
        assert!(!is_secure_or_loopback("http://127.0.0.1.evil.com/x"));
        // Userinfo cannot smuggle a non-loopback host past the check.
        assert!(!is_secure_or_loopback("http://127.0.0.1@evil.com/x"));
        // Out-of-range octets are not a valid (loopback) IP.
        assert!(!is_secure_or_loopback("http://127.999.999.999/x"));
        assert!(!is_secure_or_loopback("http://127.0.0.1.5/x"));
    }

    #[test]
    fn non_http_schemes_and_garbage_are_not_secure() {
        assert!(!is_secure_or_loopback("ftp://127.0.0.1/x"));
        assert!(!is_secure_or_loopback("file:///etc/passwd"));
        assert!(!is_secure_or_loopback("not-a-url"));
    }
}
