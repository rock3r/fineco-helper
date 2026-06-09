//! Tests for the binary's server roles: loopback bind safety, environment
//! config parsing, and a real store-server socket round-trip.

use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use fineco_helper::serve::{
    BackupConfig, GatewayConfig, PrivateWorkerConfig, RefreshTriggerConfig, StoreServerConfig,
    load_policy, parse_refresh_area, resolve_loopback_bind, run_backup, run_refresh,
    run_store_server, serve_live,
};
use fineco_ipc::{Client, RefreshRequest, Request, ResponseBody};
use fineco_store::{NewPortfolioSnapshot, Store};

/// A dummy policy path for `from_env` tests (the file is read only at run time).
const POLICY_PATH: &str = "/tmp/fineco-policy-unused.json";

/// A policy JSON document granting the owner every M4 capability.
const OWNER_POLICY_JSON: &str = r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
    "market.read","portfolio.cached.full_read","portfolio.shareable.read",
    "orders.cached.read","tax.cached.read"]}}}"#;

/// An environment getter backed by a fixed map.
fn env_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    move |key: &str| map.get(key).cloned()
}

#[test]
fn loopback_binds_are_accepted() {
    for addr in ["127.0.0.1:8765", "127.0.0.1:0", "[::1]:8765"] {
        let resolved = resolve_loopback_bind(addr).expect("loopback accepted");
        assert!(resolved.ip().is_loopback(), "{addr} should be loopback");
    }
}

#[test]
fn non_loopback_binds_are_refused() {
    for addr in ["0.0.0.0:8765", "198.51.100.10:8765", "[::]:8765"] {
        let err = resolve_loopback_bind(addr).expect_err("non-loopback refused");
        assert!(
            err.to_string().contains("non-loopback"),
            "message for {addr}: {err}"
        );
    }
}

#[test]
fn malformed_bind_is_refused() {
    for addr in ["not-an-addr", "127.0.0.1", "127.0.0.1:notaport", ""] {
        assert!(
            resolve_loopback_bind(addr).is_err(),
            "{addr} should be rejected"
        );
    }
}

#[test]
fn gateway_config_defaults_to_loopback_without_market() {
    let config = GatewayConfig::from_env(env_from(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_DISABLED", "true"),
    ]))
    .expect("config");
    assert_eq!(config.bind.to_string(), "127.0.0.1:8765");
    assert_eq!(config.socket_path.to_str(), Some("/tmp/q.sock"));
    assert_eq!(config.policy_path.to_str(), Some(POLICY_PATH));
    assert!(config.market.is_none(), "no market vars => market disabled");
}

#[test]
fn gateway_config_refuses_to_run_without_access_or_an_explicit_opt_out() {
    // The dangerous silent-off failure: a missing Access config must NOT quietly
    // disable authentication — startup fails unless explicitly opted out.
    let message = gateway_config_err(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
    ]);
    assert!(
        message.contains("Cloudflare Access is not configured"),
        "message: {message}"
    );
}

#[test]
fn gateway_config_requires_the_policy_path() {
    let message = gateway_config_err(&[("FINECO_QUERY_SOCKET", "/tmp/q.sock")]);
    assert!(message.contains("FINECO_POLICY_PATH"), "message: {message}");
}

// `GatewayConfig` holds a `MarketClient` (not `Debug`), so match on the result
// rather than using `expect_err`.
fn gateway_config_err(pairs: &[(&str, &str)]) -> String {
    match GatewayConfig::from_env(env_from(pairs)) {
        Ok(_) => panic!("expected a config error for {pairs:?}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn gateway_config_requires_the_socket() {
    assert!(gateway_config_err(&[]).contains("FINECO_QUERY_SOCKET"));
}

#[test]
fn gateway_config_refuses_a_non_loopback_bind() {
    let message = gateway_config_err(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_GATEWAY_BIND", "0.0.0.0:8765"),
    ]);
    assert!(message.contains("non-loopback"), "message: {message}");
}

#[test]
fn gateway_config_builds_market_and_an_explicit_etf_url_overrides_the_default() {
    let config = GatewayConfig::from_env(env_from(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_DISABLED", "true"),
        ("FINECO_ENRICHMENT_BASE", "https://enrich.example"),
        ("FINECO_ETF_URL", "https://etf.example/list.json"),
        ("FINECO_ENRICHMENT_HOST_HASHES", "abc123,def456"),
    ]))
    .expect("config");
    let market = config
        .market
        .expect("the enrichment pair => market enabled");
    // An explicit FINECO_ETF_URL overrides the built-in default.
    assert_eq!(
        market.zero_commission_etfs_url(),
        "https://etf.example/list.json"
    );
}

#[test]
fn gateway_config_defaults_the_etf_url_when_unset() {
    // FINECO_ETF_URL is optional: the enrichment pair alone enables the market
    // tools, and the zero-commission list defaults to the fixed public Fineco
    // endpoint (it is not per-deployment config).
    let config = GatewayConfig::from_env(env_from(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_DISABLED", "true"),
        ("FINECO_ENRICHMENT_BASE", "https://enrich.example"),
        ("FINECO_ENRICHMENT_HOST_HASHES", "abc123"),
        // no FINECO_ETF_URL
    ]))
    .expect("market enabled without an explicit ETF URL");
    let market = config.market.expect("market enabled");
    assert_eq!(
        market.zero_commission_etfs_url(),
        "https://images.finecobank.com/common-pvt/js/json/etf-zero/etf_piu_scambiati.json"
    );
}

#[test]
fn gateway_config_treats_a_blank_etf_url_as_unset() {
    // A present-but-empty/whitespace FINECO_ETF_URL must fall back to the default,
    // not become the literal (empty) ETF endpoint — same blank-is-no-override rule
    // as the Access pins. A stray `FINECO_ETF_URL=` in an env file must not break
    // the zero-commission list.
    let config = GatewayConfig::from_env(env_from(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_DISABLED", "true"),
        ("FINECO_ENRICHMENT_BASE", "https://enrich.example"),
        ("FINECO_ENRICHMENT_HOST_HASHES", "abc123"),
        ("FINECO_ETF_URL", "   "),
    ]))
    .expect("market enabled with a blank ETF URL");
    let market = config.market.expect("market enabled");
    assert_eq!(
        market.zero_commission_etfs_url(),
        "https://images.finecobank.com/common-pvt/js/json/etf-zero/etf_piu_scambiati.json"
    );
}

#[test]
fn gateway_config_rejects_partial_market() {
    // The enrichment base without the host hashes (or vice-versa) is a
    // misconfiguration (fail closed). FINECO_ETF_URL is optional, so its absence
    // is not "partial".
    let message = gateway_config_err(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ENRICHMENT_BASE", "https://enrich.example"),
    ]);
    assert!(message.contains("market config"), "message: {message}");
}

#[test]
fn gateway_config_access_disabled_opt_out_yields_no_access() {
    let config = GatewayConfig::from_env(env_from(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_DISABLED", "true"),
    ]))
    .expect("config");
    assert!(
        config.access.is_none(),
        "explicit opt-out => Access disabled"
    );
    assert!(config.allowed_origins.is_empty());
}

#[test]
fn gateway_config_builds_access_and_parses_origins() {
    let config = GatewayConfig::from_env(env_from(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_ISSUER", "https://team.cloudflareaccess.com"),
        ("FINECO_ACCESS_AUDIENCE", "aud-tag"),
        (
            "FINECO_ACCESS_JWKS_URL",
            "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
        ),
        ("FINECO_OWNER_EMAIL", "owner@example.com"),
        (
            "FINECO_ALLOWED_ORIGINS",
            "https://a.example, https://b.example",
        ),
    ]))
    .expect("config");
    let access = config.access.expect("Access configured");
    assert_eq!(access.issuer, "https://team.cloudflareaccess.com");
    assert_eq!(access.audience, "aud-tag");
    assert_eq!(access.owner_email.as_deref(), Some("owner@example.com"));
    assert_eq!(access.owner_common_name, None);
    assert_eq!(
        config.allowed_origins,
        vec![
            "https://a.example".to_string(),
            "https://b.example".to_string()
        ]
    );
}

#[test]
fn gateway_config_requires_an_identity_pin_when_access_is_enabled() {
    // Defense in depth: with Access ON but NO identity pin, ANY token the Cloudflare
    // Access policy admits maps to `owner` — so a later widening of the Access policy
    // would silently grant ownership. Remote mode must require at least one pin.
    let message = gateway_config_err(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_ISSUER", "https://team.cloudflareaccess.com"),
        ("FINECO_ACCESS_AUDIENCE", "aud-tag"),
        (
            "FINECO_ACCESS_JWKS_URL",
            "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
        ),
        // deliberately NO FINECO_OWNER_EMAIL / FINECO_ACCESS_OWNER_COMMON_NAME
    ]);
    assert!(
        message.contains("no owner identity is pinned"),
        "message should demand an identity pin, got: {message}"
    );
}

#[test]
fn gateway_config_reads_the_service_token_common_name_pin() {
    // A service-token deployment pins common_name (and leaves the email pin unset).
    let config = GatewayConfig::from_env(env_from(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_ISSUER", "https://team.cloudflareaccess.com"),
        ("FINECO_ACCESS_AUDIENCE", "aud-tag"),
        (
            "FINECO_ACCESS_JWKS_URL",
            "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
        ),
        (
            "FINECO_ACCESS_OWNER_COMMON_NAME",
            "78599ba946c2e172fc40b29726e4d835.access",
        ),
    ]))
    .expect("config");
    let access = config.access.expect("Access configured");
    assert_eq!(access.owner_email, None);
    assert_eq!(
        access.owner_common_name.as_deref(),
        Some("78599ba946c2e172fc40b29726e4d835.access")
    );
}

#[test]
fn gateway_config_accepts_both_identity_pins() {
    // Dual-pin: an email pin (interactive SSO/OAuth — ChatGPT/Claude connectors)
    // AND a common_name pin (service token — CLI clients) coexist on one
    // deployment; the verifier maps a token matching EITHER to owner. Both pins
    // are read into the Access settings (no longer a startup error).
    let config = GatewayConfig::from_env(env_from(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_ISSUER", "https://team.cloudflareaccess.com"),
        ("FINECO_ACCESS_AUDIENCE", "aud-tag"),
        (
            "FINECO_ACCESS_JWKS_URL",
            "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
        ),
        ("FINECO_OWNER_EMAIL", "owner@example.com"),
        (
            "FINECO_ACCESS_OWNER_COMMON_NAME",
            "78599ba946c2e172fc40b29726e4d835.access",
        ),
    ]))
    .expect("dual-pin config builds");
    let access = config.access.expect("Access configured");
    assert_eq!(access.owner_email.as_deref(), Some("owner@example.com"));
    assert_eq!(
        access.owner_common_name.as_deref(),
        Some("78599ba946c2e172fc40b29726e4d835.access")
    );
}

/// A dual-pin (email + service-token) Access env — the only shape with a connector
/// channel to scope.
fn dual_pin_base() -> Vec<(&'static str, &'static str)> {
    vec![
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_ISSUER", "https://team.cloudflareaccess.com"),
        ("FINECO_ACCESS_AUDIENCE", "aud-tag"),
        (
            "FINECO_ACCESS_JWKS_URL",
            "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
        ),
        ("FINECO_OWNER_EMAIL", "owner@example.com"),
        (
            "FINECO_ACCESS_OWNER_COMMON_NAME",
            "78599ba946c2e172fc40b29726e4d835.access",
        ),
    ]
}

#[test]
fn connector_allowlist_defaults_to_everything_but_detailed_portfolio_under_dual_pin() {
    let config = GatewayConfig::from_env(env_from(&dual_pin_base())).expect("config");
    let allow = config
        .connector_allowlist
        .expect("dual-pin sets a connector allowlist");
    assert!(allow.contains(&"portfolio_get_latest_shareable_report".to_string()));
    assert!(allow.contains(&"private_portfolio_refresh_live_sensitive".to_string()));
    // The four detailed-portfolio tools are excluded by default.
    assert!(!allow.contains(&"portfolio_get_latest_full_snapshot".to_string()));
    assert!(!allow.contains(&"portfolio_get_history".to_string()));
}

#[test]
fn connector_allowlist_star_opts_out_of_restriction() {
    let mut env = dual_pin_base();
    env.push(("FINECO_CONNECTOR_TOOLS", "*"));
    let config = GatewayConfig::from_env(env_from(&env)).expect("config");
    assert!(
        config.connector_allowlist.is_none(),
        "`*` means connectors get every tool"
    );
}

#[test]
fn connector_allowlist_honors_an_explicit_list() {
    let mut env = dual_pin_base();
    env.push((
        "FINECO_CONNECTOR_TOOLS",
        "portfolio_get_freshness, market_get_zero_commission_etfs",
    ));
    let config = GatewayConfig::from_env(env_from(&env)).expect("config");
    let allow = config.connector_allowlist.expect("allowlist");
    assert_eq!(allow.len(), 2);
    assert!(allow.contains(&"portfolio_get_freshness".to_string()));
    assert!(allow.contains(&"market_get_zero_commission_etfs".to_string()));
}

#[test]
fn connector_allowlist_rejects_an_unknown_tool() {
    let mut env = dual_pin_base();
    env.push((
        "FINECO_CONNECTOR_TOOLS",
        "portfolio_get_freshness,bogus_tool",
    ));
    let message = gateway_config_err(&env);
    assert!(
        message.contains("unknown tool 'bogus_tool'"),
        "message: {message}"
    );
}

#[test]
fn connector_allowlist_applies_to_a_single_email_pin() {
    // A single EMAIL pin (no service token) still has a connector channel, so the
    // allowlist is installed by default — a connector must not get the full set just
    // because no service-token pin is also configured (fail-safe vs accidental
    // exposure).
    let config = GatewayConfig::from_env(env_from(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_ISSUER", "https://team.cloudflareaccess.com"),
        ("FINECO_ACCESS_AUDIENCE", "aud-tag"),
        (
            "FINECO_ACCESS_JWKS_URL",
            "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
        ),
        ("FINECO_OWNER_EMAIL", "owner@example.com"),
    ]))
    .expect("config");
    let allow = config
        .connector_allowlist
        .expect("an email pin installs the connector allowlist");
    assert!(!allow.contains(&"portfolio_get_latest_full_snapshot".to_string()));
}

#[test]
fn connector_tools_var_requires_an_email_pin() {
    // Service-token-only (no email pin) with FINECO_CONNECTOR_TOOLS set is a hard
    // error — there is no connector channel to scope.
    let message = gateway_config_err(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_ISSUER", "https://team.cloudflareaccess.com"),
        ("FINECO_ACCESS_AUDIENCE", "aud-tag"),
        (
            "FINECO_ACCESS_JWKS_URL",
            "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
        ),
        (
            "FINECO_ACCESS_OWNER_COMMON_NAME",
            "78599ba946c2e172fc40b29726e4d835.access",
        ),
        ("FINECO_CONNECTOR_TOOLS", "portfolio_get_freshness"),
    ]);
    assert!(
        message.contains("requires an email/OAuth pin"),
        "message: {message}"
    );
}

#[test]
fn gateway_config_rejects_partial_access() {
    // Issuer without audience/jwks is a misconfiguration (fail closed).
    let message = gateway_config_err(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_ISSUER", "https://team.cloudflareaccess.com"),
    ]);
    assert!(message.contains("Access config"), "message: {message}");
}

#[test]
fn gateway_config_rejects_jwks_url_from_a_different_origin_than_issuer() {
    // The key source must be bound to the issuer. A JWKS URL on a *different*
    // origin (e.g. another Cloudflare team) than FINECO_ACCESS_ISSUER must be
    // rejected (fail closed): otherwise the gateway would trust those foreign
    // keys and only check the *claimed* iss/aud, so a token signed by that other
    // key source could assert this issuer/audience and be accepted.
    let message = gateway_config_err(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_ISSUER", "https://team.cloudflareaccess.com"),
        ("FINECO_ACCESS_AUDIENCE", "aud-tag"),
        (
            "FINECO_ACCESS_JWKS_URL",
            "https://evil.cloudflareaccess.com/cdn-cgi/access/certs",
        ),
    ]);
    assert!(
        message.contains("same origin") && message.contains("FINECO_ACCESS_ISSUER"),
        "message: {message}"
    );
}

#[test]
fn gateway_config_accepts_jwks_url_on_the_issuer_origin() {
    // The issuer's own certs endpoint (same origin) is accepted — including a
    // trailing slash on the issuer.
    let config = GatewayConfig::from_env(env_from(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_ISSUER", "https://team.cloudflareaccess.com/"),
        ("FINECO_ACCESS_AUDIENCE", "aud-tag"),
        (
            "FINECO_ACCESS_JWKS_URL",
            "https://team.cloudflareaccess.com/cdn-cgi/access/certs",
        ),
        // Access now requires an identity pin; this test is about the JWKS origin.
        ("FINECO_OWNER_EMAIL", "owner@example.com"),
    ]))
    .expect("same-origin JWKS accepted");
    let access = config.access.expect("Access configured");
    // The trailing slash must be normalized away in the *stored* issuer: it is
    // later fed to `set_issuer`, and Cloudflare's `iss` claim omits the slash, so
    // an un-normalized value would boot fine but reject every valid token (401).
    assert_eq!(access.issuer, "https://team.cloudflareaccess.com");
}

#[test]
fn gateway_config_reads_the_refresh_socket() {
    // Setting FINECO_REFRESH_SOCKET enables the gateway's live-refresh tools
    // (wired to the controller over refresh-control.sock). The gateway still has
    // no fineco-live client — only this refresh-control path.
    let config = GatewayConfig::from_env(env_from(&[
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_DISABLED", "true"),
        ("FINECO_REFRESH_SOCKET", "/run/fineco/refresh.sock"),
    ]))
    .expect("config");
    assert_eq!(
        config.refresh_socket_path.as_deref(),
        Some(std::path::Path::new("/run/fineco/refresh.sock"))
    );
}

#[test]
fn gateway_config_without_a_refresh_socket_is_cached_only() {
    let base = [
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_ACCESS_DISABLED", "true"),
    ];
    let config = GatewayConfig::from_env(env_from(&base)).expect("config");
    assert!(config.refresh_socket_path.is_none());
    // A blank/whitespace value is treated as unset (cached-only), not the literal
    // empty path — a stray `FINECO_REFRESH_SOCKET=` must not break the gateway.
    let mut blank = base.to_vec();
    blank.push(("FINECO_REFRESH_SOCKET", "   "));
    let config = GatewayConfig::from_env(env_from(&blank)).expect("config");
    assert!(config.refresh_socket_path.is_none());
}

#[test]
fn store_server_config_requires_all_paths() {
    assert!(StoreServerConfig::from_env(env_from(&[])).is_err());
    assert!(
        StoreServerConfig::from_env(env_from(&[("FINECO_DB_PATH", "/tmp/db.sqlite")])).is_err()
    );
    // DB + socket but no policy path still fails (fail closed).
    assert!(
        StoreServerConfig::from_env(env_from(&[
            ("FINECO_DB_PATH", "/tmp/db.sqlite"),
            ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ]))
        .is_err()
    );
    let config = StoreServerConfig::from_env(env_from(&[
        ("FINECO_DB_PATH", "/tmp/db.sqlite"),
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
    ]))
    .expect("all present");
    assert_eq!(config.db_path.to_str(), Some("/tmp/db.sqlite"));
    assert_eq!(config.policy_path.to_str(), Some(POLICY_PATH));
}

#[test]
fn store_server_config_pairs_refresh_and_live_sockets_and_treats_blanks_as_unset() {
    let base = [
        ("FINECO_DB_PATH", "/tmp/db.sqlite"),
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
    ];

    // Neither set -> cached-only.
    let config = StoreServerConfig::from_env(env_from(&base)).expect("cached-only");
    assert!(config.refresh_socket_path.is_none() && config.live_socket_path.is_none());

    // Both blank/whitespace -> treated as UNSET (cached-only), not enabled with
    // empty socket paths (matches GatewayConfig). Regression for the Bugbot finding.
    let mut blank = base.to_vec();
    blank.push(("FINECO_REFRESH_SOCKET", "   "));
    blank.push(("FINECO_LIVE_SOCKET", ""));
    let config = StoreServerConfig::from_env(env_from(&blank)).expect("blanks are cached-only");
    assert!(config.refresh_socket_path.is_none() && config.live_socket_path.is_none());

    // Both set -> live refresh enabled.
    let mut both = base.to_vec();
    both.push(("FINECO_REFRESH_SOCKET", "/run/fineco/refresh.sock"));
    both.push(("FINECO_LIVE_SOCKET", "/run/fineco/live.sock"));
    let config = StoreServerConfig::from_env(env_from(&both)).expect("both set");
    assert!(config.refresh_socket_path.is_some() && config.live_socket_path.is_some());

    // Exactly one REAL path set -> partial config fails closed.
    let mut partial = base.to_vec();
    partial.push(("FINECO_REFRESH_SOCKET", "/run/fineco/refresh.sock"));
    assert!(StoreServerConfig::from_env(env_from(&partial)).is_err());
}

/// Build a store-server config from the required vars plus an optional socket
/// mode override.
fn store_config_with_mode(mode: Option<&str>) -> Result<StoreServerConfig, String> {
    let mut pairs = vec![
        ("FINECO_DB_PATH", "/tmp/db.sqlite"),
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
    ];
    if let Some(mode) = mode {
        pairs.push(("FINECO_QUERY_SOCKET_MODE", mode));
    }
    StoreServerConfig::from_env(env_from(&pairs)).map_err(|e| e.to_string())
}

#[test]
fn socket_mode_defaults_to_owner_only() {
    assert_eq!(
        store_config_with_mode(None).expect("config").socket_mode,
        0o600
    );
}

#[test]
fn socket_mode_parses_octal_for_the_ipc_group() {
    // The multi-user topology shares the socket via an IPC group → 0660.
    assert_eq!(
        store_config_with_mode(Some("0660"))
            .expect("config")
            .socket_mode,
        0o660
    );
    assert_eq!(
        store_config_with_mode(Some("600"))
            .expect("config")
            .socket_mode,
        0o600
    );
}

#[test]
fn socket_mode_rejects_world_access_and_garbage() {
    // Fail closed: never a world-reachable socket, owner must keep read+write,
    // and non-octal values are rejected.
    for bad in ["0666", "0644", "0607", "0660-no", "0", "abc", "0o999"] {
        assert!(
            store_config_with_mode(Some(bad)).is_err(),
            "socket mode {bad} must be rejected"
        );
    }
}

#[test]
fn store_server_config_stays_cached_only_without_refresh_vars() {
    let config = StoreServerConfig::from_env(env_from(&[
        ("FINECO_DB_PATH", "/tmp/db.sqlite"),
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
    ]))
    .expect("config");
    assert!(config.refresh_socket_path.is_none());
    assert!(config.live_socket_path.is_none());
}

#[test]
fn store_server_config_enables_refresh_with_both_sockets() {
    let config = StoreServerConfig::from_env(env_from(&[
        ("FINECO_DB_PATH", "/tmp/db.sqlite"),
        ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
        ("FINECO_POLICY_PATH", POLICY_PATH),
        ("FINECO_REFRESH_SOCKET", "/run/fineco/refresh.sock"),
        ("FINECO_LIVE_SOCKET", "/run/fineco/live.sock"),
        ("FINECO_REFRESH_SOCKET_MODE", "0660"),
    ]))
    .expect("config");
    assert_eq!(
        config.refresh_socket_path.as_deref(),
        Some(std::path::Path::new("/run/fineco/refresh.sock"))
    );
    assert_eq!(
        config.live_socket_path.as_deref(),
        Some(std::path::Path::new("/run/fineco/live.sock"))
    );
    assert_eq!(config.refresh_socket_mode, 0o660);
}

#[test]
fn store_server_config_rejects_a_partial_refresh_config() {
    // The refresh-control socket without the worker's live socket (or vice versa)
    // is a misconfiguration — fail closed rather than silently disable refresh.
    for partial in [
        vec![("FINECO_REFRESH_SOCKET", "/run/fineco/refresh.sock")],
        vec![("FINECO_LIVE_SOCKET", "/run/fineco/live.sock")],
    ] {
        let mut pairs = vec![
            ("FINECO_DB_PATH", "/tmp/db.sqlite"),
            ("FINECO_QUERY_SOCKET", "/tmp/q.sock"),
            ("FINECO_POLICY_PATH", POLICY_PATH),
        ];
        pairs.extend(partial);
        assert!(
            StoreServerConfig::from_env(env_from(&pairs)).is_err(),
            "a partial refresh config must be rejected: {pairs:?}"
        );
    }
}

#[test]
fn backup_config_requires_both_paths() {
    assert!(BackupConfig::from_env(env_from(&[])).is_err());
    assert!(
        BackupConfig::from_env(env_from(&[("FINECO_DB_PATH", "/tmp/db.sqlite")])).is_err(),
        "the output path is required"
    );
    let config = BackupConfig::from_env(env_from(&[
        ("FINECO_DB_PATH", "/tmp/db.sqlite"),
        ("FINECO_BACKUP_OUT", "/tmp/backup.sqlite"),
    ]))
    .expect("config");
    assert_eq!(config.db_path.to_str(), Some("/tmp/db.sqlite"));
    assert_eq!(config.out_path.to_str(), Some("/tmp/backup.sqlite"));
}

#[test]
fn backup_role_writes_a_restorable_copy() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let db_path = dir.join(format!("fineco-helper-bk-{pid}.sqlite"));
    let out_path = dir.join(format!("fineco-helper-bk-out-{pid}.sqlite"));
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(&out_path);
    {
        let mut store = Store::open(&db_path).expect("open");
        store
            .capture_portfolio_snapshot(&NewPortfolioSnapshot {
                captured_at: "2026-06-05T10:00:00Z".to_string(),
                source: "test".to_string(),
                market_value: Some(500.0),
                book_value: Some(400.0),
                profit_loss: Some(100.0),
                profit_loss_perc: Some(25.0),
                positions: Vec::new(),
                fx_rates: Vec::new(),
            })
            .expect("capture");
    }

    run_backup(BackupConfig {
        db_path: db_path.clone(),
        out_path: out_path.clone(),
    })
    .expect("backup");

    // The backup re-opens with the data intact (the restore drill in miniature).
    let restored = Store::open(&out_path).expect("open backup");
    let snap = restored
        .latest_portfolio_snapshot()
        .expect("query")
        .expect("a snapshot");
    assert_eq!(snap.market_value, Some(500.0));

    for path in [&db_path, &out_path] {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn private_worker_config_requires_the_live_socket() {
    // `PrivateWorkerConfig` is not `Debug` (mirrors the other role configs), so
    // match on the result rather than `expect_err`.
    let message = match PrivateWorkerConfig::from_env(env_from(&[])) {
        Ok(_) => panic!("the live socket path is required"),
        Err(error) => error.to_string(),
    };
    assert!(message.contains("FINECO_LIVE_SOCKET"), "{message}");
}

#[test]
fn private_worker_config_trims_the_live_socket_to_match_the_store_server() {
    // The controller (StoreServerConfig) trims FINECO_LIVE_SOCKET; the worker binds
    // the SAME var, so it must trim identically or the two target different sockets
    // (Cursor Bugbot regression). Padding is stripped.
    let config = PrivateWorkerConfig::from_env(env_from(&[(
        "FINECO_LIVE_SOCKET",
        "  /run/fineco/live.sock  ",
    )]))
    .expect("a padded path is trimmed");
    assert_eq!(
        config.live_socket_path.to_str(),
        Some("/run/fineco/live.sock")
    );
    // A blank/whitespace value is "missing" — the worker requires the live socket.
    assert!(PrivateWorkerConfig::from_env(env_from(&[("FINECO_LIVE_SOCKET", "   ")])).is_err());
}

#[test]
fn private_worker_config_defaults_to_owner_only_and_production() {
    let config =
        PrivateWorkerConfig::from_env(env_from(&[("FINECO_LIVE_SOCKET", "/run/fineco/live.sock")]))
            .expect("config");
    assert_eq!(
        config.live_socket_path.to_str(),
        Some("/run/fineco/live.sock")
    );
    // Default owner-only; the multi-user deploy overrides to 0660.
    assert_eq!(config.socket_mode, 0o600);
    // No upstream base => the real Fineco production endpoints.
    assert_eq!(config.upstream_base, None);
}

#[test]
fn private_worker_config_parses_group_mode_and_mock_base() {
    let config = PrivateWorkerConfig::from_env(env_from(&[
        ("FINECO_LIVE_SOCKET", "/run/fineco/live.sock"),
        ("FINECO_LIVE_SOCKET_MODE", "0660"),
        ("FINECO_LIVE_UPSTREAM_BASE", "http://127.0.0.1:9999"),
    ]))
    .expect("config");
    assert_eq!(config.socket_mode, 0o660);
    assert_eq!(
        config.upstream_base.as_deref(),
        Some("http://127.0.0.1:9999")
    );
}

#[test]
fn private_worker_config_treats_a_blank_upstream_base_as_production() {
    // A stray `FINECO_LIVE_UPSTREAM_BASE=` in an env file must not become the
    // literal empty base (which would build broken URLs) — it means production.
    let config = PrivateWorkerConfig::from_env(env_from(&[
        ("FINECO_LIVE_SOCKET", "/run/fineco/live.sock"),
        ("FINECO_LIVE_UPSTREAM_BASE", "   "),
    ]))
    .expect("config");
    assert_eq!(config.upstream_base, None);
}

#[test]
fn private_worker_config_rejects_a_world_reachable_socket_mode() {
    for bad in ["0666", "0644", "0607", "abc"] {
        assert!(
            PrivateWorkerConfig::from_env(env_from(&[
                ("FINECO_LIVE_SOCKET", "/run/fineco/live.sock"),
                ("FINECO_LIVE_SOCKET_MODE", bad),
            ]))
            .is_err(),
            "live socket mode {bad} must be rejected"
        );
    }
}

#[test]
fn load_policy_reads_a_valid_file_and_rejects_bad_ones() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let good = dir.join(format!("fineco-policy-good-{pid}.json"));
    let bad = dir.join(format!("fineco-policy-bad-{pid}.json"));
    std::fs::write(&good, OWNER_POLICY_JSON).expect("write good policy");
    std::fs::write(
        &bad,
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":["admin"]}}}"#,
    )
    .expect("write bad policy");

    let policy = load_policy(&good).expect("valid policy loads");
    assert!(policy.allows("owner", fineco_ipc::Capability::MarketRead));

    assert!(load_policy(&bad).is_err(), "unknown capability rejected");
    assert!(
        load_policy(&dir.join("fineco-policy-does-not-exist.json")).is_err(),
        "missing file rejected"
    );

    let _ = std::fs::remove_file(&good);
    let _ = std::fs::remove_file(&bad);
}

#[test]
fn store_server_refuses_to_take_over_a_live_socket() {
    use std::os::unix::net::UnixListener;
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let db_path = dir.join(format!("fineco-helper-live-{pid}.sqlite"));
    let policy_path = dir.join(format!("fineco-helper-live-{pid}.policy.json"));
    let socket_path = dir.join(format!("fineco-helper-live-{pid}.sock"));
    let _ = std::fs::remove_file(&socket_path);
    std::fs::write(&policy_path, OWNER_POLICY_JSON).expect("write policy");

    // Simulate a running worker by holding a live listener on the socket path.
    let listener = UnixListener::bind(&socket_path).expect("bind live socket");

    let config = StoreServerConfig {
        db_path: db_path.clone(),
        socket_path: socket_path.clone(),
        policy_path: policy_path.clone(),
        socket_mode: 0o600,
        refresh_socket_path: None,
        live_socket_path: None,
        refresh_socket_mode: 0o600,
    };
    let result = run_store_server(config);
    assert!(result.is_err(), "must refuse to take over a live socket");
    assert!(socket_path.exists(), "the live socket must be left intact");

    drop(listener);
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(&policy_path);
    let _ = std::fs::remove_file(&socket_path);
}

#[test]
fn store_server_refuses_a_non_socket_query_path_without_deleting_it() {
    // A misconfigured FINECO_QUERY_SOCKET pointing at a real file (e.g. the DB or
    // a typo) must NOT be unlinked on startup.
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let db_path = dir.join(format!("fineco-helper-guard-{pid}.sqlite"));
    let policy_path = dir.join(format!("fineco-helper-guard-{pid}.policy.json"));
    let precious = dir.join(format!("fineco-helper-guard-{pid}.precious"));
    std::fs::write(&policy_path, OWNER_POLICY_JSON).expect("write policy");
    std::fs::write(&precious, b"do not delete me").expect("write precious file");

    let config = StoreServerConfig {
        db_path: db_path.clone(),
        socket_path: precious.clone(),
        policy_path: policy_path.clone(),
        socket_mode: 0o600,
        refresh_socket_path: None,
        live_socket_path: None,
        refresh_socket_mode: 0o600,
    };
    let result = run_store_server(config);
    assert!(result.is_err(), "a non-socket query path must be refused");
    assert!(
        precious.exists(),
        "the existing non-socket file must not be deleted"
    );
    assert_eq!(
        std::fs::read(&precious).expect("read precious"),
        b"do not delete me"
    );

    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(&policy_path);
    let _ = std::fs::remove_file(&precious);
}

#[test]
fn store_server_applies_a_configured_group_socket_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let db_path = dir.join(format!("fineco-helper-mode-{pid}.sqlite"));
    let policy_path = dir.join(format!("fineco-helper-mode-{pid}.policy.json"));
    let socket_path = dir.join(format!("fineco-helper-mode-{pid}.sock"));
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(&socket_path);
    std::fs::write(&policy_path, OWNER_POLICY_JSON).expect("write policy");

    let config = StoreServerConfig {
        db_path: db_path.clone(),
        socket_path: socket_path.clone(),
        policy_path: policy_path.clone(),
        socket_mode: 0o660, // shared-IPC-group topology
        refresh_socket_path: None,
        live_socket_path: None,
        refresh_socket_mode: 0o600,
    };
    thread::spawn(move || {
        let _ = run_store_server(config);
    });

    // Wait for the chmod to land (it happens after bind, before serving).
    let mut applied = false;
    for _ in 0..200 {
        let mode = std::fs::symlink_metadata(&socket_path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        if mode == 0o660 {
            applied = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(applied, "the configured 0660 socket mode must be applied");

    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&policy_path);
}

#[test]
fn store_server_answers_a_client_over_the_socket() {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let db_path = dir.join(format!("fineco-helper-serve-{pid}.sqlite"));
    let socket_path = dir.join(format!("fineco-helper-serve-{pid}.sock"));
    let policy_path = dir.join(format!("fineco-helper-serve-{pid}.policy.json"));
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(&socket_path);
    std::fs::write(&policy_path, OWNER_POLICY_JSON).expect("write policy");

    // Seed the DB with a portfolio snapshot captured "now" so it reads as fresh.
    let now_iso = fineco_core::now_iso8601_utc();
    {
        let mut store = Store::open(&db_path).expect("open store");
        store
            .capture_portfolio_snapshot(&NewPortfolioSnapshot {
                captured_at: now_iso,
                source: "test".to_string(),
                market_value: Some(1000.0),
                book_value: Some(900.0),
                profit_loss: Some(100.0),
                profit_loss_perc: Some(11.11),
                positions: Vec::new(),
                fx_rates: Vec::new(),
            })
            .expect("capture");
    }

    let config = StoreServerConfig {
        db_path: db_path.clone(),
        socket_path: socket_path.clone(),
        policy_path: policy_path.clone(),
        socket_mode: 0o600,
        refresh_socket_path: None,
        live_socket_path: None,
        refresh_socket_mode: 0o600,
    };
    thread::spawn(move || {
        let _ = run_store_server(config);
    });

    // The server binds the socket asynchronously; retry the connect briefly.
    let client = Client::new(&socket_path);
    let mut last = None;
    for _ in 0..100 {
        match client.call(&Request::PortfolioGetFreshness) {
            Ok(response) => {
                last = Some(response);
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }

    match last.expect("server answered within the retry window") {
        ResponseBody::Freshness(report) => {
            assert_eq!(report.portfolio.state, "fresh");
            assert_eq!(report.orders.state, "missing");
        }
        other => panic!("expected freshness, got {other:?}"),
    }

    // The bound socket must be owner-only (0600): no other local principal may
    // reach the worker directly, bypassing the gateway.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::symlink_metadata(&socket_path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "query socket must be owner-only, got {mode:o}");

    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&policy_path);
}

/// A fake credential worker for the private-worker serving tests: it impls the
/// three fetcher traits with canned data, so the binary's `serve_live` wiring is
/// exercised without real Fineco creds or network. Portfolio echoes the
/// controller's clock (as the real worker does).
struct FakeLiveWorker;

impl fineco_refresh::PortfolioFetcher for FakeLiveWorker {
    fn fetch_portfolio(
        &self,
        now_iso: &str,
    ) -> Result<fineco_store::NewPortfolioSnapshot, fineco_core::SafeError> {
        Ok(NewPortfolioSnapshot {
            captured_at: now_iso.to_string(),
            source: "fineco".to_string(),
            market_value: Some(1000.0),
            book_value: Some(900.0),
            profit_loss: Some(100.0),
            profit_loss_perc: Some(11.11),
            positions: vec![fineco_store::NewPosition {
                asset: fineco_store::NewAsset {
                    instr_id: "A".to_string(),
                    venue_system: "V".to_string(),
                    symbol: Some("SYM".to_string()),
                    description: None,
                    kind: None,
                    currency: Some("EUR".to_string()),
                },
                position_key_hash: None,
                qty: Some(10.0),
                avg_price: Some(90.0),
                market_price: Some(100.0),
                book_value: Some(900.0),
                market_value: Some(1000.0),
                profit_loss: Some(100.0),
                profit_loss_perc: Some(11.11),
                weight_perc: Some(100.0),
            }],
            fx_rates: Vec::new(),
        })
    }
}

impl fineco_refresh::RawOrdersFetcher for FakeLiveWorker {
    fn fetch_raw_orders(
        &self,
        _instrument_kind: &str,
        _days: u32,
    ) -> Result<Vec<fineco_store::RawOrder>, fineco_core::SafeError> {
        Ok(Vec::new())
    }
}

impl fineco_refresh::TaxFetcher for FakeLiveWorker {
    fn fetch_tax_carry_forward(
        &self,
        date_from: &str,
        date_to: &str,
    ) -> Result<fineco_store::NewTaxCarryForward, fineco_core::SafeError> {
        Ok(fineco_store::NewTaxCarryForward {
            date_from: date_from.to_string(),
            date_to: date_to.to_string(),
            total: None,
        })
    }

    fn fetch_tax_minus_by_year(
        &self,
    ) -> Result<Vec<fineco_store::NewTaxMinusByYear>, fineco_core::SafeError> {
        Ok(Vec::new())
    }
}

#[test]
fn private_worker_serves_a_live_fetch_and_keeps_the_socket_owner_only() {
    use fineco_refresh::PortfolioFetcher;

    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let socket_path = dir.join(format!("fineco-helper-live-serve-{pid}.sock"));
    let _ = std::fs::remove_file(&socket_path);

    let serve_path = socket_path.clone();
    thread::spawn(move || {
        // Owner-only by default; the deploy uses 0660 + the fineco-ipc-live group.
        let _ = serve_live(&FakeLiveWorker, &serve_path, 0o600);
    });

    // The server binds the socket asynchronously; retry the connect briefly.
    let client = fineco_live::LiveClient::new(&socket_path);
    let mut snapshot = None;
    for _ in 0..100 {
        match client.fetch_portfolio("2026-06-05T10:00:00Z") {
            Ok(s) => {
                snapshot = Some(s);
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
    let snapshot = snapshot.expect("the worker answered within the retry window");
    assert_eq!(snapshot.captured_at, "2026-06-05T10:00:00Z");

    // The live socket must be owner-only (0600) here: in production the deploy
    // widens it to 0660 for the fineco-ipc-live group (controller only), never
    // world-reachable.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::symlink_metadata(&socket_path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "live socket must be owner-only, got {mode:o}");

    let _ = std::fs::remove_file(&socket_path);
}

#[test]
fn private_worker_refuses_to_take_over_a_live_socket() {
    use std::os::unix::net::UnixListener;
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let socket_path = dir.join(format!("fineco-helper-live-takeover-{pid}.sock"));
    let _ = std::fs::remove_file(&socket_path);

    // Simulate a running worker by holding a live listener on the socket path.
    let listener = UnixListener::bind(&socket_path).expect("bind live socket");
    let result = serve_live(&FakeLiveWorker, &socket_path, 0o600);
    assert!(result.is_err(), "must refuse to take over a live socket");
    assert!(socket_path.exists(), "the live socket must be left intact");

    drop(listener);
    let _ = std::fs::remove_file(&socket_path);
}

#[test]
fn store_server_refresh_controller_drives_a_live_refresh_end_to_end() {
    // The full controller path over real sockets:
    //   RefreshClient → refresh-control.sock → controller → LiveClient →
    //   fineco-live.sock → (fake) worker → snapshot captured.
    use fineco_ipc::{RefreshClient, RefreshRequest};

    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let db_path = dir.join(format!("fineco-helper-ctrl-{pid}.sqlite"));
    let query_socket = dir.join(format!("fineco-helper-ctrl-{pid}-q.sock"));
    let refresh_socket = dir.join(format!("fineco-helper-ctrl-{pid}-r.sock"));
    let live_socket = dir.join(format!("fineco-helper-ctrl-{pid}-l.sock"));
    let policy_path = dir.join(format!("fineco-helper-ctrl-{pid}.policy.json"));
    for path in [&db_path, &query_socket, &refresh_socket, &live_socket] {
        let _ = std::fs::remove_file(path);
    }
    // A policy granting the owner live refresh (plus a cached read for realism).
    std::fs::write(
        &policy_path,
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
            "portfolio.live.refresh","orders.live.refresh","tax.live.refresh",
            "portfolio.cached.full_read"]}}}"#,
    )
    .expect("write live policy");

    // 1. Stand up the credential worker behind fineco-live.sock FIRST, and wait
    //    for it to bind — so the controller's first live fetch reaches a ready
    //    worker (a failed first attempt would then sit under the cooldown).
    let live_serve = live_socket.clone();
    thread::spawn(move || {
        let _ = serve_live(&FakeLiveWorker, &live_serve, 0o600);
    });
    let mut worker_up = false;
    for _ in 0..200 {
        if live_socket.exists() {
            worker_up = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(worker_up, "the fake worker must bind fineco-live.sock");

    // 2. Run the store-server with the refresh controller enabled.
    let config = StoreServerConfig {
        db_path: db_path.clone(),
        socket_path: query_socket.clone(),
        policy_path: policy_path.clone(),
        socket_mode: 0o600,
        refresh_socket_path: Some(refresh_socket.clone()),
        live_socket_path: Some(live_socket.clone()),
        refresh_socket_mode: 0o600,
    };
    thread::spawn(move || {
        let _ = run_store_server(config);
    });

    // 3. Drive a live refresh over refresh-control.sock (retry the connect until
    //    the controller's accept loop is up; the first connected call succeeds).
    let client = RefreshClient::new(&refresh_socket);
    let mut outcome = None;
    for _ in 0..200 {
        match client.call(&RefreshRequest::PortfolioRefreshLive) {
            Ok(o) => {
                outcome = Some(o);
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
    let outcome = outcome.expect("the controller answered a live refresh");
    assert_eq!(outcome.data_area, "portfolio");
    assert!(outcome.snapshot_id.is_some(), "a snapshot was captured");
    assert_eq!(
        outcome.count, 1,
        "one position captured (a count, never a value)"
    );

    // The refresh-control socket is owner-only here (0660 in the multi-user deploy).
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::symlink_metadata(&refresh_socket)
        .expect("refresh socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "refresh socket must be owner-only, got {mode:o}"
    );

    for path in [
        &db_path,
        &query_socket,
        &refresh_socket,
        &live_socket,
        &policy_path,
    ] {
        let _ = std::fs::remove_file(path);
    }
}

#[test]
fn store_server_applies_a_configured_refresh_socket_mode() {
    // The multi-user LXC topology shares refresh-control.sock with the gateway via
    // the fineco-ipc-refresh group → 0660. Prove the store-server applies the
    // configured mode to the refresh socket (the bind+chmod is synchronous, before
    // the controller serves; the worker need not be up).
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let db_path = dir.join(format!("fineco-helper-rmode-{pid}.sqlite"));
    let query_socket = dir.join(format!("fineco-helper-rmode-{pid}-q.sock"));
    let refresh_socket = dir.join(format!("fineco-helper-rmode-{pid}-r.sock"));
    let live_socket = dir.join(format!("fineco-helper-rmode-{pid}-l.sock"));
    let policy_path = dir.join(format!("fineco-helper-rmode-{pid}.policy.json"));
    for path in [&db_path, &query_socket, &refresh_socket, &live_socket] {
        let _ = std::fs::remove_file(path);
    }
    std::fs::write(&policy_path, OWNER_POLICY_JSON).expect("write policy");

    let config = StoreServerConfig {
        db_path: db_path.clone(),
        socket_path: query_socket.clone(),
        policy_path: policy_path.clone(),
        socket_mode: 0o600,
        refresh_socket_path: Some(refresh_socket.clone()),
        live_socket_path: Some(live_socket.clone()),
        refresh_socket_mode: 0o660, // shared fineco-ipc-refresh group topology
    };
    thread::spawn(move || {
        let _ = run_store_server(config);
    });

    let mut applied = false;
    for _ in 0..200 {
        let mode = std::fs::symlink_metadata(&refresh_socket)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        if mode == 0o660 {
            applied = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        applied,
        "the configured 0660 refresh-socket mode must be applied"
    );

    for path in [
        &db_path,
        &query_socket,
        &refresh_socket,
        &live_socket,
        &policy_path,
    ] {
        let _ = std::fs::remove_file(path);
    }
}

// --- Scheduled refresh trigger (the `refresh` subcommand) ---
//
// The timer-driven `fineco-helper refresh portfolio` is a thin RefreshClient that
// connects to refresh-control.sock and sends the param-less portfolio request. The
// transport itself is exercised by the live-refresh e2e; these cover the env/arg
// parsing that decides what gets sent.

#[test]
fn refresh_trigger_config_requires_the_socket() {
    let err = match RefreshTriggerConfig::from_env(env_from(&[])) {
        Ok(_) => panic!("expected an error when FINECO_REFRESH_SOCKET is unset"),
        Err(error) => error.to_string(),
    };
    assert!(
        err.contains("FINECO_REFRESH_SOCKET"),
        "the error should name the missing var, got: {err}"
    );
}

#[test]
fn refresh_trigger_config_reads_the_socket() {
    let config = RefreshTriggerConfig::from_env(env_from(&[(
        "FINECO_REFRESH_SOCKET",
        "/run/fineco-helper-refresh/refresh-control.sock",
    )]))
    .expect("a socket path is enough to build the config");
    assert_eq!(
        config.socket_path,
        std::path::Path::new("/run/fineco-helper-refresh/refresh-control.sock")
    );
}

#[test]
fn parse_refresh_area_maps_portfolio_to_the_param_less_request() {
    assert_eq!(
        parse_refresh_area("portfolio").expect("portfolio is supported"),
        RefreshRequest::PortfolioRefreshLive
    );
}

#[test]
fn parse_refresh_area_rejects_areas_that_need_parameters() {
    // orders/tax take params (year ranges) and stay on-demand via the MCP tools;
    // the scheduled CLI only triggers the param-less portfolio refresh.
    for area in ["orders", "tax", "", "everything"] {
        let err = match parse_refresh_area(area) {
            Ok(_) => panic!("area {area:?} must not be accepted by the CLI"),
            Err(error) => error.to_string(),
        };
        assert!(
            err.contains("portfolio"),
            "the error should name portfolio as the only supported area, got: {err}"
        );
    }
}

#[test]
fn run_refresh_fails_closed_when_the_controller_is_unreachable() {
    // A dead/absent refresh-control socket must make the subcommand exit non-zero
    // (Err), so a missed scheduled run is marked failed and the alerting path fires
    // — never a silent success. The happy path (a live controller answering the
    // exact RefreshClient call this wraps) is covered by the controller e2e above.
    let config = RefreshTriggerConfig {
        socket_path: std::path::PathBuf::from(format!(
            "{}/fineco-refresh-absent-{}.sock",
            std::env::temp_dir().display(),
            std::process::id()
        )),
    };
    let err = run_refresh(config, RefreshRequest::PortfolioRefreshLive)
        .expect_err("an unreachable controller must surface as an error");
    assert!(
        err.to_string().contains("refresh failed"),
        "the error should be the safe refresh-failure envelope, got: {err}"
    );
}
