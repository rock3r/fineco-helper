//! The gateway's Cloudflare Access middleware (M6): when Access is configured,
//! every request must carry a valid `Cf-Access-Jwt-Assertion` JWT. A missing,
//! spoofed, or invalid token is rejected with 401 before reaching the MCP
//! service; a valid owner token passes through.
//!
//! Reuses the gateway crate's offline RSA test key + JWKS fixtures.

use std::sync::Arc;
use std::time::Duration;

use fineco_gateway::Gateway;
use fineco_gateway::access::{AccessConfig, AccessVerifier};
use fineco_helper::serve::gateway_router;
use fineco_ipc::Policy;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

const TEST_KEY_PEM: &str = include_str!("../../fineco-gateway/tests/fixtures/access-test-key.pem");
const TEST_JWKS: &str = include_str!("../../fineco-gateway/tests/fixtures/access-test-jwks.json");
const ISSUER: &str = "https://team.cloudflareaccess.com";
const AUDIENCE: &str = "test-aud-tag-0123456789abcdef";
const OWNER_EMAIL: &str = "owner@example.com";

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn valid_token() -> String {
    let claims = serde_json::json!({
        "iss": ISSUER,
        "aud": [AUDIENCE],
        "exp": now() + 3600,
        "iat": now(),
        "email": OWNER_EMAIL,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());
    let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("key");
    encode(&header, &claims, &key).expect("sign")
}

fn owner_policy() -> Policy {
    Policy::from_json(
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":["portfolio.shareable.read"]}}}"#,
    )
    .expect("policy")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_middleware_enforces_a_valid_token() {
    let gateway = Gateway::new("/tmp/fineco-helper-access-unused.sock").with_policy(owner_policy());
    let keys: JwkSet = serde_json::from_str(TEST_JWKS).expect("jwks");
    let verifier = Arc::new(AccessVerifier::new(
        AccessConfig {
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            owner_email: Some(OWNER_EMAIL.to_string()),
            owner_common_name: None,
        },
        keys,
    ));
    let app = gateway_router(gateway, Some(verifier));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("http://{addr}/");
    let token = valid_token();
    let statuses = tokio::task::spawn_blocking(move || {
        let ct = ("Content-Type", "application/json");
        let acc = ("Accept", "application/json, text/event-stream");
        // No Access header → 401.
        let missing = httptiny::post(&base, &[ct, acc], INIT)
            .expect("post")
            .status;
        // A garbage token → 401.
        let bad = httptiny::post(
            &base,
            &[ct, acc, ("Cf-Access-Jwt-Assertion", "not.a.jwt")],
            INIT,
        )
        .expect("post")
        .status;
        // A valid owner token → 200 (reaches the MCP service).
        let ok = httptiny::post(
            &base,
            &[ct, acc, ("Cf-Access-Jwt-Assertion", token.as_str())],
            INIT,
        )
        .expect("post")
        .status;
        (missing, bad, ok)
    })
    .await
    .expect("join");

    assert_eq!(statuses.0, 401, "missing Access token must be rejected");
    assert_eq!(statuses.1, 401, "an invalid Access token must be rejected");
    assert_eq!(statuses.2, 200, "a valid owner token must pass through");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_access_configured_requests_pass() {
    // Loopback-only / dev mode: no Access middleware, initialize succeeds.
    let gateway = Gateway::new("/tmp/fineco-helper-access-none.sock").with_policy(owner_policy());
    let app = gateway_router(gateway, None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("http://{addr}/");
    let status = tokio::task::spawn_blocking(move || {
        httptiny::post(
            &base,
            &[
                ("Content-Type", "application/json"),
                ("Accept", "application/json, text/event-stream"),
            ],
            INIT,
        )
        .expect("post")
        .status
    })
    .await
    .expect("join");
    assert_eq!(status, 200, "no Access => initialize passes");
}

/// A Cloudflare service-token `common_name` (no `email`) — the CLI channel.
const SERVICE_CN: &str = "78599ba946c2e172fc40b29726e4d835.access";

fn service_token() -> String {
    let claims = serde_json::json!({
        "iss": ISSUER,
        "aud": [AUDIENCE],
        "exp": now() + 3600,
        "iat": now(),
        "common_name": SERVICE_CN,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());
    let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("key");
    encode(&header, &claims, &key).expect("sign")
}

/// Drive the MCP Streamable HTTP handshake (initialize → initialized → tools/list)
/// with `token` and return the raw `tools/list` response body (which contains the
/// tool names as JSON strings).
fn list_tools_body(base: &str, token: &str) -> String {
    let ct = ("Content-Type", "application/json");
    let acc = ("Accept", "application/json, text/event-stream");
    let auth = ("Cf-Access-Jwt-Assertion", token);
    let init = httptiny::post(base, &[ct, acc, auth], INIT).expect("init");
    assert_eq!(init.status, 200, "initialize should pass: {}", init.body);
    let session = init
        .header("mcp-session-id")
        .expect("initialize returns a session id")
        .to_string();
    let sid = ("Mcp-Session-Id", session.as_str());
    let _ = httptiny::post(
        base,
        &[ct, acc, auth, sid],
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    let list = httptiny::post(
        base,
        &[ct, acc, auth, sid],
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    )
    .expect("tools/list");
    assert_eq!(list.status, 200, "tools/list should pass: {}", list.body);
    list.body
}

/// Drive the handshake then `tools/call` `tool` (empty args) with `token`, and
/// return the raw response body.
fn call_tool_body(base: &str, token: &str, tool: &str) -> String {
    let ct = ("Content-Type", "application/json");
    let acc = ("Accept", "application/json, text/event-stream");
    let auth = ("Cf-Access-Jwt-Assertion", token);
    let init = httptiny::post(base, &[ct, acc, auth], INIT).expect("init");
    let session = init
        .header("mcp-session-id")
        .expect("session id")
        .to_string();
    let sid = ("Mcp-Session-Id", session.as_str());
    let _ = httptiny::post(
        base,
        &[ct, acc, auth, sid],
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"{tool}","arguments":{{}}}}}}"#
    );
    httptiny::post(base, &[ct, acc, auth, sid], &body)
        .expect("tools/call")
        .body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connector_channel_is_tool_scoped_while_cli_is_full() {
    // Dual-pin deployment with the DEFAULT connector allowlist: the connector
    // (email/OAuth) channel must NOT see the four detailed-portfolio tools, while
    // the CLI (service-token) channel keeps the full set.
    let gateway = Gateway::new("/tmp/fineco-helper-scope-unused.sock")
        .with_policy(owner_policy())
        .with_connector_allowlist(
            fineco_gateway::DEFAULT_CONNECTOR_TOOLS
                .iter()
                .map(|name| name.to_string()),
        );
    let keys: JwkSet = serde_json::from_str(TEST_JWKS).expect("jwks");
    let verifier = Arc::new(AccessVerifier::new(
        AccessConfig {
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            owner_email: Some(OWNER_EMAIL.to_string()),
            owner_common_name: Some(SERVICE_CN.to_string()),
        },
        keys,
    ));
    let app = gateway_router(gateway, Some(verifier));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("http://{addr}/");
    let connector = valid_token(); // email → connector channel
    let cli = service_token(); // common_name → CLI channel
    let (connector_tools, cli_tools, blocked_call, allowed_call) =
        tokio::task::spawn_blocking(move || {
            (
                list_tools_body(&base, &connector),
                list_tools_body(&base, &cli),
                // A blocked tool, CALLED on the connector channel, must be refused...
                call_tool_body(&base, &connector, "portfolio_get_latest_full_snapshot"),
                // ...while an allowed tool passes the scope gate (then fails on the
                // absent store socket — a different error, NOT "tool not found").
                call_tool_body(&base, &connector, "portfolio_get_freshness"),
            )
        })
        .await
        .expect("join");

    let blocked = [
        "portfolio_get_latest_snapshot_summary",
        "portfolio_get_latest_full_snapshot",
        "portfolio_get_history",
        "portfolio_get_position_history",
    ];
    for tool in blocked {
        assert!(
            !connector_tools.contains(tool),
            "connector channel must not list {tool}; got: {connector_tools}"
        );
        assert!(
            cli_tools.contains(tool),
            "CLI channel must list {tool}; got: {cli_tools}"
        );
    }
    // The connector still sees an allowed tool.
    assert!(
        connector_tools.contains("portfolio_get_latest_shareable_report"),
        "connector channel should list the shareable report; got: {connector_tools}"
    );
    // call_tool gating mirrors list_tools hiding: a blocked tool is refused, an
    // allowed tool is not (it gets past the scope gate to dispatch).
    assert!(
        blocked_call.contains("tool not found"),
        "connector call to a blocked tool must be refused; got: {blocked_call}"
    );
    assert!(
        !allowed_call.contains("tool not found"),
        "connector call to an allowed tool must pass the scope gate; got: {allowed_call}"
    );
}
