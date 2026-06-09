//! Origin validation (M6 — the half of the DNS-rebinding gate deferred from M4).
//! With allowed origins configured, a request carrying a disallowed `Origin` is
//! rejected (403); an allowed origin passes; a request with no `Origin` (a native
//! MCP client) still passes.

use std::time::Duration;

use fineco_gateway::Gateway;
use fineco_ipc::Policy;

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#;

fn owner_policy() -> Policy {
    Policy::from_json(
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":["portfolio.shareable.read"]}}}"#,
    )
    .expect("valid policy")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn origin_validation_rejects_disallowed_allows_configured_and_missing() {
    let gateway = Gateway::new("/tmp/fineco-gateway-origin-unused.sock")
        .with_policy(owner_policy())
        .with_allowed_origins(["https://allowed.example"]);
    let app = axum::Router::new().fallback_service(gateway.into_service());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let base = format!("http://{addr}/");
    let ct = ("Content-Type", "application/json");
    let acc = ("Accept", "application/json, text/event-stream");

    // Run the blocking HTTP posts off the async worker.
    let result = tokio::task::spawn_blocking(move || {
        let disallowed =
            httptiny::post(&base, &[ct, acc, ("Origin", "https://evil.example")], INIT)
                .expect("post disallowed")
                .status;
        let allowed = httptiny::post(
            &base,
            &[ct, acc, ("Origin", "https://allowed.example")],
            INIT,
        )
        .expect("post allowed")
        .status;
        let missing = httptiny::post(&base, &[ct, acc], INIT)
            .expect("post missing")
            .status;
        // DNS-rebinding-style request: a non-loopback Host must be rejected
        // (rmcp validates Host to the loopback allowlist by default).
        let bad_host = httptiny::post(&base, &[ct, acc, ("Host", "evil.example")], INIT)
            .expect("post bad host")
            .status;
        (disallowed, allowed, missing, bad_host)
    })
    .await
    .expect("join");

    assert_eq!(result.0, 403, "a disallowed Origin must be forbidden");
    assert_eq!(result.1, 200, "an allowed Origin must pass");
    assert_eq!(result.2, 200, "a missing Origin (native client) must pass");
    assert_eq!(result.3, 403, "a non-loopback Host must be forbidden");
}
