//! E2E smoke driver. Verifies the mock Fineco and mock enrichment servers are
//! reachable and serve their canned synthetic fixtures. Run by the Docker
//! compose harness; exits non-zero on the first failed check.
//!
//! Test infrastructure only — not part of the shipped product.

use std::process::ExitCode;
use std::time::Duration;

/// GET `url`, retrying connection failures while the mock server is still
/// starting up. Returns the final `(status, body)` or an error after the budget
/// is exhausted.
fn get_ready(url: &str, attempts: u32, delay: Duration) -> Result<(u16, String), String> {
    let mut last_err = String::new();
    for _ in 0..attempts {
        match httptiny::get(url) {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_err = e.to_string();
                std::thread::sleep(delay);
            }
        }
    }
    Err(format!(
        "{url}: not reachable after {attempts} attempts: {last_err}"
    ))
}

fn require(
    name: &str,
    status: u16,
    body: &str,
    expect_status: u16,
    must_contain: &str,
) -> Result<(), String> {
    if status != expect_status {
        return Err(format!(
            "{name}: returned {status}, expected {expect_status}"
        ));
    }
    if !body.contains(must_contain) {
        return Err(format!("{name}: body missing marker {must_contain:?}"));
    }
    println!("ok: {name} -> {status}");
    Ok(())
}

/// POST with connection-failure retries while the target is still starting up.
fn post_ready(
    url: &str,
    headers: &[(&str, &str)],
    body: &str,
    attempts: u32,
    delay: Duration,
) -> Result<httptiny::HttpResponse, String> {
    let mut last_err = String::new();
    for _ in 0..attempts {
        match httptiny::post(url, headers, body) {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                last_err = e.to_string();
                std::thread::sleep(delay);
            }
        }
    }
    Err(format!(
        "{url}: not reachable after {attempts} attempts: {last_err}"
    ))
}

/// Drive a real MCP Streamable-HTTP session against the gateway: initialize,
/// call a policy-granted tool (must succeed), and call a policy-denied tool
/// (must be refused). This exercises the full gateway → socket → store-server
/// path plus capability enforcement, end to end over the network.
fn check_gateway(base: &str) -> Result<(), String> {
    const JSON_SSE: [(&str, &str); 2] = [
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
    ];

    // initialize (retry while the gateway boots).
    let init = post_ready(
        base,
        &JSON_SSE,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}"#,
        40,
        Duration::from_millis(250),
    )?;
    if init.status != 200 {
        return Err(format!("gateway-initialize: status {}", init.status));
    }
    let session = init
        .header("mcp-session-id")
        .ok_or("gateway-initialize: missing mcp-session-id header")?
        .to_string();
    if !init.body.contains("\"protocolVersion\"") {
        return Err("gateway-initialize: result missing protocolVersion".to_string());
    }
    println!("ok: gateway-initialize -> session {session}");

    let with_session: [(&str, &str); 3] = [JSON_SSE[0], JSON_SSE[1], ("mcp-session-id", &session)];
    // Politely complete the handshake.
    let _ = httptiny::post(
        base,
        &with_session,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );

    // Granted tool: portfolio_get_freshness (needs portfolio.shareable.read).
    // The store-server socket may lag the gateway at startup, so retry until the
    // call returns a definitive answer. Empty store → every area reads "missing",
    // proving the full gateway → socket → store-server round-trip returns
    // structured data.
    let mut granted_body = String::new();
    for _ in 0..40 {
        let resp = httptiny::post(
            base,
            &with_session,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"portfolio_get_freshness","arguments":{}}}"#,
        )
        .map_err(|e| format!("gateway-freshness: {e}"))?;
        granted_body = resp.body;
        if granted_body.contains("\"state\":\"missing\"")
            || granted_body.contains("does not permit")
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    if granted_body.contains("does not permit") {
        return Err("gateway-freshness: wrongly denied by policy".to_string());
    }
    if !granted_body.contains("\"state\":\"missing\"") {
        return Err(format!(
            "gateway-freshness: unexpected result body: {granted_body}"
        ));
    }
    println!("ok: gateway-freshness -> structured result");

    // Denied tool: portfolio_get_latest_snapshot_summary (needs full_read, which
    // the E2E policy does not grant). Capability enforcement must refuse it.
    let denied = httptiny::post(
        base,
        &with_session,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"portfolio_get_latest_snapshot_summary","arguments":{}}}"#,
    )
    .map_err(|e| format!("gateway-summary: {e}"))?;
    if !denied.body.contains("does not permit") {
        return Err(format!(
            "gateway-summary: expected a policy denial, got: {}",
            denied.body
        ));
    }
    println!("ok: gateway-summary-denied -> policy refused full-read tool");
    Ok(())
}

fn run() -> Result<(), String> {
    let fineco =
        std::env::var("MOCK_FINECO_URL").unwrap_or_else(|_| "http://127.0.0.1:8081".to_string());
    let enrichment = std::env::var("MOCK_ENRICHMENT_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8082".to_string());

    // Wait for each server to accept connections (health endpoint), then assert
    // the canned content. ~10s budget per server.
    let (status, body) = get_ready(&format!("{fineco}/healthz"), 40, Duration::from_millis(250))?;
    require("fineco-health", status, &body, 200, "ok")?;

    let (status, body) = get_ready(
        &format!("{enrichment}/healthz"),
        40,
        Duration::from_millis(250),
    )?;
    require("enrichment-health", status, &body, 200, "ok")?;

    // Public zero-commission ETF list needs no session cookie, so the GET-only
    // smoke client can assert it directly. The authenticated Fineco reads
    // (login + cookie-gated portfolio/orders/tax) are covered by the worker's
    // integration tests, which use a real HTTP client.
    let (status, body) = httptiny::get(&format!(
        "{fineco}/common-pvt/js/json/etf-zero/etf_piu_scambiati.json"
    ))
    .map_err(|e| e.to_string())?;
    require("fineco-etfs", status, &body, 200, "SYNTHETIC")?;

    // A private read is gated: without the session cookie it must be 401 and
    // must not leak fixture data.
    let (status, body) = httptiny::get(&format!(
        "{fineco}/v1/private/tol/positions/summary?type=sintesi"
    ))
    .map_err(|e| e.to_string())?;
    if status != 401 {
        return Err(format!(
            "fineco-private-unauth: returned {status}, expected 401"
        ));
    }
    if body.contains("SYNTHETIC") {
        return Err("fineco-private-unauth: leaked fixture data without a session".to_string());
    }
    println!("ok: fineco-private-unauth -> {status}");

    let (status, body) = httptiny::get(&format!(
        "{enrichment}/stocks/it/diversified-financials/syn-tip/synth-shares"
    ))
    .map_err(|e| e.to_string())?;
    require("enrichment-stock", status, &body, 200, "SYNTHETIC")?;

    // When the gateway role is part of the topology, drive a real MCP session
    // through it (initialize + a granted and a denied tool call).
    if let Ok(gateway) = std::env::var("GATEWAY_URL") {
        check_gateway(&gateway)?;
    }

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("E2E smoke: all checks passed");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("E2E smoke FAILED: {e}");
            ExitCode::FAILURE
        }
    }
}
