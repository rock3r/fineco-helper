//! Integration test: the gateway's live-refresh tools forward to the refresh
//! controller over `refresh-control.sock` and return operation/snapshot status
//! only. They are owner-only (capability-gated before any socket hop), bounded at
//! the gateway end, and — crucially — the gateway has NO live-socket client, so a
//! cached-only or unconfigured gateway can never reach Fineco. (The build-time
//! half of that gate is the architecture test: the gateway never depends on
//! `fineco-live`.)

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;

use fineco_core::SafeError;
use fineco_gateway::Gateway;
use fineco_ipc::{
    OrdersRefreshParams, Policy, RefreshClient, RefreshOutcome, RefreshRequest, TaxRefreshParams,
    serve_refresh_blocking,
};
use rmcp::handler::server::wrapper::Parameters;

/// A policy granting the owner the three live-refresh capabilities.
fn owner_live_policy() -> Policy {
    Policy::from_json(
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
            "portfolio.live.refresh","orders.live.refresh","tax.live.refresh"]}}}"#,
    )
    .expect("valid live policy")
}

/// A policy granting only cached reads — NO live refresh.
fn owner_cached_only_policy() -> Policy {
    Policy::from_json(
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
            "portfolio.cached.full_read","orders.cached.read","tax.cached.read"]}}}"#,
    )
    .expect("valid cached policy")
}

/// Stub controller: portfolio "succeeds" with op/snapshot status; the rest report
/// `already_refreshing`.
fn refresh_handle(request: RefreshRequest) -> Result<RefreshOutcome, SafeError> {
    match request {
        RefreshRequest::PortfolioRefreshLive => Ok(RefreshOutcome {
            data_area: "portfolio".to_string(),
            captured_at: "2026-06-05T10:00:00Z".to_string(),
            snapshot_id: Some(7),
            count: 5,
        }),
        _ => Err(SafeError::already_refreshing()),
    }
}

/// Bind a refresh-control socket, serve the stub controller, return the path.
fn spawn_controller(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "fineco-gateway-refresh-{}-{tag}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind refresh socket");
    thread::spawn(move || {
        let _ = serve_refresh_blocking(&listener, refresh_handle);
    });
    path
}

#[tokio::test]
async fn portfolio_refresh_tool_returns_status_only() {
    let path = spawn_controller("portfolio");
    let gateway = Gateway::new("/tmp/fineco-gw-refresh-unused-q.sock")
        .with_policy(owner_live_policy())
        .with_refresh_client(RefreshClient::new(&path));

    let outcome = gateway
        .private_portfolio_refresh_live_sensitive()
        .await
        .expect("refresh tool")
        .0;
    assert_eq!(outcome.data_area, "portfolio");
    assert_eq!(outcome.snapshot_id, Some(7));
    assert_eq!(outcome.count, 5);
    assert_eq!(outcome.captured_at, "2026-06-05T10:00:00Z");

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn a_concurrent_refresh_surfaces_as_a_safe_error() {
    let path = spawn_controller("concurrent");
    let gateway = Gateway::new("/tmp/fineco-gw-refresh-unused-q.sock")
        .with_policy(owner_live_policy())
        .with_refresh_client(RefreshClient::new(&path));

    // `Json` has no `Debug`, so match rather than `expect_err`.
    let err = match gateway
        .private_orders_refresh_live_sensitive(Parameters(OrdersRefreshParams {
            instrument_kind: "equity".to_string(),
            days: 7,
        }))
        .await
    {
        Ok(_) => panic!("a concurrent refresh must surface as an error"),
        Err(err) => err,
    };
    assert!(!err.message.is_empty());

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn a_cached_only_policy_denies_live_refresh_before_any_socket_hop() {
    // The refresh client points at a socket that does NOT exist. If the gateway
    // reached it we'd get a transport error; instead the capability check denies
    // the call first, proving owner-only live refresh is enforced before dispatch.
    let gateway = Gateway::new("/tmp/fineco-gw-refresh-unused-q.sock")
        .with_policy(owner_cached_only_policy())
        .with_refresh_client(RefreshClient::new("/tmp/fineco-gw-refresh-dead.sock"));

    let err = match gateway.private_portfolio_refresh_live_sensitive().await {
        Ok(_) => panic!("a cached-only policy must deny live refresh"),
        Err(err) => err,
    };
    assert!(
        err.message.contains("policy"),
        "expected a policy denial, got: {}",
        err.message
    );
}

#[tokio::test]
async fn live_refresh_without_a_configured_client_is_a_safe_error() {
    // A gateway with the live capability but NO refresh client must fail safely —
    // it has no live-socket client and cannot reach Fineco by any path. This is
    // the runtime half of the "gateway never touches the live socket" gate.
    let gateway =
        Gateway::new("/tmp/fineco-gw-refresh-unused-q.sock").with_policy(owner_live_policy());

    let err = match gateway.private_portfolio_refresh_live_sensitive().await {
        Ok(_) => panic!("live refresh without a controller must be a safe error"),
        Err(err) => err,
    };
    assert!(
        err.message.contains("not configured"),
        "expected a not-configured error, got: {}",
        err.message
    );
}

#[tokio::test]
async fn out_of_range_orders_days_is_rejected_at_the_gateway_before_dispatch() {
    // days over the cap must be rejected by the gateway's own bounds check, before
    // the socket — the dead refresh client is never reached.
    let gateway = Gateway::new("/tmp/fineco-gw-refresh-unused-q.sock")
        .with_policy(owner_live_policy())
        .with_refresh_client(RefreshClient::new("/tmp/fineco-gw-refresh-dead.sock"));

    let err = match gateway
        .private_orders_refresh_live_sensitive(Parameters(OrdersRefreshParams {
            instrument_kind: "equity".to_string(),
            days: 999,
        }))
        .await
    {
        Ok(_) => panic!("days over the cap must be rejected"),
        Err(err) => err,
    };
    assert!(
        err.message.contains("30") || err.message.to_lowercase().contains("days"),
        "expected a bounds error, got: {}",
        err.message
    );
}

#[tokio::test]
async fn tax_refresh_validates_the_range_at_the_gateway() {
    let gateway = Gateway::new("/tmp/fineco-gw-refresh-unused-q.sock")
        .with_policy(owner_live_policy())
        .with_refresh_client(RefreshClient::new("/tmp/fineco-gw-refresh-dead.sock"));

    // An inverted range is rejected before any socket hop.
    let err = match gateway
        .private_tax_refresh_live_sensitive(Parameters(TaxRefreshParams {
            date_from: "2026-12-31".to_string(),
            date_to: "2026-01-01".to_string(),
        }))
        .await
    {
        Ok(_) => panic!("an inverted tax range must be rejected"),
        Err(err) => err,
    };
    assert!(!err.message.is_empty());
}
