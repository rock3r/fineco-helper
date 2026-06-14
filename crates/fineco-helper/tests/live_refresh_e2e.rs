//! The truest live-refresh end-to-end: the **real** `FinecoWorker` (login +
//! allowlisted reads + parse) behind `fineco-live.sock`, driven through the
//! store-server's refresh controller (preflight + controller-side hashing +
//! capture) over `refresh-control.sock`, against the synthetic mock Fineco. No
//! real credentials — the mock accepts the synthetic login.
//!
//! This composes the worker read path, the fineco-live socket, and the controller
//! into one path — the closest stand-in for the production credentialed boundary
//! before S4 wires real creds.

use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use fineco_helper::serve::{StoreServerConfig, run_store_server, serve_live};
use fineco_ipc::{OrdersRefreshParams, RefreshClient, RefreshRequest};
use fineco_worker::{FinecoEndpoints, FinecoWorker, StaticCredentialSource};

/// A policy granting the owner live refresh for every area.
const OWNER_LIVE_POLICY: &str = r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
    "portfolio.live.refresh","orders.live.refresh","tax.live.refresh"]}}}"#;

/// Bind an ephemeral port and serve the synthetic mock Fineco; return its base URL.
fn spawn_mock_fineco() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, mock_fineco::route);
    });
    format!("http://{addr}")
}

#[test]
fn real_worker_live_refresh_through_the_controller_captures_a_snapshot() {
    let base = spawn_mock_fineco();

    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let db_path = dir.join(format!("fineco-helper-e2e-{pid}.sqlite"));
    let query_socket = dir.join(format!("fineco-helper-e2e-{pid}-q.sock"));
    let refresh_socket = dir.join(format!("fineco-helper-e2e-{pid}-r.sock"));
    let live_socket = dir.join(format!("fineco-helper-e2e-{pid}-l.sock"));
    let policy_path = dir.join(format!("fineco-helper-e2e-{pid}.policy.json"));
    for path in [&db_path, &query_socket, &refresh_socket, &live_socket] {
        let _ = std::fs::remove_file(path);
    }
    std::fs::write(&policy_path, OWNER_LIVE_POLICY).expect("write policy");

    // 1. The REAL credential worker behind fineco-live.sock, pointed at the mock,
    //    with synthetic creds (the mock accepts any login). Wait for it to bind.
    let live_serve = live_socket.clone();
    thread::spawn(move || {
        let worker = FinecoWorker::new(
            FinecoEndpoints::for_base(&base),
            Box::new(StaticCredentialSource::new(
                "synthetic-user",
                "synthetic-pass",
            )),
        );
        let _ = serve_live(&worker, &live_serve, 0o600);
    });
    let mut worker_up = false;
    for _ in 0..1000 {
        if live_socket.exists() {
            worker_up = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(worker_up, "the real worker must bind fineco-live.sock");

    // 2. The store-server with the refresh controller enabled.
    let config = StoreServerConfig {
        db_path: db_path.clone(),
        socket_path: query_socket.clone(),
        policy_path: policy_path.clone(),
        socket_mode: 0o600,
        refresh_socket_path: Some(refresh_socket.clone()),
        market_control_socket_path: None,
        live_socket_path: Some(live_socket.clone()),
        refresh_socket_mode: 0o600,
    };
    thread::spawn(move || {
        let _ = run_store_server(config);
    });

    let client = RefreshClient::new(&refresh_socket);

    // 3a. Drive a portfolio live refresh: the controller logs in via the worker,
    //     parses the mock's positions summary, and captures the snapshot.
    let mut portfolio = None;
    for _ in 0..1000 {
        match client.call(&RefreshRequest::PortfolioRefreshLive) {
            Ok(outcome) => {
                portfolio = Some(outcome);
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
    let portfolio = portfolio.expect("a live portfolio refresh completed");
    assert_eq!(portfolio.data_area, "portfolio");
    assert!(portfolio.snapshot_id.is_some(), "a snapshot was captured");
    // The synthetic positions summary carries two positions.
    assert_eq!(
        portfolio.count, 2,
        "two positions captured (a count, never values)"
    );

    // 3b. A second immediate live login is now blocked by the shared live-session
    //     gate (refresh and authenticated-market reads use the same footprint
    //     policy). Tests that need orders data drive it with an injected clock at
    //     the controller/protocol layer; this socket E2E has no test-time clock
    //     override and must not sleep for the production cooldown.
    let err = client
        .call(&RefreshRequest::OrdersRefreshLive(OrdersRefreshParams {
            instrument_kind: "equity".to_string(),
            days: 7,
        }))
        .expect_err("a second immediate live login is rate-limited");
    assert_eq!(err.code, "market_rate_limited");

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
