//! Contract tests for the refresh-control protocol (gateway ↔ refresh
//! controller): the `*.live.refresh` capabilities, the command allowlist +
//! bounds, capability/tool/data-area mapping, and a real-socket round-trip
//! returning operation/snapshot status only (never a payload).

use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

use fineco_core::SafeError;
use fineco_ipc::{
    Capability, MovementsRefreshParams, OWNER_AUTH_ID, OrdersRefreshParams, Policy, RefreshClient,
    RefreshOutcome, RefreshRequest, TaxRefreshParams, serve_refresh_blocking, write_message,
};

const OWNER_LIVE: &str = r#"{
    "version": 1,
    "auth_ids": {
        "owner": {
            "capabilities": [
                "portfolio.live.refresh",
                "orders.live.refresh",
                "tax.live.refresh",
                "movements.live.refresh"
            ]
        }
    }
}"#;

#[test]
fn live_refresh_capabilities_parse_and_are_owner_only() {
    let policy = Policy::from_json(OWNER_LIVE).expect("valid policy");
    for capability in [
        Capability::PortfolioLiveRefresh,
        Capability::OrdersLiveRefresh,
        Capability::TaxLiveRefresh,
        Capability::MovementsLiveRefresh,
    ] {
        assert!(
            policy.allows(OWNER_AUTH_ID, capability),
            "owner should hold {}",
            capability.as_str()
        );
        // No other identity has live refresh (fail closed).
        assert!(!policy.allows("intruder", capability));
        // Live commands are the credentialed-live data class for the audit log.
        assert_eq!(capability.audit_data_class(), "credentialed_live");
    }
}

#[test]
fn a_cached_only_policy_does_not_grant_live_refresh() {
    // Holding the cached read does NOT imply the live refresh (separate caps).
    let json =
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":["portfolio.cached.full_read"]}}}"#;
    let policy = Policy::from_json(json).expect("valid policy");
    assert!(!policy.allows(OWNER_AUTH_ID, Capability::PortfolioLiveRefresh));
}

#[test]
fn parameterless_portfolio_refresh_round_trips_as_json() {
    let request =
        RefreshRequest::from_json(r#"{"command": "portfolio_refresh_live"}"#).expect("parse");
    assert_eq!(request, RefreshRequest::PortfolioRefreshLive);
    let json = request.to_json().expect("serialize");
    assert_eq!(RefreshRequest::from_json(&json).expect("reparse"), request);
}

#[test]
fn orders_and_tax_refresh_carry_their_bounded_params() {
    let orders = RefreshRequest::from_json(
        r#"{"command":"orders_refresh_live","params":{"instrument_kind":"equity","days":7}}"#,
    )
    .expect("parse orders");
    assert_eq!(
        orders,
        RefreshRequest::OrdersRefreshLive(OrdersRefreshParams {
            instrument_kind: "equity".to_string(),
            days: 7,
        })
    );

    let tax = RefreshRequest::from_json(
        r#"{"command":"tax_refresh_live","params":{"date_from":"2026-01-01","date_to":"2026-01-31"}}"#,
    )
    .expect("parse tax");
    assert_eq!(
        tax,
        RefreshRequest::TaxRefreshLive(TaxRefreshParams {
            date_from: "2026-01-01".to_string(),
            date_to: "2026-01-31".to_string(),
        })
    );

    let movements =
        RefreshRequest::from_json(r#"{"command":"movements_refresh_live","params":{"days":30}}"#)
            .expect("parse movements");
    assert_eq!(
        movements,
        RefreshRequest::MovementsRefreshLive(MovementsRefreshParams { days: 30 })
    );
}

#[test]
fn unknown_commands_and_smuggled_fields_are_rejected() {
    // An unknown / generic-proxy command.
    assert!(RefreshRequest::from_json(r#"{"command":"fineco_proxy"}"#).is_err());
    assert!(RefreshRequest::from_json(r#"{"command":"portfolio_get_freshness"}"#).is_err());
    // A smuggled envelope field (additionalProperties: false at the envelope).
    assert!(
        RefreshRequest::from_json(r#"{"command":"portfolio_refresh_live","url":"http://x"}"#)
            .is_err()
    );
    // A smuggled param (deny_unknown_fields on the params).
    assert!(
        RefreshRequest::from_json(
            r#"{"command":"orders_refresh_live","params":{"instrument_kind":"equity","days":7,"url":"http://x"}}"#
        )
        .is_err()
    );
}

#[test]
fn out_of_bounds_refresh_params_are_rejected() {
    // days over the cap.
    assert!(
        RefreshRequest::from_json(
            r#"{"command":"orders_refresh_live","params":{"instrument_kind":"equity","days":999}}"#
        )
        .is_err()
    );
    // a query-injecting (non-alphanumeric) instrument kind.
    assert!(
        RefreshRequest::from_json(
            r#"{"command":"orders_refresh_live","params":{"instrument_kind":"a&b","days":1}}"#
        )
        .is_err()
    );
    // an overlong (but alphanumeric) instrument kind: the cached IPC path caps
    // client strings at 256, and the live path must too (else a multi-MB kind
    // flows into the Fineco URL + frame allocations).
    let overlong = "a".repeat(257);
    assert!(
        RefreshRequest::from_json(&format!(
            r#"{{"command":"orders_refresh_live","params":{{"instrument_kind":"{overlong}","days":1}}}}"#
        ))
        .is_err()
    );
    // exactly the 256-char cap is allowed.
    let at_cap = "a".repeat(256);
    assert!(
        RefreshRequest::from_json(&format!(
            r#"{{"command":"orders_refresh_live","params":{{"instrument_kind":"{at_cap}","days":1}}}}"#
        ))
        .is_ok()
    );
    // an inverted / malformed tax range.
    assert!(
        RefreshRequest::from_json(
            r#"{"command":"tax_refresh_live","params":{"date_from":"2026-01-31","date_to":"2026-01-01"}}"#
        )
        .is_err()
    );
    // an overlong date string is rejected on shape (length != 10) before the
    // format!/parse, so a multi-MB date can't drive a large allocation/scan.
    let overlong_date = "2".repeat(5000);
    assert!(
        RefreshRequest::from_json(&format!(
            r#"{{"command":"tax_refresh_live","params":{{"date_from":"{overlong_date}","date_to":"2026-01-31"}}}}"#
        ))
        .is_err()
    );
    assert!(
        RefreshRequest::from_json(
            r#"{"command":"tax_refresh_live","params":{"date_from":"2026-13-01","date_to":"2026-12-31"}}"#
        )
        .is_err()
    );
    // movements days over the 90-day cap is rejected; exactly the cap is allowed.
    assert!(
        RefreshRequest::from_json(r#"{"command":"movements_refresh_live","params":{"days":91}}"#)
            .is_err()
    );
    assert!(
        RefreshRequest::from_json(r#"{"command":"movements_refresh_live","params":{"days":90}}"#)
            .is_ok()
    );
}

#[test]
fn each_refresh_maps_to_its_capability_tool_and_area() {
    let portfolio = RefreshRequest::PortfolioRefreshLive;
    assert_eq!(
        portfolio.required_capability(),
        Capability::PortfolioLiveRefresh
    );
    assert_eq!(
        portfolio.audit_tool(),
        "private_portfolio_refresh_live_sensitive"
    );
    assert_eq!(portfolio.data_area(), "portfolio");

    let orders = RefreshRequest::OrdersRefreshLive(OrdersRefreshParams {
        instrument_kind: "equity".to_string(),
        days: 1,
    });
    assert_eq!(orders.required_capability(), Capability::OrdersLiveRefresh);
    assert_eq!(orders.audit_tool(), "private_orders_refresh_live_sensitive");
    assert_eq!(orders.data_area(), "orders");

    let tax = RefreshRequest::TaxRefreshLive(TaxRefreshParams {
        date_from: "2026-01-01".to_string(),
        date_to: "2026-01-31".to_string(),
    });
    assert_eq!(tax.required_capability(), Capability::TaxLiveRefresh);
    assert_eq!(tax.audit_tool(), "private_tax_refresh_live_sensitive");
    assert_eq!(tax.data_area(), "tax");

    let movements = RefreshRequest::MovementsRefreshLive(MovementsRefreshParams { days: 30 });
    assert_eq!(
        movements.required_capability(),
        Capability::MovementsLiveRefresh
    );
    assert_eq!(
        movements.audit_tool(),
        "private_movements_refresh_live_sensitive"
    );
    assert_eq!(movements.data_area(), "movements");
}

/// A unique socket path for this test (the `tag` keeps the two socket tests from
/// colliding when run as threads in one process under `cargo test`).
fn socket_path(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "fineco-ipc-refresh-{}-{tag}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

/// Stub controller handler: portfolio "succeeds" with an op/snapshot status, the
/// rest report `already_refreshing` (proving the error path crosses cleanly).
fn handle(request: RefreshRequest) -> Result<RefreshOutcome, SafeError> {
    match request {
        RefreshRequest::PortfolioRefreshLive => Ok(RefreshOutcome {
            data_area: "portfolio".to_string(),
            captured_at: "2026-06-05T10:00:00Z".to_string(),
            snapshot_id: Some(42),
            count: 3,
        }),
        _ => Err(SafeError::already_refreshing()),
    }
}

#[test]
fn refresh_request_reply_over_a_unix_socket() {
    let path = socket_path("round-trip");
    let listener = UnixListener::bind(&path).expect("bind socket");
    thread::spawn(move || {
        let _ = serve_refresh_blocking(&listener, handle);
    });

    let client = RefreshClient::new(&path);

    // Ok path: the controller returns operation/snapshot status only — no payload.
    match client.call(&RefreshRequest::PortfolioRefreshLive) {
        Ok(outcome) => {
            assert_eq!(outcome.data_area, "portfolio");
            assert_eq!(outcome.snapshot_id, Some(42));
            assert_eq!(outcome.count, 3);
            assert_eq!(outcome.captured_at, "2026-06-05T10:00:00Z");
        }
        Err(err) => panic!("unexpected error reply: {err:?}"),
    }

    // Err path: a concurrent refresh crosses as the safe envelope.
    let err = client
        .call(&RefreshRequest::OrdersRefreshLive(OrdersRefreshParams {
            instrument_kind: "equity".to_string(),
            days: 7,
        }))
        .expect_err("handler returns already_refreshing");
    assert_eq!(err.code, "already_refreshing");
    assert!(err.retryable);
}

#[test]
fn a_panicking_handler_does_not_kill_the_refresh_loop() {
    // The controller runs on a DETACHED thread; a panic inside its handler must
    // not unwind out of the accept loop and silently take live refresh down until
    // a manual restart. A panic must become a safe error reply, and the loop must
    // keep serving subsequent requests.
    let path = socket_path("panic");
    let listener = UnixListener::bind(&path).expect("bind socket");
    thread::spawn(move || {
        let _ = serve_refresh_blocking(&listener, |request| match request {
            RefreshRequest::OrdersRefreshLive(_) => panic!("boom inside the handler"),
            RefreshRequest::PortfolioRefreshLive => Ok(RefreshOutcome {
                data_area: "portfolio".to_string(),
                captured_at: "2026-06-05T10:00:00Z".to_string(),
                snapshot_id: Some(7),
                count: 1,
            }),
            _ => Err(SafeError::already_refreshing()),
        });
    });

    let client = RefreshClient::new(&path);
    // A handler panic surfaces as the safe `internal` envelope, not a dropped
    // connection.
    let err = client
        .call(&RefreshRequest::OrdersRefreshLive(OrdersRefreshParams {
            instrument_kind: "equity".to_string(),
            days: 1,
        }))
        .expect_err("a panicking handler should yield a safe error reply");
    assert_eq!(err.code, "internal");
    // The accept loop SURVIVED the panic: a later request is still served.
    let outcome = client
        .call(&RefreshRequest::PortfolioRefreshLive)
        .expect("the loop must keep serving after a handler panic");
    assert_eq!(outcome.snapshot_id, Some(7));
}

#[test]
fn the_server_rejects_a_forged_command_without_reaching_the_handler() {
    // A hostile frame (unknown command, smuggled url) must be rejected by the
    // server's re-validation, never reaching the controller's refresh.
    let path = socket_path("forged");
    let listener = UnixListener::bind(&path).expect("bind socket");
    thread::spawn(move || {
        let _ = serve_refresh_blocking(&listener, handle);
    });

    let mut stream = UnixStream::connect(&path).expect("connect");
    write_message(
        &mut stream,
        &serde_json::json!({"command": "fineco_proxy", "params": {"url": "http://attacker"}}),
    )
    .expect("write forged frame");
    let reply: serde_json::Value = fineco_ipc::read_message(&mut stream).expect("read reply");
    assert_eq!(reply.get("status").and_then(|s| s.as_str()), Some("err"));
}
