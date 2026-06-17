//! Contract tests for the internal command protocol: the command allowlist,
//! `additionalProperties: false` at the envelope and params, forbidden-field
//! rejection, and string bounds.

use fineco_ipc::Request;

#[test]
fn parameterless_command_round_trips() {
    let request = Request::from_json(r#"{"command": "portfolio_get_freshness"}"#).expect("parse");
    assert_eq!(request, Request::PortfolioGetFreshness);
    // Re-serialize and re-parse to confirm the wire form is stable.
    let json = request.to_json().expect("serialize");
    assert_eq!(Request::from_json(&json).expect("reparse"), request);
}

#[test]
fn all_parameterless_cached_commands_parse() {
    for command in [
        "portfolio_get_freshness",
        "portfolio_get_latest_snapshot_summary",
        "portfolio_get_latest_full_snapshot",
        "portfolio_get_latest_shareable_report",
        "orders_get_latest_monitor",
        "tax_get_latest_carry_forward",
        "tax_get_latest_minus_by_year",
    ] {
        let json = format!(r#"{{"command": "{command}"}}"#);
        assert!(Request::from_json(&json).is_ok(), "{command} should parse");
    }
}

#[test]
fn etfs_query_is_optional() {
    // The `query` filter is optional within `params` (empty params = no filter).
    assert!(
        Request::from_json(r#"{"command": "market_get_zero_commission_etfs", "params": {}}"#)
            .is_ok()
    );
    assert!(
        Request::from_json(
            r#"{"command": "market_get_zero_commission_etfs", "params": {"query": "world"}}"#
        )
        .is_ok()
    );
}

#[test]
fn unknown_command_is_rejected() {
    let err = Request::from_json(r#"{"command": "fineco_proxy"}"#).expect_err("unknown command");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn generic_proxy_shaped_commands_are_rejected() {
    // None of the forbidden generic tools exist as commands.
    for command in ["http_request", "sql_query", "read_file", "fineco_fetch"] {
        let json = format!(r#"{{"command": "{command}"}}"#);
        assert!(
            Request::from_json(&json).is_err(),
            "{command} must be rejected"
        );
    }
}

#[test]
fn smuggled_envelope_field_is_rejected() {
    // A forbidden field alongside a valid command must not slip through.
    for extra in [
        r#""url": "http://evil""#,
        r#""sql": "DROP TABLE""#,
        r#""headers": {}"#,
    ] {
        let json = format!(r#"{{"command": "portfolio_get_freshness", {extra}}}"#);
        let err = Request::from_json(&json).expect_err("smuggled field");
        assert_eq!(err.code(), "invalid_request", "{extra}");
    }
}

#[test]
fn unknown_param_field_is_rejected() {
    // deny_unknown_fields on the params struct rejects a forbidden option.
    let err = Request::from_json(
        r#"{"command": "market_get_zero_commission_etfs",
            "params": {"query": "x", "userAgent": "bot", "validateSource": false}}"#,
    )
    .expect_err("unknown params");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn non_object_request_is_rejected() {
    assert!(Request::from_json("[1, 2, 3]").is_err());
    assert!(Request::from_json("\"portfolio_get_freshness\"").is_err());
    assert!(Request::from_json("not json").is_err());
}

#[test]
fn overlong_identifier_is_rejected() {
    let instr_id = "a".repeat(257);
    let json = format!(
        r#"{{"command": "portfolio_get_position_history", "params": {{"instr_id": "{instr_id}", "venue_system": "V"}}}}"#
    );
    let err = Request::from_json(&json).expect_err("too long");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn empty_identifier_is_rejected() {
    let err = Request::from_json(
        r#"{"command": "portfolio_get_position_history", "params": {"instr_id": "", "venue_system": "V"}}"#,
    )
    .expect_err("empty identifier");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn history_command_carries_its_limit() {
    let request =
        Request::from_json(r#"{"command": "portfolio_get_history", "params": {"limit": 30}}"#)
            .expect("parse");
    match request {
        Request::PortfolioGetHistory(params) => assert_eq!(params.limit, 30),
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn history_limit_out_of_range_is_rejected() {
    for limit in ["0", "1001", "100000"] {
        let json =
            format!(r#"{{"command": "portfolio_get_history", "params": {{"limit": {limit}}}}}"#);
        let err = Request::from_json(&json).expect_err("out-of-range limit");
        assert_eq!(err.code(), "invalid_request", "limit {limit}");
    }
}

#[test]
fn allocation_history_is_parameterless() {
    let request =
        Request::from_json(r#"{"command": "portfolio_get_allocation_history"}"#).expect("parse");
    assert_eq!(request, Request::PortfolioGetAllocationHistory);
}

#[test]
fn position_history_carries_its_key() {
    let request = Request::from_json(
        r#"{"command": "portfolio_get_position_history",
            "params": {"instr_id": "AAA", "venue_system": "MOT"}}"#,
    )
    .expect("parse");
    match request {
        Request::PortfolioGetPositionHistory(params) => {
            assert_eq!(params.instr_id, "AAA");
            assert_eq!(params.venue_system, "MOT");
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn position_history_empty_key_is_rejected() {
    for params in [
        r#"{"instr_id": "", "venue_system": "MOT"}"#,
        r#"{"instr_id": "AAA", "venue_system": ""}"#,
    ] {
        let json =
            format!(r#"{{"command": "portfolio_get_position_history", "params": {params}}}"#);
        let err = Request::from_json(&json).expect_err("empty key");
        assert_eq!(err.code(), "invalid_request", "{params}");
    }
}
