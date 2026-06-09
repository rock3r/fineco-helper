//! Tests for the store-query handler: freshness mapping with a deterministic
//! clock, plus a real end-to-end socket round-trip through `fineco-ipc`.

use std::os::unix::net::UnixListener;
use std::thread;

use fineco_core::parse_iso8601_utc;
use fineco_ipc::{Client, Policy, Request, ResponseBody, serve_blocking};
use fineco_query::{FreshnessMaxAge, QueryHandler};
use fineco_store::{
    NewAsset, NewOrder, NewPortfolioSnapshot, NewPosition, NewTaxCarryForward, NewTaxMinusByYear,
    Store,
};

fn epoch(iso: &str) -> i64 {
    parse_iso8601_utc(iso).expect("valid iso")
}

/// A policy granting the owner every M4 capability (so the handler authorizes).
fn owner_policy() -> Policy {
    Policy::from_json(
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
            "market.read","portfolio.cached.full_read","portfolio.shareable.read",
            "orders.cached.read","tax.cached.read"]}}}"#,
    )
    .expect("valid owner policy")
}

fn empty_snapshot(captured_at: &str) -> NewPortfolioSnapshot {
    NewPortfolioSnapshot {
        captured_at: captured_at.to_string(),
        source: "test".to_string(),
        market_value: None,
        book_value: None,
        profit_loss: None,
        profit_loss_perc: None,
        positions: Vec::new(),
        fx_rates: Vec::new(),
    }
}

fn store_with_portfolio_at(captured_at: &str) -> Store {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_portfolio_snapshot(&empty_snapshot(captured_at))
        .expect("capture");
    store
}

fn freshness(response: ResponseBody) -> fineco_ipc::FreshnessReportDto {
    match response {
        ResponseBody::Freshness(report) => report,
        other => panic!("expected a freshness report, got {other:?}"),
    }
}

#[test]
fn freshness_reports_every_area() {
    let store = store_with_portfolio_at("2026-06-03T12:00:00Z");
    let handler = QueryHandler::new(store, FreshnessMaxAge::default(), owner_policy());

    // One minute after the portfolio capture; orders/tax were never captured.
    let now = epoch("2026-06-03T12:01:00Z");
    let report = freshness(
        handler
            .handle(Request::PortfolioGetFreshness, now)
            .expect("freshness"),
    );

    assert_eq!(report.portfolio.state, "fresh");
    assert_eq!(
        report.portfolio.captured_at.as_deref(),
        Some("2026-06-03T12:00:00Z")
    );
    assert_eq!(report.orders.state, "missing");
    assert_eq!(report.tax.state, "missing");
}

#[test]
fn portfolio_goes_stale_past_max_age() {
    let store = store_with_portfolio_at("2026-06-01T00:00:00Z");
    let handler = QueryHandler::new(store, FreshnessMaxAge::default(), owner_policy());

    // Three days later — past the 24h portfolio max age.
    let now = epoch("2026-06-04T00:00:00Z");
    let report = freshness(
        handler
            .handle(Request::PortfolioGetFreshness, now)
            .expect("freshness"),
    );
    assert_eq!(report.portfolio.state, "stale");
}

#[test]
fn store_worker_rejects_market_commands() {
    // Market tools are served by the gateway in-process, not the store worker;
    // a market command arriving here is invalid for this worker.
    let handler = QueryHandler::new(
        Store::open_in_memory().expect("open"),
        FreshnessMaxAge::default(),
        owner_policy(),
    );
    let err = handler
        .handle(
            Request::MarketGetZeroCommissionEtfs(fineco_ipc::MarketEtfsParams { query: None }),
            0,
        )
        .expect_err("market command is not served by the store worker");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn worker_denies_a_command_the_policy_does_not_grant() {
    // Independent capability enforcement: a policy without the orders cap makes
    // the worker refuse the orders command (defense in depth behind the gateway).
    let policy = Policy::from_json(
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":["portfolio.shareable.read"]}}}"#,
    )
    .expect("valid policy");
    let handler = QueryHandler::new(
        Store::open_in_memory().expect("open"),
        FreshnessMaxAge::default(),
        policy,
    );
    let err = handler
        .handle(Request::OrdersGetLatestMonitor, 0)
        .expect_err("orders command not granted by the policy");
    assert_eq!(err.code(), "invalid_request");

    // The granted shareable read still works (freshness is shareable-safe).
    assert!(handler.handle(Request::PortfolioGetFreshness, 0).is_ok());
}

#[test]
fn freshness_served_over_the_socket() {
    let store = store_with_portfolio_at("2026-06-03T12:00:00Z");
    let handler = QueryHandler::new(store, FreshnessMaxAge::default(), owner_policy());
    let now = epoch("2026-06-03T12:01:00Z");

    let mut path = std::env::temp_dir();
    path.push(format!("fineco-query-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    let serve_path = path.clone();
    thread::spawn(move || {
        // A fixed clock keeps the socket round-trip deterministic.
        let _ = serve_blocking(&listener, move |request| handler.handle(request, now));
        drop(serve_path);
    });

    let client = Client::new(&path);
    let report = freshness(
        client
            .call(&Request::PortfolioGetFreshness)
            .expect("socket freshness"),
    );
    assert_eq!(report.portfolio.state, "fresh");
    assert_eq!(report.orders.state, "missing");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn latest_orders_and_tax_are_served() {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_orders(
            "2026-06-03T10:00:00Z",
            &[NewOrder {
                trans_id_hash: "HASH1".to_string(),
                asset: NewAsset {
                    instr_id: "AAA".to_string(),
                    venue_system: "MOT".to_string(),
                    symbol: None,
                    description: None,
                    kind: None,
                    currency: None,
                },
                status: Some("filled".to_string()),
                sign: Some("BUY".to_string()),
                order_size: Some(10.0),
                size_filled: Some(10.0),
                avg_price: Some(100.0),
                submit_time: Some("2026-06-03T09:00:00Z".to_string()),
            }],
        )
        .expect("capture orders");
    store
        .capture_tax(
            "2026-06-03T10:00:00Z",
            &[NewTaxCarryForward {
                date_from: "2025-01-01".to_string(),
                date_to: "2025-12-31".to_string(),
                total: Some(1234.5),
            }],
            &[NewTaxMinusByYear {
                year: 2024,
                minus_residue: Some(500.0),
                expiration_date: Some("2028-12-31".to_string()),
            }],
        )
        .expect("capture tax");

    let handler = QueryHandler::new(store, FreshnessMaxAge::default(), owner_policy());

    match handler
        .handle(Request::OrdersGetLatestMonitor, 0)
        .expect("orders")
    {
        ResponseBody::Orders(dto) => {
            assert_eq!(dto.captured_at.as_deref(), Some("2026-06-03T10:00:00Z"));
            assert_eq!(dto.orders.len(), 1);
            assert_eq!(dto.orders[0].trans_id_hash, "HASH1");
            assert_eq!(dto.orders[0].instr_id, "AAA");
            assert_eq!(dto.orders[0].venue_system, "MOT");
            assert_eq!(dto.orders[0].avg_price, Some(100.0));
        }
        other => panic!("expected orders, got {other:?}"),
    }

    match handler
        .handle(Request::TaxGetLatestCarryForward, 0)
        .expect("tax cf")
    {
        ResponseBody::TaxCarryForward(dto) => {
            assert_eq!(dto.entries.len(), 1);
            assert_eq!(dto.entries[0].date_from, "2025-01-01");
            assert_eq!(dto.entries[0].total, Some(1234.5));
        }
        other => panic!("expected tax carry-forward, got {other:?}"),
    }

    match handler
        .handle(Request::TaxGetLatestMinusByYear, 0)
        .expect("tax minus")
    {
        ResponseBody::TaxMinus(dto) => {
            assert_eq!(dto.entries.len(), 1);
            assert_eq!(dto.entries[0].year, 2024);
            assert_eq!(dto.entries[0].minus_residue, Some(500.0));
        }
        other => panic!("expected tax minus, got {other:?}"),
    }
}

#[test]
fn an_empty_orders_capture_reports_its_own_timestamp() {
    // A non-empty capture, then a fresh empty one: the latest monitor must report
    // the empty capture's timestamp (from the data_captures marker), not re-
    // surface the previous capture and not collapse to `None`.
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_orders(
            "2026-06-03T09:00:00Z",
            &[NewOrder {
                trans_id_hash: "OLD".to_string(),
                asset: NewAsset {
                    instr_id: "AAA".to_string(),
                    venue_system: "MOT".to_string(),
                    symbol: None,
                    description: None,
                    kind: None,
                    currency: None,
                },
                status: Some("filled".to_string()),
                sign: Some("BUY".to_string()),
                order_size: Some(1.0),
                size_filled: Some(1.0),
                avg_price: Some(10.0),
                submit_time: None,
            }],
        )
        .expect("capture orders T1");
    store
        .capture_orders("2026-06-03T10:00:00Z", &[])
        .expect("capture empty orders T2");

    let handler = QueryHandler::new(store, FreshnessMaxAge::default(), owner_policy());
    match handler
        .handle(Request::OrdersGetLatestMonitor, 0)
        .expect("orders")
    {
        ResponseBody::Orders(dto) => {
            assert!(dto.orders.is_empty(), "the latest capture is empty");
            assert_eq!(
                dto.captured_at.as_deref(),
                Some("2026-06-03T10:00:00Z"),
                "must report the empty capture's own timestamp"
            );
        }
        other => panic!("expected orders, got {other:?}"),
    }
}

#[test]
fn empty_tax_captures_report_their_own_timestamp() {
    // Non-empty tax (both sublists), then a fresh fully-empty capture: both tax
    // DTOs must report the empty capture's timestamp from the shared marker.
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_tax(
            "2026-06-03T09:00:00Z",
            &[NewTaxCarryForward {
                date_from: "2025-01-01".to_string(),
                date_to: "2025-12-31".to_string(),
                total: Some(100.0),
            }],
            &[NewTaxMinusByYear {
                year: 2024,
                minus_residue: Some(50.0),
                expiration_date: None,
            }],
        )
        .expect("capture tax T1");
    store
        .capture_tax("2026-06-03T10:00:00Z", &[], &[])
        .expect("capture empty tax T2");

    let handler = QueryHandler::new(store, FreshnessMaxAge::default(), owner_policy());

    match handler
        .handle(Request::TaxGetLatestCarryForward, 0)
        .expect("tax cf")
    {
        ResponseBody::TaxCarryForward(dto) => {
            assert!(dto.entries.is_empty());
            assert_eq!(dto.captured_at.as_deref(), Some("2026-06-03T10:00:00Z"));
        }
        other => panic!("expected tax carry-forward, got {other:?}"),
    }
    match handler
        .handle(Request::TaxGetLatestMinusByYear, 0)
        .expect("tax minus")
    {
        ResponseBody::TaxMinus(dto) => {
            assert!(dto.entries.is_empty());
            assert_eq!(dto.captured_at.as_deref(), Some("2026-06-03T10:00:00Z"));
        }
        other => panic!("expected tax minus, got {other:?}"),
    }
}

#[test]
fn empty_orders_capture_is_an_empty_list() {
    let handler = QueryHandler::new(
        Store::open_in_memory().expect("open"),
        FreshnessMaxAge::default(),
        owner_policy(),
    );
    match handler
        .handle(Request::OrdersGetLatestMonitor, 0)
        .expect("orders")
    {
        ResponseBody::Orders(dto) => {
            assert!(dto.orders.is_empty());
            assert!(dto.captured_at.is_none());
        }
        other => panic!("expected orders, got {other:?}"),
    }
}

#[test]
fn portfolio_summary_full_and_shareable_are_served() {
    let mut store = Store::open_in_memory().expect("open");
    let mut snapshot = empty_snapshot("2026-06-03T12:00:00Z");
    snapshot.source = "fineco".to_string();
    snapshot.market_value = Some(1750.0);
    snapshot.book_value = Some(1500.0);
    snapshot.profit_loss = Some(250.0);
    snapshot.profit_loss_perc = Some(16.67);
    snapshot.positions = vec![NewPosition {
        asset: NewAsset {
            instr_id: "SYNTH1".to_string(),
            venue_system: "SYNTHV".to_string(),
            symbol: Some("SYN-A".to_string()),
            description: Some("Synthetic A".to_string()),
            kind: Some("EQUITY".to_string()),
            currency: Some("EUR".to_string()),
        },
        position_key_hash: None,
        qty: Some(10.0),
        avg_price: Some(100.0),
        market_price: Some(120.0),
        book_value: Some(1000.0),
        market_value: Some(1200.0),
        profit_loss: Some(200.0),
        profit_loss_perc: Some(20.0),
        weight_perc: Some(68.57),
    }];
    store
        .capture_portfolio_snapshot(&snapshot)
        .expect("capture snapshot");

    let handler = QueryHandler::new(store, FreshnessMaxAge::default(), owner_policy());

    match handler
        .handle(Request::PortfolioGetLatestSnapshotSummary, 0)
        .expect("summary")
    {
        ResponseBody::PortfolioSummary(dto) => {
            assert_eq!(dto.captured_at.as_deref(), Some("2026-06-03T12:00:00Z"));
            assert_eq!(dto.source.as_deref(), Some("fineco"));
            assert_eq!(dto.market_value, Some(1750.0));
            assert_eq!(dto.book_value, Some(1500.0));
        }
        other => panic!("expected summary, got {other:?}"),
    }

    match handler
        .handle(Request::PortfolioGetLatestFullSnapshot, 0)
        .expect("full")
    {
        ResponseBody::PortfolioFullSnapshot(dto) => {
            assert_eq!(dto.summary.market_value, Some(1750.0));
            assert_eq!(dto.positions.len(), 1);
            assert_eq!(dto.positions[0].instr_id, "SYNTH1");
            assert_eq!(dto.positions[0].market_value, Some(1200.0));
            assert_eq!(dto.positions[0].weight_perc, Some(68.57));
        }
        other => panic!("expected full snapshot, got {other:?}"),
    }

    match handler
        .handle(Request::PortfolioGetLatestShareableReport, 0)
        .expect("shareable")
    {
        ResponseBody::PortfolioShareableReport(dto) => {
            assert_eq!(dto.captured_at.as_deref(), Some("2026-06-03T12:00:00Z"));
            assert_eq!(dto.rows.len(), 1);
            assert_eq!(dto.rows[0].instr_id, "SYNTH1");
            assert_eq!(dto.rows[0].symbol, "SYN-A");
            assert_eq!(dto.rows[0].weight_perc, Some(68.57));
            assert_eq!(dto.rows[0].profit_loss_perc, Some(20.0));
        }
        other => panic!("expected shareable report, got {other:?}"),
    }
}

#[test]
fn portfolio_history_commands_are_served() {
    let mut store = Store::open_in_memory().expect("open");
    // Two snapshots of the same instrument, different totals/weights over time.
    for (captured_at, market_value, weight) in [
        ("2026-06-01T12:00:00Z", 1000.0_f64, 50.0_f64),
        ("2026-06-02T12:00:00Z", 1100.0, 55.0),
    ] {
        let mut snapshot = empty_snapshot(captured_at);
        snapshot.market_value = Some(market_value);
        snapshot.book_value = Some(900.0);
        snapshot.profit_loss = Some(market_value - 900.0);
        snapshot.profit_loss_perc = Some(10.0);
        snapshot.positions = vec![NewPosition {
            asset: NewAsset {
                instr_id: "AAA".to_string(),
                venue_system: "MOT".to_string(),
                symbol: Some("AAA-S".to_string()),
                description: Some("Asset A".to_string()),
                kind: Some("EQUITY".to_string()),
                currency: Some("EUR".to_string()),
            },
            position_key_hash: None,
            qty: Some(10.0),
            avg_price: Some(90.0),
            market_price: Some(market_value / 10.0),
            book_value: Some(900.0),
            market_value: Some(market_value),
            profit_loss: Some(market_value - 900.0),
            profit_loss_perc: Some(10.0),
            weight_perc: Some(weight),
        }];
        store
            .capture_portfolio_snapshot(&snapshot)
            .expect("capture");
    }

    let handler = QueryHandler::new(store, FreshnessMaxAge::default(), owner_policy());

    match handler
        .handle(
            Request::PortfolioGetHistory(fineco_ipc::HistoryParams { limit: 10 }),
            0,
        )
        .expect("history")
    {
        ResponseBody::PortfolioHistory(dto) => {
            // Chronological: oldest first.
            assert_eq!(dto.points.len(), 2);
            assert_eq!(dto.points[0].captured_at, "2026-06-01T12:00:00Z");
            assert_eq!(dto.points[0].market_value, Some(1000.0));
            assert_eq!(dto.points[1].captured_at, "2026-06-02T12:00:00Z");
            assert_eq!(dto.points[1].market_value, Some(1100.0));
        }
        other => panic!("expected history, got {other:?}"),
    }

    match handler
        .handle(Request::PortfolioGetAllocationHistory, 0)
        .expect("allocation")
    {
        ResponseBody::AllocationHistory(dto) => {
            assert_eq!(dto.points.len(), 2);
            assert_eq!(dto.points[0].instr_id, "AAA");
            assert_eq!(dto.points[0].venue_system, "MOT");
            assert_eq!(dto.points[0].symbol.as_deref(), Some("AAA-S"));
            assert_eq!(dto.points[0].weight_perc, Some(50.0));
            assert_eq!(dto.points[1].weight_perc, Some(55.0));
        }
        other => panic!("expected allocation history, got {other:?}"),
    }

    match handler
        .handle(
            Request::PortfolioGetPositionHistory(fineco_ipc::PositionHistoryParams {
                instr_id: "AAA".to_string(),
                venue_system: "MOT".to_string(),
            }),
            0,
        )
        .expect("position history")
    {
        ResponseBody::PositionHistory(dto) => {
            assert_eq!(dto.points.len(), 2);
            assert_eq!(dto.points[0].weight_perc, Some(50.0));
            assert_eq!(dto.points[0].market_value, Some(1000.0));
            assert_eq!(dto.points[1].weight_perc, Some(55.0));
            assert_eq!(dto.points[1].market_value, Some(1100.0));
        }
        other => panic!("expected position history, got {other:?}"),
    }
}

#[test]
fn empty_store_summary_is_all_none() {
    let handler = QueryHandler::new(
        Store::open_in_memory().expect("open"),
        FreshnessMaxAge::default(),
        owner_policy(),
    );
    match handler
        .handle(Request::PortfolioGetLatestSnapshotSummary, 0)
        .expect("summary")
    {
        ResponseBody::PortfolioSummary(dto) => {
            assert!(dto.captured_at.is_none());
            assert!(dto.market_value.is_none());
        }
        other => panic!("expected summary, got {other:?}"),
    }
}
