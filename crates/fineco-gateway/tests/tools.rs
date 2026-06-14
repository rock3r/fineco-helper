//! Integration test: the gateway's MCP tools answer from a real store-query
//! worker over a Unix socket. The gateway holds only the socket client — no DB.

use std::os::unix::net::UnixListener;
use std::thread;

use fineco_gateway::Gateway;
use fineco_ipc::{HistoryParams, Policy, PositionHistoryParams, serve_blocking};
use fineco_query::{FreshnessMaxAge, QueryHandler};
use fineco_store::{NewAsset, NewPortfolioSnapshot, NewPosition, Store};
use rmcp::handler::server::wrapper::Parameters;

/// A policy granting the owner every M4 capability (so tools are authorized).
fn owner_policy() -> Policy {
    Policy::from_json(
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":[
            "market.read","portfolio.cached.full_read","portfolio.shareable.read",
            "orders.cached.read","tax.cached.read"]}}}"#,
    )
    .expect("valid owner policy")
}

/// Bind a socket and serve a store-query worker (seeded with one portfolio
/// snapshot) on a background thread; return the socket path. `tag` makes the
/// socket path unique per test so concurrent tests (under `cargo test`'s thread
/// parallelism) never share one socket.
fn spawn_worker(captured_at: &str, tag: &str) -> std::path::PathBuf {
    let mut store = Store::open_in_memory().expect("open");
    store
        .capture_portfolio_snapshot(&NewPortfolioSnapshot {
            captured_at: captured_at.to_string(),
            source: "test".to_string(),
            market_value: Some(1750.0),
            book_value: Some(1500.0),
            profit_loss: Some(250.0),
            profit_loss_perc: Some(16.67),
            positions: Vec::new(),
            fx_rates: Vec::new(),
        })
        .expect("capture");
    let handler = QueryHandler::new(store, FreshnessMaxAge::default(), owner_policy());

    let mut path = std::env::temp_dir();
    path.push(format!("fineco-gateway-{}-{tag}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    // Fixed clock so freshness is deterministic (one minute after the capture).
    let now = fineco_core::parse_iso8601_utc("2026-06-03T12:01:00Z").expect("epoch");
    thread::spawn(move || {
        let _ = serve_blocking(&listener, move |request| handler.handle(request, now));
    });
    path
}

#[tokio::test]
async fn freshness_tool_answers_from_the_worker() {
    let path = spawn_worker("2026-06-03T12:00:00Z", "freshness");
    let gateway = Gateway::new(&path).with_policy(owner_policy());

    let report = gateway
        .portfolio_get_freshness()
        .await
        .expect("freshness tool")
        .0;
    assert_eq!(report.portfolio.state, "fresh");
    assert_eq!(
        report.portfolio.captured_at.as_deref(),
        Some("2026-06-03T12:00:00Z")
    );
    assert_eq!(report.orders.state, "missing");

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn summary_tool_answers_from_the_worker() {
    let path = spawn_worker("2026-06-03T12:00:00Z", "summary");
    let gateway = Gateway::new(&path).with_policy(owner_policy());

    let summary = gateway
        .portfolio_get_latest_snapshot_summary()
        .await
        .expect("summary tool")
        .0;
    assert_eq!(summary.market_value, Some(1750.0));
    assert_eq!(summary.book_value, Some(1500.0));
    assert_eq!(summary.captured_at.as_deref(), Some("2026-06-03T12:00:00Z"));

    let _ = std::fs::remove_file(&path);
}

/// Serve a worker seeded with two snapshots that both hold one position for
/// instrument `AAA`/`MOT`, on a uniquely-named socket; return the socket path.
fn spawn_history_worker(tag: &str) -> std::path::PathBuf {
    let mut store = Store::open_in_memory().expect("open");
    for (captured_at, market_value, weight) in [
        ("2026-06-01T12:00:00Z", 1000.0_f64, 50.0_f64),
        ("2026-06-02T12:00:00Z", 1100.0, 55.0),
    ] {
        store
            .capture_portfolio_snapshot(&NewPortfolioSnapshot {
                captured_at: captured_at.to_string(),
                source: "test".to_string(),
                market_value: Some(market_value),
                book_value: Some(900.0),
                profit_loss: Some(market_value - 900.0),
                profit_loss_perc: Some(10.0),
                positions: vec![NewPosition {
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
                }],
                fx_rates: Vec::new(),
            })
            .expect("capture");
    }
    let handler = QueryHandler::new(store, FreshnessMaxAge::default(), owner_policy());

    let mut path = std::env::temp_dir();
    path.push(format!("fineco-gateway-{}-{tag}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind");
    thread::spawn(move || {
        let _ = serve_blocking(&listener, move |request| handler.handle(request, 0));
    });
    path
}

#[tokio::test]
async fn history_tools_answer_from_the_worker() {
    let path = spawn_history_worker("history");
    let gateway = Gateway::new(&path).with_policy(owner_policy());

    let history = gateway
        .portfolio_get_history(Parameters(HistoryParams { limit: 10 }))
        .await
        .expect("history tool")
        .0;
    assert_eq!(history.points.len(), 2);
    assert_eq!(history.points[0].captured_at, "2026-06-01T12:00:00Z");
    assert_eq!(history.points[0].market_value, Some(1000.0));
    assert_eq!(history.points[1].market_value, Some(1100.0));

    let allocation = gateway
        .portfolio_get_allocation_history()
        .await
        .expect("allocation tool")
        .0;
    assert_eq!(allocation.points.len(), 2);
    assert_eq!(allocation.points[0].instr_id, "AAA");
    assert_eq!(allocation.points[0].venue_system, "MOT");
    assert_eq!(allocation.points[0].weight_perc, Some(50.0));

    let position = gateway
        .portfolio_get_position_history(Parameters(PositionHistoryParams {
            instr_id: "AAA".to_string(),
            venue_system: "MOT".to_string(),
        }))
        .await
        .expect("position tool")
        .0;
    assert_eq!(position.points.len(), 2);
    assert_eq!(position.points[0].weight_perc, Some(50.0));
    assert_eq!(position.points[1].market_value, Some(1100.0));

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn out_of_range_limit_is_rejected_before_the_socket() {
    // Gateway-side bounds validation runs before any socket call, so even with no
    // worker listening an out-of-range limit is a safe validation error.
    let gateway =
        Gateway::new("/tmp/fineco-gateway-absent-bounds.sock").with_policy(owner_policy());
    let err = match gateway
        .portfolio_get_history(Parameters(HistoryParams { limit: 0 }))
        .await
    {
        Ok(_) => panic!("limit 0 must be rejected"),
        Err(err) => err,
    };
    assert!(err.message.contains("limit"), "message: {}", err.message);

    let _ = std::fs::remove_file("/tmp/fineco-gateway-absent-bounds.sock");
}

#[tokio::test]
async fn tool_against_a_dead_worker_is_a_safe_error() {
    // No worker listening: the tool must surface a safe MCP error, not hang/panic.
    let gateway = Gateway::new("/tmp/fineco-gateway-absent.sock").with_policy(owner_policy());
    // `Json` has no `Debug`, so match rather than `expect_err`.
    let err = match gateway.orders_get_latest_monitor().await {
        Ok(_) => panic!("a dead worker must produce an error"),
        Err(err) => err,
    };
    assert!(!err.message.is_empty());
}

#[tokio::test]
async fn a_gateway_without_a_policy_denies_every_tool() {
    // Fail closed: no policy => no capability is granted, before any socket hop.
    let gateway = Gateway::new("/tmp/fineco-gateway-no-policy.sock");
    let err = match gateway.portfolio_get_freshness().await {
        Ok(_) => panic!("a tool with no policy must be denied"),
        Err(err) => err,
    };
    assert!(err.message.contains("policy"), "message: {}", err.message);
}

#[tokio::test]
async fn a_narrow_policy_denies_ungranted_tools_but_allows_granted_ones() {
    // Grant only the shareable read; the full-read summary must be denied while
    // the shareable-safe freshness tool is allowed (it reaches the dead socket).
    let narrow = Policy::from_json(
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":["portfolio.shareable.read"]}}}"#,
    )
    .expect("valid policy");
    let gateway = Gateway::new("/tmp/fineco-gateway-narrow.sock").with_policy(narrow);

    let denied = match gateway.portfolio_get_latest_snapshot_summary().await {
        Ok(_) => panic!("full-read summary must be denied under a shareable-only policy"),
        Err(err) => err,
    };
    assert!(
        denied.message.contains("policy"),
        "message: {}",
        denied.message
    );

    // Freshness is authorized; with no worker it fails at the socket, not authz.
    let freshness_err = match gateway.portfolio_get_freshness().await {
        Ok(_) => panic!("expected a socket error against the dead worker"),
        Err(err) => err,
    };
    assert!(
        !freshness_err.message.contains("policy"),
        "freshness should pass authz, got: {}",
        freshness_err.message
    );
}

#[test]
fn default_connector_allowlist_is_valid_and_excludes_default_blocked_tools() {
    use fineco_gateway::DEFAULT_CONNECTOR_TOOLS;
    let all: std::collections::HashSet<String> = Gateway::tool_names().into_iter().collect();
    // Every default-allowlisted tool is a real registered tool (catches a typo).
    for name in DEFAULT_CONNECTOR_TOOLS {
        assert!(
            all.contains(*name),
            "default connector tool '{name}' is not a registered MCP tool"
        );
    }
    // The sensitive/owner-only-by-default tools are real tools, and NONE of them
    // is in the default connector allowlist.
    for blocked in [
        "portfolio_get_latest_snapshot_summary",
        "portfolio_get_latest_full_snapshot",
        "portfolio_get_history",
        "portfolio_get_position_history",
        "market_search_asset",
        "market_get_asset_details",
    ] {
        assert!(
            all.contains(blocked),
            "sanity: {blocked} should be a real tool"
        );
        assert!(
            !DEFAULT_CONNECTOR_TOOLS.contains(&blocked),
            "{blocked} must be blocked for connectors by default"
        );
    }
    // The default is exactly "every tool minus those blocked tools". This assertion is a
    // forcing function: adding a tool breaks it until you DECIDE — list the new tool
    // in DEFAULT_CONNECTOR_TOOLS, or add it to the blocked set (and update this
    // count). The connector filter itself is allowlist-based at runtime (a tool
    // absent from the resolved allowlist is hidden), so the posture is fail-safe.
    assert_eq!(
        DEFAULT_CONNECTOR_TOOLS.len(),
        all.len() - 6,
        "the default allowlist should be every tool except the default-blocked tools"
    );
}
