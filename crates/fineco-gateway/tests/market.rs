//! Integration tests: the gateway's market tools answer in-process from the
//! credential-free `fineco-market` client against the SYNTHETIC mock servers
//! (enrichment page + public ETF list) over loopback. No store socket is
//! touched by these tools, and no real host is used — the allowlist pins the
//! loopback mock.

use std::net::TcpListener;
use std::thread;

use fineco_gateway::Gateway;
use fineco_ipc::{MarketEnrichmentParams, MarketEtfsParams, Policy};
use fineco_market::{EnrichmentHostAllowlist, MarketClient};
use rmcp::handler::server::wrapper::Parameters;

/// A policy granting the owner `market.read` (so the market tools authorize).
fn owner_policy() -> Policy {
    Policy::from_json(r#"{"version":1,"auth_ids":{"owner":{"capabilities":["market.read"]}}}"#)
        .expect("valid owner policy")
}

const ETF_PATH: &str = "/common-pvt/js/json/etf-zero/etf_piu_scambiati.json";
const ENRICHMENT_ID: &str = "it/diversified-financials/syn-tip/synth-shares";
/// The market tools never reach the store socket; this path is never bound.
const UNUSED_SOCKET: &str = "/tmp/fineco-gateway-market-unused.sock";

/// Serve `handler` on an ephemeral loopback port; return its base URL.
fn spawn<F>(handler: F) -> String
where
    F: Fn(&httptiny::Request) -> httptiny::Response + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, handler);
    });
    format!("http://{addr}")
}

/// A market client pinned to the loopback mock host.
fn market_client(enrichment_base: &str, etf_url: &str) -> MarketClient {
    MarketClient::new(
        enrichment_base,
        EnrichmentHostAllowlist::from_allowed_hosts(["127.0.0.1"]),
        etf_url,
    )
}

#[tokio::test]
async fn etf_tool_answers_from_the_mock() {
    let etf = spawn(mock_fineco::route);
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_market(market_client(
            "http://127.0.0.1:9",
            &format!("{etf}{ETF_PATH}"),
        ))
        .with_policy(owner_policy());

    let etfs = gateway
        .market_get_zero_commission_etfs(Parameters(MarketEtfsParams { query: None }))
        .await
        .expect("etf tool")
        .0;
    assert_eq!(etfs.count, 2);
    assert_eq!(etfs.instruments.len(), 2);
    assert_eq!(etfs.instruments[0].instr_id, "SYNTHETF0001");
    assert!(!etfs.captured_at.is_empty());
}

#[tokio::test]
async fn etf_tool_applies_the_query_filter() {
    let etf = spawn(mock_fineco::route);
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_market(market_client(
            "http://127.0.0.1:9",
            &format!("{etf}{ETF_PATH}"),
        ))
        .with_policy(owner_policy());

    // A substring of the first instrument id matches exactly one.
    let filtered = gateway
        .market_get_zero_commission_etfs(Parameters(MarketEtfsParams {
            query: Some("0001".to_string()),
        }))
        .await
        .expect("etf tool")
        .0;
    assert_eq!(filtered.count, 1);
    assert_eq!(filtered.instruments[0].instr_id, "SYNTHETF0001");

    // A non-matching query yields an empty (but valid) list.
    let none = gateway
        .market_get_zero_commission_etfs(Parameters(MarketEtfsParams {
            query: Some("zzz-no-such-etf".to_string()),
        }))
        .await
        .expect("etf tool")
        .0;
    assert_eq!(none.count, 0);
    assert!(none.instruments.is_empty());
}

#[tokio::test]
async fn enrichment_tool_answers_from_the_mock() {
    let enrichment = spawn(mock_enrichment::route);
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_market(market_client(&enrichment, "http://127.0.0.1:9/etf"))
        .with_policy(owner_policy());

    let report = gateway
        .market_get_stock_enrichment(Parameters(MarketEnrichmentParams {
            identifier: ENRICHMENT_ID.to_string(),
            fineco_title: Some("Tamburi Investment Partners IT0003153621".to_string()),
        }))
        .await
        .expect("enrichment tool")
        .0;
    assert_eq!(
        report.company.name,
        "SYNTHETIC Tamburi Investment Partners SpA"
    );
    assert_eq!(report.company.isin, "IT0003153621");
    assert_eq!(report.title_match.expect("a match").verdict, "strong");
    assert_eq!(
        report.source_url,
        format!("{enrichment}/stocks/{ENRICHMENT_ID}")
    );
}

#[tokio::test]
async fn enrichment_tool_rejects_an_empty_identifier_before_any_request() {
    // Bounds validation runs at the gateway before the market client; an empty
    // identifier is a safe validation error even pointed at a dead port.
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_market(market_client(
            "http://127.0.0.1:9",
            "http://127.0.0.1:9/etf",
        ))
        .with_policy(owner_policy());
    let err = match gateway
        .market_get_stock_enrichment(Parameters(MarketEnrichmentParams {
            identifier: String::new(),
            fineco_title: None,
        }))
        .await
    {
        Ok(_) => panic!("empty identifier must be rejected"),
        Err(err) => err,
    };
    assert!(
        err.message.contains("identifier"),
        "message: {}",
        err.message
    );
}

#[tokio::test]
async fn market_tools_without_a_client_are_a_safe_error() {
    // Authorized (policy grants market.read) but no market client configured:
    // a private-cached-only gateway returns a safe error rather than panicking.
    let gateway = Gateway::new(UNUSED_SOCKET).with_policy(owner_policy());
    let err = match gateway
        .market_get_zero_commission_etfs(Parameters(MarketEtfsParams { query: None }))
        .await
    {
        Ok(_) => panic!("an unconfigured market tool must error"),
        Err(err) => err,
    };
    assert!(!err.message.is_empty());

    // And without a policy the same tool is denied before reaching the client.
    let denied = Gateway::new(UNUSED_SOCKET);
    let err = match denied
        .market_get_zero_commission_etfs(Parameters(MarketEtfsParams { query: None }))
        .await
    {
        Ok(_) => panic!("an unauthorized market tool must error"),
        Err(err) => err,
    };
    assert!(err.message.contains("policy"), "message: {}", err.message);
}
