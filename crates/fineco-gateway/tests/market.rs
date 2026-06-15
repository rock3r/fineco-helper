//! Integration tests: the gateway's market tools answer in-process from the
//! credential-free `fineco-market` client against the SYNTHETIC mock servers
//! (enrichment page + public ETF list) over loopback. No store socket is
//! touched by these tools, and no real host is used — the allowlist pins the
//! loopback mock.

use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use fineco_gateway::Gateway;
use fineco_ipc::{
    MarketAssetDetailsResult, MarketAssetIdentity, MarketAssetSections, MarketAssetType,
    MarketControlClient, MarketControlOutcome, MarketControlRequest, MarketDetailsParams,
    MarketDetailsSection, MarketEnrichmentParams, MarketEtfsParams, MarketField,
    MarketSearchCandidate, MarketSearchGroup, MarketSearchParams, MarketSearchResult, Policy,
    serve_market_control_blocking,
};
use fineco_market::{EnrichmentHostAllowlist, MarketClient};
use rmcp::handler::server::wrapper::Parameters;

/// A policy granting the owner `market.read` (so the market tools authorize).
fn owner_policy() -> Policy {
    Policy::from_json(r#"{"version":1,"auth_ids":{"owner":{"capabilities":["market.read"]}}}"#)
        .expect("valid owner policy")
}

fn owner_authenticated_market_policy() -> Policy {
    Policy::from_json(
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":["market.authenticated.read"]}}}"#,
    )
    .expect("valid owner policy")
}

const ETF_PATH: &str = "/common-pvt/js/json/etf-zero/etf_piu_scambiati.json";
const ENRICHMENT_ID: &str = "BIT/TIP";
/// The market tools never reach the store socket; this path is never bound.
const UNUSED_SOCKET: &str = "/tmp/fineco-gateway-market-unused.sock";
static SOCKET_COUNTER: AtomicU32 = AtomicU32::new(0);

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

fn market_control_socket_path() -> PathBuf {
    let mut path = PathBuf::from("/tmp");
    let tag = SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    path.push(format!("fgmc-{}-{tag}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn sample_search_result(query: &str) -> MarketSearchResult {
    MarketSearchResult {
        query: query.to_string(),
        data_class: "authenticated_market".to_string(),
        source: "fineco.search.global".to_string(),
        captured_at: "2026-06-14T09:30:00Z".to_string(),
        groups: vec![MarketSearchGroup {
            asset_type: MarketAssetType::Etf,
            result_count: 1,
            candidates: vec![MarketSearchCandidate {
                fineco_key: "IE00B8GKDB10.AFF".to_string(),
                identifier: "AFF/VHYL".to_string(),
                name: "Vanguard FTSE All-World High Dividend Yield UCITS ETF Dis".to_string(),
                venue: "AFF".to_string(),
                symbol: "VHYL".to_string(),
                display_symbol: "VHYL.MI".to_string(),
                isin: Some("IE00B8GKDB10".to_string()),
                currency: Some("EUR".to_string()),
                asset_type: MarketAssetType::Etf,
                preferred: true,
            }],
        }],
    }
}

fn sample_details_result(identifier: &str) -> MarketAssetDetailsResult {
    MarketAssetDetailsResult {
        schema_version: 1,
        data_class: "authenticated_market".to_string(),
        captured_at: "2026-06-14T09:30:00Z".to_string(),
        asset: MarketAssetIdentity {
            identifier: identifier.to_string(),
            fineco_key: MarketField::high_string(
                "IE00B8GKDB10.AFF",
                "fineco",
                "authenticated_market",
                "search.global",
                "2026-06-14T09:30:00Z",
            ),
            asset_type: MarketField::high(
                MarketAssetType::Etf,
                None,
                "fineco",
                "authenticated_market",
                "search.global",
                None,
                "2026-06-14T09:30:00Z",
            ),
            name: None,
            isin: Some(MarketField::high_string(
                "IE00B8GKDB10",
                "fineco",
                "authenticated_market",
                "search.global",
                "2026-06-14T09:30:00Z",
            )),
            venue: MarketField::high_string(
                "AFF",
                "fineco",
                "authenticated_market",
                "search.global",
                "2026-06-14T09:30:00Z",
            ),
            symbol: MarketField::medium_string(
                "VHYL",
                "fineco",
                "authenticated_market",
                "search.global",
                "2026-06-14T09:30:00Z",
            ),
            display_symbol: Some(MarketField::medium_string(
                "VHYL.MI",
                "fineco",
                "authenticated_market",
                "search.global",
                "2026-06-14T09:30:00Z",
            )),
            currency: Some(MarketField::high_string(
                "EUR",
                "fineco",
                "authenticated_market",
                "search.global",
                "2026-06-14T09:30:00Z",
            )),
        },
        sections: MarketAssetSections::default(),
        sources: vec![],
        warnings: vec![],
    }
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
    let enrichment = spawn(|req| {
        let path = req.path.split('?').next().unwrap_or(&req.path);
        if req.method == "GET" && path == "/stock/BIT/TIP" {
            mock_enrichment::route(&httptiny::Request {
                method: req.method.clone(),
                path: "/stocks/it/diversified-financials/syn-tip/synth-shares".to_string(),
                headers: req.headers.clone(),
                body: String::new(),
            })
        } else {
            httptiny::Response::not_found()
        }
    });
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_market(market_client(&enrichment, "http://127.0.0.1:9/etf"))
        .with_policy(owner_policy());

    let report = gateway
        .market_get_stock_enrichment(Parameters(MarketEnrichmentParams {
            identifier: ENRICHMENT_ID.to_string(),
            expected_isin: Some("IT0003153621".to_string()),
        }))
        .await
        .expect("enrichment tool")
        .0;
    assert_eq!(
        report.company.name,
        "SYNTHETIC Tamburi Investment Partners SpA"
    );
    assert_eq!(report.company.isin, "IT0003153621");
    assert_eq!(report.source_url, format!("{enrichment}/stock/BIT/TIP"));
}

#[tokio::test]
async fn authenticated_market_search_routes_through_the_controller_socket() {
    let path = market_control_socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |request| match request {
            MarketControlRequest::MarketSearchAsset(params) => {
                assert_eq!(params.query, "VHYL");
                assert_eq!(params.asset_type, Some(MarketAssetType::Etf));
                Ok(MarketControlOutcome::Search {
                    result: sample_search_result(&params.query),
                    session: fineco_ipc::MarketSessionStatus::fresh_login(),
                })
            }
            MarketControlRequest::MarketGetAssetDetails(_) => panic!("wrong request"),
        });
    });

    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_authenticated_market_policy())
        .with_market_control_client(MarketControlClient::new(&path));

    let result = gateway
        .market_search_asset(Parameters(MarketSearchParams {
            query: "VHYL".to_string(),
            asset_type: Some(MarketAssetType::Etf),
            limit: Some(5),
        }))
        .await
        .expect("authenticated market search")
        .0;

    assert_eq!(result.data_class, "authenticated_market");
    assert_eq!(result.source, "fineco.search.global");
    assert_eq!(
        result.groups[0].candidates[0].fineco_key,
        "IE00B8GKDB10.AFF"
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn authenticated_market_details_routes_through_the_controller_socket() {
    let path = market_control_socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |request| match request {
            MarketControlRequest::MarketGetAssetDetails(params) => {
                assert_eq!(params.identifier, "AFF/VHYL");
                assert_eq!(params.expected_isin.as_deref(), Some("IE00B8GKDB10"));
                assert_eq!(
                    params.sections,
                    Some(vec![
                        MarketDetailsSection::Identity,
                        MarketDetailsSection::Etf
                    ])
                );
                Ok(MarketControlOutcome::Details {
                    result: Box::new(sample_details_result(&params.identifier)),
                    session: fineco_ipc::MarketSessionStatus::fresh_login(),
                })
            }
            MarketControlRequest::MarketSearchAsset(_) => panic!("wrong request"),
        });
    });

    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_authenticated_market_policy())
        .with_market_control_client(MarketControlClient::new(&path));

    let result = gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "AFF/VHYL".to_string(),
            expected_isin: Some("IE00B8GKDB10".to_string()),
            sections: Some(vec![
                MarketDetailsSection::Identity,
                MarketDetailsSection::Etf,
            ]),
        }))
        .await
        .expect("authenticated market details")
        .0;

    assert_eq!(result.data_class, "authenticated_market");
    assert_eq!(result.asset.fineco_key.value, "IE00B8GKDB10.AFF");
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn authenticated_market_details_requires_the_authenticated_capability() {
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_policy())
        .with_market_control_client(MarketControlClient::new(
            "/tmp/fineco-gateway-market-control-dead.sock",
        ));

    let err = match gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "AFF/VHYL".to_string(),
            expected_isin: Some("IE00B8GKDB10".to_string()),
            sections: None,
        }))
        .await
    {
        Ok(_) => panic!("market_get_asset_details must require market.authenticated.read"),
        Err(err) => err,
    };
    assert!(err.message.contains("policy"), "message: {}", err.message);
}

#[tokio::test]
async fn authenticated_market_details_rejects_wrong_controller_outcome_variant() {
    let path = market_control_socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |_request| {
            Ok(MarketControlOutcome::Search {
                result: sample_search_result("VHYL"),
                session: fineco_ipc::MarketSessionStatus::fresh_login(),
            })
        });
    });

    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_authenticated_market_policy())
        .with_market_control_client(MarketControlClient::new(&path));

    let err = match gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "AFF/VHYL".to_string(),
            expected_isin: Some("IE00B8GKDB10".to_string()),
            sections: Some(vec![MarketDetailsSection::Identity]),
        }))
        .await
    {
        Ok(_) => panic!("wrong outcome variant must fail closed"),
        Err(err) => err,
    };

    assert!(
        err.message.contains("market request failed"),
        "message: {}",
        err.message
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn authenticated_market_search_requires_the_authenticated_capability() {
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_policy())
        .with_market_control_client(MarketControlClient::new(
            "/tmp/fineco-gateway-market-control-dead.sock",
        ));

    let err = match gateway
        .market_search_asset(Parameters(MarketSearchParams {
            query: "VHYL".to_string(),
            asset_type: Some(MarketAssetType::Etf),
            limit: Some(5),
        }))
        .await
    {
        Ok(_) => panic!("market_search_asset must require market.authenticated.read"),
        Err(err) => err,
    };
    assert!(err.message.contains("policy"), "message: {}", err.message);
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
            expected_isin: None,
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
