//! Integration tests: the gateway's market tools answer in-process from the
//! credential-free `fineco-market` client against the SYNTHETIC mock servers
//! (enrichment page + public ETF list) over loopback. No store socket is
//! touched by these tools, and no real host is used — the allowlist pins the
//! loopback mock.

use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use fineco_gateway::Gateway;
use fineco_ipc::{
    MarketAssetDetailsResult, MarketAssetIdentity, MarketAssetSections, MarketAssetType,
    MarketControlClient, MarketControlOutcome, MarketControlRequest, MarketDetailsParams,
    MarketDetailsSection, MarketEtfsParams, MarketField, MarketIndexCard, MarketIndexRegion,
    MarketIndicesParams, MarketIndicesResult, MarketSearchCandidate, MarketSearchGroup,
    MarketSearchParams, MarketSearchResult, MarketSource, MarketWarning, Policy,
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

fn owner_all_market_policy() -> Policy {
    Policy::from_json(
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":["market.read","market.authenticated.read"]}}}"#,
    )
    .expect("valid owner policy")
}

const ETF_PATH: &str = "/common-pvt/js/json/etf-zero/etf_piu_scambiati.json";
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

fn sample_indices_result() -> MarketIndicesResult {
    MarketIndicesResult {
        schema_version: 1,
        data_class: "authenticated_market".to_string(),
        source: "fineco.indicesbar".to_string(),
        captured_at: "2026-06-14T09:30:00Z".to_string(),
        indices: vec![MarketIndexCard {
            symbol: MarketField::high_string(
                "^FTMIB.affIdx",
                "fineco.indicesbar",
                "authenticated_market",
                "indicesbar",
                "2026-06-14T09:30:00Z",
            ),
            label: MarketField::high_string(
                "Ftse mib",
                "fineco.indicesbar",
                "authenticated_market",
                "indicesbar",
                "2026-06-14T09:30:00Z",
            ),
            region: MarketIndexRegion::Europe,
            value: None,
            change_percent: Some(MarketField::medium(
                1.97,
                Some("percent"),
                "fineco.indicesbar",
                "authenticated_market",
                "indicesbar",
                None,
                "2026-06-14T09:30:00Z",
            )),
        }],
        warnings: vec![],
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

fn sample_stock_details_result(identifier: &str) -> MarketAssetDetailsResult {
    MarketAssetDetailsResult {
        schema_version: 1,
        data_class: "authenticated_market".to_string(),
        captured_at: "2026-06-14T09:30:00Z".to_string(),
        asset: MarketAssetIdentity {
            identifier: identifier.to_string(),
            fineco_key: MarketField::high_string(
                "IT0003153621.BIT",
                "fineco",
                "authenticated_market",
                "search.global",
                "2026-06-14T09:30:00Z",
            ),
            asset_type: MarketField::high(
                MarketAssetType::Stock,
                None,
                "fineco",
                "authenticated_market",
                "search.global",
                None,
                "2026-06-14T09:30:00Z",
            ),
            name: None,
            isin: Some(MarketField::high_string(
                "IT0003153621",
                "fineco",
                "authenticated_market",
                "search.global",
                "2026-06-14T09:30:00Z",
            )),
            venue: MarketField::high_string(
                "BIT",
                "fineco",
                "authenticated_market",
                "search.global",
                "2026-06-14T09:30:00Z",
            ),
            symbol: MarketField::medium_string(
                "TIP",
                "fineco",
                "authenticated_market",
                "search.global",
                "2026-06-14T09:30:00Z",
            ),
            display_symbol: Some(MarketField::medium_string(
                "TIP.MI",
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
            _ => panic!("wrong request"),
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
async fn authenticated_market_indices_routes_through_the_controller_socket() {
    let path = market_control_socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |request| match request {
            MarketControlRequest::MarketGetIndices(params) => {
                assert_eq!(params.region, Some(MarketIndexRegion::Europe));
                assert_eq!(params.limit, Some(10));
                Ok(MarketControlOutcome::Indices {
                    result: sample_indices_result(),
                    session: fineco_ipc::MarketSessionStatus::fresh_login(),
                })
            }
            _ => panic!("wrong request"),
        });
    });

    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_authenticated_market_policy())
        .with_market_control_client(MarketControlClient::new(&path));

    let result = gateway
        .market_get_indices(Parameters(MarketIndicesParams {
            region: Some(MarketIndexRegion::Europe),
            limit: Some(10),
        }))
        .await
        .expect("authenticated market indices")
        .0;

    assert_eq!(result.data_class, "authenticated_market");
    assert_eq!(result.source, "fineco.indicesbar");
    assert_eq!(result.indices[0].symbol.value, "^FTMIB.affIdx");
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
            _ => panic!("wrong request"),
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
async fn asset_details_can_fold_stock_external_enrichment_outside_the_worker() {
    let enrichment_hits = Arc::new(AtomicU32::new(0));
    let enrichment_hits_for_server = Arc::clone(&enrichment_hits);
    let enrichment = spawn(move |req| {
        let path = req.path.split('?').next().unwrap_or(&req.path);
        if req.method == "GET" && path == "/stock/BIT/TIP" {
            enrichment_hits_for_server.fetch_add(1, Ordering::SeqCst);
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
    let path = market_control_socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |request| match request {
            MarketControlRequest::MarketGetAssetDetails(params) => {
                assert_eq!(params.identifier, "BIT/TIP");
                assert_eq!(params.expected_isin.as_deref(), Some("IT0003153621"));
                assert_eq!(
                    params.sections,
                    Some(vec![
                        MarketDetailsSection::Identity,
                        MarketDetailsSection::Stock
                    ])
                );
                Ok(MarketControlOutcome::Details {
                    result: Box::new(sample_stock_details_result(&params.identifier)),
                    session: fineco_ipc::MarketSessionStatus::fresh_login(),
                })
            }
            _ => panic!("wrong request"),
        });
    });

    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_all_market_policy())
        .with_market(market_client(&enrichment, "http://127.0.0.1:9/etf"))
        .with_market_control_client(MarketControlClient::new(&path));

    let result = gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "BIT/TIP".to_string(),
            expected_isin: Some("IT0003153621".to_string()),
            sections: Some(vec![
                MarketDetailsSection::Identity,
                MarketDetailsSection::Stock,
                MarketDetailsSection::ExternalEnrichment,
            ]),
        }))
        .await
        .expect("details with external enrichment")
        .0;

    let external = result
        .sections
        .external_enrichment
        .expect("external enrichment section");
    assert_eq!(external.data_class, "external_enrichment");
    assert_eq!(
        external.company.name,
        "SYNTHETIC Tamburi Investment Partners SpA"
    );
    assert_eq!(external.company.isin, "IT0003153621");
    assert_eq!(external.source_url, format!("{enrichment}/stock/BIT/TIP"));
    assert_eq!(enrichment_hits.load(Ordering::SeqCst), 1);
    assert!(result.sources.iter().any(|source| {
        source.data_class == "external_enrichment"
            && source.source_ref == format!("{enrichment}/stock/BIT/TIP")
    }));
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn folded_external_enrichment_returns_the_full_report_payload() {
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
    let path = market_control_socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |request| match request {
            MarketControlRequest::MarketGetAssetDetails(params) => {
                assert_eq!(
                    params.sections,
                    Some(vec![MarketDetailsSection::Identity]),
                    "external-only details must ask the worker for identity only"
                );
                Ok(MarketControlOutcome::Details {
                    result: Box::new(sample_stock_details_result(&params.identifier)),
                    session: fineco_ipc::MarketSessionStatus::fresh_login(),
                })
            }
            _ => panic!("wrong request"),
        });
    });

    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_all_market_policy())
        .with_market(market_client(&enrichment, "http://127.0.0.1:9/etf"))
        .with_market_control_client(MarketControlClient::new(&path));

    let folded = gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "BIT/TIP".to_string(),
            expected_isin: Some("IT0003153621".to_string()),
            sections: Some(vec![MarketDetailsSection::ExternalEnrichment]),
        }))
        .await
        .expect("folded enrichment")
        .0
        .sections
        .external_enrichment
        .expect("external enrichment section");

    // An external-enrichment-only request (the socket handler above asserts the
    // worker is asked for `identity` only) still yields the full enrichment report
    // the standalone tool used to return: data-class tag, source URL, and the
    // parsed company overview.
    assert_eq!(folded.data_class, "external_enrichment");
    assert_eq!(folded.source_url, format!("{enrichment}/stock/BIT/TIP"));
    assert_eq!(
        folded.company.name,
        "SYNTHETIC Tamburi Investment Partners SpA"
    );
    assert_eq!(folded.company.isin, "IT0003153621");
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn asset_details_external_enrichment_still_requires_authenticated_market_read() {
    let enrichment_hits = Arc::new(AtomicU32::new(0));
    let enrichment_hits_for_server = Arc::clone(&enrichment_hits);
    let enrichment = spawn(move |_req| {
        enrichment_hits_for_server.fetch_add(1, Ordering::SeqCst);
        httptiny::Response::not_found()
    });
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_policy())
        .with_market(market_client(&enrichment, "http://127.0.0.1:9/etf"))
        .with_market_control_client(MarketControlClient::new(
            "/tmp/fineco-gateway-market-control-dead.sock",
        ));

    let err = match gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "BIT/TIP".to_string(),
            expected_isin: Some("IT0003153621".to_string()),
            sections: Some(vec![MarketDetailsSection::ExternalEnrichment]),
        }))
        .await
    {
        Ok(_) => panic!("details external_enrichment must require authenticated market read"),
        Err(err) => err,
    };

    assert!(err.message.contains("policy"), "message: {}", err.message);
    assert_eq!(enrichment_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn asset_details_external_enrichment_also_requires_market_read() {
    let enrichment_hits = Arc::new(AtomicU32::new(0));
    let enrichment_hits_for_server = Arc::clone(&enrichment_hits);
    let enrichment = spawn(move |_req| {
        enrichment_hits_for_server.fetch_add(1, Ordering::SeqCst);
        httptiny::Response::not_found()
    });
    let path = market_control_socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |request| match request {
            MarketControlRequest::MarketGetAssetDetails(params) => {
                assert_eq!(params.sections, Some(vec![MarketDetailsSection::Identity]));
                Ok(MarketControlOutcome::Details {
                    result: Box::new(sample_stock_details_result(&params.identifier)),
                    session: fineco_ipc::MarketSessionStatus::fresh_login(),
                })
            }
            _ => panic!("unexpected search request"),
        });
    });
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_authenticated_market_policy())
        .with_market(market_client(&enrichment, "http://127.0.0.1:9/etf"))
        .with_market_control_client(MarketControlClient::new(&path));

    let err = match gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "BIT/TIP".to_string(),
            expected_isin: Some("IT0003153621".to_string()),
            sections: Some(vec![MarketDetailsSection::ExternalEnrichment]),
        }))
        .await
    {
        Ok(_) => panic!("details external_enrichment must require market.read"),
        Err(err) => err,
    };

    assert!(err.message.contains("policy"), "message: {}", err.message);
    assert_eq!(enrichment_hits.load(Ordering::SeqCst), 0);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn asset_details_rejects_over_limit_sections_before_stripping_external_enrichment() {
    let enrichment_hits = Arc::new(AtomicU32::new(0));
    let enrichment_hits_for_server = Arc::clone(&enrichment_hits);
    let enrichment = spawn(move |_req| {
        enrichment_hits_for_server.fetch_add(1, Ordering::SeqCst);
        httptiny::Response::not_found()
    });
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_all_market_policy())
        .with_market(market_client(&enrichment, "http://127.0.0.1:9/etf"))
        .with_market_control_client(MarketControlClient::new(
            "/tmp/fineco-gateway-market-control-dead.sock",
        ));

    let err = match gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "BIT/TIP".to_string(),
            expected_isin: Some("IT0003153621".to_string()),
            sections: Some(vec![
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
            ]),
        }))
        .await
    {
        Ok(_) => panic!("over-limit original sections must be rejected"),
        Err(err) => err,
    };

    assert!(err.message.contains("sections"), "message: {}", err.message);
    assert_eq!(enrichment_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn asset_details_authorizes_before_validating_external_enrichment_sections() {
    let enrichment_hits = Arc::new(AtomicU32::new(0));
    let enrichment_hits_for_server = Arc::clone(&enrichment_hits);
    let enrichment = spawn(move |_req| {
        enrichment_hits_for_server.fetch_add(1, Ordering::SeqCst);
        httptiny::Response::not_found()
    });
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_policy())
        .with_market(market_client(&enrichment, "http://127.0.0.1:9/etf"))
        .with_market_control_client(MarketControlClient::new(
            "/tmp/fineco-gateway-market-control-dead.sock",
        ));

    let err = match gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "BIT/TIP".to_string(),
            expected_isin: Some("IT0003153621".to_string()),
            sections: Some(vec![
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
                MarketDetailsSection::ExternalEnrichment,
            ]),
        }))
        .await
    {
        Ok(_) => panic!("unauthorized details must be denied before validation"),
        Err(err) => err,
    };

    assert!(err.message.contains("policy"), "message: {}", err.message);
    assert_eq!(enrichment_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn asset_details_warns_when_external_enrichment_identity_disagrees() {
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
    let path = market_control_socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |request| match request {
            MarketControlRequest::MarketGetAssetDetails(params) => {
                let mut result = sample_stock_details_result(&params.identifier);
                result.asset.isin.as_mut().expect("isin").value = "GB0000000000".to_string();
                Ok(MarketControlOutcome::Details {
                    result: Box::new(result),
                    session: fineco_ipc::MarketSessionStatus::fresh_login(),
                })
            }
            _ => panic!("wrong request"),
        });
    });
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_all_market_policy())
        .with_market(market_client(&enrichment, "http://127.0.0.1:9/etf"))
        .with_market_control_client(MarketControlClient::new(&path));

    let result = gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "BIT/TIP".to_string(),
            expected_isin: None,
            sections: Some(vec![MarketDetailsSection::ExternalEnrichment]),
        }))
        .await
        .expect("details with disagreement warning")
        .0;

    assert!(result.warnings.iter().any(|warning| {
        warning.code == "external_enrichment_isin_disagreement"
            && warning.message.contains("Fineco identity is canonical")
    }));
    assert!(result.sections.external_enrichment.is_some());
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn asset_details_keeps_fineco_details_when_external_enrichment_fails() {
    let path = market_control_socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |request| match request {
            MarketControlRequest::MarketGetAssetDetails(params) => {
                Ok(MarketControlOutcome::Details {
                    result: Box::new(sample_stock_details_result(&params.identifier)),
                    session: fineco_ipc::MarketSessionStatus::fresh_login(),
                })
            }
            _ => panic!("wrong request"),
        });
    });
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_all_market_policy())
        .with_market(market_client(
            "http://127.0.0.1:9",
            "http://127.0.0.1:9/etf",
        ))
        .with_market_control_client(MarketControlClient::new(&path));

    let result = gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "BIT/TIP".to_string(),
            expected_isin: Some("IT0003153621".to_string()),
            sections: Some(vec![MarketDetailsSection::ExternalEnrichment]),
        }))
        .await
        .expect("Fineco details should survive supplemental enrichment failure")
        .0;

    assert_eq!(result.asset.identifier, "BIT/TIP");
    assert!(result.sections.external_enrichment.is_none());
    assert!(result.warnings.iter().any(|warning| {
        warning.code.starts_with("external_enrichment_")
            && warning.message.contains("Fineco details are returned")
    }));
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn asset_details_does_not_warn_for_external_exchange_suffix() {
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
    let path = market_control_socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |request| match request {
            MarketControlRequest::MarketGetAssetDetails(params) => {
                let mut result = sample_stock_details_result(&params.identifier);
                result.asset.symbol.value = "TIP.MI".to_string();
                Ok(MarketControlOutcome::Details {
                    result: Box::new(result),
                    session: fineco_ipc::MarketSessionStatus::fresh_login(),
                })
            }
            _ => panic!("wrong request"),
        });
    });
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_all_market_policy())
        .with_market(market_client(&enrichment, "http://127.0.0.1:9/etf"))
        .with_market_control_client(MarketControlClient::new(&path));

    let result = gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "BIT/TIP".to_string(),
            expected_isin: Some("IT0003153621".to_string()),
            sections: Some(vec![MarketDetailsSection::ExternalEnrichment]),
        }))
        .await
        .expect("details with external exchange suffix")
        .0;

    assert!(result.sections.external_enrichment.is_some());
    assert!(
        !result
            .warnings
            .iter()
            .any(|warning| warning.code == "external_enrichment_symbol_disagreement")
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn asset_details_external_enrichment_keeps_warning_and_source_caps() {
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
    let path = market_control_socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |request| match request {
            MarketControlRequest::MarketGetAssetDetails(params) => {
                let mut result = sample_stock_details_result(&params.identifier);
                result.asset.isin.as_mut().expect("isin").value = "GB0000000000".to_string();
                result.warnings = (0..fineco_ipc::MAX_WARNINGS)
                    .map(|idx| MarketWarning {
                        code: format!("worker_warning_{idx}"),
                        message: "bounded worker warning".to_string(),
                    })
                    .collect();
                result.sources = (0..fineco_ipc::MAX_SOURCES)
                    .map(|idx| MarketSource {
                        source: "fineco".to_string(),
                        data_class: "authenticated_market".to_string(),
                        source_ref: format!("worker-source-{idx}"),
                        captured_at: "2026-06-14T09:30:00Z".to_string(),
                    })
                    .collect();
                Ok(MarketControlOutcome::Details {
                    result: Box::new(result),
                    session: fineco_ipc::MarketSessionStatus::fresh_login(),
                })
            }
            _ => panic!("wrong request"),
        });
    });
    let gateway = Gateway::new(UNUSED_SOCKET)
        .with_policy(owner_all_market_policy())
        .with_market(market_client(&enrichment, "http://127.0.0.1:9/etf"))
        .with_market_control_client(MarketControlClient::new(&path));

    let result = gateway
        .market_get_asset_details(Parameters(MarketDetailsParams {
            identifier: "BIT/TIP".to_string(),
            expected_isin: None,
            sections: Some(vec![MarketDetailsSection::ExternalEnrichment]),
        }))
        .await
        .expect("details with capped gateway additions")
        .0;

    assert_eq!(result.warnings.len(), fineco_ipc::MAX_WARNINGS);
    assert_eq!(result.warnings[0].code, "worker_warning_0");
    assert!(
        !result
            .warnings
            .iter()
            .any(|warning| warning.code == "external_enrichment_isin_disagreement")
    );
    assert_eq!(result.sources.len(), fineco_ipc::MAX_SOURCES);
    assert_eq!(result.sources[0].source_ref, "worker-source-0");
    assert!(
        !result
            .sources
            .iter()
            .any(|source| source.data_class == "external_enrichment")
    );
    assert!(result.sections.external_enrichment.is_some());
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
