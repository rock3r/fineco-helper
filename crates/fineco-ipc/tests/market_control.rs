//! Contract tests for the authenticated market-control socket: gateway requests
//! are typed, strict, capability-gated as `market.authenticated.read`, and return
//! normalized search results rather than raw Fineco payloads.

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use fineco_ipc::{
    Capability, MarketAssetType, MarketControlClient, MarketControlOutcome, MarketControlRequest,
    MarketDetailsParams, MarketDetailsSection, MarketField, MarketSearchCandidate,
    MarketSearchGroup, MarketSearchParams, MarketSearchResult, serve_market_control_blocking,
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn sample_result() -> MarketSearchResult {
    MarketSearchResult {
        query: "VHYL".to_string(),
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

fn sample_details() -> fineco_ipc::MarketAssetDetailsResult {
    fineco_ipc::MarketAssetDetailsResult {
        schema_version: 1,
        data_class: "authenticated_market".to_string(),
        captured_at: "2026-06-14T09:30:00Z".to_string(),
        asset: fineco_ipc::MarketAssetIdentity {
            identifier: "AFF/VHYL".to_string(),
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
            name: Some(MarketField::high_string(
                "Vanguard FTSE All-World High Dividend Yield UCITS ETF Dis",
                "fineco",
                "authenticated_market",
                "search.global",
                "2026-06-14T09:30:00Z",
            )),
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
        sections: fineco_ipc::MarketAssetSections::default(),
        sources: vec![],
        warnings: vec![],
    }
}

fn socket_path() -> PathBuf {
    let mut path = PathBuf::from("/tmp");
    let tag = COUNTER.fetch_add(1, Ordering::Relaxed);
    path.push(format!("fmc-{}-{tag}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn market_search_request_is_strict_and_authenticated() {
    let request = MarketControlRequest::from_json(
        r#"{"command":"market_search_asset","params":{"query":"VHYL","type":"etf","limit":5}}"#,
    )
    .expect("parse request");
    assert_eq!(
        request.required_capability(),
        Capability::MarketAuthenticatedRead
    );

    match request {
        MarketControlRequest::MarketSearchAsset(params) => {
            assert_eq!(params.query, "VHYL");
            assert_eq!(params.asset_type, Some(MarketAssetType::Etf));
            assert_eq!(params.limit, Some(5));
        }
        MarketControlRequest::MarketGetAssetDetails(_) => panic!("wrong command"),
    }

    for bad in [
        r#"{"command":"market_search_asset","params":{"query":"","limit":5}}"#,
        r#"{"command":"market_search_asset","params":{"query":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","limit":5}}"#,
        r#"{"command":"market_search_asset","params":{"query":"VHYL","limit":0}}"#,
        r#"{"command":"market_search_asset","params":{"query":"VHYL","limit":31}}"#,
        r#"{"command":"market_search_asset","params":{"query":"VHYL","asset_type":"etf"}}"#,
        r#"{"command":"market_search_asset","params":{"query":"VHYL","url":"http://example.test"}}"#,
        r#"{"command":"market_search_asset","params":{"query":"VHYL"},"headers":{}}"#,
    ] {
        assert!(
            MarketControlRequest::from_json(bad).is_err(),
            "bad request must be rejected: {bad}"
        );
    }
}

#[test]
fn market_details_request_is_strict_and_authenticated() {
    let request = MarketControlRequest::from_json(
        r#"{"command":"market_get_asset_details","params":{"identifier":"AFF/VHYL","expected_isin":"IE00B8GKDB10.AFF","sections":["identity","listing","quote","profile","etf"]}}"#,
    )
    .expect("parse request");
    assert_eq!(
        request.required_capability(),
        Capability::MarketAuthenticatedRead
    );

    match request {
        MarketControlRequest::MarketGetAssetDetails(params) => {
            assert_eq!(params.identifier, "AFF/VHYL");
            assert_eq!(params.expected_isin.as_deref(), Some("IE00B8GKDB10.AFF"));
            assert_eq!(
                params.sections,
                Some(vec![
                    MarketDetailsSection::Identity,
                    MarketDetailsSection::Listing,
                    MarketDetailsSection::Quote,
                    MarketDetailsSection::Profile,
                    MarketDetailsSection::Etf,
                ])
            );
        }
        MarketControlRequest::MarketSearchAsset(_) => panic!("wrong command"),
    }

    let external = MarketControlRequest::from_json(
        r#"{"command":"market_get_asset_details","params":{"identifier":"BIT/TIP","sections":["external_enrichment"]}}"#,
    )
    .expect("external enrichment is a valid details section");
    match external {
        MarketControlRequest::MarketGetAssetDetails(params) => {
            assert_eq!(
                params.sections,
                Some(vec![MarketDetailsSection::ExternalEnrichment])
            );
        }
        MarketControlRequest::MarketSearchAsset(_) => panic!("wrong command"),
    }

    for bad in [
        r#"{"command":"market_get_asset_details","params":{"identifier":"VHYL"}}"#,
        r#"{"command":"market_get_asset_details","params":{"identifier":"AFF/"}}"#,
        r#"{"command":"market_get_asset_details","params":{"identifier":"AFF/VHYL","expected_isin":"Vanguard"}}"#,
        r#"{"command":"market_get_asset_details","params":{"identifier":"AFF/VHYL","sections":["identity","listing","quote","profile","etf","stock","holdings","exposures","returns","risk","ratios","chart","news"]}}"#,
        r#"{"command":"market_get_asset_details","params":{"identifier":"AFF/VHYL","sections":["chart"]}}"#,
        r#"{"command":"market_get_asset_details","params":{"identifier":"AFF/VHYL","sections":["news"]}}"#,
        r#"{"command":"market_get_asset_details","params":{"identifier":"AFF/VHYL","url":"http://example.test"}}"#,
        r#"{"command":"market_get_asset_details","params":{"identifier":"AFF/VHYL"},"headers":{}}"#,
    ] {
        assert!(
            MarketControlRequest::from_json(bad).is_err(),
            "bad request must be rejected: {bad}"
        );
    }
}

#[test]
fn market_details_response_enforces_serialized_size_cap() {
    let mut details = sample_details();
    details.asset.name = Some(MarketField::high_string(
        &"A".repeat(fineco_ipc::MAX_DETAILS_RESPONSE_BYTES),
        "fineco",
        "authenticated_market",
        "test",
        "2026-06-14T09:30:00Z",
    ));

    let err = details
        .validate_response_size()
        .expect_err("oversized details must fail");
    assert_eq!(err.code(), "market_unexpected_response");
}

#[test]
fn market_control_socket_round_trips_search_results() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |request| {
            assert_eq!(
                request.required_capability(),
                Capability::MarketAuthenticatedRead
            );
            Ok(MarketControlOutcome::Search {
                result: sample_result(),
                session: fineco_ipc::MarketSessionStatus::fresh_login(),
            })
        });
    });

    let client = MarketControlClient::new(&path);
    let outcome = client
        .call(&MarketControlRequest::MarketSearchAsset(
            MarketSearchParams {
                query: "VHYL".to_string(),
                asset_type: Some(MarketAssetType::Etf),
                limit: Some(5),
            },
        ))
        .expect("market-control call");

    match outcome {
        MarketControlOutcome::Search { result, session } => {
            assert!(session.login_performed);
            assert_eq!(result.captured_at, "2026-06-14T09:30:00Z");
            assert_eq!(
                result.groups[0].candidates[0].fineco_key,
                "IE00B8GKDB10.AFF"
            );
        }
        MarketControlOutcome::Details { .. } => panic!("wrong outcome"),
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn market_control_socket_round_trips_details_results() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).expect("bind market-control socket");
    thread::spawn(move || {
        let _ = serve_market_control_blocking(&listener, |request| {
            assert_eq!(
                request.required_capability(),
                Capability::MarketAuthenticatedRead
            );
            match request {
                MarketControlRequest::MarketGetAssetDetails(params) => {
                    assert_eq!(params.identifier, "AFF/VHYL");
                    Ok(MarketControlOutcome::Details {
                        result: Box::new(sample_details()),
                        session: fineco_ipc::MarketSessionStatus::fresh_login(),
                    })
                }
                MarketControlRequest::MarketSearchAsset(_) => panic!("wrong request"),
            }
        });
    });

    let client = MarketControlClient::new(&path);
    let outcome = client
        .call(&MarketControlRequest::MarketGetAssetDetails(
            MarketDetailsParams {
                identifier: "AFF/VHYL".to_string(),
                expected_isin: Some("IE00B8GKDB10".to_string()),
                sections: Some(vec![
                    MarketDetailsSection::Identity,
                    MarketDetailsSection::Etf,
                ]),
            },
        ))
        .expect("market-control call");

    match outcome {
        MarketControlOutcome::Details { result, session } => {
            assert!(session.login_performed);
            assert_eq!(result.schema_version, 1);
            assert_eq!(result.asset.fineco_key.value, "IE00B8GKDB10.AFF");
        }
        MarketControlOutcome::Search { .. } => panic!("wrong outcome"),
    }
    let _ = std::fs::remove_file(&path);
}
