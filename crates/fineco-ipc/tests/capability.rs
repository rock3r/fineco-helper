//! Capability-policy contract tests (plan "Capability Model"): the owner can
//! call the expected tools, unknown/generic capabilities fail to parse, and
//! every command maps to a capability.

use fineco_ipc::{Capability, OWNER_AUTH_ID, Policy, Request};

const OWNER_FULL: &str = r#"{
    "version": 1,
    "auth_ids": {
        "owner": {
            "capabilities": [
                "market.read",
                "portfolio.cached.full_read",
                "portfolio.shareable.read",
                "orders.cached.read",
                "tax.cached.read"
            ]
        }
    }
}"#;

#[test]
fn owner_policy_grants_every_m4_capability() {
    let policy = Policy::from_json(OWNER_FULL).expect("valid policy");
    for capability in [
        Capability::MarketRead,
        Capability::PortfolioCachedFullRead,
        Capability::PortfolioShareableRead,
        Capability::OrdersCachedRead,
        Capability::TaxCachedRead,
    ] {
        assert!(
            policy.allows(OWNER_AUTH_ID, capability),
            "owner should hold {}",
            capability.as_str()
        );
    }
}

#[test]
fn unknown_identity_is_denied() {
    let policy = Policy::from_json(OWNER_FULL).expect("valid policy");
    assert!(!policy.allows("intruder", Capability::MarketRead));
}

#[test]
fn a_narrow_policy_denies_ungranted_capabilities() {
    // Only the shareable read is granted.
    let json =
        r#"{"version":1,"auth_ids":{"owner":{"capabilities":["portfolio.shareable.read"]}}}"#;
    let policy = Policy::from_json(json).expect("valid policy");
    assert!(policy.allows(OWNER_AUTH_ID, Capability::PortfolioShareableRead));
    assert!(!policy.allows(OWNER_AUTH_ID, Capability::PortfolioCachedFullRead));
    assert!(!policy.allows(OWNER_AUTH_ID, Capability::MarketRead));
}

#[test]
fn authenticated_market_read_is_distinct_from_public_market_read() {
    let json = r#"{
        "version": 1,
        "auth_ids": {
            "owner": {
                "capabilities": ["market.authenticated.read"]
            }
        }
    }"#;
    let policy = Policy::from_json(json).expect("valid policy");
    assert!(policy.allows(OWNER_AUTH_ID, Capability::MarketAuthenticatedRead));
    assert!(!policy.allows(OWNER_AUTH_ID, Capability::MarketRead));
    assert_eq!(
        Capability::MarketAuthenticatedRead.as_str(),
        "market.authenticated.read"
    );
    assert_eq!(
        Capability::MarketAuthenticatedRead.audit_data_class(),
        "authenticated_market"
    );
}

#[test]
fn generic_or_wildcard_capabilities_are_rejected() {
    for bad in ["admin", "private.read", "fineco.proxy", "*", "portfolio.*"] {
        let json =
            format!(r#"{{"version":1,"auth_ids":{{"owner":{{"capabilities":["{bad}"]}}}}}}"#);
        assert!(
            Policy::from_json(&json).is_err(),
            "capability {bad} must be rejected"
        );
    }
}

#[test]
fn unknown_fields_and_zero_version_are_rejected() {
    // Unknown top-level field.
    assert!(Policy::from_json(r#"{"version":1,"auth_ids":{},"extra":true}"#).is_err());
    // Unknown per-identity field.
    assert!(Policy::from_json(r#"{"version":1,"auth_ids":{"owner":{"role":"admin"}}}"#).is_err());
    // Zero version.
    assert!(Policy::from_json(r#"{"version":0,"auth_ids":{}}"#).is_err());
    // Malformed JSON.
    assert!(Policy::from_json("not json").is_err());
}

#[test]
fn every_command_maps_to_its_capability() {
    use fineco_ipc::{HistoryParams, MarketEtfsParams, PositionHistoryParams};

    let cases: [(Request, Capability); 11] = [
        (
            Request::PortfolioGetFreshness,
            Capability::PortfolioShareableRead,
        ),
        (
            Request::PortfolioGetLatestShareableReport,
            Capability::PortfolioShareableRead,
        ),
        (
            Request::PortfolioGetAllocationHistory,
            Capability::PortfolioShareableRead,
        ),
        (
            Request::PortfolioGetLatestSnapshotSummary,
            Capability::PortfolioCachedFullRead,
        ),
        (
            Request::PortfolioGetLatestFullSnapshot,
            Capability::PortfolioCachedFullRead,
        ),
        (
            Request::PortfolioGetHistory(HistoryParams { limit: 5 }),
            Capability::PortfolioCachedFullRead,
        ),
        (
            Request::PortfolioGetPositionHistory(PositionHistoryParams {
                instr_id: "A".to_string(),
                venue_system: "V".to_string(),
            }),
            Capability::PortfolioCachedFullRead,
        ),
        (
            Request::OrdersGetLatestMonitor,
            Capability::OrdersCachedRead,
        ),
        (Request::TaxGetLatestCarryForward, Capability::TaxCachedRead),
        (Request::TaxGetLatestMinusByYear, Capability::TaxCachedRead),
        (
            Request::MarketGetZeroCommissionEtfs(MarketEtfsParams { query: None }),
            Capability::MarketRead,
        ),
    ];
    for (request, expected) in cases {
        assert_eq!(
            request.required_capability(),
            expected,
            "unexpected capability for {request:?}"
        );
    }
}
