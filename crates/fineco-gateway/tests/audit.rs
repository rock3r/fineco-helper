//! Audit log (plan §"Logging And Audit") — the allowlist gate.
//!
//! Verifies the per-request audit record logs who/when/tool/data-class/outcome/
//! count, and that it can NEVER carry the payload: a read whose result holds
//! owner-only absolute values logs the row count, never a value. This is the
//! "Logging allowlist" Remote Full Cached P0 gate (tests fail if a forbidden
//! pattern appears in a log line).

use fineco_gateway::audit::AuditRecord;
use fineco_ipc::{
    Capability, PortfolioHistoryDto, PortfolioHistoryPointDto, Request, ResponseBody,
};

fn point(captured_at: &str, market_value: f64) -> PortfolioHistoryPointDto {
    PortfolioHistoryPointDto {
        captured_at: captured_at.to_string(),
        market_value: Some(market_value),
        book_value: None,
        profit_loss: None,
        profit_loss_perc: None,
    }
}

#[test]
fn audit_line_logs_the_count_never_the_values() {
    // A history read returns points carrying owner-only ABSOLUTE values. The audit
    // record for that read must log only the row count, never any value.
    let body = ResponseBody::PortfolioHistory(PortfolioHistoryDto {
        points: vec![
            point("2026-06-01T00:00:00Z", 123_456.78),
            point("2026-06-02T00:00:00Z", 222_333.44),
        ],
    });
    let record = AuditRecord {
        ts: "2026-06-05T11:00:00Z".to_string(),
        auth_id: "owner",
        tool: "portfolio_get_history",
        data_class: "sensitive_private_cached",
        outcome: "ok",
        error_code: None,
        duration_ms: 4,
        result_count: body.audit_count(),
    };
    let line = record.to_log_line();

    // who / when / tool / class / outcome / count are present...
    assert!(line.contains(r#""auth_id":"owner""#), "{line}");
    assert!(line.contains(r#""tool":"portfolio_get_history""#), "{line}");
    assert!(
        line.contains(r#""data_class":"sensitive_private_cached""#),
        "{line}"
    );
    assert!(line.contains(r#""outcome":"ok""#), "{line}");
    assert!(line.contains(r#""result_count":2"#), "{line}");
    // ...but the sensitive ABSOLUTE values never appear.
    assert!(!line.contains("123456"), "leaked a value: {line}");
    assert!(!line.contains("222333"), "leaked a value: {line}");
}

#[test]
fn audit_count_is_a_length_not_a_value() {
    assert_eq!(
        ResponseBody::PortfolioHistory(PortfolioHistoryDto { points: vec![] }).audit_count(),
        Some(0)
    );
    assert_eq!(
        ResponseBody::PortfolioHistory(PortfolioHistoryDto {
            points: vec![point("t", 1.0)],
        })
        .audit_count(),
        Some(1)
    );
}

#[test]
fn audit_tool_and_data_class_map_each_request() {
    assert_eq!(
        Request::PortfolioGetFreshness.audit_tool(),
        "portfolio_get_freshness"
    );
    assert_eq!(
        Request::PortfolioGetFreshness
            .required_capability()
            .audit_data_class(),
        "shareable_private"
    );
    assert_eq!(
        Request::PortfolioGetLatestFullSnapshot.audit_tool(),
        "portfolio_get_latest_full_snapshot"
    );
    assert_eq!(
        Request::PortfolioGetLatestFullSnapshot
            .required_capability()
            .audit_data_class(),
        "sensitive_private_cached"
    );
    // The two market tools share Capability::MarketRead but are DISTINCT data
    // classes (the public ETF list vs a third-party enrichment fetch that reveals
    // ticker interest to an external host); the gateway labels them per-tool, so
    // the capability-level default is the public class.
    assert_eq!(Capability::MarketRead.audit_data_class(), "public_market");
}

#[test]
fn audit_record_omits_optional_fields_when_absent() {
    let ok = AuditRecord {
        ts: "t".to_string(),
        auth_id: "owner",
        tool: "x",
        data_class: "public_market",
        outcome: "ok",
        error_code: None,
        duration_ms: 1,
        result_count: None,
    };
    let line = ok.to_log_line();
    assert!(!line.contains("error_code"), "{line}");
    assert!(!line.contains("result_count"), "{line}");

    let err = AuditRecord {
        ts: "t".to_string(),
        auth_id: "owner",
        tool: "x",
        data_class: "public_market",
        outcome: "error",
        error_code: Some("fineco_timeout".to_string()),
        duration_ms: 1,
        result_count: None,
    };
    let line = err.to_log_line();
    assert!(line.contains(r#""error_code":"fineco_timeout""#), "{line}");
    assert!(line.contains(r#""outcome":"error""#), "{line}");
}
