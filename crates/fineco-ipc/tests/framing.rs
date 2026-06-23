//! Tests for the length-prefixed framing and the reply envelope.

use std::io::Cursor;

use fineco_core::SafeError;
use fineco_ipc::{
    FreshnessDto, FreshnessReportDto, Request, ResponseBody, SafeErrorDto, WireReply, read_message,
    write_message,
};

/// A freshness report with every area `missing` except an explicit portfolio.
fn report(portfolio: FreshnessDto) -> FreshnessReportDto {
    let missing = || FreshnessDto {
        state: "missing".to_string(),
        captured_at: None,
    };
    FreshnessReportDto {
        portfolio,
        orders: missing(),
        tax: missing(),
        movements: missing(),
    }
}

#[test]
fn request_frame_round_trips() {
    let request = Request::PortfolioGetFreshness;
    let mut buffer = Vec::new();
    write_message(&mut buffer, &request).expect("write");

    let mut cursor = Cursor::new(buffer);
    let decoded: Request = read_message(&mut cursor).expect("read");
    assert_eq!(decoded, request);
}

#[test]
fn ok_reply_round_trips() {
    let reply = WireReply::from_result(Ok(ResponseBody::Freshness(report(FreshnessDto {
        state: "fresh".to_string(),
        captured_at: Some("2026-06-03T12:00:00Z".to_string()),
    }))));

    let mut buffer = Vec::new();
    write_message(&mut buffer, &reply).expect("write");
    let mut cursor = Cursor::new(buffer);
    let decoded: WireReply = read_message(&mut cursor).expect("read");

    match decoded.into_result() {
        Ok(ResponseBody::Freshness(report)) => {
            assert_eq!(report.portfolio.state, "fresh");
            assert_eq!(
                report.portfolio.captured_at.as_deref(),
                Some("2026-06-03T12:00:00Z")
            );
            assert_eq!(report.orders.state, "missing");
        }
        Ok(other) => panic!("unexpected ok variant: {other:?}"),
        Err(err) => panic!("unexpected error reply: {err:?}"),
    }
}

#[test]
fn error_reply_carries_only_safe_fields() {
    let reply = WireReply::from_result(Err(SafeError::auth_required()));
    let mut buffer = Vec::new();
    write_message(&mut buffer, &reply).expect("write");
    let mut cursor = Cursor::new(buffer);
    let decoded: WireReply = read_message(&mut cursor).expect("read");

    match decoded.into_result() {
        Ok(body) => panic!("unexpected ok reply: {body:?}"),
        Err(err) => {
            assert_eq!(err.code, "auth_required");
            assert_eq!(err.class, "auth");
            assert!(!err.retryable);
            assert!(!err.safe_message.is_empty());
        }
    }
}

#[test]
fn safe_error_dto_maps_fields() {
    let dto = SafeErrorDto::from(&SafeError::invalid_request("days must be <= 30."));
    assert_eq!(dto.code, "invalid_request");
    assert_eq!(dto.class, "validation");
    assert!(!dto.retryable);
    assert_eq!(dto.safe_message, "days must be <= 30.");
}

#[test]
fn oversized_length_prefix_is_rejected_without_allocating() {
    // A 4-byte big-endian length of u32::MAX must be rejected by the size guard
    // before any body allocation.
    let buffer = u32::MAX.to_be_bytes().to_vec();
    let mut cursor = Cursor::new(buffer);
    let result: std::io::Result<WireReply> = read_message(&mut cursor);
    assert!(result.is_err(), "oversized frame must be rejected");
}

#[test]
fn truncated_frame_errors() {
    // A length prefix promising more bytes than follow must error, not hang.
    let mut buffer = 16u32.to_be_bytes().to_vec();
    buffer.extend_from_slice(b"short");
    let mut cursor = Cursor::new(buffer);
    let result: std::io::Result<Request> = read_message(&mut cursor);
    assert!(result.is_err());
}
