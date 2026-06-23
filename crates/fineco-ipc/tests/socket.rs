//! End-to-end transport test: a real Unix-domain socket carries a request to a
//! stub handler and the typed reply back, including the safe-error path.

use std::os::unix::net::UnixListener;
use std::thread;

use fineco_core::SafeError;
use fineco_ipc::{Client, FreshnessDto, FreshnessReportDto, Request, ResponseBody, serve_blocking};

/// A unique, short socket path for this test process (nextest = one process per
/// test, so the pid is unique).
fn socket_path() -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("fineco-ipc-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

/// Stub handler: freshness for the portfolio command, an auth error otherwise.
fn handle(request: Request) -> Result<ResponseBody, SafeError> {
    let area = |state: &str| FreshnessDto {
        state: state.to_string(),
        captured_at: Some("2026-06-03T12:00:00Z".to_string()),
    };
    match request {
        Request::PortfolioGetFreshness => Ok(ResponseBody::Freshness(FreshnessReportDto {
            portfolio: area("fresh"),
            orders: area("stale"),
            tax: area("missing"),
            movements: area("missing"),
        })),
        _ => Err(SafeError::auth_required()),
    }
}

#[test]
fn request_reply_over_a_unix_socket() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).expect("bind socket");
    thread::spawn(move || {
        let _ = serve_blocking(&listener, handle);
    });

    let client = Client::new(&path);

    // Ok path: the typed freshness result round-trips.
    match client.call(&Request::PortfolioGetFreshness) {
        Ok(ResponseBody::Freshness(report)) => {
            assert_eq!(report.portfolio.state, "fresh");
            assert_eq!(report.orders.state, "stale");
            assert_eq!(report.tax.state, "missing");
        }
        Ok(other) => panic!("unexpected ok variant: {other:?}"),
        Err(err) => panic!("unexpected error reply: {err:?}"),
    }

    // Err path: the handler's safe error crosses the socket as the safe envelope.
    let err = client
        .call(&Request::OrdersGetLatestMonitor)
        .expect_err("handler returns an error");
    assert_eq!(err.code, "auth_required");
    assert_eq!(err.class, "auth");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn client_against_a_dead_socket_is_a_safe_internal_error() {
    let client = Client::new("/tmp/fineco-ipc-does-not-exist.sock");
    let err = client
        .call(&Request::PortfolioGetFreshness)
        .expect_err("no server listening");
    // Transport failure surfaces as a safe envelope, not a raw OS error.
    assert_eq!(err.code, "internal");
    assert!(!err.safe_message.is_empty());
}
