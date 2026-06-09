//! A stalled upstream must not hang a market fetch forever. With a global fetch
//! timeout on the client, a server that accepts the connection but never sends a
//! response maps to the safe `fineco_timeout` envelope — mirroring the JWKS
//! fetch posture so a slow/hostile CDN cannot pin a gateway worker thread.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use fineco_market::{EnrichmentHostAllowlist, MarketClient};

/// Bind a loopback listener that accepts connections, reads the request, and then
/// holds the socket open without ever writing a response, so the client blocks on
/// the read until its own timeout fires. The listener thread is detached.
fn hanging_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            // Hold the connection; never respond. The client must time out.
            std::thread::sleep(Duration::from_secs(30));
        }
    });
    format!("http://{addr}")
}

#[test]
fn a_stalled_etf_endpoint_times_out() {
    let base = hanging_server();
    let etf_url = format!("{base}/etf.json");
    let client = MarketClient::new_with_timeout(
        base.clone(),
        EnrichmentHostAllowlist::from_allowed_hosts(["127.0.0.1"]),
        etf_url,
        Duration::from_millis(750),
    );
    let err = client
        .fetch_zero_commission_etfs("2026-06-05T00:00:00Z")
        .expect_err("a stalled ETF endpoint must time out, not hang");
    assert_eq!(
        err.code(),
        "fineco_timeout",
        "unexpected code: {}",
        err.code()
    );
}

#[test]
fn a_stalled_enrichment_endpoint_times_out() {
    let base = hanging_server();
    let client = MarketClient::new_with_timeout(
        base.clone(),
        EnrichmentHostAllowlist::from_allowed_hosts(["127.0.0.1"]),
        format!("{base}/etf.json"),
        Duration::from_millis(750),
    );
    let err = client
        .fetch_enrichment("it/sector/exchange/acme", None, "2026-06-05T00:00:00Z")
        .expect_err("a stalled enrichment endpoint must time out, not hang");
    assert_eq!(
        err.code(),
        "fineco_timeout",
        "unexpected code: {}",
        err.code()
    );
}

/// Send a complete set of response headers (promising a body via Content-Length)
/// and then never send the body, so the client's body read — not `.call()` —
/// blocks until its timeout fires. This is the common stalled-CDN shape.
fn header_then_stall_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n",
            );
            let _ = stream.flush();
            // Headers sent; never send the promised body.
            std::thread::sleep(Duration::from_secs(30));
        }
    });
    format!("http://{addr}")
}

#[test]
fn a_stalled_etf_response_body_times_out() {
    // Headers arrive fast, the body stalls: the timeout fires during the body
    // read, not in `.call()`. It must still map to `fineco_timeout`, never the
    // generic internal error.
    let base = header_then_stall_server();
    let client = MarketClient::new_with_timeout(
        base.clone(),
        EnrichmentHostAllowlist::from_allowed_hosts(["127.0.0.1"]),
        format!("{base}/etf.json"),
        Duration::from_millis(750),
    );
    let err = client
        .fetch_zero_commission_etfs("2026-06-05T00:00:00Z")
        .expect_err("a stalled response body must time out");
    assert_eq!(
        err.code(),
        "fineco_timeout",
        "unexpected code: {}",
        err.code()
    );
}

#[test]
fn a_stalled_enrichment_response_body_times_out() {
    let base = header_then_stall_server();
    let client = MarketClient::new_with_timeout(
        base.clone(),
        EnrichmentHostAllowlist::from_allowed_hosts(["127.0.0.1"]),
        format!("{base}/etf.json"),
        Duration::from_millis(750),
    );
    let err = client
        .fetch_enrichment("it/sector/exchange/acme", None, "2026-06-05T00:00:00Z")
        .expect_err("a stalled response body must time out");
    assert_eq!(
        err.code(),
        "fineco_timeout",
        "unexpected code: {}",
        err.code()
    );
}
