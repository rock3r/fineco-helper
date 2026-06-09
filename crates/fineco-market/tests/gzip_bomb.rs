//! A hostile/compromised market upstream must not be able to exhaust gateway
//! memory with a decompression bomb. The enrichment provider is explicitly
//! untrusted; the public ETF host is third-party too. ureq's `.limit()` bounds
//! the *compressed* bytes read off the socket (the limit reader sits beneath the
//! gzip decoder), so a small gzip body that inflates to gigabytes slips past a
//! compressed-size cap. The client must additionally bound the **decompressed**
//! output and reject anything larger, rather than materialize the whole inflated
//! body in memory.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use fineco_market::{EnrichmentHostAllowlist, MarketClient};
use flate2::Compression;
use flate2::write::GzEncoder;

/// gzip-compress `data` (fast, since the payload is highly repetitive).
fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

/// Bind a loopback listener that answers every request with a fixed
/// `Content-Encoding: gzip` body. The body is precompressed once; the listener
/// thread is detached.
fn gzip_body_server(decompressed: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let body = gzip(&decompressed);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

/// Valid JSON that decompresses to ~5 MiB (above the 4 MiB cap) but gzips to a
/// few KiB. The `_pad` field is ignored by the ETF deserializer, so without a
/// decompressed-size bound the OLD client parses it successfully and returns an
/// (empty) list; with the bound it must fail closed instead.
fn oversized_etf_json() -> Vec<u8> {
    let pad = "a".repeat(5 * 1024 * 1024);
    format!("{{\"_pad\":\"{pad}\",\"instruments\":[]}}").into_bytes()
}

// The ETF/get_json path is the clean discriminator: serde imposes no secondary
// size cap, so without a decompressed bound the OLD client parses the inflated
// body and returns `Ok` (an empty list). The bound flips that to a fail-closed
// error — a true red→green on the fix.
#[test]
fn a_gzip_bomb_etf_body_is_rejected_not_inflated() {
    let base = gzip_body_server(oversized_etf_json());
    let client = MarketClient::new_with_timeout(
        base.clone(),
        EnrichmentHostAllowlist::from_allowed_hosts(["127.0.0.1"]),
        format!("{base}/etf.json"),
        Duration::from_secs(10),
    );
    let err = client
        .fetch_zero_commission_etfs("2026-06-05T00:00:00Z")
        .expect_err("a gzip body inflating past the decompressed cap must be rejected");
    assert_eq!(err.code(), "internal", "unexpected code: {}", err.code());
}

// The enrichment/get_text path shares the same bounded body read. Here the
// parser (`state.rs`) also caps page size at 4 MiB, so the distinction the fix
// makes is *where* the oversize is caught: the bounded read rejects it as
// `internal` BEFORE the body is inflated whole, whereas the old client inflated
// the full 5 MiB into memory and only then had the parser reject it as
// `invalid_request`. Asserting the `internal` code proves the read-layer guard
// fires first (red→green: old code returned `invalid_request`).
#[test]
fn a_gzip_bomb_enrichment_body_is_rejected_not_inflated() {
    let base = gzip_body_server("a".repeat(5 * 1024 * 1024).into_bytes());
    let client = MarketClient::new_with_timeout(
        base.clone(),
        EnrichmentHostAllowlist::from_allowed_hosts(["127.0.0.1"]),
        format!("{base}/etf.json"),
        Duration::from_secs(10),
    );
    let err = client
        .fetch_enrichment("it/sector/exchange/acme", None, "2026-06-05T00:00:00Z")
        .expect_err("a gzip body inflating past the decompressed cap must be rejected");
    assert_eq!(err.code(), "internal", "unexpected code: {}", err.code());
}
