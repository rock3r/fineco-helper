//! Mock enrichment server binary. Binds to `MOCK_ENRICHMENT_ADDR` (default
//! `127.0.0.1:8082`) and serves a canned synthetic stock page. Test infra only.

fn main() -> std::io::Result<()> {
    let addr =
        std::env::var("MOCK_ENRICHMENT_ADDR").unwrap_or_else(|_| "127.0.0.1:8082".to_string());
    eprintln!("mock-enrichment listening on {addr}");
    httptiny::serve(&addr, mock_enrichment::route)
}
