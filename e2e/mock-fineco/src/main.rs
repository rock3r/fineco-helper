//! Mock Fineco server binary. Binds to `MOCK_FINECO_ADDR` (default
//! `127.0.0.1:8081`) and serves canned synthetic fixtures. Test infra only.

fn main() -> std::io::Result<()> {
    let addr = std::env::var("MOCK_FINECO_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string());
    eprintln!("mock-fineco listening on {addr}");
    httptiny::serve(&addr, mock_fineco::route)
}
