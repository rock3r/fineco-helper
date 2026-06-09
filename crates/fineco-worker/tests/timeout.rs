//! A stalled Fineco endpoint must not hold the refresh lock forever. With a
//! global HTTP timeout on the worker's agent, a server that accepts the
//! connection but never responds maps to the safe `fineco_timeout` envelope
//! (not a generic internal error), so the refresh orchestrator's 5xx/timeout
//! retry + circuit-breaker logic gets a predictable signal.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use fineco_refresh::PortfolioFetcher;
use fineco_worker::{FinecoEndpoints, FinecoWorker, StaticCredentialSource};

/// Bind a loopback listener that accepts connections, reads the request, then
/// holds the socket open without ever responding — so the worker's first request
/// (the login preflight) blocks until the agent's own timeout fires. Detached.
fn hanging_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            std::thread::sleep(Duration::from_secs(30));
        }
    });
    format!("http://{addr}")
}

#[test]
fn a_stalled_fineco_endpoint_times_out() {
    let base = hanging_server();
    let worker = FinecoWorker::new_with_timeout(
        FinecoEndpoints::for_base(&base),
        Box::new(StaticCredentialSource::new(
            "synthetic-user",
            "synthetic-pass",
        )),
        Duration::from_millis(750),
    );
    let err = worker
        .fetch_portfolio("2026-06-03T12:00:00Z")
        .expect_err("a stalled Fineco endpoint must time out, not hang");
    assert_eq!(
        err.code(),
        "fineco_timeout",
        "unexpected code: {}",
        err.code()
    );
}

/// A server that completes the login flow (a 200 + session cookie on the home
/// preflight and the login POST) but, on a private read (positions summary),
/// sends the response headers promising a body and then **stalls the body** — so
/// the timeout fires during the worker's body read, not in `.call()`. This is the
/// "headers sent, body stalls" shape that must still map to `fineco_timeout`
/// (otherwise the controller's retry + circuit logic mis-classifies it).
fn login_ok_then_read_body_stall() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            std::thread::spawn(move || serve_conn(stream));
        }
    });
    format!("http://{addr}")
}

fn serve_conn(mut stream: TcpStream) {
    loop {
        let Some(head) = read_headers(&mut stream) else {
            return;
        };
        let first_line = head.lines().next().unwrap_or("").to_string();
        // Consume any request body (the login POST) so a keep-alive connection
        // stays aligned for the next request.
        if let Some(len) = header_value(&head, "content-length")
            && let Ok(n) = len.parse::<usize>()
        {
            let mut body = vec![0u8; n];
            if stream.read_exact(&mut body).is_err() {
                return;
            }
        }
        if first_line.contains("/positions/summary") {
            // Promise a body, then never send it: the worker blocks in the body
            // read until its own timeout fires.
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n",
            );
            let _ = stream.flush();
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
        // Preflight (home) + login: a complete 200 with a session cookie, no body.
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nSet-Cookie: SESSION=synthetic\r\nContent-Length: 0\r\n\r\n",
        );
        let _ = stream.flush();
    }
}

/// Read request headers up to the blank-line terminator.
fn read_headers(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    return Some(String::from_utf8_lossy(&buf).into_owned());
                }
                if buf.len() > 64 * 1024 {
                    return None;
                }
            }
        }
    }
}

/// Case-insensitive header lookup over a raw request head.
fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

#[test]
fn a_stalled_private_read_body_times_out() {
    // Login succeeds; then the positions-summary body stalls. The timeout fires
    // in the body read, which must still surface as `fineco_timeout` — not the
    // generic internal error (so the refresh circuit/retry logic keys correctly).
    let base = login_ok_then_read_body_stall();
    let worker = FinecoWorker::new_with_timeout(
        FinecoEndpoints::for_base(&base),
        Box::new(StaticCredentialSource::new(
            "synthetic-user",
            "synthetic-pass",
        )),
        Duration::from_millis(750),
    );
    let err = worker
        .fetch_portfolio("2026-06-03T12:00:00Z")
        .expect_err("a stalled private-read body must time out");
    assert_eq!(
        err.code(),
        "fineco_timeout",
        "unexpected code: {}",
        err.code()
    );
}
