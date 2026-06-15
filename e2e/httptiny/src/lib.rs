//! Minimal std-only HTTP/1.1 helpers for the E2E harness — no external deps.
//!
//! Test infrastructure ONLY; not part of the shipped product. It exists so the
//! mock Fineco / mock enrichment servers and the Docker smoke driver can share
//! one tiny implementation without pulling an HTTP framework into the supply
//! chain. It is deliberately not a general-purpose HTTP stack: client GET plus a
//! minimal POST (with custom headers + response headers, enough to drive the MCP
//! Streamable HTTP handshake in the smoke driver), no TLS, no redirects;
//! headers/bodies on the server side are read and discarded.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Max bytes of request head (request line + headers) the server reads before
/// answering; bounds memory/time per connection so a slow or oversized client
/// cannot pin a thread.
const MAX_HEAD_BYTES: u64 = 16 * 1024;
/// Max response bytes the client reads; bounds a misbehaving server.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
/// Per-connection read/write timeout (server and client).
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Client TCP connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A parsed request: method, path, headers, and a small bounded body. Mocks
/// route on method + path and may inspect headers/body to model authenticated
/// Fineco APIs.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Request headers as `(name, value)` pairs, in order, as sent.
    pub headers: Vec<(String, String)>,
    /// Request body decoded as UTF-8 lossily. Test fixtures only; product code
    /// never depends on this helper.
    pub body: String,
}

impl Request {
    /// First header value matching `name` (case-insensitive), if any.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A response the handler wants written back to the client.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: String,
    /// Extra response headers (e.g. `Set-Cookie`), beyond the standard ones.
    pub headers: Vec<(String, String)>,
}

impl Response {
    /// Build a response with an explicit content type.
    #[must_use]
    pub fn new(status: u16, content_type: &str, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: content_type.to_string(),
            body: body.into(),
            headers: Vec::new(),
        }
    }

    /// Add an extra response header (builder style).
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// `text/plain` response.
    #[must_use]
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Self::new(status, "text/plain; charset=utf-8", body)
    }

    /// `application/json` response.
    #[must_use]
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self::new(status, "application/json; charset=utf-8", body)
    }

    /// `text/html` response.
    #[must_use]
    pub fn html(status: u16, body: impl Into<String>) -> Self {
        Self::new(status, "text/html; charset=utf-8", body)
    }

    /// Canonical 404 response.
    #[must_use]
    pub fn not_found() -> Self {
        Self::text(404, "not found")
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

/// Serve `handler` on `addr` (e.g. `"127.0.0.1:8081"`) forever, one thread per
/// connection.
///
/// # Errors
/// Returns an error if the listener cannot bind to `addr`.
pub fn serve(
    addr: &str,
    handler: impl Fn(&Request) -> Response + Send + Sync + 'static,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    serve_listener(listener, handler)
}

/// Serve an already-bound listener. Lets a caller bind an ephemeral port
/// (`127.0.0.1:0`), discover it via [`TcpListener::local_addr`], then serve —
/// e.g. an integration test that points a real HTTP client at the mock.
///
/// # Errors
/// Returns an error if accepting connections fails irrecoverably.
pub fn serve_listener(
    listener: TcpListener,
    handler: impl Fn(&Request) -> Response + Send + Sync + 'static,
) -> std::io::Result<()> {
    let handler = Arc::new(handler);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let handler = Arc::clone(&handler);
        thread::spawn(move || {
            let _ = handle_connection(&stream, handler.as_ref());
        });
    }
    Ok(())
}

fn handle_connection(
    stream: &TcpStream,
    handler: &(impl Fn(&Request) -> Response + ?Sized),
) -> std::io::Result<()> {
    // Fail closed: bound how long a connection may block and how many bytes of
    // request head we read, so a slow/oversized client cannot pin a thread.
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let mut reader = BufReader::new(stream).take(MAX_HEAD_BYTES);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(()); // client closed without sending anything
    }
    // Read headers up to the blank line. The `take` wrapper caps total head
    // bytes — if the budget is exhausted before the blank line, `saw_blank`
    // stays false and we answer 400.
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut saw_blank = false;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            saw_blank = true;
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let response = match parse_request_line(&request_line) {
        Some(mut req) if saw_blank => {
            req.headers = headers;
            let content_length = req
                .header("Content-Length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if content_length > 0 {
                let mut body = vec![0; content_length];
                reader.read_exact(&mut body)?;
                req.body = String::from_utf8_lossy(&body).into_owned();
            }
            handler(&req)
        }
        _ => Response::text(400, "bad request"),
    };
    write_response(stream, &response)
}

/// Parse a strict `METHOD path HTTP/x.y` request line. Returns `None` for
/// anything malformed (wrong token count, empty method/path, bad version),
/// which the caller turns into a 400.
fn parse_request_line(line: &str) -> Option<Request> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let path = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || method.is_empty() || path.is_empty() {
        return None;
    }
    if !is_http_version(version) {
        return None;
    }
    Some(Request {
        method: method.to_string(),
        path: path.to_string(),
        headers: Vec::new(),
        body: String::new(),
    })
}

/// True for a well-formed `HTTP/<digits>.<digits>` version token.
fn is_http_version(version: &str) -> bool {
    let Some(rest) = version.strip_prefix("HTTP/") else {
        return false;
    };
    let mut parts = rest.split('.');
    let (Some(major), Some(minor), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && minor.bytes().all(|b| b.is_ascii_digit())
}

fn write_response(mut stream: &TcpStream, response: &Response) -> std::io::Result<()> {
    let body = response.body.as_bytes();
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        body.len(),
    );
    for (name, value) in &response.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Perform a blocking `GET url` and return `(status, body)`.
///
/// Accepts `http://host:port/path` URLs only (no TLS, no redirects) — enough for
/// the local E2E harness.
///
/// # Errors
/// Returns an error if the URL is malformed or the request/response fails.
pub fn get(url: &str) -> std::io::Result<(u16, String)> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only http:// URLs are supported",
        )
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let addr = authority.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "unresolvable authority")
    })?;
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    (&mut stream)
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut raw)?;
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> std::io::Result<(u16, String)> {
    let text = String::from_utf8_lossy(raw);
    let status_line = text.split("\r\n").next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing status code")
        })?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

/// A client HTTP response carrying status, headers, and body. Used by the MCP
/// smoke driver, which needs response headers (e.g. `mcp-session-id`).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Raw response body. For a chunked/SSE response this still contains the
    /// `data: {json}` lines, which is enough for the smoke driver's checks.
    pub body: String,
}

impl HttpResponse {
    /// First header value matching `name` (case-insensitive), if any.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// POST `body` to `url` with the given extra `headers`, returning the response
/// status, headers, and body. `Connection: close` is sent so the server ends the
/// (possibly SSE) stream after the response. `http://` only, no TLS/redirects.
///
/// # Errors
/// Returns an error if the URL is malformed or the request/response fails.
pub fn post(url: &str, headers: &[(&str, &str)], body: &str) -> std::io::Result<HttpResponse> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only http:// URLs are supported",
        )
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let addr = authority.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "unresolvable authority")
    })?;
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    // Let the caller override `Host` (e.g. to test Host/DNS-rebinding validation);
    // otherwise default to the connect authority.
    let custom_host = headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host"));
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !custom_host {
        req.push_str(&format!("Host: {authority}\r\n"));
    }
    for (name, value) in headers {
        req.push_str(name);
        req.push_str(": ");
        req.push_str(value);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    (&mut stream)
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut raw)?;
    parse_response_full(&raw)
}

fn parse_response_full(raw: &[u8]) -> std::io::Result<HttpResponse> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .map_or((text.as_ref(), ""), |(h, b)| (h, b));
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing status code")
        })?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Ok(HttpResponse {
        status,
        headers,
        body: body.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::{Request, Response, get, parse_request_line, serve_listener};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn parse_request_line_is_strict() {
        let ok = parse_request_line("GET /p HTTP/1.1\r\n").expect("valid line");
        assert_eq!(ok.method, "GET");
        assert_eq!(ok.path, "/p");
        assert!(parse_request_line("GET /p HTTP/foobar\r\n").is_none()); // bad version
        assert!(parse_request_line("GET /p\r\n").is_none()); // missing version
        assert!(parse_request_line("GET /p HTTP/1.1 extra\r\n").is_none()); // extra token
        assert!(parse_request_line("\r\n").is_none()); // empty
    }

    fn spawn(handler: impl Fn(&Request) -> Response + Send + Sync + 'static) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        std::thread::spawn(move || {
            let _ = serve_listener(listener, handler);
        });
        port
    }

    #[test]
    fn get_roundtrip_returns_status_and_body() {
        let port = spawn(|req| {
            if req.path == "/hello" {
                Response::text(200, "hi")
            } else {
                Response::not_found()
            }
        });

        let (status, body) = get(&format!("http://127.0.0.1:{port}/hello")).expect("get /hello");
        assert_eq!(status, 200);
        assert_eq!(body, "hi");

        let (status, _) = get(&format!("http://127.0.0.1:{port}/nope")).expect("get /nope");
        assert_eq!(status, 404);
    }

    #[test]
    fn get_rejects_non_http_url() {
        assert!(get("https://example.com/").is_err());
    }

    #[test]
    fn post_returns_status_headers_and_body() {
        use super::post;
        let port = spawn(|req| {
            if req.method == "POST" && req.path == "/echo" {
                Response::text(200, "pong").with_header("X-Session", "abc-123")
            } else {
                Response::not_found()
            }
        });

        let resp = post(
            &format!("http://127.0.0.1:{port}/echo"),
            &[("Content-Type", "application/json")],
            "{\"ping\":true}",
        )
        .expect("post /echo");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.header("x-session"), Some("abc-123"));
        assert!(resp.body.contains("pong"));
    }

    #[test]
    fn malformed_request_line_yields_400() {
        // Even though the handler would answer 200, a malformed request line is
        // rejected before the handler runs — the harness fails closed.
        let port = spawn(|_| Response::text(200, "should not be reached"));
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.write_all(b"GARBAGE\r\n\r\n").expect("write");
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).expect("read");
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.starts_with("HTTP/1.1 400"),
            "expected 400, got: {text}"
        );
    }
}
