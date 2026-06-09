//! `DeadlineReader` bounds the TOTAL wall-clock a framed read may take. The
//! socket's per-read timeout (`SO_RCVTIMEO`) re-arms on every partial read, so a
//! peer trickling bytes under that timeout could otherwise hold a connection —
//! and the single-consumer accept loop — open indefinitely. The serve loops wrap
//! their framed read in this; here we pin the adapter's contract directly (a full
//! slow-loris integration test would need the production 30 s timeout).

use std::io::Read;
use std::time::{Duration, Instant};

use fineco_ipc::DeadlineReader;

#[test]
fn a_passed_deadline_fails_the_read_even_with_data_ready() {
    let data = b"hello";
    let mut src = &data[..];
    let mut reader = DeadlineReader::new(&mut src, Instant::now() - Duration::from_secs(1));
    let mut buf = [0u8; 5];
    let err = reader
        .read(&mut buf)
        .expect_err("a read attempted after the deadline must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

#[test]
fn a_future_deadline_reads_through() {
    let data = b"hello";
    let mut src = &data[..];
    let mut reader = DeadlineReader::new(&mut src, Instant::now() + Duration::from_secs(60));
    let mut buf = [0u8; 5];
    let n = reader
        .read(&mut buf)
        .expect("a read before the deadline should delegate to the inner reader");
    assert_eq!(&buf[..n], b"hello");
}
