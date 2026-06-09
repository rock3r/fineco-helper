//! `DeadlineReader` bounds the TOTAL wall-clock a framed read may take. The
//! socket's per-read timeout (`SO_RCVTIMEO`) re-arms on every partial read, so a
//! peer trickling bytes under that timeout could otherwise hold a connection —
//! and the single-consumer accept loop — open indefinitely. It caps each read's
//! socket timeout to the remaining budget so even a single blocking read cannot
//! overshoot the deadline. The serve loops wrap their framed read in this; here we
//! pin the adapter's contract directly.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use fineco_ipc::DeadlineReader;

#[test]
fn a_passed_deadline_fails_the_read_without_blocking() {
    // No data is ever written to the peer, and the deadline is already past: the
    // read must fail immediately with `TimedOut`, not block on the empty socket.
    let (mut near, _far) = UnixStream::pair().expect("socketpair");
    let mut reader = DeadlineReader::new(&mut near, Instant::now() - Duration::from_secs(1));
    let mut buf = [0u8; 4];
    let err = reader
        .read(&mut buf)
        .expect_err("a read attempted after the deadline must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

#[test]
fn a_future_deadline_reads_available_data() {
    let (mut near, mut far) = UnixStream::pair().expect("socketpair");
    far.write_all(b"hello").expect("write");
    let mut reader = DeadlineReader::new(&mut near, Instant::now() + Duration::from_secs(60));
    let mut buf = [0u8; 5];
    let n = reader
        .read(&mut buf)
        .expect("a read before the deadline should return the available data");
    assert_eq!(&buf[..n], b"hello");
}
