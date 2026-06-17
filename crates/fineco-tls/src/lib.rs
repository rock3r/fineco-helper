//! Workspace TLS backend: a single rustls [`CryptoProvider`] (aws-lc-rs) shared
//! by every ureq agent that talks HTTPS.
//!
//! The whole binary negotiates TLS through ONE crypto backend — aws-lc-rs — and
//! `ring` is absent from the dependency tree. See `Cargo.toml` for the why
//! (jsonwebtoken 10.x dropped ring; we unified on aws-lc-rs rather than ship
//! two crypto backends). Because ureq is compiled with `rustls-no-provider`, an
//! agent that does NOT install a provider would *panic* on its first HTTPS
//! request — so every TLS-using agent in this workspace builds its config with
//! [`tls_config`].

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use ureq::tls::{TlsConfig, TlsProvider};

/// The one crypto backend for the whole workspace: aws-lc-rs.
///
/// Returned as an `Arc` so callers (and ureq) share a single provider instance.
#[must_use]
pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// ureq TLS config pinned to the aws-lc-rs provider, with the default WebPki
/// root store (Mozilla CA bundle) for verifying real upstream certificates.
///
/// Every agent that does HTTPS must pass this to `Agent::config_builder().tls_config(..)`.
#[must_use]
pub fn tls_config() -> TlsConfig {
    TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        // UNSTABLE ureq API (rustls is pre-1.0): ureq does not promise semver on
        // this method. Pinned to ureq 3.3 / rustls 0.23; revisit on a ureq bump.
        .unversioned_rustls_crypto_provider(crypto_provider())
        .build()
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};

    use super::{crypto_provider, tls_config};

    /// End-to-end proof that the aws-lc-rs provider actually negotiates a TLS
    /// handshake through a real ureq agent — the only thing that exercises the
    /// crypto backend, since every other test/mock in this workspace is plain
    /// HTTP over loopback. A missing/broken provider would either panic (ureq
    /// has no `_ring` fallback) or fail the handshake here.
    #[test]
    fn aws_lc_rs_completes_a_real_tls_handshake_through_ureq() {
        // Synthetic self-signed cert for the loopback server (aws-lc-rs keygen).
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate self-signed cert");
        let cert_der = CertificateDer::from(issued.cert);
        let key_der =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(issued.key_pair.serialize_der()));

        let server_config = Arc::new(
            ServerConfig::builder_with_provider(crypto_provider())
                .with_safe_default_protocol_versions()
                .expect("server protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .expect("server cert"),
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut conn = ServerConnection::new(server_config).expect("server conn");
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            // Drive the handshake + read the request line/headers.
            let mut buf = [0u8; 1024];
            let _ = tls.read(&mut buf);
            let body = "ok";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            tls.write_all(response.as_bytes()).expect("write response");
            let _ = tls.flush();
        });

        // Client uses the provider under test. Verification is disabled because
        // the server cert is self-signed — this test proves the *crypto
        // handshake*, not the (separately-tested) WebPki root store.
        let agent = ureq::Agent::config_builder()
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .provider(ureq::tls::TlsProvider::Rustls)
                    .unversioned_rustls_crypto_provider(crypto_provider())
                    .disable_verification(true)
                    .build(),
            )
            .build()
            .new_agent();

        let mut response = agent
            .get(format!("https://127.0.0.1:{port}/"))
            .call()
            .expect("TLS request succeeds");
        let body = response.body_mut().read_to_string().expect("read body");

        assert_eq!(body, "ok", "aws-lc-rs handshake should round-trip a body");
        server.join().expect("server thread");
    }

    /// `tls_config()` is constructible (provider wiring compiles + resolves);
    /// guards against a future ureq/rustls API drift on the unstable method.
    #[test]
    fn tls_config_builds() {
        let _ = tls_config();
    }
}
