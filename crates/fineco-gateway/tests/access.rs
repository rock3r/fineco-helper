//! Cloudflare Access JWT verification (plan §"Cloudflare Access"): the gateway
//! verifies issuer / audience / expiry / signature against the team JWKS and
//! maps the verified owner identity to the fixed `auth_id: owner`. A spoofed
//! `Cf-Access-*` header without a valid JWT must fail.
//!
//! Signed with an offline RSA test keypair (fixtures/access-test-key.pem) whose
//! public JWK is fixtures/access-test-jwks.json (kid `test-key-1`).

use std::net::TcpListener;
use std::thread;

use fineco_gateway::access::{AccessConfig, AccessError, AccessVerifier, AuthChannel, fetch_jwks};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;

const TEST_KEY_PEM: &str = include_str!("fixtures/access-test-key.pem");
const TEST_JWKS: &str = include_str!("fixtures/access-test-jwks.json");

const ISSUER: &str = "https://team.cloudflareaccess.com";
const AUDIENCE: &str = "test-aud-tag-0123456789abcdef";
const OWNER_EMAIL: &str = "owner@example.com";
/// A Cloudflare service-token `common_name` (the token's Client ID). Service
/// tokens carry this stable claim and NO `email`.
const SERVICE_CN: &str = "78599ba946c2e172fc40b29726e4d835.access";

#[derive(Serialize)]
struct Claims {
    iss: String,
    aud: Vec<String>,
    exp: u64,
    iat: u64,
    email: String,
    sub: String,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Sign a token (RS256, kid `test-key-1`) with overridable claim parts.
fn sign(iss: &str, aud: &str, exp: u64, email: &str) -> String {
    let claims = Claims {
        iss: iss.to_string(),
        aud: vec![aud.to_string()],
        exp,
        iat: now(),
        email: email.to_string(),
        sub: "owner-subject-id".to_string(),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());
    let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("encoding key");
    encode(&header, &claims, &key).expect("sign")
}

/// Sign an arbitrary claims object (RS256, kid `test-key-1`) — for tokens whose
/// claim shape differs from the standard owner token (e.g. a service token that
/// carries `common_name` and no `email`).
fn sign_json(claims: serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());
    let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("key");
    encode(&header, &claims, &key).expect("sign")
}

fn jwks() -> JwkSet {
    serde_json::from_str(TEST_JWKS).expect("parse jwks")
}

fn verifier(owner_email: Option<&str>) -> AccessVerifier {
    AccessVerifier::new(
        AccessConfig {
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            owner_email: owner_email.map(str::to_string),
            owner_common_name: None,
        },
        jwks(),
    )
}

/// A verifier that pins the service-token `common_name` (and no email).
fn verifier_cn(owner_common_name: Option<&str>) -> AccessVerifier {
    AccessVerifier::new(
        AccessConfig {
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            owner_email: None,
            owner_common_name: owner_common_name.map(str::to_string),
        },
        jwks(),
    )
}

#[test]
fn a_valid_owner_token_maps_to_auth_id_owner() {
    let token = sign(ISSUER, AUDIENCE, now() + 3600, OWNER_EMAIL);
    let identity = verifier(Some(OWNER_EMAIL))
        .verify(&token)
        .expect("valid token verifies");
    assert_eq!(identity.auth_id(), "owner");
}

#[test]
fn an_expired_token_is_rejected() {
    let token = sign(ISSUER, AUDIENCE, now() - 3600, OWNER_EMAIL);
    assert!(verifier(Some(OWNER_EMAIL)).verify(&token).is_err());
}

#[test]
fn a_wrong_issuer_is_rejected() {
    let token = sign(
        "https://evil.cloudflareaccess.com",
        AUDIENCE,
        now() + 3600,
        OWNER_EMAIL,
    );
    assert!(verifier(Some(OWNER_EMAIL)).verify(&token).is_err());
}

#[test]
fn a_wrong_audience_is_rejected() {
    let token = sign(ISSUER, "some-other-app-aud", now() + 3600, OWNER_EMAIL);
    assert!(verifier(Some(OWNER_EMAIL)).verify(&token).is_err());
}

#[test]
fn an_unknown_kid_is_rejected() {
    // A token whose header kid is not in the JWKS must fail (no key to verify).
    let claims = Claims {
        iss: ISSUER.to_string(),
        aud: vec![AUDIENCE.to_string()],
        exp: now() + 3600,
        iat: now(),
        email: OWNER_EMAIL.to_string(),
        sub: "x".to_string(),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("not-in-jwks".to_string());
    let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("key");
    let token = encode(&header, &claims, &key).expect("sign");
    assert!(verifier(Some(OWNER_EMAIL)).verify(&token).is_err());
}

#[test]
fn a_tampered_signature_is_rejected() {
    let mut token = sign(ISSUER, AUDIENCE, now() + 3600, OWNER_EMAIL);
    // Flip the last character of the signature segment.
    let last = token.pop().unwrap();
    token.push(if last == 'A' { 'B' } else { 'A' });
    assert!(verifier(Some(OWNER_EMAIL)).verify(&token).is_err());
}

#[test]
fn an_hmac_alg_confusion_token_is_rejected() {
    // alg=HS256 must be refused even with the right kid (only RS256 is allowed,
    // and the key is RSA) — defends against algorithm-confusion attacks.
    let claims = Claims {
        iss: ISSUER.to_string(),
        aud: vec![AUDIENCE.to_string()],
        exp: now() + 3600,
        iat: now(),
        email: OWNER_EMAIL.to_string(),
        sub: "x".to_string(),
    };
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key-1".to_string());
    let token = encode(&header, &claims, &EncodingKey::from_secret(b"secret")).expect("sign");
    assert!(verifier(Some(OWNER_EMAIL)).verify(&token).is_err());
}

#[test]
fn a_non_owner_email_is_rejected_when_owner_is_pinned() {
    // A validly-signed token for a different identity must be refused when the
    // owner email is pinned (defense in depth behind the Access policy).
    let token = sign(ISSUER, AUDIENCE, now() + 3600, "intruder@evil.com");
    assert!(verifier(Some(OWNER_EMAIL)).verify(&token).is_err());

    // Without a pin, any validly-signed Access token is accepted as owner.
    let identity = verifier(None).verify(&token).expect("verifies without pin");
    assert_eq!(identity.auth_id(), "owner");
}

/// A service-token JWT: stable `common_name` (the Client ID), no `email`.
fn service_token(common_name: &str, exp: u64) -> String {
    sign_json(serde_json::json!({
        "iss": ISSUER,
        "aud": [AUDIENCE],
        "exp": exp,
        "iat": now(),
        "common_name": common_name,
        "sub": "",
        "type": "app",
    }))
}

#[test]
fn a_service_token_with_the_pinned_common_name_maps_to_owner() {
    let token = service_token(SERVICE_CN, now() + 3600);
    let identity = verifier_cn(Some(SERVICE_CN))
        .verify(&token)
        .expect("the pinned service token verifies");
    assert_eq!(identity.auth_id(), "owner");
}

#[test]
fn a_service_token_with_a_different_common_name_is_rejected() {
    // Even validly signed for the right issuer/audience, a DIFFERENT service token
    // must not map to owner when the common_name is pinned.
    let token = service_token("11112222333344445555666677778888.access", now() + 3600);
    assert!(
        matches!(
            verifier_cn(Some(SERVICE_CN)).verify(&token),
            Err(AccessError::NotOwner)
        ),
        "a different service token must be rejected under a common_name pin"
    );
}

#[test]
fn a_common_name_pin_rejects_a_token_that_lacks_the_claim() {
    // An SSO/email token (no common_name) must not satisfy a service-token pin.
    let token = sign(ISSUER, AUDIENCE, now() + 3600, OWNER_EMAIL);
    assert!(
        matches!(
            verifier_cn(Some(SERVICE_CN)).verify(&token),
            Err(AccessError::NotOwner)
        ),
        "a token without common_name must be rejected under a common_name pin"
    );
}

#[test]
fn without_a_common_name_pin_a_service_token_still_verifies() {
    // The pin is optional defense in depth: unset, a valid service token (no email)
    // still maps to owner, gated solely by the Access policy.
    let token = service_token(SERVICE_CN, now() + 3600);
    let identity = verifier_cn(None)
        .verify(&token)
        .expect("verifies without a common_name pin");
    assert_eq!(identity.auth_id(), "owner");
}

/// A verifier pinning BOTH an owner email AND a service-token common_name
/// (dual-pin): the single owner reaches the gateway as EITHER their interactive
/// SSO/OAuth email (ChatGPT/Claude connectors) OR their service token (CLI), and
/// a token matching EITHER configured pin maps to owner.
fn verifier_dual(owner_email: &str, owner_common_name: &str) -> AccessVerifier {
    AccessVerifier::new(
        AccessConfig {
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            owner_email: Some(owner_email.to_string()),
            owner_common_name: Some(owner_common_name.to_string()),
        },
        jwks(),
    )
}

#[test]
fn dual_pin_accepts_the_owner_email_identity() {
    // Both pins set: an SSO/OAuth token carrying the pinned email (and no
    // common_name) is the owner — the connector auth path.
    let token = sign(ISSUER, AUDIENCE, now() + 3600, OWNER_EMAIL);
    let identity = verifier_dual(OWNER_EMAIL, SERVICE_CN)
        .verify(&token)
        .expect("the pinned email identity verifies under dual-pin");
    assert_eq!(identity.auth_id(), "owner");
    // An email-authenticated identity is the connector channel (tool-scopable).
    assert_eq!(identity.channel(), AuthChannel::Connector);
}

#[test]
fn dual_pin_accepts_the_service_token_identity() {
    // Both pins set: a service token carrying the pinned common_name (and no
    // email) is the owner — the existing CLI auth path keeps working.
    let token = service_token(SERVICE_CN, now() + 3600);
    let identity = verifier_dual(OWNER_EMAIL, SERVICE_CN)
        .verify(&token)
        .expect("the pinned service token verifies under dual-pin");
    assert_eq!(identity.auth_id(), "owner");
    // A service-token identity is the CLI channel (full tool set).
    assert_eq!(identity.channel(), AuthChannel::Cli);
}

#[test]
fn dual_pin_rejects_a_token_matching_neither_pin() {
    // Both pins set, but a validly-signed token whose email matches neither pin
    // (and carries no common_name) is NOT the owner — OR-semantics must not
    // become accept-anything; fail closed.
    let token = sign(ISSUER, AUDIENCE, now() + 3600, "intruder@example.com");
    assert!(
        matches!(
            verifier_dual(OWNER_EMAIL, SERVICE_CN).verify(&token),
            Err(AccessError::NotOwner)
        ),
        "a token matching neither the email nor the common_name pin must be rejected"
    );
}

#[test]
fn dual_pin_accepts_a_token_matching_one_pin_even_if_the_other_claim_differs() {
    // OR-semantics: a token whose `email` matches the email pin is owner even if it
    // also carries a (non-matching) `common_name` — a match on EITHER pin suffices,
    // and the pins compare against their OWN claim only (no claim confusion).
    let token = sign_json(serde_json::json!({
        "iss": ISSUER,
        "aud": [AUDIENCE],
        "exp": now() + 3600,
        "iat": now(),
        "email": OWNER_EMAIL,
        "common_name": "11112222333344445555666677778888.access",
    }));
    let identity = verifier_dual(OWNER_EMAIL, SERVICE_CN)
        .verify(&token)
        .expect("an email-pin match verifies even with a different common_name");
    assert_eq!(identity.auth_id(), "owner");
}

#[test]
fn dual_pin_accepts_a_service_token_match_even_with_a_nonmatching_email() {
    // Symmetric to the above: a token whose `common_name` matches the service-token
    // pin is owner even if it also carries a (non-matching) `email` — a wrong email
    // must NOT veto a valid common_name match under OR-semantics.
    let token = sign_json(serde_json::json!({
        "iss": ISSUER,
        "aud": [AUDIENCE],
        "exp": now() + 3600,
        "iat": now(),
        "email": "intruder@example.com",
        "common_name": SERVICE_CN,
    }));
    let identity = verifier_dual(OWNER_EMAIL, SERVICE_CN)
        .verify(&token)
        .expect("a common_name-pin match verifies even with a different email");
    assert_eq!(identity.auth_id(), "owner");
}

#[test]
fn dual_pin_rejects_a_token_with_empty_claim_strings() {
    // Defense in depth: a validly-signed token carrying EMPTY email/common_name
    // strings matches neither (non-empty) pin — an empty claim is never a match.
    let token = sign_json(serde_json::json!({
        "iss": ISSUER,
        "aud": [AUDIENCE],
        "exp": now() + 3600,
        "iat": now(),
        "email": "",
        "common_name": "",
    }));
    assert!(
        matches!(
            verifier_dual(OWNER_EMAIL, SERVICE_CN).verify(&token),
            Err(AccessError::NotOwner)
        ),
        "empty claim strings must not match a non-empty pin"
    );
}

#[test]
fn garbage_and_empty_tokens_are_rejected() {
    let v = verifier(Some(OWNER_EMAIL));
    assert!(v.verify("").is_err());
    assert!(v.verify("not.a.jwt").is_err());
    assert!(v.verify("a.b.c.d").is_err());
}

#[test]
fn a_token_missing_iss_or_aud_is_rejected() {
    // A validly-signed, unexpired token that OMITS iss or aud must still fail —
    // the issuer/audience pin requires the claims to be present, not just matched
    // when present.
    let sign_value = |claims: serde_json::Value| -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());
        let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("key");
        encode(&header, &claims, &key).expect("sign")
    };
    let no_iss = sign_value(
        serde_json::json!({ "aud": [AUDIENCE], "exp": now() + 3600, "email": OWNER_EMAIL }),
    );
    assert!(
        verifier(Some(OWNER_EMAIL)).verify(&no_iss).is_err(),
        "missing iss"
    );
    let no_aud =
        sign_value(serde_json::json!({ "iss": ISSUER, "exp": now() + 3600, "email": OWNER_EMAIL }));
    assert!(
        verifier(Some(OWNER_EMAIL)).verify(&no_aud).is_err(),
        "missing aud"
    );
}

#[test]
fn fetch_jwks_reads_and_parses_the_keys_then_verifies_end_to_end() {
    // Serve the test JWKS over loopback, fetch it, and verify a token against the
    // fetched keys — the full team-JWKS → DecodingKey → verify path.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, |req| {
            if req.path == "/cdn-cgi/access/certs" {
                httptiny::Response::json(200, TEST_JWKS)
            } else {
                httptiny::Response::not_found()
            }
        });
    });

    let keys =
        fetch_jwks(&format!("http://127.0.0.1:{port}/cdn-cgi/access/certs")).expect("fetch jwks");
    let verifier = AccessVerifier::new(
        AccessConfig {
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            owner_email: Some(OWNER_EMAIL.to_string()),
            owner_common_name: None,
        },
        keys,
    );
    let token = sign(ISSUER, AUDIENCE, now() + 3600, OWNER_EMAIL);
    assert_eq!(verifier.verify(&token).expect("verify").auth_id(), "owner");
}

#[test]
fn fetch_jwks_rejects_an_empty_key_set() {
    // A 200 response that parses to an empty JWKS must be an error, not an
    // authoritative result: returning it would let the background refresh wipe a
    // good cache (every later verify -> UnknownKey/401), and a startup fetch would
    // bring up a gateway that can verify nothing. Fail closed so callers keep the
    // previous keys / refuse to start.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        let _ = httptiny::serve_listener(listener, |req| {
            if req.path == "/cdn-cgi/access/certs" {
                httptiny::Response::json(200, r#"{"keys":[]}"#)
            } else {
                httptiny::Response::not_found()
            }
        });
    });
    assert!(fetch_jwks(&format!("http://127.0.0.1:{port}/cdn-cgi/access/certs")).is_err());
}

#[test]
fn fetch_jwks_refuses_an_insecure_non_loopback_url() {
    // Keys must come over HTTPS (or loopback in tests) — never plain http to a
    // remote host, which could be tampered in transit.
    assert!(fetch_jwks("http://keys.example.com/certs").is_err());
}

#[test]
fn replace_keys_swaps_in_rotated_keys() {
    // A verifier that starts with an empty JWKS rejects everything; after a
    // refresh (replace_keys) with the real keys, the same token verifies — this
    // is how the background refresh tracks a Cloudflare key rotation.
    let empty: JwkSet = serde_json::from_str(r#"{"keys":[]}"#).expect("empty jwks");
    let verifier = AccessVerifier::new(
        AccessConfig {
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            owner_email: Some(OWNER_EMAIL.to_string()),
            owner_common_name: None,
        },
        empty,
    );
    let token = sign(ISSUER, AUDIENCE, now() + 3600, OWNER_EMAIL);
    assert!(verifier.verify(&token).is_err(), "no keys => reject");

    verifier.replace_keys(jwks());
    assert_eq!(
        verifier
            .verify(&token)
            .expect("verifies after refresh")
            .auth_id(),
        "owner"
    );
}
