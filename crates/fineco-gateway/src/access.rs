//! Cloudflare Access JWT verification (plan §"Cloudflare Access").
//!
//! The gateway sits behind a Cloudflare Tunnel + Access; a local `cloudflared`
//! forwards requests carrying a `Cf-Access-Jwt-Assertion` header. This module
//! verifies that JWT — **issuer, audience, expiry, and signature against the
//! team JWKS** — and maps the verified owner to the fixed [`OWNER_AUTH_ID`]. A
//! request with no token, a spoofed `Cf-Access-*` header, or any invalid token
//! is rejected; nothing about the failure leaks to the client.
//!
//! The team domain (issuer) and the Access application AUD tag (audience) are
//! **config-only** (set from the environment), never hard-coded. An optional
//! owner-identity pin — an email (SSO/OAuth), a service-token `common_name`, or
//! both (dual-pin: a token matching either is the owner) — adds defense in depth
//! behind the Access policy itself.

use fineco_core::is_secure_or_loopback;
use fineco_ipc::OWNER_AUTH_ID;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

/// Max bytes read from the JWKS endpoint (bounds a hostile/oversized response).
const MAX_JWKS_BYTES: u64 = 256 * 1024;

/// Upper bound on a single JWKS fetch (connect + transfer). A stalled endpoint
/// must not block gateway startup or wedge the background refresh thread.
const JWKS_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Verification config. Issuer + audience come from the team's Access setup and
/// are supplied via the environment.
#[derive(Clone)]
pub struct AccessConfig {
    /// Expected `iss` — the team domain, e.g. `https://<team>.cloudflareaccess.com`.
    pub issuer: String,
    /// Expected `aud` — the Access application's AUD tag.
    pub audience: String,
    /// Optional owner identity (email) to pin: a verified token whose `email`
    /// matches maps to `owner`. `None` does not pin on email. Can be set
    /// alongside [`Self::owner_common_name`] (dual-pin): a token matching EITHER
    /// pin is the owner — this is how an interactive SSO/OAuth identity
    /// (ChatGPT/Claude connectors) and a service token (CLI) share one gateway.
    pub owner_email: Option<String>,
    /// Optional service-token identity (`common_name` claim — Cloudflare's stable
    /// per-service-token Client ID) to pin. For SERVICE-TOKEN deployments (whose
    /// JWTs carry no `email`), this is the gateway-side binding to one specific
    /// token: even if the Access app is later widened to admit another token, only
    /// the pinned `common_name` maps to `owner`. `None` does not pin on it. Can be
    /// set alongside [`Self::owner_email`] (dual-pin): a token matching EITHER pin
    /// is the owner.
    pub owner_common_name: Option<String>,
}

/// The claims read **after** signature/issuer/audience/expiry validation.
#[derive(Debug, Deserialize)]
struct AccessClaims {
    #[serde(default)]
    email: Option<String>,
    /// Cloudflare service-token Client ID. Present on service-token JWTs, absent
    /// on interactive/SSO tokens.
    #[serde(default)]
    common_name: Option<String>,
}

/// Which Cloudflare Access channel authenticated the (single) owner. Both channels
/// map to the same `auth_id: owner`; the distinction only scopes the exposed tool
/// surface (the connector channel can be restricted to an allowlist).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthChannel {
    /// Authenticated by the service-token `common_name` pin — the owner's trusted
    /// CLI clients. Always gets the full tool set.
    Cli,
    /// Authenticated by the `email` pin only — an interactive SSO/OAuth identity,
    /// i.e. the ChatGPT/Claude connectors. May be restricted to a tool allowlist.
    Connector,
}

/// A verified Access identity. In the owner-only system the `auth_id` is always the
/// fixed `owner` (the capability layer keys on it); the [`AuthChannel`] records how
/// the owner authenticated, for tool scoping.
pub struct AccessIdentity {
    auth_id: &'static str,
    channel: AuthChannel,
}

impl AccessIdentity {
    /// The mapped `auth_id` (always [`OWNER_AUTH_ID`]).
    #[must_use]
    pub fn auth_id(&self) -> &str {
        self.auth_id
    }

    /// Which Access channel authenticated this identity (CLI service token vs
    /// interactive/OAuth connector).
    #[must_use]
    pub fn channel(&self) -> AuthChannel {
        self.channel
    }
}

/// Why verification failed. All variants are surfaced to the client as a single
/// opaque "unauthorized" — the distinction is for local reasoning/tests only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessError {
    /// The token is missing, not a JWT, or has no key id.
    Malformed,
    /// The token's `kid` is not in the configured JWKS.
    UnknownKey,
    /// Signature / issuer / audience / expiry validation failed.
    Invalid,
    /// Validly signed, but not the pinned owner identity.
    NotOwner,
}

/// True iff a *configured* pin matches the token's claim (case-insensitive). An
/// unconfigured pin (`None`) never matches — it does not authorize on its own —
/// and a configured pin against an absent claim (`None`) fails closed.
fn matches_pin(pin: Option<&str>, claim: Option<&str>) -> bool {
    matches!((pin, claim), (Some(pin), Some(claim)) if claim.eq_ignore_ascii_case(pin))
}

/// Verifies Cloudflare Access JWTs against a fixed config + the team JWKS. The
/// keys are swappable ([`AccessVerifier::replace_keys`]) so a background task can
/// refresh them when Cloudflare rotates its signing keys, without rebuilding the
/// shared verifier.
pub struct AccessVerifier {
    config: AccessConfig,
    keys: std::sync::RwLock<JwkSet>,
}

impl AccessVerifier {
    /// Build a verifier from the config and the team's JWKS (public keys).
    #[must_use]
    pub fn new(config: AccessConfig, keys: JwkSet) -> Self {
        Self {
            config,
            keys: std::sync::RwLock::new(keys),
        }
    }

    /// Swap in a freshly-fetched JWKS (after a key rotation). Keeps the existing
    /// keys if the lock is poisoned.
    pub fn replace_keys(&self, keys: JwkSet) {
        if let Ok(mut guard) = self.keys.write() {
            *guard = keys;
        }
    }

    /// Verify `token` and return the mapped identity.
    ///
    /// Enforces (via the JWKS key matched by `kid`): RS256 signature, `iss` ==
    /// the team domain, `aud` == the AUD tag, and a non-expired `exp`. Only
    /// RS256 is accepted, so an `alg=none`/HMAC algorithm-confusion token is
    /// refused. Then the owner-identity pin is applied: with both an email and a
    /// `common_name` pin set (dual-pin) the token must match AT LEAST ONE; with a
    /// single pin it must match that one; with no pin any validly-signed token
    /// maps to owner. A token matching no configured pin fails closed.
    ///
    /// # Errors
    /// [`AccessError`] on any failure; carries no token detail.
    pub fn verify(&self, token: &str) -> Result<AccessIdentity, AccessError> {
        let header = decode_header(token).map_err(|_| AccessError::Malformed)?;
        let kid = header.kid.ok_or(AccessError::Malformed)?;
        let key = {
            let keys = self.keys.read().map_err(|_| AccessError::Invalid)?;
            let jwk = keys.find(&kid).ok_or(AccessError::UnknownKey)?;
            DecodingKey::from_jwk(jwk).map_err(|_| AccessError::Invalid)?
        };

        // RS256 only (defeats algorithm confusion); validate iss/aud/exp, and
        // require all three to be PRESENT (a token omitting iss/aud must not slip
        // past the issuer/audience pin).
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);

        let data =
            decode::<AccessClaims>(token, &key, &validation).map_err(|_| AccessError::Invalid)?;

        // Owner-identity pin (defense in depth behind the Access policy). The ONE
        // owner reaches the gateway as EITHER an interactive SSO/OAuth identity (the
        // `email` claim — ChatGPT/Claude connectors) OR a service token (the
        // `common_name` claim — CLI clients). Semantics:
        //   * BOTH pins set (dual-pin): the token is owner if it matches AT LEAST
        //     ONE — an `email` token matches the email pin, a service token matches
        //     the common_name pin. This is what lets the connector and CLI paths
        //     coexist on one deployment.
        //   * a SINGLE pin set: the token must match that pin (a token lacking the
        //     claim fails closed, since the claim is absent).
        //   * NO pin (unit tests only — the production `from_env` refuses to build
        //     one): any validly-signed token maps to owner, gated solely by the
        //     Access policy.
        // A token matching no configured pin fails closed as `NotOwner`.
        let email_matches = matches_pin(
            self.config.owner_email.as_deref(),
            data.claims.email.as_deref(),
        );
        let common_name_matches = matches_pin(
            self.config.owner_common_name.as_deref(),
            data.claims.common_name.as_deref(),
        );
        let has_pin = self.config.owner_email.is_some() || self.config.owner_common_name.is_some();
        if has_pin && !(email_matches || common_name_matches) {
            return Err(AccessError::NotOwner);
        }

        // Channel for tool scoping: a service-token (`common_name`) match is the
        // trusted CLI; an email-only match is the connector/OAuth surface. No-pin
        // (tests) defaults to the full CLI channel. A `common_name` match takes
        // precedence (a service token is the explicitly-trusted credential).
        let channel = if common_name_matches {
            AuthChannel::Cli
        } else if email_matches {
            AuthChannel::Connector
        } else {
            AuthChannel::Cli
        };

        Ok(AccessIdentity {
            auth_id: OWNER_AUTH_ID,
            channel,
        })
    }
}

/// Fetch the team's JWKS (the Access public keys) from `jwks_url`.
///
/// The URL must be HTTPS (a loopback host is allowed for tests) so the keys
/// cannot be tampered in transit. Redirects are disabled and the body is bounded
/// to [`MAX_JWKS_BYTES`]. The real endpoint is
/// `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`.
///
/// # Errors
/// [`AccessError::Invalid`] on an insecure URL, transport failure, non-2xx
/// status, or an unparseable JWKS. No URL/response detail leaks.
pub fn fetch_jwks(jwks_url: &str) -> Result<JwkSet, AccessError> {
    if !is_secure_or_loopback(jwks_url) {
        return Err(AccessError::Invalid);
    }
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .max_redirects_will_error(false)
        // Bound the whole fetch: a JWKS endpoint that accepts the connection but
        // stalls must not block gateway startup (the startup fetch runs before the
        // bind) or wedge the background refresh thread forever.
        .timeout_global(Some(JWKS_FETCH_TIMEOUT))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut response = agent
        .get(jwks_url)
        .header("Accept", "application/json")
        .call()
        .map_err(|_| AccessError::Invalid)?;
    if !(200..300).contains(&response.status().as_u16()) {
        return Err(AccessError::Invalid);
    }
    let keys = response
        .body_mut()
        .with_config()
        .limit(MAX_JWKS_BYTES)
        .read_json::<JwkSet>()
        .map_err(|_| AccessError::Invalid)?;
    // A successful fetch with no signing keys is not authoritative: returning it
    // would let the background refresh wipe a good cache (every later verify then
    // fails) and a startup fetch would bring up a gateway that can verify nothing.
    // Fail closed so callers keep the previous keys / refuse to start.
    if keys.keys.is_empty() {
        return Err(AccessError::Invalid);
    }
    Ok(keys)
}
