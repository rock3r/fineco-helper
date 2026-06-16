//! Server roles for the self-contained binary (plan "Migration target": one
//! binary, subcommands/roles).
//!
//! Three roles form the process boundary:
//! - **`gateway`** — hosts the rmcp Streamable HTTP MCP service (a tower
//!   `Service`) over axum, bound to **loopback only**. It holds no credentials,
//!   no DB handle, and no live socket; private cached reads go over the
//!   snapshot-query socket and the credential-free market reads run in-process.
//! - **`store-server`** — opens the local SQLite store and answers the cached
//!   reads on the snapshot-query Unix socket via [`fineco_ipc::serve_blocking`].
//! - **`private-worker`** — the sole credential holder: builds the Fineco worker
//!   (creds + network, **no DB**) and serves `fineco-live.sock` via the
//!   fineco-live protocol. Orders cross the socket un-hashed; the controller
//!   hashes them. This role never opens the SQLite DB and has no public listener.
//!
//! Config comes from environment variables (documented on each loader). The
//! enrichment host stays **config-only**: it enters via `FINECO_ENRICHMENT_BASE`
//! / `FINECO_ENRICHMENT_HOST_HASHES`, never hard-coded here.

use std::net::SocketAddr;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::response::IntoResponse;
use fineco_gateway::Gateway;
use fineco_gateway::access::{AccessConfig, AccessVerifier, fetch_jwks};
use fineco_ipc::{MarketControlClient, Policy, RefreshClient, RefreshRequest};
use fineco_live::{LiveClient, MarketAssetDetailsLiveFetcher, MarketSearchLiveFetcher};
use fineco_market::{DEFAULT_ZERO_COMMISSION_ETFS_URL, EnrichmentHostAllowlist, MarketClient};
use fineco_query::{FreshnessMaxAge, QueryHandler};
use fineco_refresh::{PortfolioFetcher, RawOrdersFetcher, TaxFetcher};
use fineco_store::Store;
use fineco_worker::{EnvCredentialSource, FinecoEndpoints, FinecoWorker};

use crate::controller::{RefreshController, RefreshLimitsByArea};

/// An error configuring or running a server role. Carries only safe,
/// developer-authored messages — never a secret, payload, or raw cause.
#[derive(Debug)]
pub struct ServeError(String);

impl ServeError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ServeError {}

impl From<std::io::Error> for ServeError {
    fn from(_: std::io::Error) -> Self {
        // The raw I/O cause may name a path; keep the surfaced message generic.
        Self::new("a server I/O operation failed")
    }
}

/// Parse `addr` (`host:port`) and require a **loopback** bind. A non-loopback
/// bind is refused: the gateway is unauthenticated until the Cloudflare Access
/// remote mode lands (plan "owner-mcp-gateway": bind only to `127.0.0.1` or a
/// local `cloudflared` socket; refuse non-loopback unless an authenticated
/// remote mode is explicitly enabled).
///
/// # Errors
/// [`ServeError`] if `addr` is not a valid `host:port`, or is not loopback.
pub fn resolve_loopback_bind(addr: &str) -> Result<SocketAddr, ServeError> {
    let parsed: SocketAddr = addr
        .parse()
        .map_err(|_| ServeError::new("bind address must be a valid host:port"))?;
    if !parsed.ip().is_loopback() {
        return Err(ServeError::new(
            "refusing a non-loopback bind (authenticated remote mode is not enabled)",
        ));
    }
    Ok(parsed)
}

/// Cloudflare Access verification settings (M6). Present only when fully
/// configured; the team domain (issuer) + AUD tag (audience) are config-only.
pub struct AccessSettings {
    /// Expected `iss` — the team domain.
    pub issuer: String,
    /// Expected `aud` — the Access application's AUD tag.
    pub audience: String,
    /// The team JWKS endpoint (HTTPS) the gateway fetches the public keys from.
    pub jwks_url: String,
    /// Optional owner-email pin (defense in depth behind the Access policy).
    pub owner_email: Option<String>,
    /// Optional service-token `common_name` pin (the per-token Client ID) — the
    /// local binding to one specific service token for service-token deployments.
    pub owner_common_name: Option<String>,
}

/// Configuration for the `gateway` role.
pub struct GatewayConfig {
    /// The loopback address to bind the MCP HTTP service to.
    pub bind: SocketAddr,
    /// Path to the snapshot-query Unix socket the worker listens on.
    pub socket_path: PathBuf,
    /// The in-process market reader, if market config is present (else the
    /// market tools report "not configured").
    pub market: Option<MarketClient>,
    /// Path to the required capability-policy JSON file.
    pub policy_path: PathBuf,
    /// Cloudflare Access verification, if configured. `None` runs the gateway
    /// loopback-only without Access (local/dev); the remote deployment sets it.
    pub access: Option<AccessSettings>,
    /// Allowed `Origin` values for DNS-rebinding protection (empty = off).
    pub allowed_origins: Vec<String>,
    /// Path to the refresh-control socket (M8 live refresh). `Some` wires the
    /// gateway's live-refresh tools to the controller; `None` leaves them
    /// returning a safe "not configured" error (a cached-only gateway). The
    /// gateway never gets a `fineco-live` client — only this refresh-control path.
    pub refresh_socket_path: Option<PathBuf>,
    /// Path to the controller-owned authenticated market-control socket. `Some`
    /// wires the gateway's Fineco authenticated market tools to the controller.
    pub market_control_socket_path: Option<PathBuf>,
    /// Connector (email/OAuth) tool allowlist. `Some` restricts the connector
    /// Access channel to exactly these tools (the CLI/service-token channel is
    /// never restricted); `None` leaves connectors unrestricted. `Some` whenever
    /// Access has an email pin (the connector channel exists) — resolved from
    /// `FINECO_CONNECTOR_TOOLS`.
    pub connector_allowlist: Option<Vec<String>>,
}

impl GatewayConfig {
    /// Build from an environment getter.
    ///
    /// - `FINECO_GATEWAY_BIND` (default `127.0.0.1:8765`) — loopback `host:port`.
    /// - `FINECO_QUERY_SOCKET` (required) — snapshot-query socket path.
    /// - `FINECO_POLICY_PATH` (required) — capability-policy JSON file.
    /// - Market (all-or-nothing): `FINECO_ENRICHMENT_BASE`, `FINECO_ETF_URL`,
    ///   and `FINECO_ENRICHMENT_HOST_HASHES` (comma-separated SHA-256 host
    ///   hashes). Absent → market tools disabled; partial → an error.
    /// - Access (all-or-nothing): `FINECO_ACCESS_ISSUER`, `FINECO_ACCESS_AUDIENCE`,
    ///   `FINECO_ACCESS_JWKS_URL` (+ optional `FINECO_OWNER_EMAIL` and
    ///   `FINECO_ACCESS_OWNER_COMMON_NAME`, the service-token Client-ID pin).
    ///   Absent → Access disabled (loopback-only); partial → an error. The JWKS URL must be
    ///   on the issuer's own origin (key source bound to the issuer) → an error.
    /// - `FINECO_ALLOWED_ORIGINS` (optional, comma-separated) — Origin allowlist.
    /// - `FINECO_REFRESH_SOCKET` (optional) — the refresh-control socket; set it to
    ///   enable the live-refresh tools, leave it unset for a cached-only gateway.
    /// - `FINECO_MARKET_CONTROL_SOCKET` (optional, explicit-only) — the
    ///   authenticated market-control socket; leave unset until market
    ///   live-session controls are enabled. Requires `FINECO_REFRESH_SOCKET`
    ///   and `FINECO_LIVE_SOCKET`, because the same controller serves both
    ///   refresh and authenticated-market live commands.
    ///
    /// # Errors
    /// [`ServeError`] on a missing required var, a non-loopback bind, or a
    /// partially-specified market/Access config.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, ServeError> {
        let bind = resolve_loopback_bind(
            &get("FINECO_GATEWAY_BIND").unwrap_or_else(|| "127.0.0.1:8765".to_string()),
        )?;
        let socket_path = get("FINECO_QUERY_SOCKET")
            .map(PathBuf::from)
            .ok_or_else(|| ServeError::new("FINECO_QUERY_SOCKET is required"))?;
        let policy_path = get("FINECO_POLICY_PATH")
            .map(PathBuf::from)
            .ok_or_else(|| ServeError::new("FINECO_POLICY_PATH is required"))?;
        let market = build_market(&get)?;
        let access = build_access(&get)?;
        let connector_allowlist = resolve_connector_allowlist(&get, &access)?;
        let allowed_origins = get("FINECO_ALLOWED_ORIGINS")
            .map(|raw| {
                raw.split(',')
                    .map(|o| o.trim().to_string())
                    .filter(|o| !o.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        // Optional: the refresh-control socket enables the live-refresh tools. A
        // blank value means "cached-only" (no refresh), not the literal empty path.
        let refresh_socket_path = get("FINECO_REFRESH_SOCKET")
            .map(|path| path.trim().to_string())
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        let market_control_socket_path = get("FINECO_MARKET_CONTROL_SOCKET")
            .map(|path| path.trim().to_string())
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        Ok(Self {
            bind,
            socket_path,
            market,
            policy_path,
            access,
            allowed_origins,
            refresh_socket_path,
            market_control_socket_path,
            connector_allowlist,
        })
    }
}

/// Resolve the connector (email/OAuth) tool allowlist from `FINECO_CONNECTOR_TOOLS`.
/// The connector channel exists whenever Access is enabled with an **email pin**
/// (`FINECO_OWNER_EMAIL`) — an email/OAuth identity authenticates on it (a service
/// token authenticates on the always-full CLI channel). So the allowlist is
/// installed whenever an email pin is set (including a single email pin — NOT only
/// dual-pin), which is what keeps a single-email-pin connector deployment from
/// exposing the blocked tools. With no email pin there is no connector channel, so
/// this is `None`, and setting the var then is a hard error.
///
/// - unset → the default allowlist (every tool except the default blocked tools
///   — see [`fineco_gateway::DEFAULT_CONNECTOR_TOOLS`]);
/// - `*` / `all` → `None` (connectors get the full tool set — explicit opt-out);
/// - a `+`-prefixed comma-separated list → the default set PLUS those tools
///   (deduplicated) — the fail-safe way to widen the surface (e.g. enabling the
///   authenticated market tools) without re-listing every default tool;
/// - any other comma-separated list → exactly those tools.
///
/// Every listed name must be a real tool (fail closed on a typo).
fn resolve_connector_allowlist(
    get: &impl Fn(&str) -> Option<String>,
    access: &Option<AccessSettings>,
) -> Result<Option<Vec<String>>, ServeError> {
    let raw = get("FINECO_CONNECTOR_TOOLS")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let has_email_pin = access.as_ref().is_some_and(|a| a.owner_email.is_some());
    if !has_email_pin {
        if raw.is_some() {
            return Err(ServeError::new(
                "FINECO_CONNECTOR_TOOLS requires an email/OAuth pin (FINECO_OWNER_EMAIL): the \
                 connector channel it scopes only exists when email/OAuth Access auth is enabled",
            ));
        }
        return Ok(None);
    }
    let names: Vec<String> = match raw.as_deref() {
        None => fineco_gateway::DEFAULT_CONNECTOR_TOOLS
            .iter()
            .map(|name| (*name).to_string())
            .collect(),
        // Explicit opt-out: connectors get every tool (the pre-scoping behaviour).
        Some("*" | "all") => return Ok(None),
        // `+`-prefixed: the default set plus the listed tools (deduplicated), so
        // widening the surface keeps every fail-safe default.
        Some(list) if list.starts_with('+') => {
            let mut names: Vec<String> = fineco_gateway::DEFAULT_CONNECTOR_TOOLS
                .iter()
                .map(|name| (*name).to_string())
                .collect();
            for name in list[1..]
                .split(',')
                .map(str::trim)
                .filter(|n| !n.is_empty())
            {
                if !names.iter().any(|existing| existing == name) {
                    names.push(name.to_string());
                }
            }
            names
        }
        Some(list) => list
            .split(',')
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect(),
    };
    // Fail closed on a typo: a misspelled tool name would silently drop a tool from
    // the connector surface (allowlist) rather than expose one, but it still means
    // the deployer's intent isn't met — surface it loudly at startup.
    let known: std::collections::HashSet<String> = Gateway::tool_names().into_iter().collect();
    if let Some(unknown) = names.iter().find(|name| !known.contains(name.as_str())) {
        return Err(ServeError::new(format!(
            "FINECO_CONNECTOR_TOOLS lists an unknown tool '{unknown}' (not a registered MCP tool)"
        )));
    }
    Ok(Some(names))
}

/// Build the optional Cloudflare Access settings. The three core vars are
/// all-or-nothing (fail closed on a partial config). A fully-absent config is an
/// **error** unless `FINECO_ACCESS_DISABLED=true` is set explicitly, so a
/// production misconfiguration can never silently run the gateway with no
/// authentication. When Access IS enabled, AT LEAST ONE identity pin is REQUIRED
/// (`FINECO_OWNER_EMAIL` and/or `FINECO_ACCESS_OWNER_COMMON_NAME` — both may be set
/// for dual-pin: a token matching either maps to owner); a blank value is treated
/// as no pin, so an Access config with neither set refuses to start.
fn build_access(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<Option<AccessSettings>, ServeError> {
    let issuer = get("FINECO_ACCESS_ISSUER");
    let audience = get("FINECO_ACCESS_AUDIENCE");
    let jwks_url = get("FINECO_ACCESS_JWKS_URL");
    match (issuer, audience, jwks_url) {
        (Some(issuer), Some(audience), Some(jwks_url)) => {
            // Bind the key source to the issuer (fail closed). The JWKS URL must be
            // on the issuer's own origin (its `/cdn-cgi/access/certs` endpoint). The
            // signature is verified against whatever keys this URL serves, while
            // iss/aud are only *claims* in the payload — so a JWKS pointing at a
            // different origin (e.g. another Cloudflare team, or an attacker host)
            // would let a token signed there assert this issuer/audience and pass.
            let issuer_base = issuer.trim_end_matches('/');
            let same_origin = jwks_url == issuer_base
                || jwks_url
                    .strip_prefix(issuer_base)
                    .is_some_and(|rest| rest.starts_with('/'));
            if !same_origin {
                return Err(ServeError::new(
                    "FINECO_ACCESS_JWKS_URL must be on the same origin as \
                     FINECO_ACCESS_ISSUER (the issuer's own /cdn-cgi/access/certs \
                     endpoint): a key source on a different origin would let a token \
                     signed elsewhere assert this issuer/audience",
                ));
            }
            // A blank/whitespace pin must not mean "accept any token without the
            // claim" — treat it as no pin.
            let owner_email = get("FINECO_OWNER_EMAIL")
                .map(|email| email.trim().to_string())
                .filter(|email| !email.is_empty());
            // Same blank-is-no-pin rule for the service-token common_name pin.
            let owner_common_name = get("FINECO_ACCESS_OWNER_COMMON_NAME")
                .map(|cn| cn.trim().to_string())
                .filter(|cn| !cn.is_empty());
            // The two pins may BOTH be set (dual-pin): the verifier maps a token
            // matching EITHER to owner, so the one owner can reach the gateway as
            // their interactive SSO/OAuth email (ChatGPT/Claude connectors, whose
            // tokens carry `email` and no `common_name`) OR their service token
            // (CLI clients, which carry `common_name` and no `email`). An email
            // pin alone admits only SSO/OAuth; a common_name pin alone admits only
            // the service token.
            // Require AT LEAST ONE identity pin whenever Access is enabled (defense in
            // depth). With no pin the gateway maps EVERY validly-signed Access token to
            // `owner`, so a later widening of the Cloudflare Access policy (an added
            // user/service token) would silently grant ownership. Fail closed: the
            // deployer must pin at least one identity. (The verifier still supports a
            // no-pin mode for unit tests; the single production caller — this from_env —
            // refuses to build one.)
            if owner_email.is_none() && owner_common_name.is_none() {
                return Err(ServeError::new(
                    "Cloudflare Access is enabled but no owner identity is pinned: set at \
                     least one of FINECO_OWNER_EMAIL (SSO/OAuth) or \
                     FINECO_ACCESS_OWNER_COMMON_NAME (service token) — set both to admit both \
                     (dual-pin). Without a pin, any token the Access policy admits maps to \
                     owner.",
                ));
            }
            Ok(Some(AccessSettings {
                // Store the normalized issuer (no trailing slash): it is fed to
                // `set_issuer`, and Cloudflare's `iss` claim has no trailing slash,
                // so a slashed env value would otherwise boot but reject every token.
                issuer: issuer_base.to_string(),
                audience,
                jwks_url,
                owner_email,
                owner_common_name,
            }))
        }
        (None, None, None) => {
            if get("FINECO_ACCESS_DISABLED").as_deref() == Some("true") {
                Ok(None)
            } else {
                Err(ServeError::new(
                    "Cloudflare Access is not configured: set FINECO_ACCESS_ISSUER, \
                     FINECO_ACCESS_AUDIENCE and FINECO_ACCESS_JWKS_URL, or set \
                     FINECO_ACCESS_DISABLED=true to run loopback-only without auth",
                ))
            }
        }
        _ => Err(ServeError::new(
            "Cloudflare Access config needs FINECO_ACCESS_ISSUER, FINECO_ACCESS_AUDIENCE and FINECO_ACCESS_JWKS_URL together",
        )),
    }
}

/// Build the optional market client from config. The enrichment pair —
/// `FINECO_ENRICHMENT_BASE` + `FINECO_ENRICHMENT_HOST_HASHES` — enables the market
/// tools (both together → `Some`; neither → `None`; one alone → an error, fail
/// closed). `FINECO_ETF_URL` is **optional**: the zero-commission ETF list is a
/// fixed public Fineco endpoint, so it defaults to
/// [`DEFAULT_ZERO_COMMISSION_ETFS_URL`] and a deployment only sets it to point at
/// a mock or a moved list.
fn build_market(get: &impl Fn(&str) -> Option<String>) -> Result<Option<MarketClient>, ServeError> {
    let base = get("FINECO_ENRICHMENT_BASE");
    let hashes = get("FINECO_ENRICHMENT_HOST_HASHES");
    match (base, hashes) {
        (Some(base), Some(hashes)) => {
            let allowlist = EnrichmentHostAllowlist::from_host_hashes(
                hashes
                    .split(',')
                    .map(|hash| hash.trim().to_string())
                    .filter(|hash| !hash.is_empty()),
            );
            // A blank/whitespace override must fall back to the default, not become
            // the literal (empty) ETF endpoint — same rule as the Access pins.
            let etf_url = get("FINECO_ETF_URL")
                .map(|url| url.trim().to_string())
                .filter(|url| !url.is_empty())
                .unwrap_or_else(|| DEFAULT_ZERO_COMMISSION_ETFS_URL.to_string());
            Ok(Some(MarketClient::new(base, allowlist, etf_url)))
        }
        (None, None) => Ok(None),
        _ => Err(ServeError::new(
            "market config needs FINECO_ENRICHMENT_BASE and FINECO_ENRICHMENT_HOST_HASHES together \
             (FINECO_ETF_URL is optional and defaults to Fineco's public zero-commission list)",
        )),
    }
}

/// Default snapshot-query socket mode: owner-only (single-user / same-user
/// deployments, e.g. the Docker E2E). The multi-user LXC topology overrides this
/// to `0660` so the gateway can reach the socket via a shared IPC group.
const DEFAULT_SOCKET_MODE: u32 = 0o600;

/// Configuration for the `store-server` role.
pub struct StoreServerConfig {
    /// Path to the SQLite store database.
    pub db_path: PathBuf,
    /// Path to bind the snapshot-query Unix socket on.
    pub socket_path: PathBuf,
    /// Path to the required capability-policy JSON file.
    pub policy_path: PathBuf,
    /// Filesystem mode the bound snapshot-query socket is restricted to (octal).
    /// Defaults to owner-only; set `0660` in the multi-user topology (gateway
    /// reaches it via the shared IPC group).
    pub socket_mode: u32,
    /// Path to bind the refresh-control Unix socket on. `Some` (together with
    /// [`live_socket_path`]) enables the live-refresh controller on a second
    /// thread; `None` runs the store-server cached-only.
    ///
    /// [`live_socket_path`]: StoreServerConfig::live_socket_path
    pub refresh_socket_path: Option<PathBuf>,
    /// Path to bind the authenticated market-control Unix socket on. Explicitly
    /// set only when authenticated market tools are intentionally enabled.
    pub market_control_socket_path: Option<PathBuf>,
    /// Path to the credential worker's `fineco-live.sock`, which the controller's
    /// live client reaches. Required iff [`refresh_socket_path`] is set.
    ///
    /// [`refresh_socket_path`]: StoreServerConfig::refresh_socket_path
    pub live_socket_path: Option<PathBuf>,
    /// Filesystem mode the bound refresh-control socket is restricted to (octal).
    /// Defaults to owner-only; the multi-user topology sets `0660` for the
    /// `fineco-ipc-refresh` group (the gateway joins it only after the live gates).
    pub refresh_socket_mode: u32,
}

impl StoreServerConfig {
    /// Build from an environment getter.
    ///
    /// - `FINECO_DB_PATH` (required) — SQLite database path.
    /// - `FINECO_QUERY_SOCKET` (required) — snapshot-query socket path.
    /// - `FINECO_POLICY_PATH` (required) — capability-policy JSON file.
    /// - `FINECO_QUERY_SOCKET_MODE` (optional, default `0600`) — octal socket
    ///   mode; must grant the owner read+write and must NOT grant any access to
    ///   "other" (world). Set `0660` for the shared-IPC-group topology.
    ///
    /// # Errors
    /// [`ServeError`] if a required var is missing or the socket mode is invalid.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, ServeError> {
        let db_path = get("FINECO_DB_PATH")
            .map(PathBuf::from)
            .ok_or_else(|| ServeError::new("FINECO_DB_PATH is required"))?;
        let socket_path = get("FINECO_QUERY_SOCKET")
            .map(PathBuf::from)
            .ok_or_else(|| ServeError::new("FINECO_QUERY_SOCKET is required"))?;
        let policy_path = get("FINECO_POLICY_PATH")
            .map(PathBuf::from)
            .ok_or_else(|| ServeError::new("FINECO_POLICY_PATH is required"))?;
        let socket_mode = match get("FINECO_QUERY_SOCKET_MODE") {
            Some(raw) => parse_socket_mode(&raw)?,
            None => DEFAULT_SOCKET_MODE,
        };
        // Controller-backed live reads are opt-in: the refresh-control socket,
        // authenticated market-control socket, and worker live socket must be
        // configured consistently. A partial config fails closed rather than
        // silently disabling it. A blank/whitespace value means "unset"
        // (cached-only) — matching `GatewayConfig` — so stray empties can't enable
        // the controller with empty socket paths.
        let refresh_socket_path = get("FINECO_REFRESH_SOCKET")
            .map(|path| path.trim().to_string())
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        let live_socket_path = get("FINECO_LIVE_SOCKET")
            .map(|path| path.trim().to_string())
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        let market_control_socket_path = get("FINECO_MARKET_CONTROL_SOCKET")
            .map(|path| path.trim().to_string())
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);
        if refresh_socket_path.is_some() != live_socket_path.is_some() {
            return Err(ServeError::new(
                "live refresh needs FINECO_REFRESH_SOCKET and FINECO_LIVE_SOCKET together (or neither)",
            ));
        }
        if market_control_socket_path.is_some()
            && (refresh_socket_path.is_none() || live_socket_path.is_none())
        {
            return Err(ServeError::new(
                "authenticated market reads need FINECO_REFRESH_SOCKET and FINECO_LIVE_SOCKET (or unset FINECO_MARKET_CONTROL_SOCKET)",
            ));
        }
        let refresh_socket_mode = match get("FINECO_REFRESH_SOCKET_MODE") {
            Some(raw) => parse_socket_mode(&raw)?,
            None => DEFAULT_SOCKET_MODE,
        };
        Ok(Self {
            db_path,
            socket_path,
            policy_path,
            socket_mode,
            refresh_socket_path,
            market_control_socket_path,
            live_socket_path,
            refresh_socket_mode,
        })
    }
}

/// Load and validate the capability policy from its JSON file. Fails closed: a
/// missing or invalid policy aborts startup.
///
/// # Errors
/// [`ServeError`] if the file cannot be read or is not a valid policy.
pub fn load_policy(path: &Path) -> Result<Policy, ServeError> {
    let json = std::fs::read_to_string(path)
        .map_err(|_| ServeError::new("failed to read the capability policy file"))?;
    Policy::from_json(&json).map_err(|_| ServeError::new("the capability policy is invalid"))
}

/// Run the `gateway` role: host the MCP service over axum on the loopback bind
/// until a shutdown signal. The bind was already validated as loopback.
///
/// # Errors
/// [`ServeError`] if binding the listener or serving fails.
pub async fn run_gateway(config: GatewayConfig) -> Result<(), ServeError> {
    let policy = load_policy(&config.policy_path)?;
    let mut gateway = Gateway::new(&config.socket_path)
        .with_policy(policy)
        .with_allowed_origins(config.allowed_origins);
    if let Some(market) = config.market {
        gateway = gateway.with_market(market);
    }
    // Wire the live-refresh tools to the controller over refresh-control.sock when
    // configured (the gateway holds NO live-socket client — only this path).
    if let Some(refresh_socket) = config.refresh_socket_path {
        gateway = gateway.with_refresh_client(RefreshClient::new(refresh_socket));
    }
    if let Some(market_control_socket) = config.market_control_socket_path {
        gateway =
            gateway.with_market_control_client(MarketControlClient::new(market_control_socket));
    }
    // Scope the connector (email/OAuth) channel to its tool allowlist when one is
    // configured (any email-pinned deployment; the CLI/service-token channel stays
    // unrestricted).
    if let Some(allowlist) = config.connector_allowlist {
        gateway = gateway.with_connector_allowlist(allowlist);
    }

    // When Cloudflare Access is configured, fetch the team JWKS at startup (fail
    // closed) and build the verifier; the router then enforces it on every
    // request. Without it the gateway runs loopback-only (dev).
    let verifier = match config.access {
        Some(access) => {
            let keys = fetch_jwks(&access.jwks_url)
                .map_err(|_| ServeError::new("failed to fetch the Cloudflare Access JWKS"))?;
            let verifier = Arc::new(AccessVerifier::new(
                AccessConfig {
                    issuer: access.issuer,
                    audience: access.audience,
                    owner_email: access.owner_email,
                    owner_common_name: access.owner_common_name,
                },
                keys,
            ));
            // Track Cloudflare key rotations: periodically re-fetch the JWKS in
            // the background (a failed refresh keeps the current keys).
            spawn_jwks_refresh(Arc::clone(&verifier), access.jwks_url);
            Some(verifier)
        }
        None => None,
    };

    let app = gateway_router(gateway, verifier);
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Build the gateway's axum router: rmcp's tower service as the fallback, plus —
/// when `access` is present — a middleware that requires a valid Cloudflare
/// Access JWT on every request. Exposed for integration tests that drive the
/// router on their own listener.
pub fn gateway_router(gateway: Gateway, access: Option<Arc<AccessVerifier>>) -> axum::Router {
    let mut app = axum::Router::new().fallback_service(gateway.into_service());
    if let Some(verifier) = access {
        app = app.layer(axum::middleware::from_fn_with_state(
            verifier,
            enforce_access,
        ));
    }
    // Bound the request body on every request (independent of auth): the rmcp
    // Streamable HTTP handler buffers the whole body before parsing, so without a
    // cap an (authenticated) client could force an unbounded allocation. Added
    // last so it is the OUTERMOST layer and caps before anything reads the body.
    app.layer(axum::middleware::from_fn(limit_request_body))
}

/// Cap on the gateway request body. MCP JSON-RPC requests are small (a few KiB);
/// this is a generous bound against an oversized body, not a tight limit.
const MAX_REQUEST_BODY_BYTES: usize = 256 * 1024;

/// axum middleware bounding the request body. A declared `Content-Length` over the
/// cap is rejected fast with `413`; the body is then wrapped in a hard limiter so a
/// chunked or mis-declared body still cannot be buffered past the cap downstream.
async fn limit_request_body(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if let Some(len) = request
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        && len > MAX_REQUEST_BODY_BYTES as u64
    {
        return axum::http::StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let (parts, body) = request.into_parts();
    let limited = http_body_util::Limited::new(body, MAX_REQUEST_BODY_BYTES);
    let request = axum::extract::Request::from_parts(parts, axum::body::Body::new(limited));
    next.run(request).await
}

/// axum middleware enforcing Cloudflare Access: every request must carry a valid
/// `Cf-Access-Jwt-Assertion` JWT (verified against the team JWKS). Anything else
/// — missing, spoofed, or invalid — is rejected with `401` and no detail.
async fn enforce_access(
    axum::extract::State(verifier): axum::extract::State<Arc<AccessVerifier>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let identity = request
        .headers()
        .get("cf-access-jwt-assertion")
        .and_then(|value| value.to_str().ok())
        .and_then(|token| verifier.verify(token).ok());
    match identity {
        Some(identity) => {
            // Stamp the verified Access channel (CLI service token vs interactive
            // OAuth connector) into the request extensions so the gateway's
            // tool-scoping wrapper can read it (rmcp surfaces the request `Parts`
            // in the MCP request context).
            request.extensions_mut().insert(identity.channel());
            next.run(request).await
        }
        None => axum::http::StatusCode::UNAUTHORIZED.into_response(),
    }
}

/// How often the gateway re-fetches the team JWKS to track Cloudflare key
/// rotations.
const JWKS_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// Periodically re-fetch the team JWKS and swap it into `verifier` so a
/// Cloudflare key rotation doesn't start rejecting valid tokens. A failed
/// refresh leaves the existing keys in place. Runs for the process lifetime.
fn spawn_jwks_refresh(verifier: Arc<AccessVerifier>, jwks_url: String) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(JWKS_REFRESH_INTERVAL);
            if let Ok(keys) = fetch_jwks(&jwks_url) {
                verifier.replace_keys(keys);
            }
        }
    });
}

/// Resolve when the process receives Ctrl-C (SIGINT), for graceful shutdown.
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Run the `store-server` role: open the store and answer cached reads on the
/// snapshot-query socket. Blocks (sequential accept loop) until the listener
/// errors irrecoverably.
///
/// # Errors
/// [`ServeError`] if the store cannot be opened or the socket cannot be bound.
pub fn run_store_server(config: StoreServerConfig) -> Result<(), ServeError> {
    if config.market_control_socket_path.is_some()
        && (config.refresh_socket_path.is_none() || config.live_socket_path.is_none())
    {
        return Err(ServeError::new(
            "authenticated market reads need refresh-control and fineco-live sockets",
        ));
    }

    let policy = load_policy(&config.policy_path)?;

    // Optionally stand up controller sockets, with their OWN Store connection (the
    // snapshot-query loop keeps its own; SQLite serializes the two via
    // `busy_timeout`). The controller reaches the credential worker over
    // `fineco-live.sock`; the gateway never does.
    if config.refresh_socket_path.is_some() || config.market_control_socket_path.is_some() {
        let live_socket = config.live_socket_path.clone().ok_or_else(|| {
            ServeError::new(
                "controller sockets need FINECO_LIVE_SOCKET (or unset controller sockets)",
            )
        })?;
        let refresh_store = Store::open(&config.db_path)
            .map_err(|_| ServeError::new("failed to open the store for the refresh controller"))?;
        let controller = Arc::new(RefreshController::new(
            refresh_store,
            LiveClient::new(&live_socket),
            policy.clone(),
            RefreshLimitsByArea::defaults(),
        ));

        if let Some(refresh_socket) = config.refresh_socket_path.clone() {
            prepare_socket_path(&refresh_socket)?;
            let refresh_listener = std::os::unix::net::UnixListener::bind(&refresh_socket)?;
            restrict_socket_permissions(&refresh_socket, config.refresh_socket_mode)?;
            // `serve_refresh_blocking` is a SINGLE-consumer accept loop (one request
            // at a time), so refreshes never overlap within this process. The
            // authoritative cross-connection concurrency guard is still
            // `already_refreshing` (the running-job lock that `refresh_preflight`
            // checks) — it holds even across a process restart or a future move to a
            // concurrent accept loop, where the single-thread serialization would not.
            let refresh_controller = Arc::clone(&controller);
            std::thread::spawn(move || {
                let _ = fineco_ipc::serve_refresh_blocking(&refresh_listener, move |request| {
                    refresh_controller.handle(request, &fineco_core::now_iso8601_utc())
                });
            });
        }
        if let Some(market_control_socket) = config.market_control_socket_path.clone() {
            prepare_socket_path(&market_control_socket)?;
            let market_control_listener =
                std::os::unix::net::UnixListener::bind(&market_control_socket)?;
            restrict_socket_permissions(&market_control_socket, config.refresh_socket_mode)?;
            let market_controller = Arc::clone(&controller);
            std::thread::spawn(move || {
                let _ = fineco_ipc::serve_market_control_blocking(
                    &market_control_listener,
                    move |request| {
                        market_controller
                            .handle_market_control(request, &fineco_core::now_iso8601_utc())
                    },
                );
            });
        }
    }

    let store =
        Store::open(&config.db_path).map_err(|_| ServeError::new("failed to open the store"))?;
    let handler = QueryHandler::new(store, FreshnessMaxAge::default(), policy);

    // Clear only a confirmed **stale Unix socket** before binding. Never unlink a
    // regular file/dir at this path: a misconfigured `FINECO_QUERY_SOCKET` (e.g.
    // pointing at the DB or a typo) must not be able to destroy data on startup.
    prepare_socket_path(&config.socket_path)?;
    let listener = std::os::unix::net::UnixListener::bind(&config.socket_path)?;
    // Restrict the socket to the configured mode (default owner-only; 0660 +
    // shared IPC group in the multi-user topology). The worker treats every peer
    // as the implicit owner identity, so without this any local principal that
    // could reach the path would bypass the gateway and exercise owner-granted
    // cached reads directly. The residual bind→chmod window is closed in practice
    // and not safely closable in std (no `umask`/mode-on-bind without `unsafe`,
    // which the workspace lint forbids): systemd sets `UMask=0077` so the socket
    // is born 0600, the parent dir is `2750` (owner + IPC group only), and even
    // under a permissive umask a Unix socket's umask-derived mode denies `connect`
    // to non-owners — connecting requires the write bit, which group/other lack at
    // the 0755 a default umask would produce.
    restrict_socket_permissions(&config.socket_path, config.socket_mode)?;
    fineco_ipc::serve_blocking(&listener, move |request| {
        handler.handle(request, fineco_core::now_epoch_seconds())
    })?;
    Ok(())
}

/// Configuration for the `private-worker` role: the credential-holding Fineco
/// fetch behind `fineco-live.sock`. It holds the Fineco credentials and reaches
/// Fineco, but **never opens the SQLite DB** — orders cross the socket un-hashed
/// and are hashed by the controller.
pub struct PrivateWorkerConfig {
    /// Path to bind the `fineco-live.sock` Unix socket on.
    pub live_socket_path: PathBuf,
    /// Filesystem mode the bound socket is restricted to (octal). Defaults to
    /// owner-only; set `0660` in the multi-user topology so the refresh
    /// controller — the only legitimate caller — can reach it via the shared
    /// `fineco-ipc-live` group. The internet-facing gateway is never in that group.
    pub socket_mode: u32,
    /// Optional upstream base URL. Unset → the real Fineco production endpoints;
    /// set → every endpoint is collapsed onto this base (the mock server, for
    /// e2e/tests). Either way the worker builds every request URL from its fixed
    /// endpoint set — there is no client-supplied URL.
    pub upstream_base: Option<String>,
}

impl PrivateWorkerConfig {
    /// Build from an environment getter.
    ///
    /// - `FINECO_LIVE_SOCKET` (required) — `fineco-live.sock` path.
    /// - `FINECO_LIVE_SOCKET_MODE` (optional, default `0600`) — octal socket mode;
    ///   must grant the owner read+write and must NOT grant any access to "other"
    ///   (world). Set `0660` for the shared `fineco-ipc-live` group topology.
    /// - `FINECO_LIVE_UPSTREAM_BASE` (optional) — collapse the Fineco endpoints
    ///   onto this base (the mock); unset uses the real production endpoints.
    ///
    /// The Fineco credentials are read at run time from the worker's own
    /// environment (`FINECO_USER_ID` / `FINECO_PASSWORD`) via
    /// [`EnvCredentialSource`], never through this getter — so config parsing
    /// carries no secret.
    ///
    /// # Errors
    /// [`ServeError`] if the socket path is missing or the socket mode is invalid.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, ServeError> {
        // Trim + treat blank as unset, identically to how `StoreServerConfig`
        // parses the SAME `FINECO_LIVE_SOCKET`: the controller connects to the path
        // the worker binds, so stray padding must not make them target different
        // sockets. Still required for the worker (a blank value is "missing").
        let live_socket_path = get("FINECO_LIVE_SOCKET")
            .map(|path| path.trim().to_string())
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| ServeError::new("FINECO_LIVE_SOCKET is required"))?;
        let socket_mode = match get("FINECO_LIVE_SOCKET_MODE") {
            Some(raw) => parse_socket_mode(&raw)?,
            None => DEFAULT_SOCKET_MODE,
        };
        // A blank/whitespace upstream base must mean "use production", not the
        // literal empty base (which would build broken `/`-rooted URLs).
        let upstream_base = get("FINECO_LIVE_UPSTREAM_BASE")
            .map(|base| base.trim().to_string())
            .filter(|base| !base.is_empty());
        Ok(Self {
            live_socket_path,
            socket_mode,
            upstream_base,
        })
    }
}

/// Run the `private-worker` role: build the credential-holding Fineco worker and
/// serve `fineco-live.sock` for the refresh controller. Blocks (sequential accept
/// loop) until the listener errors irrecoverably.
///
/// The worker reads its Fineco credentials from the environment
/// (`FINECO_USER_ID` / `FINECO_PASSWORD`); a missing credential surfaces as
/// `auth_required` on the first fetch, never a panic or a leak.
///
/// # Errors
/// [`ServeError`] if the socket cannot be prepared or bound.
pub fn run_private_worker(config: PrivateWorkerConfig) -> Result<(), ServeError> {
    let endpoints = match &config.upstream_base {
        Some(base) => FinecoEndpoints::for_base(base),
        None => FinecoEndpoints::production(),
    };
    let worker = FinecoWorker::new(endpoints, Box::new(EnvCredentialSource));
    // Zeroize an idle held market session at its reuse-window expiry (AC-22), so a
    // dead cookie never lingers in the credential process past the TTL. The reaper
    // uses wall-clock time and exits when the worker is dropped.
    worker.spawn_session_reaper();
    serve_live(&worker, &config.live_socket_path, config.socket_mode)
}

/// Bind `socket_path` and serve the fineco-live protocol for `worker`. Shared by
/// [`run_private_worker`] and tests (which inject a fetcher directly). The socket
/// is prepared (only a confirmed stale socket is cleared — never a regular file,
/// never a live worker's socket) and restricted to `socket_mode` before serving.
///
/// # Errors
/// [`ServeError`] if the socket path cannot be prepared, bound, or restricted.
pub fn serve_live<W>(worker: &W, socket_path: &Path, socket_mode: u32) -> Result<(), ServeError>
where
    W: PortfolioFetcher
        + RawOrdersFetcher
        + TaxFetcher
        + MarketSearchLiveFetcher
        + MarketAssetDetailsLiveFetcher
        + fineco_live::MarketIndicesLiveFetcher,
{
    prepare_socket_path(socket_path)?;
    let listener = UnixListener::bind(socket_path)?;
    restrict_socket_permissions(socket_path, socket_mode)?;
    fineco_live::serve_live_blocking(&listener, worker)?;
    Ok(())
}

/// Configuration for the one-shot `backup` role.
pub struct BackupConfig {
    /// Path to the SQLite store database to back up.
    pub db_path: PathBuf,
    /// Path to write the backup copy to. Must NOT already exist (`VACUUM INTO`
    /// refuses to overwrite, so a backup can never clobber data).
    pub out_path: PathBuf,
}

impl BackupConfig {
    /// Build from an environment getter.
    ///
    /// - `FINECO_DB_PATH` (required) — the SQLite database to back up.
    /// - `FINECO_BACKUP_OUT` (required) — where to write the backup copy.
    ///
    /// # Errors
    /// [`ServeError`] if a required var is missing.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, ServeError> {
        let db_path = get("FINECO_DB_PATH")
            .map(PathBuf::from)
            .ok_or_else(|| ServeError::new("FINECO_DB_PATH is required"))?;
        let out_path = get("FINECO_BACKUP_OUT")
            .map(PathBuf::from)
            .ok_or_else(|| ServeError::new("FINECO_BACKUP_OUT is required"))?;
        Ok(Self { db_path, out_path })
    }
}

/// Run a one-shot online backup: open the store and `VACUUM INTO` the output
/// path. The deploy wrapper then compresses + age-encrypts the result.
///
/// # Errors
/// [`ServeError`] if the store cannot be opened or the backup cannot be written
/// (e.g. the output path already exists).
pub fn run_backup(config: BackupConfig) -> Result<(), ServeError> {
    let store = Store::open(&config.db_path)
        .map_err(|_| ServeError::new("failed to open the store for backup"))?;
    store
        .backup_to(&config.out_path)
        .map_err(|_| ServeError::new("failed to write the backup (does the output already exist?)"))
}

/// Configuration for the one-shot `refresh` subcommand — the timer-driven trigger
/// that asks the controller to perform a scheduled live refresh. It is purely a
/// refresh-control *client*: it holds no credentials, never opens the DB, and never
/// reaches the live socket (the controller owns all of that).
#[derive(Debug, Clone)]
pub struct RefreshTriggerConfig {
    /// Path to the refresh-control socket the controller serves.
    pub socket_path: PathBuf,
}

impl RefreshTriggerConfig {
    /// Build from an environment getter.
    ///
    /// - `FINECO_REFRESH_SOCKET` (required) — the refresh-control socket to drive.
    ///
    /// # Errors
    /// [`ServeError`] if the socket var is missing.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, ServeError> {
        let socket_path = get("FINECO_REFRESH_SOCKET")
            .map(PathBuf::from)
            .ok_or_else(|| ServeError::new("FINECO_REFRESH_SOCKET is required"))?;
        Ok(Self { socket_path })
    }
}

/// Map a CLI area argument to the refresh request to send. Only the param-less
/// `portfolio` refresh is schedulable from the CLI; orders and tax take parameters
/// (year ranges) and stay on-demand through the gated MCP tools.
///
/// # Errors
/// [`ServeError`] for any area other than `portfolio`.
pub fn parse_refresh_area(area: &str) -> Result<RefreshRequest, ServeError> {
    match area {
        "portfolio" => Ok(RefreshRequest::PortfolioRefreshLive),
        other => Err(ServeError::new(format!(
            "unsupported refresh area {other:?}; the scheduled CLI refresh supports only \
             'portfolio' (orders and tax take parameters and stay on-demand via the MCP tools)"
        ))),
    }
}

/// Run a one-shot live refresh by sending `request` to the controller on
/// `refresh-control.sock`. Prints a status-only line (data area + row count, never a
/// value) on success; a failed refresh — SCA, a timeout, a gate denial — surfaces as
/// a [`ServeError`] so the unit exits non-zero and the alerting path fires.
///
/// # Errors
/// [`ServeError`] (carrying the controller's safe message) if the refresh fails or
/// the socket is unreachable.
pub fn run_refresh(
    config: RefreshTriggerConfig,
    request: RefreshRequest,
) -> Result<(), ServeError> {
    match RefreshClient::new(&config.socket_path).call(&request) {
        Ok(outcome) => {
            // Status only — a row count, never a value (the controller's contract).
            println!(
                "refresh {}: ok ({} rows, captured {})",
                outcome.data_area, outcome.count, outcome.captured_at
            );
            Ok(())
        }
        Err(error) => Err(ServeError::new(format!(
            "refresh failed: {}",
            error.safe_message
        ))),
    }
}

/// Parse and validate an octal socket-mode string (`0600`, `0660`, `660`, …).
/// Fails closed: the owner must keep read+write and "other" (world) must have no
/// access, so the socket is reachable only by the owner and (optionally) the
/// shared IPC group.
fn parse_socket_mode(raw: &str) -> Result<u32, ServeError> {
    let digits = raw
        .strip_prefix("0o")
        .or_else(|| raw.strip_prefix("0O"))
        .unwrap_or(raw);
    let mode = u32::from_str_radix(digits, 8).map_err(|_| {
        ServeError::new("FINECO_QUERY_SOCKET_MODE must be an octal mode like 0600 or 0660")
    })?;
    if mode > 0o777 {
        return Err(ServeError::new("FINECO_QUERY_SOCKET_MODE is out of range"));
    }
    if mode & 0o007 != 0 {
        return Err(ServeError::new(
            "FINECO_QUERY_SOCKET_MODE must not grant any access to other (world)",
        ));
    }
    if mode & 0o600 != 0o600 {
        return Err(ServeError::new(
            "FINECO_QUERY_SOCKET_MODE must grant the owner read+write",
        ));
    }
    Ok(mode)
}

/// Restrict the just-bound socket at `path` to `mode` (octal). Connecting to a
/// Unix socket requires write access to the socket file, so this is the
/// binary-level guard that the worker is reached only by the owner — and, with
/// `0660`, the shared IPC group (the loopback gateway) — not by any other local
/// principal. `mode` was already validated to deny "other" access.
fn restrict_socket_permissions(path: &Path, mode: u32) -> Result<(), ServeError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|_| ServeError::new("failed to restrict the query socket permissions"))
}

/// Ready `path` for a fresh `UnixListener::bind`: if it is an existing **stale**
/// socket (no listener answers), remove it; if a worker is **still listening**,
/// refuse (don't sever a running instance and take over its socket); if it is any
/// other existing file or directory, refuse rather than overwrite it; if it is
/// absent, do nothing.
fn prepare_socket_path(path: &Path) -> Result<(), ServeError> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            // Probe for a live listener before unlinking: a successful connect
            // means another store-server is running on this socket — refuse
            // rather than hijack it. Only a stale socket (connection refused) is
            // safe to remove.
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(ServeError::new(
                    "another process is already listening on the socket path; refusing to take it over",
                ));
            }
            std::fs::remove_file(path)
                .map_err(|_| ServeError::new("failed to remove the stale socket"))
        }
        Ok(_) => Err(ServeError::new(
            "the socket path points at an existing non-socket file; refusing to overwrite it",
        )),
        Err(_) => Ok(()), // absent (or unreadable) — let bind create / fail
    }
}
