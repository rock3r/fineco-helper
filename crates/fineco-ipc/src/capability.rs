//! Capability policy (plan "Capability Model").
//!
//! One explicit, versioned allowlist maps each authenticated identity to the
//! capabilities it may exercise. Every tool/command is gated by a capability —
//! there is no generic `admin`/`private.read`/`fineco.proxy` shortcut, and
//! unknown capability strings fail to parse (so an accidental new tool is not
//! remotely callable by default).
//!
//! M4 has a single implicit identity, [`OWNER_AUTH_ID`] (the gateway is
//! loopback-only; verified Cloudflare Access identity arrives in M6). Both the
//! gateway and the worker load the **same** policy file read-only and enforce it
//! independently; no `auth_id` string is trusted inside an IPC message. The
//! `*.live.refresh` capabilities land in M8: they gate the owner-only live
//! refresh, enforced by the gateway, the refresh controller, and the dedicated
//! `refresh-control.sock` (never the cached-read socket).

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::SafeError;

/// The single authenticated identity in M4 (verified-identity mapping is M6).
pub const OWNER_AUTH_ID: &str = "owner";

/// A capability a tool/command requires. Serialized as the plan's dotted names;
/// an unknown name fails to deserialize (startup failure on unknown/wildcard
/// capabilities). Refresh capabilities are deliberately omitted until M8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum Capability {
    /// Public market reads (ETF list, third-party enrichment).
    #[serde(rename = "market.read")]
    MarketRead,
    /// Authenticated Fineco market-data reads (instrument search/details).
    #[serde(rename = "market.authenticated.read")]
    MarketAuthenticatedRead,
    /// Cached portfolio reads that expose owner-only absolute values.
    #[serde(rename = "portfolio.cached.full_read")]
    PortfolioCachedFullRead,
    /// Cached portfolio reads limited to shareable, non-absolute data.
    #[serde(rename = "portfolio.shareable.read")]
    PortfolioShareableRead,
    /// Cached order-monitor reads.
    #[serde(rename = "orders.cached.read")]
    OrdersCachedRead,
    /// Cached tax reads.
    #[serde(rename = "tax.cached.read")]
    TaxCachedRead,
    /// Live portfolio refresh (logs in to Fineco). Owner-only, gated by the
    /// refresh controller's cooldown/budget/circuit and the dedicated
    /// `refresh-control.sock`.
    #[serde(rename = "portfolio.live.refresh")]
    PortfolioLiveRefresh,
    /// Live order-monitor refresh (logs in to Fineco). Owner-only.
    #[serde(rename = "orders.live.refresh")]
    OrdersLiveRefresh,
    /// Live tax refresh (logs in to Fineco). Owner-only.
    #[serde(rename = "tax.live.refresh")]
    TaxLiveRefresh,
}

impl Capability {
    /// The stable dotted wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::MarketRead => "market.read",
            Capability::MarketAuthenticatedRead => "market.authenticated.read",
            Capability::PortfolioCachedFullRead => "portfolio.cached.full_read",
            Capability::PortfolioShareableRead => "portfolio.shareable.read",
            Capability::OrdersCachedRead => "orders.cached.read",
            Capability::TaxCachedRead => "tax.cached.read",
            Capability::PortfolioLiveRefresh => "portfolio.live.refresh",
            Capability::OrdersLiveRefresh => "orders.live.refresh",
            Capability::TaxLiveRefresh => "tax.live.refresh",
        }
    }

    /// The data class this capability reads, for the audit log — one of the
    /// plan's §"Data Classes" labels, never the payload. `MarketRead` covers two
    /// classes (the public ETF list `public_market` vs a third-party
    /// `external_enrichment` fetch); the gateway labels those two tools per-tool,
    /// so the capability-level default here is the public class.
    #[must_use]
    pub fn audit_data_class(self) -> &'static str {
        match self {
            Capability::MarketRead => "public_market",
            Capability::MarketAuthenticatedRead => "authenticated_market",
            Capability::PortfolioShareableRead => "shareable_private",
            Capability::PortfolioCachedFullRead
            | Capability::OrdersCachedRead
            | Capability::TaxCachedRead => "sensitive_private_cached",
            Capability::PortfolioLiveRefresh
            | Capability::OrdersLiveRefresh
            | Capability::TaxLiveRefresh => "credentialed_live",
        }
    }
}

/// One identity's granted capabilities.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthIdPolicy {
    #[serde(default)]
    pub capabilities: BTreeSet<Capability>,
}

/// The versioned capability policy: identity → granted capabilities.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Monotonic policy version. Gateway and worker must agree on it.
    pub version: u32,
    /// Per-identity capability grants.
    pub auth_ids: BTreeMap<String, AuthIdPolicy>,
}

impl Policy {
    /// Parse and validate a policy from its JSON document.
    ///
    /// Schema validation is structural: unknown top-level/identity fields and
    /// unknown capability names (including wildcard/generic ones like
    /// `private.read` or `fineco.proxy`) are rejected, and `version` must be
    /// non-zero. The offending text is never echoed.
    ///
    /// # Errors
    /// [`SafeError::invalid_request`] on malformed JSON, an unknown capability,
    /// an unknown field, or a zero version.
    pub fn from_json(json: &str) -> Result<Self, SafeError> {
        let policy: Policy = serde_json::from_str(json).map_err(|_| {
            SafeError::invalid_request(
                "policy is invalid (malformed, unknown field, or unknown capability).",
            )
        })?;
        if policy.version == 0 {
            return Err(SafeError::invalid_request(
                "policy version must be non-zero.",
            ));
        }
        Ok(policy)
    }

    /// Whether `auth_id` is granted `capability`. Unknown identity → `false`
    /// (fail closed).
    #[must_use]
    pub fn allows(&self, auth_id: &str, capability: Capability) -> bool {
        self.auth_ids
            .get(auth_id)
            .is_some_and(|grant| grant.capabilities.contains(&capability))
    }
}
