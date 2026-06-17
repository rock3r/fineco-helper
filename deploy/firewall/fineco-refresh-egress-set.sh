#!/usr/bin/env bash
#
# Populate the fineco-worker AND fineco-gateway egress nftables sets (see
# deploy/firewall/fineco-egress.nft). Run by fineco-refresh-egress-set.timer
# (OnBootSec + every 5 min, and after any nft reload).
#
# It resolves the worker's hostnames (the public Fineco API hosts; later the
# 1Password host), the gateway's hostnames (the public ETF CDN + the CF Access JWKS
# and enrichment hosts read from the gateway's OWN config), and the CT's configured
# DNS resolvers, and replaces all six allow sets in a SINGLE atomic `nft -f`
# transaction (`flush set` + `add element` per set). Atomic, so in-flight packets
# never see an empty set (no deny window); the per-element `timeout` is a dead-timer
# backstop (a stopped timer lets the sets expire rather than persist stale). It takes
# no worker/client input — only the owner's own config — and is the DNS trust
# boundary; each process's HTTPS client still enforces TLS as the second layer.
#
# Fails LOUDLY (no `|| true`): a malformed element or a missing set aborts the
# whole transaction and the unit reports failure (so the egress-deny path is never
# masked by an empty allow set). If resolution is incomplete (a transient resolver
# outage), it keeps the LAST-KNOWN-GOOD sets and exits nonzero instead of emptying
# them. Root-only (writes nftables). Install at
# /usr/local/libexec/fineco-refresh-egress-set.
set -euo pipefail

FAMILY="inet"
TABLE="fineco"
# The element timeout is a backstop only (refreshed every run by the 5-min timer);
# it just bounds how long a stale set lingers if the timer dies.
TIMEOUT="1h"

# Fixed public Fineco API hosts (from FinecoEndpoints::production) — the WORKER's
# egress targets under uid fineco-worker.
FINECO_HOSTS=(
    it.finecobank.com
    public-api.finecobank.com
    private-api.finecobank.com
    finecobank.com
)
# 1Password API host(s) — append to FINECO_HOSTS when the 1Password-backed
# credential path replaces the env file (plan "Credential Storage"). Fixed
# literal; never worker input.

# The GATEWAY's egress targets (uid fineco-gateway): the public ETF CDN (fixed) plus
# the CF Access JWKS host and the enrichment host, read from the gateway's OWN config
# at runtime. The enrichment host is config-only — NEVER hardcoded here or logged,
# only read from the env file and resolved to IPs.
GATEWAY_HOSTS=()
ACCESS_ENV="${FINECO_ACCESS_ENV:-/etc/fineco/access.env}"
ENRICHMENT_ENV="${FINECO_ENRICHMENT_ENV:-/etc/fineco/enrichment.env}"
# Extract the bare host from a `VAR=scheme://host[:port]/...` line in a (root-only)
# env file. Tolerates an optional surrounding quote (`VAR="https://…"`); `[a-z]*://`
# matches http/https portably (avoids GNU-only BRE `\?`); the capture stops at `:` so
# an explicit `:port` is dropped (getent resolves a bare host, not `host:port`).
host_from_url() { # var_name file
    sed -n "s|^$1=[\"']\\{0,1\\}[a-z]*://\\([^/:\"']*\\).*|\\1|p" "$2" 2>/dev/null | head -1
}
# Add a gateway target host parsed from a config URL. A PRESENT-but-unparseable value
# is a config error that would silently omit a critical target (e.g. no JWKS -> the
# gateway can't authenticate): flag it (gateway_parse_error) so the gateway set is
# left at last-known-good and the run exits nonzero — but does NOT abort here, so the
# INDEPENDENT worker/DNS refresh still happens. An ABSENT var is fine (Access disabled
# -> no JWKS; market off -> no enrichment; default ETF host); a BLANK value (`VAR=` /
# whitespace / `VAR=""`) is also "unset" (the gateway code falls back to its default).
gateway_parse_error=0
add_gateway_host() { # var_name file
    local h port
    h="$(host_from_url "$1" "$2")"
    if [[ -n "$h" ]]; then
        # The gateway egress allowlist is HTTPS/443 only. If the URL pins a NON-443
        # port, the host would resolve + be allowlisted but the gateway's connect to
        # that port would be denied (a silent break) — fail closed loudly instead.
        port="$(sed -n "s|^$1=[\"']\\{0,1\\}[a-z]*://[^/:\"']*:\\([0-9]\\{1,\\}\\).*|\\1|p" "$2" 2>/dev/null | head -1)"
        if [[ -n "$port" && "$port" != "443" ]]; then
            echo "fineco-refresh-egress-set: $1 pins port $port; the gateway egress allowlist is HTTPS/443 only — keeping the gateway set at last-known-good" >&2
            gateway_parse_error=1
            return
        fi
        GATEWAY_HOSTS+=("$h")
    elif grep -qE "^$1=[\"']?[^[:space:]\"']" "$2" 2>/dev/null; then
        echo "fineco-refresh-egress-set: $1 is set but its host could not be parsed — keeping the gateway set at last-known-good" >&2
        gateway_parse_error=1
    fi
}
# JWKS host — only when Cloudflare Access is configured (no Access -> no JWKS fetch).
add_gateway_host FINECO_ACCESS_JWKS_URL "$ACCESS_ENV"
# Market targets (the enrichment host + the ETF list host) ONLY when the market pair is
# configured — without it GatewayConfig::build_market returns None and the gateway never
# calls those paths, so they must not be allowlisted.
if grep -qE "^FINECO_ENRICHMENT_BASE=[\"']?[^[:space:]\"']" "$ENRICHMENT_ENV" 2>/dev/null; then
    add_gateway_host FINECO_ENRICHMENT_BASE "$ENRICHMENT_ENV"
    # The ETF list endpoint: an explicit FINECO_ETF_URL override, else the default host.
    if grep -qE "^FINECO_ETF_URL=[\"']?[^[:space:]\"']" "$ENRICHMENT_ENV" 2>/dev/null; then
        add_gateway_host FINECO_ETF_URL "$ENRICHMENT_ENV"
    else
        GATEWAY_HOSTS+=(images.finecobank.com)
    fi
fi
# The ETF reference-data enrichment host — config-only, NEVER hardcoded here — is
# allowlisted only when its own pair is configured (GatewayConfig layers it onto the
# market client; without it the gateway never calls that host).
if grep -qE "^FINECO_ETF_ENRICHMENT_BASE=[\"']?[^[:space:]\"']" "$ENRICHMENT_ENV" 2>/dev/null; then
    add_gateway_host FINECO_ETF_ENRICHMENT_BASE "$ENRICHMENT_ENV"
fi

resolve4() { getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u; }
resolve6() { getent ahostsv6 "$1" 2>/dev/null | awk '{print $1}' | sort -u; }

worker4=() worker6=() gateway4=() gateway6=() dns4=() dns6=()
for host in "${FINECO_HOSTS[@]}"; do
    while read -r a; do [[ -n "$a" ]] && worker4+=("$a"); done < <(resolve4 "$host")
    while read -r a; do [[ -n "$a" ]] && worker6+=("$a"); done < <(resolve6 "$host")
done
gateway_incomplete=0
for host in "${GATEWAY_HOSTS[@]}"; do
    before=$((${#gateway4[@]} + ${#gateway6[@]}))
    while read -r a; do [[ -n "$a" ]] && gateway4+=("$a"); done < <(resolve4 "$host")
    while read -r a; do [[ -n "$a" ]] && gateway6+=("$a"); done < <(resolve6 "$host")
    # EVERY gateway host must resolve to >=1 address: a partial resolution (e.g. the
    # JWKS host fails while the ETF host succeeds) would otherwise flush the set with
    # the partial result, dropping a CRITICAL target (no JWKS -> the gateway can't
    # authenticate). On any per-host miss, keep last-known-good (the guard below).
    (((${#gateway4[@]} + ${#gateway6[@]}) == before)) && gateway_incomplete=1
done
# Pin the worker's + gateway's DNS to the CT's configured resolvers (not "any").
while read -r r; do
    case "$r" in
    *:*) dns6+=("$r") ;;
    ?*) dns4+=("$r") ;;
    esac
done < <(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | sort -u)

# Each group (worker+DNS vs gateway) is refreshed INDEPENDENTLY: a gateway-host DNS
# failure must NOT block the worker/DNS refresh (their elements carry a 1h timeout and
# would otherwise expire and break a working worker allowlist), and vice-versa. Keep
# last-known-good for a failed group rather than emptying its sets. The run still exits
# nonzero (below) so a failure is visible.
worker_dns_ok=1
((${#worker4[@]} + ${#worker6[@]} == 0)) && worker_dns_ok=0
((${#dns4[@]} + ${#dns6[@]} == 0)) && worker_dns_ok=0
gateway_ok=1
# A deployment with NO gateway targets configured (no Access -> no JWKS, market off ->
# no enrichment/ETF) legitimately makes no gateway egress, so an empty gateway set is
# fine — only REQUIRE resolution when targets are actually configured.
if ((${#GATEWAY_HOSTS[@]} > 0)); then
    ((${#gateway4[@]} + ${#gateway6[@]} == 0)) && gateway_ok=0
    ((gateway_incomplete)) && gateway_ok=0
fi
((gateway_parse_error)) && gateway_ok=0

# Emit `flush set` + `add element` lines for one set, then apply all six as one
# atomic transaction via `nft -f -`.
emit_set() { # set_name addr...
    local set="$1"
    shift
    # A family that resolved NO addresses is left untouched (last-known-good): we
    # neither flush nor repopulate it, so a transient PER-FAMILY resolver gap (e.g.
    # IPv6 only) cannot empty a working set. The total-failure guard above already
    # fails the whole run if a kind's BOTH families come back empty; the per-element
    # timeout still ages out a set whose host genuinely dropped that family.
    (($# == 0)) && return 0
    printf 'flush set %s %s %s\n' "$FAMILY" "$TABLE" "$set"
    local a
    for a in "$@"; do
        printf 'add element %s %s %s { %s timeout %s }\n' "$FAMILY" "$TABLE" "$set" "$a" "$TIMEOUT"
    done
}
# Emit only the groups that resolved cleanly, in ONE atomic transaction; a failed
# group is left untouched (last-known-good).
{
    if ((worker_dns_ok)); then
        emit_set fineco_worker_v4 "${worker4[@]}"
        emit_set fineco_worker_v6 "${worker6[@]}"
        emit_set fineco_dns_v4 "${dns4[@]}"
        emit_set fineco_dns_v6 "${dns6[@]}"
    fi
    if ((gateway_ok)); then
        if ((${#GATEWAY_HOSTS[@]} == 0)); then
            # No gateway targets configured (Access + market both off, or disabled after
            # a prior authenticated setup): the gateway needs no egress, so FLUSH the sets
            # to empty rather than leaving stale elements from the previous config alive
            # (emit_set with no addresses would skip the flush -> last-known-good lingers).
            printf 'flush set %s %s fineco_gateway_v4\n' "$FAMILY" "$TABLE"
            printf 'flush set %s %s fineco_gateway_v6\n' "$FAMILY" "$TABLE"
        else
            emit_set fineco_gateway_v4 "${gateway4[@]}"
            emit_set fineco_gateway_v6 "${gateway6[@]}"
        fi
    fi
} | nft -f -

# A failed group keeps last-known-good but the run exits nonzero so the failure is
# visible (a green unit must never mask an unresolved/expiring allowlist).
if ((!worker_dns_ok)) || ((!gateway_ok)); then
    echo "fineco-refresh-egress-set: incomplete resolution (worker/dns=$worker_dns_ok gateway=$gateway_ok); kept last-known-good for the affected group(s)" >&2
    exit 1
fi
