#!/usr/bin/env bash
#
# Comprehensive remote-MCP validation against a DEPLOYED gateway, through the
# Cloudflare tunnel + Access (the real owner path). Drives a full MCP
# Streamable-HTTP session: initialize -> tools/list (asserts the remote tool set is
# EXACTLY the gateway's registered tools — missing or extra both fail) -> tools/call
# for every read tool that takes no required arguments. The two read tools needing a
# specific instrument id (position_history, enrichment) are verified via tools/list.
# A privacy-safe ongoing regression check for the live deployment; exits non-zero on
# any failure.
#
# Usage:   e2e/spike/validate-mcp.sh path/to/cf-spike.env
# The env file (see cf-spike.env.example) provides SPIKE_PUBLIC_URL (the tunnel
# hostname) + CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET (the Access service
# token). Nothing host-specific is baked into this script.
#
# PRIVACY-SAFE: prints only tool NAMES + per-tool ok/error — never a value, count,
# or payload body. The CF service-token secret is fed via `curl --config -`
# (stdin), so it never appears in argv / a process listing. The three live-refresh
# tools are listed but NOT fired (each is a real credentialed Fineco login subject
# to lockout). Requires curl + jq. Exits non-zero (SOME_FAILED) on any failure.
set -uo pipefail

ENVFILE="${1:?usage: validate-mcp.sh path/to/cf-spike.env}"
# Source WITHOUT `set -a`: the CF service token must stay a shell-local variable and
# never be EXPORTED into curl's environment (where a same-user/root observer could read
# it from /proc/<pid>/environ). curl receives the credentials only via `--config -` on
# stdin below — never argv, never env.
# shellcheck disable=SC1090
source "$ENVFILE"
# Belt-and-suspenders: if the CALLER already exported these (a profile / a prior
# `set -a; source`), plain sourcing preserves the export attribute, so strip it
# explicitly — otherwise every curl child would still inherit the token via environ.
export -n CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET 2>/dev/null || true
URL="${SPIKE_PUBLIC_URL:?SPIKE_PUBLIC_URL not set}"
ACCEPT='application/json, text/event-stream'
CFG="$(printf 'header = "CF-Access-Client-Id: %s"\nheader = "CF-Access-Client-Secret: %s"\n' \
    "$CF_ACCESS_CLIENT_ID" "$CF_ACCESS_CLIENT_SECRET")"

pass=0 fail=0
ok() {
    echo "  PASS: $1"
    pass=$((pass + 1))
}
no() {
    echo "  FAIL: $1"
    fail=$((fail + 1))
}

# POST a JSON-RPC body; echo the SSE `data:` JSON line(s). Always sends the CF
# headers (+ the session header when set). Never prints the body itself.
session=""
mcp() {
    local extra=()
    [ -n "$session" ] && extra=(-H "mcp-session-id: $session")
    printf '%s' "$CFG" | curl -sS --max-time 35 -X POST "$URL" --config - \
        -H "Content-Type: application/json" -H "Accept: $ACCEPT" "${extra[@]}" \
        --data "$1" 2>/dev/null | tr -d '\r' | sed -n 's/^data: //p'
}

echo "== initialize (remote MCP + Cloudflare Access) =="
hdr="$(mktemp)"
printf '%s' "$CFG" | curl -sS --max-time 25 -D "$hdr" -o /dev/null -X POST "$URL" --config - \
    -H "Content-Type: application/json" -H "Accept: $ACCEPT" \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"validate","version":"0"}}}' 2>/dev/null
session="$(tr -d '\r' <"$hdr" | sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: //p' | head -1)"
rm -f "$hdr"
if [ -n "$session" ]; then
    ok "initialize -> 200 + session ${session:0:8}…"
else
    no "initialize -> no mcp-session-id (Access/tunnel/gateway?)"
    echo "ABORT"
    exit 1
fi
mcp '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null

echo "== tools/list (full remote tool surface) =="
tools_json="$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')"
names="$(printf '%s' "$tools_json" | jq -r '.result.tools[].name' 2>/dev/null | sort)"
echo "$names" | sed 's/^/    /'
n="$(printf '%s\n' "$names" | grep -c .)"
# The full registered tool surface (crates/fineco-gateway/src/lib.rs). The guard
# test mcp_validator_expected_tools_match_the_gateway keeps this list in sync.
EXPECTED="market_get_asset_details market_get_indices market_get_zero_commission_etfs market_search_asset movements_get_latest orders_get_latest_monitor portfolio_get_allocation_history portfolio_get_freshness portfolio_get_history portfolio_get_latest_full_snapshot portfolio_get_latest_shareable_report portfolio_get_latest_snapshot_summary portfolio_get_position_history private_movements_refresh_live_sensitive private_orders_refresh_live_sensitive private_portfolio_refresh_live_sensitive private_tax_refresh_live_sensitive tax_get_latest_carry_forward tax_get_latest_minus_by_year"
# The remote set must EXACTLY equal EXPECTED — a MISSING tool is a regression, and
# an EXTRA tool (e.g. a mutation/proxy tool that slipped in) is a security one.
missing="" extra=""
for t in $EXPECTED; do printf '%s\n' "$names" | grep -qx "$t" || missing="$missing$t "; done
for t in $names; do case " $EXPECTED " in *" $t "*) ;; *) extra="$extra$t " ;; esac; done
if [ -z "$missing$extra" ]; then
    ok "exactly the expected tools exposed (got $n)"
else
    no "tool-surface mismatch — missing:[${missing:-none}] extra:[${extra:-none}]"
fi

# Call a READ tool; report ok/error ONLY (never the body). isError/error => fail.
call() { # $1=name $2=args-json
    local r err
    r="$(mcp "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}")"
    err="$(printf '%s' "$r" | jq -r 'if .error then "rpc:"+(.error.message//"err") elif (.result.isError==true) then "tool-error" else empty end' 2>/dev/null)"
    if [ -z "$err" ] && printf '%s' "$r" | jq -e '.result' >/dev/null 2>&1; then ok "$1 -> ok"; else no "$1 -> ${err:-no-result}"; fi
}

echo "== cached read tools (real data; ok/error only, no values) =="
call portfolio_get_freshness '{}'
call portfolio_get_latest_shareable_report '{}'
call portfolio_get_latest_snapshot_summary '{}'
call portfolio_get_latest_full_snapshot '{}'
call portfolio_get_allocation_history '{}'
call portfolio_get_history '{"limit":10}'
call orders_get_latest_monitor '{}'
call tax_get_latest_carry_forward '{}'
call tax_get_latest_minus_by_year '{}'

echo "== market tools =="
call market_get_zero_commission_etfs '{}'

# These read tools need a specific instrument identifier or perform authenticated
# Fineco market reads, so they are verified via tools/list, not tools/call (their
# call paths are unit + e2e tested).
echo "== read tools exposed but not called =="
for t in portfolio_get_position_history market_search_asset market_get_asset_details; do
    printf '%s\n' "$names" | grep -qx "$t" && ok "$t exposed (not called)" || no "$t missing"
done

echo "== live-refresh tools: exposed but NOT fired (credentialed login + lockout) =="
for t in private_portfolio_refresh_live_sensitive private_orders_refresh_live_sensitive private_tax_refresh_live_sensitive; do
    printf '%s\n' "$names" | grep -qx "$t" && ok "$t exposed (not fired)" || no "$t missing"
done

echo
echo "VALIDATION SUMMARY: $pass passed, $fail failed"
# Exit non-zero on any failure so CI / a wrapper can detect it.
if [ "$fail" -eq 0 ]; then echo "ALL_GREEN"; else echo "SOME_FAILED"; exit 1; fi
