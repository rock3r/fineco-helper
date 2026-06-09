#!/usr/bin/env bash
# Cloudflare Access spike — verification probes. Run AFTER ./run-spike.sh
# is up (in another terminal). Exercises the scriptable subset of the spike's
# exit criteria against the REAL Cloudflare Access ingress and the running
# gateway. The two that need an external vantage point or a dashboard change
# (full WAN-unreachability, revocation) are guided as manual steps at the end.
#
# Reads config + the service-token credential from cf-spike.env. Nothing here is
# printed in a way that echoes the secret; keep cf-spike.env gitignored.
set -uo pipefail
cd "$(dirname "$0")"

[[ -f cf-spike.env ]] || { echo "cf-spike.env not found (see README.md)." >&2; exit 1; }
# Source WITHOUT `set -a`: the CF service token must stay a shell-local var and never be
# EXPORTED into the env of curl/docker children (readable via /proc/<pid>/environ). curl
# gets the credentials only via `--config -` on stdin below; `export -n` also clears any
# inherited export attribute if the caller already exported them.
# shellcheck disable=SC1091
source cf-spike.env
export -n CF_ACCESS_CLIENT_ID CF_ACCESS_CLIENT_SECRET 2>/dev/null || true

GW_CONTAINER="fineco-helper-cf-spike-gateway-1"
# A minimal MCP initialize body — enough to get a real 200 + session back.
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"spike","version":"0"}}}'
ACCEPT='application/json, text/event-stream'
pass=0 fail=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
no()  { echo "  FAIL: $1"; fail=$((fail+1)); }

echo "== Check A: valid service token through Cloudflare Access -> 200 =="
# Proves: headless client sends CF-Access-Client-Id/-Secret -> CF validates the
# service token -> injects Cf-Access-Jwt-Assertion -> gateway verifies -> MCP works.
# The service-token headers are fed via `curl --config -` on stdin (printf is a
# shell builtin, so it spawns no process whose argv holds the value) — the secret
# never appears in curl's argv / a process listing.
code=$(printf 'header = "CF-Access-Client-Id: %s"\nheader = "CF-Access-Client-Secret: %s"\n' \
    "$CF_ACCESS_CLIENT_ID" "$CF_ACCESS_CLIENT_SECRET" \
  | curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -X POST "$SPIKE_PUBLIC_URL" \
      --config - -H "Content-Type: application/json" -H "Accept: ${ACCEPT}" \
      --data "$INIT" 2>/dev/null)
[[ "$code" == "200" ]] && ok "valid token -> 200" || no "valid token -> got $code (want 200)"

echo "== Check B: NO credentials -> blocked at the Cloudflare edge =="
# Proves CF Access blocks unauthenticated callers before the origin (302 to login
# for SSO policies, or 403 for a service-token-only policy). The origin never sees it.
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$SPIKE_PUBLIC_URL" \
  -H "Content-Type: application/json" -H "Accept: ${ACCEPT}" --data "$INIT" 2>/dev/null)
[[ "$code" =~ ^(401|403|302)$ ]] && ok "no creds -> $code (edge-blocked)" || no "no creds -> got $code (want 401/403/302)"

echo "== Check C: spoofed Cf-Access-Jwt-Assertion straight at the origin -> 401 =="
# Bypass CF entirely: join the gateway's netns and forge the header. The gateway
# must reject a bogus JWT (defence in depth even if something reached the origin).
code=$(docker run --rm --network "container:${GW_CONTAINER}" curlimages/curl:8.11.1 \
  -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:8799/" \
  -H "Cf-Access-Jwt-Assertion: not.a.valid.jwt" \
  -H "Content-Type: application/json" -H "Accept: ${ACCEPT}" --data "$INIT" 2>/dev/null)
[[ "$code" == "401" ]] && ok "spoofed JWT -> 401" || no "spoofed JWT -> got $code (want 401)"

echo "== Check D: no-JWT request at the origin (bad Host) -> rejected 401 =="
# NOTE (why 401, not 403): with Access ENABLED, gateway_router wraps the rmcp
# fallback with `enforce_access`, which rejects any request lacking a valid
# Cf-Access-Jwt-Assertion with 401 *before* rmcp's Host/Origin (403) check runs.
# So a no-JWT probe with a spoofed Host can only demonstrate the access layer
# rejecting it (401) — the security property at the origin (nothing without a
# valid JWT passes, even with a forged Host). The rmcp Host/Origin 403
# DNS-rebinding gate itself is exercised directly (no access layer) by the
# `origin.rs` unit tests; reproducing it here would require minting a real
# CF-issued JWT, which this script can't do. Hence Origin/Host 403 is NOT
# asserted end-to-end here — see crates/fineco-gateway/tests/origin.rs.
code=$(docker run --rm --network "container:${GW_CONTAINER}" curlimages/curl:8.11.1 \
  -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:8799/" \
  -H "Host: evil.example" \
  -H "Content-Type: application/json" -H "Accept: ${ACCEPT}" --data "$INIT" 2>/dev/null)
[[ "$code" == "401" ]] && ok "no-JWT + bad Host -> 401 (rejected by access layer)" \
  || no "no-JWT + bad Host -> got $code (want 401)"

echo
echo "Automated: ${pass} passed, ${fail} failed."
echo "MANUAL (cannot be scripted from this host):"
echo "  - Direct-origin unreachable from LAN/WAN: from a DIFFERENT machine/network,"
echo "    confirm there is no route to the origin (no public port; only the Tunnel"
echo "    hostname resolves, and only to the Cloudflare edge)."
echo "  - Revocation: in the dashboard revoke the service token (or remove its"
echo "    policy), wait for propagation, then re-run Check A -> must STOP being 200."
[[ "$fail" -eq 0 ]] || exit 1
