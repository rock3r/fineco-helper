# Cloudflare Access spike (owner-supervised)

Runs the **real product gateway behind a real Cloudflare Tunnel + Access** to
validate the Cloudflare Access path end-to-end against the design spec's exit
criteria. This is **not** a CI gate — it touches a real Cloudflare account and is
driven by the owner.

Target client = **headless/programmatic**, so auth = **service token**
(`CF-Access-Client-Id` / `CF-Access-Client-Secret`). A service-token JWT has **no
`email` claim**, so `FINECO_OWNER_EMAIL` is left **unset** (an email pin would
fail-closed against that client). Instead pin the service token's **`common_name`**
(its Client ID) via `FINECO_ACCESS_OWNER_COMMON_NAME` — the gateway requires at least
one identity pin, and `common_name` is the right one for a headless client.

## Topology

```
your MCP client ──HTTPS──▶ Cloudflare edge (Access: validates service token)
                                    │  injects Cf-Access-Jwt-Assertion
                                    ▼
                          cloudflared (Tunnel connector)
                                    │  shares the gateway's netns
                                    ▼
                          gateway  127.0.0.1:8799   ← loopback only, never exposed
                                    │  verifies iss/aud/exp/RS256 vs real JWKS
                                    ▼  (Unix socket, shared volume)
                          store-server  (empty SQLite, cached reads)
```

`cloudflared` shares the gateway's network namespace, so it reaches the loopback
bind exactly as on the real LXC host — the origin has **no published port**.

## What you do in the Cloudflare dashboard

1. **Tunnel** — Networks → Tunnels → Create. Copy the **connector token** (the
   long string after `--token` in the Docker install command; secret →
   `TUNNEL_TOKEN`). The wizard won't enable the routing step until it "detects a
   connection", so run the dashboard's `docker run cloudflare/cloudflared:latest
   tunnel --no-autoupdate run --token …` **once** to flip it to *connected*, add a
   **Public hostname** routing `https://<your-host>` → service `HTTP`
   `http://127.0.0.1:8799`, then **Ctrl-C that container** — it was only to advance
   the wizard. The real run uses `./run-spike.sh`, which starts the connector in
   the gateway's netns (the standalone one can't reach the loopback origin).
   **Never run the standalone connector and `run-spike.sh` at the same time** — two
   connectors on one token become HA replicas and the standalone one 502s.
2. **Access application** — Access → Applications → Add (Self-hosted), protecting
   `<your-host>`. Copy its **Application Audience (AUD) tag** (→ `FINECO_ACCESS_AUDIENCE`).
3. **Service token** — Access → Service Auth → Create. Copy **Client ID** and
   **Client Secret** (secrets → `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET`).
4. **Policy** — on the app, add a policy with action **Service Auth** that allows
   that service token. (Add a separate Allow-your-email policy only if you also
   want interactive SSO.)
5. **Team domain** — your `https://<team>.cloudflareaccess.com`
   (→ `FINECO_ACCESS_ISSUER`, and `…/cdn-cgi/access/certs` → `FINECO_ACCESS_JWKS_URL`).

### Required: rewrite the origin Host header to loopback

The gateway keeps rmcp's **loopback-only `Host` validation** (DNS-rebinding
defense). cloudflared forwards the *public* `Host` (e.g. `mcp.example.com`) by
default, which the gateway rejects with `Forbidden: Host header is not allowed`.
On the tunnel's public-hostname route, open **Origin request and connection
settings → HTTP Settings → HTTP Host Header** and set it to the gateway's
loopback bind (`127.0.0.1:8799`). cloudflared then presents a loopback Host and
the gateway accepts it; the Access JWT remains the real auth gate. (Confirmed in
the spike — without this, the full-token path 200→403s at the origin.)

## Configure (secrets stay out of git and out of chat)

    cp cf-spike.env.example cf-spike.env
    # edit cf-spike.env with the values above

`cf-spike.env` is gitignored. The non-secret Access config (team domain, AUD,
JWKS URL) is safe to share; the **`TUNNEL_TOKEN` and service-token secret are
credentials** — never commit them, never paste them into chat or logs.

## Run

    ./run-spike.sh        # builds the image, brings up store-server + gateway + cloudflared; Ctrl-C to stop

The gateway fetches the **real team JWKS at startup and fails closed** if it
can't — a clean boot already proves live JWKS reachability. In another terminal:

    ./verify-spike.sh     # runs the scriptable spike checks

## Validate the DEPLOYED gateway (ongoing remote-MCP regression)

`validate-mcp.sh` drives a full MCP Streamable-HTTP session against a **live**
deployment through the tunnel + Access — the real owner path — and confirms the
whole tool surface works:

    ./validate-mcp.sh path/to/cf-spike.env

It runs `initialize` → `tools/list` (asserts the remote set is **exactly** the
gateway's registered tools — a missing tool or an unexpected extra both fail) →
`tools/call` for every **read** tool that takes no required arguments (the two that
need a specific instrument id — `position_history`, `enrichment` — are verified via
`tools/list`), and prints `ALL_GREEN` / exits **non-zero** on any failure.
**Privacy-safe:** it prints only tool **names + ok/error**,
never a value or payload; the service-token secret is fed to curl via stdin
(`--config -`), never argv. The three `private_*_refresh_live_sensitive` tools are
listed but **not fired** (each is a real credentialed Fineco login, subject to
lockout). The same `cf-spike.env` (URL + service token) the spike uses drives it;
nothing host-specific is baked in. The expected-tool list is kept in sync with the
gateway by `crates/fineco-helper/tests/mcp_validator.rs`. Needs `curl` + `jq`.

## Exit criteria → how each is covered

| Plan requirement | Covered by |
| --- | --- |
| Access JWT verified (issuer/audience/expiry/signature via JWKS) | gateway boot (JWKS fetch) + verify Check A |
| Owner identity → fixed `auth_id: owner` | Check A returns a working MCP session (service-token identity mapped to owner) |
| Spoofed `Cf-Access-*` without a valid JWT fails | verify Check C (forged JWT straight at the origin → 401) |
| Unauthenticated request blocked | verify Check B (no creds → edge-blocked 401/403/302) |
| `Origin`/`Host` validation (M4 deferral) | rmcp 403 gate unit-covered in `crates/fineco-gateway/tests/origin.rs`; verify Check D only confirms a no-JWT + bad-Host probe is rejected (401) by the access layer (which short-circuits before the 403 check) |
| Direct origin unreachable from LAN/WAN | **manual** — no published port locally; confirm from another network |
| Tested revocation path | **manual** — revoke the service token, re-run Check A → no longer 200 |
| Service-token vs SSO identified | **decided**: headless client → service token (this doc) |

Record the outcomes (and the SSO-vs-service-token determination) in your own
private notes; do **not** write any real hostnames/tokens there — the
enrichment/host-style secrets rule applies to the Cloudflare values too.
