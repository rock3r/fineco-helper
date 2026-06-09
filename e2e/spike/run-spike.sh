#!/usr/bin/env bash
# Owner-supervised Cloudflare Access spike runner. Brings up the real
# product binary (store-server + loopback gateway with Access ENABLED against the
# real team JWKS) plus a cloudflared Tunnel, all configured from the gitignored
# cf-spike.env. Unlike e2e/run.sh this is NOT a CI gate and does NOT exit on its
# own — it stays up so you can drive the real MCP client through Cloudflare
# Access. Press Ctrl-C to tear it down.
set -uo pipefail
cd "$(dirname "$0")"

if [[ ! -f cf-spike.env ]]; then
  echo "cf-spike.env not found — copy cf-spike.env.example to cf-spike.env and" >&2
  echo "fill it in from your Cloudflare dashboard (see README.md). Never commit it." >&2
  exit 1
fi

cleanup() {
  docker compose --env-file cf-spike.env -f docker-compose.cf-spike.yml \
    down --remove-orphans -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose --env-file cf-spike.env -f docker-compose.cf-spike.yml up --build
