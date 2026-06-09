#!/usr/bin/env bash
# Local Docker E2E runner. Builds the harness image, brings up the mock Fineco +
# mock enrichment servers, the real product binary as the two-process boundary
# (store-server + loopback gateway), and the smoke driver, then exits with the
# smoke driver's status. The smoke driver fails closed on the first unreachable
# server, wrong canned response, or failed MCP gateway check.
set -uo pipefail
cd "$(dirname "$0")"

docker compose up --build --abort-on-container-exit --exit-code-from smoke
status=$?

# `-v` drops the shared socket/DB volume so every run starts from a fresh, empty
# store (the gateway smoke check expects "missing" freshness).
docker compose down --remove-orphans -v >/dev/null 2>&1 || true
exit "$status"
