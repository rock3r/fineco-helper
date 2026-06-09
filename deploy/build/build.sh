#!/usr/bin/env bash
# Build the `fineco-helper` release binary for the LXC target (x86_64 / Debian
# bookworm / glibc) and export it to deploy/build/dist/fineco-helper. Runs even
# on an arm64 host via buildx linux/amd64 emulation (slower, but reproducible and
# matched to a Debian 12 LXC). The deployed binary must come from this recipe,
# not an ad-hoc local build.
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

docker buildx build --platform linux/amd64 \
  -f deploy/build/Dockerfile --target export \
  --output type=local,dest=deploy/build/dist .

chmod +x deploy/build/dist/fineco-helper 2>/dev/null || true
echo "== built: deploy/build/dist/fineco-helper =="
file deploy/build/dist/fineco-helper 2>/dev/null || true
sha256sum deploy/build/dist/fineco-helper 2>/dev/null || shasum -a 256 deploy/build/dist/fineco-helper
