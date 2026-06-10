# Runtime image for the docker-compose topology. The binary is built separately
# (deploy/build/build.sh → deploy/build/dist/fineco-helper, x86_64/glibc); this
# just wraps it in a minimal base with TLS roots and a non-root user. Build from
# the REPO ROOT so the COPY path resolves:
#   deploy/build/build.sh
#   docker build -f deploy/docker/Dockerfile -t fineco-helper:latest .
# Digest-pinned (like the release-build image) so the base under the
# credential-holding worker can't drift; bump deliberately, not by tag movement.
FROM debian:12-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin fineco \
    # Pre-own the socket + data mount points so a FRESH named volume mounted here
    # inherits uid 10001 (Docker copies the image dir's ownership into an empty
    # volume) and the non-root process can write to it.
    && mkdir -p /run/ipc /run/live /var/lib/fineco-helper \
    && chown 10001:10001 /run/ipc /run/live /var/lib/fineco-helper \
    && rm -rf /var/lib/apt/lists/*
COPY deploy/build/dist/fineco-helper /usr/local/bin/fineco-helper
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/fineco-helper"]
