# E2E harness image: builds the std-only mock servers, the smoke driver, and the
# real product binary with the pinned toolchain, then ships them in a minimal
# runtime image. One image serves every compose role (mock-fineco /
# mock-enrichment / smoke / fineco-helper gateway+store-server), selected by the
# compose `command`.

# --- build stage -----------------------------------------------------------
FROM rust:1.96-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release \
    --bin mock-fineco \
    --bin mock-enrichment \
    --bin smoke \
    --bin fineco-helper

# --- runtime stage ---------------------------------------------------------
FROM debian:bookworm-slim AS runtime
COPY --from=build /src/target/release/mock-fineco /usr/local/bin/mock-fineco
COPY --from=build /src/target/release/mock-enrichment /usr/local/bin/mock-enrichment
COPY --from=build /src/target/release/smoke /usr/local/bin/smoke
COPY --from=build /src/target/release/fineco-helper /usr/local/bin/fineco-helper
# The E2E capability policy (grants the owner shareable + market reads, but NOT
# full_read — so the smoke driver can prove both a granted and a denied tool).
COPY e2e/fixtures/policy.json /etc/fineco/policy.json
# Shared runtime dir for the snapshot-query socket + the (empty) store DB; owned
# by the unprivileged user so the gateway/store-server roles can write it when
# the named volume inherits these permissions.
RUN mkdir -p /run/fineco && chown nobody:nogroup /run/fineco
# Unprivileged by default; the servers listen on high ports / loopback and the
# Unix socket, and need no root.
USER nobody
