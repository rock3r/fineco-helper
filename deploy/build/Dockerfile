# Reproducible release build of the `fineco-helper` binary for the LXC deploy
# target (x86_64 / Debian bookworm / glibc). Built for linux/amd64 even on an
# arm64 host (buildx emulation), so the binary matches a Debian 12 LXC.
# `deploy/build/build.sh` exports just the binary to deploy/build/dist/.
#
# The base image is pinned by manifest-list digest (not just the floating tag)
# so the toolchain can't silently change under us — `rust:1.96-slim-bookworm`
# resolved on 2026-06-05. The digest is the multi-arch index, so buildx still
# selects linux/amd64. Re-pin deliberately (with `docker buildx imagetools
# inspect rust:1.96-slim-bookworm`) when bumping the Rust toolchain.
FROM rust:1.96-slim-bookworm@sha256:b5f842fac1e3b4ff718a652a8e0173b62d9403ec826ef4998880b9347db30684 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin fineco-helper

# Export-only stage: buildx `--output type=local` extracts this stage's root,
# i.e. just the binary — no image is published.
FROM scratch AS export
COPY --from=build /src/target/release/fineco-helper /fineco-helper
