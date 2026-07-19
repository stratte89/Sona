# Sona relay + auditor image. Build from the REPO ROOT:
#
#     docker build -f deploy/Dockerfile -t sona-relay .
#
# Multi-stage: the builder compiles the backend workspace; the runtime stage is a
# minimal Debian with just the two static-ish binaries and CA certs. The relay speaks
# plain HTTP on :5002 — TLS is the reverse proxy's job (see docker-compose.yml).

# Builder pinned to the exact toolchain from rust-toolchain.toml, sources at a fixed
# path, deps --locked, host paths remapped — so two independent builds of the same
# commit produce bit-identical binaries (see docs/REPRODUCIBLE_BUILDS.md and
# deploy/verify-reproducible.sh).
FROM rust:1.96.0-slim-trixie AS builder
WORKDIR /src
ENV RUSTFLAGS="--remap-path-prefix=/src=/build --remap-path-prefix=/usr/local/cargo=/cargo"
COPY Cargo.toml Cargo.lock rust-toolchain.toml deny.toml ./
COPY crates ./crates
RUN cargo build --release --locked -p server -p auditor

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /var/lib/sona --create-home sona
COPY --from=builder /src/target/release/server /usr/local/bin/sona-relay
COPY --from=builder /src/target/release/sona-auditor /usr/local/bin/sona-auditor
USER sona
WORKDIR /var/lib/sona
# The relay reads BIND (default 127.0.0.1:5002 — override for containers), KT_SIGNING_KEY,
# DB_PATH, STORAGE_KEY, PROD, ALLOWED_ORIGINS, RATE_SALT. See docs/DEPLOYMENT.md.
ENV BIND=0.0.0.0:5002
EXPOSE 5002
ENTRYPOINT ["/usr/local/bin/sona-relay"]
