# syntax=docker/dockerfile:1.7

FROM rust:1.95-bookworm AS builder
WORKDIR /build

COPY RP/Cargo.toml RP/Cargo.lock ./
COPY RP/src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/RP /usr/local/bin/rp-web
COPY RP/web ./web

ENV PORT=3002 \
    DIDSSO_BIND_HOST=0.0.0.0

EXPOSE 3002
CMD ["/usr/local/bin/rp-web"]
