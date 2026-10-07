# syntax=docker/dockerfile:1.7

FROM rust:1.95-bookworm AS builder
WORKDIR /build

COPY IdP/Cargo.toml IdP/Cargo.lock ./
COPY IdP/src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/id_p /usr/local/bin/idp-web
COPY IdP/web ./web

RUN mkdir -p /data
ENV PORT=3001 \
    DIDSSO_BIND_HOST=0.0.0.0 \
    DIDSSO_DATA_DIR=/data

EXPOSE 3001
CMD ["/usr/local/bin/idp-web"]
