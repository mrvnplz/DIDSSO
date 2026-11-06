# syntax=docker/dockerfile:1.7

FROM rust:1.95-bookworm AS risc0-builder

ARG RISC0_VERSION=3.0.6
ARG RISC0_RUST_VERSION=1.97.0
ARG RISC0_CPP_VERSION=2024.1.5

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        libssl-dev \
        ninja-build \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -LsSf https://risczero.com/install | bash
ENV PATH=/root/.risc0/bin:/root/.cargo/bin:${PATH}

RUN rzup install rust ${RISC0_RUST_VERSION} \
    && rzup install cpp ${RISC0_CPP_VERSION} \
    && rzup install cargo-risczero ${RISC0_VERSION} \
    && rzup install r0vm ${RISC0_VERSION}

WORKDIR /src/zk-risc0
COPY zk-risc0/Cargo.toml zk-risc0/Cargo.lock zk-risc0/rust-toolchain.toml ./
COPY zk-risc0/host ./host
COPY zk-risc0/methods ./methods
COPY zk-risc0/types ./types

RUN cargo build --release --locked --package host \
    && mkdir -p /artifacts \
    && install -m 0755 target/release/host /artifacts/credential-risc0 \
    && install -m 0755 "$(find /root/.risc0 -type f -name r0vm -print -quit)" /artifacts/r0vm

FROM python:3.11-slim-bookworm AS python-dependencies

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        git \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:${PATH}

COPY requirements-didcomm.txt /build/requirements-didcomm.txt
COPY IdP/didcomm-backend/requirements.txt /build/IdP/didcomm-backend/requirements.txt
WORKDIR /build/IdP/didcomm-backend
RUN pip install --no-cache-dir --upgrade pip uv-build \
    && pip install --no-cache-dir --requirement requirements.txt

FROM python:3.11-slim-bookworm AS common

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        libgcc-s1 \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/zk-risc0 /data

COPY --from=python-dependencies /opt/venv /opt/venv
COPY --from=risc0-builder /artifacts/credential-risc0 /usr/local/bin/credential-risc0
COPY sso_claims.py /app/sso_claims.py
COPY evaluation_trace.py /app/evaluation_trace.py
COPY zk-risc0/credential_risc0.py /app/zk-risc0/credential_risc0.py

ENV PATH=/opt/venv/bin:${PATH} \
    PYTHONPATH=/app:/app/zk-risc0 \
    PYTHONUNBUFFERED=1 \
    AUTHLIB_JOSE_MAX_CIPHERTEXT_SIZE=16777216 \
    DIDSSO_BIND_HOST=0.0.0.0 \
    DIDSSO_DATA_DIR=/data \
    DIDSSO_PROOF_BACKEND=risc0 \
    RISC0_CREDENTIAL_CLI=/usr/local/bin/credential-risc0

FROM common AS idp
COPY IdP/didcomm-backend /app/IdP/didcomm-backend
WORKDIR /app/IdP/didcomm-backend
ENV DIDSSO_PORT=8770
EXPOSE 8770
CMD ["python", "-u", "server.py"]

FROM common AS rp
COPY --from=risc0-builder /artifacts/r0vm /usr/local/bin/r0vm
COPY RP/didcomm-backend /app/RP/didcomm-backend
COPY RP/data/authorization_config.json /data/data/authorization_config.json
WORKDIR /app/RP/didcomm-backend
ENV DIDSSO_PORT=8771 \
    RISC0_PROVER=ipc \
    RISC0_SERVER_PATH=/usr/local/bin/r0vm
EXPOSE 8771
CMD ["python", "-u", "server.py"]
