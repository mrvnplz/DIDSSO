# syntax=docker/dockerfile:1.7

FROM python:3.11-slim-bookworm AS builder

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
RUN pip install --no-cache-dir --upgrade pip uv-build \
    && pip install --no-cache-dir --requirement /build/requirements-didcomm.txt

FROM python:3.11-slim-bookworm AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data

COPY --from=builder /opt/venv /opt/venv
COPY firefox-extension/backend /app/firefox-extension/backend

WORKDIR /app/firefox-extension/backend
ENV PATH=/opt/venv/bin:${PATH} \
    PYTHONUNBUFFERED=1 \
    AUTHLIB_JOSE_MAX_CIPHERTEXT_SIZE=16777216 \
    DIDSSO_BIND_HOST=0.0.0.0 \
    DIDSSO_PORT=8765 \
    DIDSSO_DATA_DIR=/data

EXPOSE 8765
CMD ["python", "-u", "server.py"]
