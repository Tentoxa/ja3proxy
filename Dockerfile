# syntax=docker/dockerfile:1.7
FROM rust:1.97.0-bookworm@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073 AS builder
ARG TARGETARCH

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    build-essential \
    golang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Compile the real source once. A cached dummy main must never become the
# shipped executable; target caches remain isolated between architectures.
RUN --mount=type=cache,id=ja3proxy-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=ja3proxy-target-${TARGETARCH},target=/app/target,sharing=locked \
    cargo build --release --locked \
    && cp /app/target/release/ja3proxy /ja3proxy

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false ja3proxy

# Runtime code is root-owned; the service user can execute but not replace it.
COPY --from=builder --chmod=0555 /ja3proxy /usr/local/bin/ja3proxy
USER ja3proxy

EXPOSE 8080
ENV PORT=8080 \
    LOG_LEVEL=info \
    MAX_CONCURRENT=100 \
    DEFAULT_TIMEOUT=30 \
    MAX_REQUEST_BODY_SIZE=10485760 \
    MAX_RESPONSE_BODY_SIZE=52428800 \
    SERVER_TIMEOUT=120 \
    ALLOW_PRIVATE_IPS=false

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

CMD ["ja3proxy"]
