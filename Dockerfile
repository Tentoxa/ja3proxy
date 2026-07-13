# syntax=docker/dockerfile:1.7

# Build stage
FROM rust:1.97.0-bookworm AS builder

WORKDIR /app

# Install build dependencies for BoringSSL
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    build-essential \
    golang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Compile dependencies once and retain BoringSSL artifacts across source changes.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release --locked && \
    rm -rf src

# Copy actual source code
COPY src ./src

# Reuse dependency artifacts, but force Cargo to replace the cached dummy binary
# with the real source before copying it outside the cache mount.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    touch src/main.rs && \
    cargo build --release --locked && \
    cp /app/target/release/ja3proxy /ja3proxy

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies (including curl for health checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false ja3proxy

# Copy binary from builder
COPY --from=builder /ja3proxy /usr/local/bin/ja3proxy

# Set ownership
RUN chown ja3proxy:ja3proxy /usr/local/bin/ja3proxy

# Switch to non-root user
USER ja3proxy

# Expose default port
EXPOSE 8080

# Environment variables with defaults
ENV PORT=8080 \
    LOG_LEVEL=info \
    MAX_CONCURRENT=100 \
    DEFAULT_TIMEOUT=30 \
    MAX_REQUEST_BODY_SIZE=10485760 \
    MAX_RESPONSE_BODY_SIZE=52428800 \
    SERVER_TIMEOUT=120 \
    ALLOW_PRIVATE_IPS=false

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Run the application
CMD ["ja3proxy"]
