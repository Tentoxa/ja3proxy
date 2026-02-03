# Build stage
FROM rust:latest AS builder

WORKDIR /app

# Install build dependencies for BoringSSL
RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    golang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create dummy source to build dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source code
COPY src ./src

# Build the application
RUN touch src/main.rs && \
    cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies (including curl for health checks)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false ja3proxy

# Copy binary from builder
COPY --from=builder /app/target/release/ja3proxy /usr/local/bin/ja3proxy

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
