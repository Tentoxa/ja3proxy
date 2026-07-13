# JA3Proxy

A high-performance Rust HTTP service that forwards requests with reproducible
browser TLS, HTTP/2, JA3, and JA4 fingerprints.

The transport is pinned to the compatible `wreq 6.0.0-rc.29` and
`wreq-util 3.0.0-rc.14` release pair. The minimum supported Rust version is
1.86.

## Features

- Dynamic TLS profile registry for Chrome, Firefox, Safari, Edge, and OkHttp
- Upstream proxy support (HTTP, HTTPS, and SOCKS5)
- Manual redirect handling so callers retain protocol state
- Incremental response-size enforcement
- SSRF protection with private IPs blocked by default
- Request-body, timeout, and concurrency limits
- Graceful shutdown, structured tracing, and Docker health checks

## API

### Health Check
```
GET /health
```
Returns service status and available TLS profiles.

### Execute Request
```
POST /request
```

**Request Body:**
```json
{
  "url": "https://example.com",
  "method": "GET",
  "headers": {},
  "body": null,
  "proxy": "socks5://127.0.0.1:1080",
  "timeout": 30,
  "tlsProfile": "chrome_120"
}
```

**Response:**
```json
{
  "status": 200,
  "headers": {},
  "body": "...",
  "bodyBase64": "...",
  "elapsed": 123
}
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 8080 | Server port |
| `LOG_LEVEL` | info | Logging level |
| `MAX_CONCURRENT` | 100 | Maximum concurrent requests |
| `DEFAULT_TIMEOUT` | 30 | Default request timeout (seconds) |
| `ALLOW_PRIVATE_IPS` | false | Allow requests to private IP ranges |
| `MAX_REQUEST_BODY_SIZE` | 10485760 | Maximum request body size in bytes |
| `MAX_RESPONSE_BODY_SIZE` | 52428800 | Maximum response body size in bytes |
| `SERVER_TIMEOUT` | 120 | End-to-end server request timeout in seconds |

## Usage

### Local
```bash
cargo run --locked
```

### Quality checks
```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

### Docker
```bash
docker build -t ja3proxy .
docker run -p 8080:8080 ja3proxy
```

## License

No license specified.
