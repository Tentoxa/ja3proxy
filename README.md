# JA3Proxy

A high-performance HTTP proxy service written in Rust that emulates TLS fingerprints (JA3/JA4) of popular browsers to bypass bot detection systems.

> **Disclaimer:** This project was 100% vibe-coded due to time constraints. It works, but don't expect pristine code architecture or comprehensive test coverage.

## Features

- TLS fingerprint emulation (Chrome, Firefox, Safari, Edge, OkHttp)
- Upstream proxy support (HTTP, HTTPS, SOCKS5)
- SSRF protection (private IPs blocked by default)
- Concurrency limiting
- Environment-based configuration
- Docker support

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
  "tlsProfile": "chrome_131"
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

## Usage

### Local
```bash
cargo run --release
```

### Docker
```bash
docker build -t ja3proxy .
docker run -p 8080:8080 ja3proxy
```

## License

No license specified.
