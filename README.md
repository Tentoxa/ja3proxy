# ja3proxy

A Rust HTTP service for reproducible browser TLS, HTTP/2, JA3 and JA4 profiles.
It forwards explicitly requested HTTP operations and returns both a text and a
binary-safe representation of the upstream response.

[Repository](https://github.com/sellaro-net/ja3proxy) ·
[CI and images](https://github.com/sellaro-net/ja3proxy/actions/workflows/docker-build.yml) ·
[Report a vulnerability privately](https://github.com/sellaro-net/ja3proxy/security/advisories/new)

## Operating contract

- One independently deployable service; it is not part of the Sellaro monorepo.
- Rust **1.97.0** is selected by [`rust-toolchain.toml`](rust-toolchain.toml).
  Dependencies are resolved by [`Cargo.lock`](Cargo.lock).
- `wreq` and `wreq-util` are an exactly pinned, tested release-candidate pair.
  Upgrade them together rather than resolving unrelated prereleases.
- Published images use `ghcr.io/sellaro-net/ja3proxy` and include native
  `linux/amd64` and `linux/arm64` manifests, provenance and an SBOM.
- The runtime is non-root. Its executable is root-owned, and PR CI verifies
  startup with a read-only filesystem and dropped capabilities.

## Security boundary

**This service is not an authentication gateway.** Put caller authentication,
TLS and network access control in front of it. Do not expose an unrestricted
public proxy.

Private/internal request targets are blocked by default. Enabling
`ALLOW_PRIVATE_IPS` expands that boundary and belongs only in an explicitly
trusted, network-restricted deployment. Request/response sizes, concurrency and
request lifetimes are bounded. Redirects are returned to the caller rather
than followed automatically.

Never put proxy credentials or private request/response bodies into issues or
logs. Use the repository's private vulnerability-reporting channel for security
reports. Public visibility does not imply a project license grant; this
repository currently has no project `LICENSE` file. Third-party code keeps its
own license terms.

## Local development

Install Rust through rustup and provide the native BoringSSL build prerequisites:
a C/C++ build toolchain, CMake, Go and Clang/libclang. The Docker build declares
the corresponding Linux packages.

```sh
git clone https://github.com/sellaro-net/ja3proxy.git
cd ja3proxy
cargo run --locked
```

The toolchain file installs the selected compiler, Clippy and rustfmt. Quality
checks use the same selection:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Changing the Rust baseline requires updating both the toolchain file and the
Docker builder tag/digest, then verifying the native and container builds.

## Container usage

For local evaluation, use a successful published image or build the repository
locally. Registry access depends on the package's actual visibility and grants;
a repository URL alone does not prove anonymous image access.

```sh
docker run --rm --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/sellaro-net/ja3proxy:latest
```

`latest` is for discovery, not a production pin. Select the complete
`ghcr.io/sellaro-net/ja3proxy@sha256:...` reference from a verified publish for an
actual deployment. The former public package `ghcr.io/tentoxa/ja3proxy` remains
a separate artifact: the GitHub transfer did not move its images or digests.
Do not rewrite an existing deployment's image reference merely because the
repository moved.

## API

### `GET /health`

Returns `status`, the compiled service `version`, and the current `profiles`
list. Obtain profile identifiers from this response instead of copying a stale
hard-coded browser list.

```sh
curl --fail http://127.0.0.1:8080/health
```

### `POST /request`

`url` and `method` are required. Request field names use camelCase.

```sh
curl --fail-with-body http://127.0.0.1:8080/request \
  -H 'Content-Type: application/json' \
  --data '{"url":"https://example.com/","method":"GET","timeout":30}'
```

| Field | Meaning |
|---|---|
| `url` | Target HTTP/HTTPS URL |
| `method` | HTTP method such as `GET` or `POST` |
| `headers` | Optional object of string header values |
| `body` | Optional request-body string |
| `proxy` | Optional HTTP, HTTPS or SOCKS5 upstream proxy URL |
| `timeout` | Seconds; omitted means 30, `0` selects `DEFAULT_TIMEOUT`, explicit values above 300 are capped |
| `tlsProfile` | Optional identifier from `/health`; omitted selects the transport default |

A completed upstream exchange returns JSON with these fields:

| Field | Meaning |
|---|---|
| `status` | Upstream HTTP status, including upstream errors or redirects |
| `headers` | Header values as arrays, preserving repeated headers |
| `body` | Lossy UTF-8 text representation |
| `bodyBase64` | Binary-safe Base64 representation |
| `elapsed` | Request duration in milliseconds |

Use `status` to evaluate the upstream result; a successfully completed proxy
exchange is not a promise that the upstream returned 2xx. Invalid/blocked
requests and transport failures are distinct proxy errors.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `PORT` | `8080` | Listening port inside the container |
| `LOG_LEVEL` | `info` | Structured log verbosity |
| `MAX_CONCURRENT` | `100` | Concurrent request permits |
| `DEFAULT_TIMEOUT` | `30` | Fallback when a request explicitly supplies `timeout: 0` |
| `MAX_REQUEST_BODY_SIZE` | `10485760` | Maximum incoming request bytes |
| `MAX_RESPONSE_BODY_SIZE` | `52428800` | Maximum upstream response bytes |
| `SERVER_TIMEOUT` | `120` | Outer server request lifetime in seconds |
| `ALLOW_PRIVATE_IPS` | `false` | Explicit opt-in for private/internal targets |

Use positive operational limits. Preserve existing service, network and image
pins when changing repository metadata; a generated container name is not an
API contract.

## CI and releases

The existing `quality` check runs formatting, Clippy and tests. On pull requests
it also builds the actual image without publishing, starts an isolated
read-only container, verifies health/non-root operation and confirms the default
private-target rejection. Workflow definitions are checked with a pinned,
checksum-verified actionlint binary.

Only permitted `main` or `v*` refs can enter the publisher. The native amd64 and
arm64 jobs publish their digests, then a separate job combines and verifies the
multi-architecture manifest. Publishers are not cancelled midway through a
newer push. They do not delete package versions as a cleanup side effect.

Dependency updates arrive as ordinary reviewed pull requests. Required checks,
immutable release tags and branch protection remain in force; no team bypass or
self-approval requirement is introduced.
