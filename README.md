# go-drp — Dynamic Reverse Proxy Gateway

A lightweight, secure HTTP gateway written in Go. It lets a client on one network reach any HTTPS upstream by tunnelling requests through a single, token-protected endpoint.

**Typical use-case:** a server in Singapore needs to call Indonesian APIs that block foreign IPs. Deploy `go-drp` on a Jakarta server and route all calls through it.

```
Client (Singapore)
  │  POST /kci.id/jakarta/endpoint
  │  X-Proxy-Token: <secret>
  ▼
go-drp (Jakarta :8080)
  │  https://kci.id/jakarta/endpoint
  ▼
Upstream API
```

---

## Features

- **Dynamic routing** — encode the upstream host in the URL path: `/<host>/<path>`
- **Token authentication** — `X-Proxy-Token` header, constant-time comparison
- **IP allowlisting** — optional comma-separated list of permitted client IPs
- **SSRF protection** — upstream hosts validated against an allowlist or a built-in private-IP blocklist (RFC 1918, cloud metadata endpoints)
- **Proxy-header trust guard** — `X-Real-IP`/`X-Forwarded-For` only trusted when `TRUST_PROXY_HEADERS=true`
- **Health endpoint** — `GET /health` returns `{"status":"ok"}` without requiring a token
- **Graceful shutdown** — handles `SIGINT`/`SIGTERM` with a 30 s drain period
- **Production-ready timeouts** — read/write/idle timeouts configured on the HTTP server

---

## Quick Start

### Binary (recommended for production)

Download the latest binary for your platform from the [Releases page](../../releases):

```bash
# Linux amd64
curl -LO https://gitlab.example.com/<group>/<project>/-/packages/generic/go-drp/<version>/go-drp-linux-amd64
chmod +x go-drp-linux-amd64

# Create .env
cp .env.example .env
# Edit .env and set PROXY_TOKEN

./go-drp-linux-amd64
```

### Docker

```bash
cp .env.example .env
# Edit .env and set PROXY_TOKEN at minimum

docker compose up -d
```

### From Source

```bash
git clone <repo-url> && cd go-drp
cp .env.example .env   # configure PROXY_TOKEN
make run
```

---

## Configuration

All configuration is provided via environment variables (or a `.env` file loaded at startup).

| Variable                 | Required | Default | Description |
|--------------------------|----------|---------|-------------|
| `PROXY_TOKEN`            | **Yes**  | —       | Shared secret. Clients must send this in `X-Proxy-Token`. Generate one with `openssl rand -hex 32`. |
| `PORT`                   | No       | `8080`  | Port to listen on. |
| `WHITELIST_IP`           | No       | *(all)* | Comma-separated list of allowed **client** IPs. Leave empty to allow all. |
| `ALLOWED_UPSTREAM_HOSTS` | No       | *(blocklist)* | Comma-separated allowlist of **upstream** hosts (SSRF protection). When set, only listed hosts are permitted. When empty, the built-in private-IP blocklist is used. |
| `TRUST_PROXY_HEADERS`    | No       | `false` | Set `true`/`1` only when the gateway is behind a trusted reverse proxy that sets `X-Real-IP`/`X-Forwarded-For`. |

### Example `.env`

```env
PROXY_TOKEN=a1b2c3d4e5f6...   # openssl rand -hex 32
PORT=8080
WHITELIST_IP=203.0.113.10
ALLOWED_UPSTREAM_HOSTS=api.stripe.com,api.github.com
TRUST_PROXY_HEADERS=true       # only if behind Caddy/Nginx
```

---

## Request Format

```
GET /<upstream-host>/<path>?<query>
X-Proxy-Token: <token>
```

### Examples

```bash
TOKEN="your-secret-token"
GATEWAY="https://gateway.example.com"

# Proxy to https://api.example.com/v1/users
curl -H "X-Proxy-Token: $TOKEN" "$GATEWAY/api.example.com/v1/users"

# With query parameters
curl -H "X-Proxy-Token: $TOKEN" "$GATEWAY/api.example.com/search?q=hello&limit=10"

# POST request
curl -X POST \
     -H "X-Proxy-Token: $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"key":"value"}' \
     "$GATEWAY/api.example.com/v1/data"

# Health check (no token required)
curl "$GATEWAY/health"
```

---

## Development

### Prerequisites

- Go 1.22+
- `make`
- Docker & Docker Compose (optional)

### Common Commands

```bash
make help           # list all targets

make run            # run locally (reads .env)
make test           # run tests with race detector
make coverage       # generate HTML coverage report
make coverage-text  # per-function coverage in terminal

make check          # fmt + vet + test (run before every commit)
make lint           # golangci-lint (install: make install-tools)

make build          # compile binary → bin/go-drp
make build-all      # cross-compile all platforms → bin/
make clean          # remove build artefacts
```

### Project Structure

```
go-drp/
├── main.go                # entry point: env loading, server setup, graceful shutdown
├── proxy/
│   ├── proxy.go           # Handler, Config, SSRF guard, IP extraction
│   └── proxy_test.go      # unit tests
├── Makefile
├── Dockerfile
├── docker-compose.yml
├── .gitlab-ci.yml
├── .env.example
└── README.md
```

### Running Tests

```bash
make test            # all tests, race detector
make coverage-text   # see which lines are not covered
```

### Adding a New Feature

1. Write a failing test in `proxy/proxy_test.go`.
2. Implement the change in `proxy/proxy.go` (or `main.go` if config-related).
3. Run `make check` — all checks must pass.
4. Commit.

---

## Production Deployment

### Recommended Architecture

```
Internet → Caddy/Nginx (TLS termination) → go-drp → Upstream APIs
```

> **Why a reverse proxy in front?** `go-drp` itself only speaks HTTP. Putting it behind Caddy or Nginx provides TLS so the `X-Proxy-Token` is never sent in cleartext.

### Caddy Example

```caddyfile
gateway.example.com {
    reverse_proxy localhost:8080
}
```

With Caddy in front, set `TRUST_PROXY_HEADERS=true` in `.env` so that client IPs in `WHITELIST_IP` are correctly extracted from `X-Forwarded-For`.

### Nginx Example

```nginx
server {
    listen 443 ssl;
    server_name gateway.example.com;

    ssl_certificate     /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   Host $host;
    }
}
```

Set `TRUST_PROXY_HEADERS=true` in `.env` when using this setup.

### Systemd Unit

```ini
[Unit]
Description=go-drp Gateway
After=network.target

[Service]
User=drp
WorkingDirectory=/opt/go-drp
EnvironmentFile=/opt/go-drp/.env
ExecStart=/opt/go-drp/go-drp
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now go-drp
```

### Docker (Production)

The `Dockerfile` uses a **distroless** base image (`gcr.io/distroless/static-debian12:nonroot`) for minimal attack surface — no shell, no package manager, runs as non-root (uid 65532).

```bash
# Build with version tag
VERSION=v1.2.3 docker compose build
VERSION=v1.2.3 docker compose up -d

# View logs
docker compose logs -f
```

---

## Releasing (GitLab CI/CD)

Push a semver tag to trigger the full build-and-release pipeline:

```bash
git tag v1.2.3
git push origin v1.2.3
```

The pipeline will:
1. Run all tests with the race detector.
2. Cross-compile binaries for Linux/macOS/Windows (amd64 + arm64).
3. Upload binaries to the GitLab Generic Packages Registry.
4. Create a GitLab Release with direct download links.

---

## Security Notes

| Topic | Implementation |
|-------|---------------|
| Token secrecy | Always run behind TLS; never expose the gateway on plain HTTP over the internet. |
| Token strength | Use `openssl rand -hex 32` to generate a 256-bit random token. |
| IP spoofing | Only set `TRUST_PROXY_HEADERS=true` if a trusted reverse proxy strips and re-sets `X-Real-IP`/`X-Forwarded-For`. |
| SSRF | Set `ALLOWED_UPSTREAM_HOSTS` to a strict allowlist of upstream hosts. The default blocklist covers RFC 1918 ranges and cloud metadata endpoints but cannot protect against DNS-rebinding attacks. |
| DNS rebinding | If `ALLOWED_UPSTREAM_HOSTS` is not set, an attacker could craft a hostname that initially resolves to a public IP (passing the check) and then resolves to an internal IP. Mitigate by always setting an explicit `ALLOWED_UPSTREAM_HOSTS` allowlist. |
| Rate limiting | `go-drp` has no built-in rate limiter. Use Nginx/Caddy rate-limiting or a WAF in front to prevent token brute-forcing. |
| TLS verification | `go-drp` uses the default Go HTTP transport, which validates upstream TLS certificates. Do not disable `InsecureSkipVerify` in production. |

---

## What's Next (Recommended Improvements)

| Priority | Feature | Rationale |
|----------|---------|-----------|
| High | **`ALLOWED_UPSTREAM_HOSTS` allowlist** | Already supported. Strongly recommended in production to eliminate SSRF entirely. |
| High | **Rate limiting** | Prevent token brute-forcing. Consider Caddy's `rate_limit` plugin or Nginx `limit_req`. |
| Medium | **Request IDs** | Add `X-Request-ID` to all logs for distributed tracing. |
| Medium | **Prometheus metrics** | Expose request counts, latency histograms, upstream error rates via `/metrics`. |
| Medium | **mTLS for clients** | Replace the shared `X-Proxy-Token` with mutual TLS client certificates for stronger authentication. |
| Low | **Per-upstream timeouts** | Allow different upstream connect/response timeouts via config. |
| Low | **Response streaming** | Ensure large responses (files, streams) are forwarded efficiently (the current `httputil.ReverseProxy` already handles this). |
