# go-drp — Cloudflare Worker Edition

A port of the [go-drp Dynamic Reverse Proxy Gateway](../README.md) to **Cloudflare Workers**. This Worker provides the same feature set as the Go version — token-authenticated, SSRF-protected dynamic reverse proxying — running on Cloudflare's global edge network.

```
Client
  │  POST /api.example.com/some/endpoint
  │  X-Proxy-Token: <secret>
  ▼
go-drp (Cloudflare Worker — edge)
  │  https://api.example.com/some/endpoint
  ▼
Upstream API
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Dynamic routing** | Encode the upstream host in the URL path: `/<host>/<path>` |
| **Token authentication** | `X-Proxy-Token` header with constant-time comparison |
| **IP allowlisting** | Optional comma-separated list of permitted client IPs (via `CF-Connecting-IP`) |
| **SSRF protection** | Upstream hosts validated against an allowlist or a built-in private-IP blocklist (RFC 1918, cloud metadata endpoints) |
| **Per-IP rate limiting** | In-memory token-bucket rate limiter (per-isolate) |
| **Request IDs** | UUID v4 generated for every request; client-provided IDs are preserved |
| **Health endpoint** | `GET /health` — no auth required |
| **Metrics endpoint** | `GET /metrics` — JSON request/latency/error stats (per-isolate) |
| **Global edge** | Runs on Cloudflare's 300+ data centers worldwide |
| **Zero servers** | No infrastructure to manage — deploy with one command |

### Differences from the Go Version

| Feature | Go version | Cloudflare Worker |
|---------|-----------|-------------------|
| **TLS termination** | Requires Caddy/Nginx in front | Handled by Cloudflare automatically |
| **mTLS client auth** | Built-in | Use [Cloudflare mTLS](https://developers.cloudflare.com/ssl/client-certificates/) instead |
| **Prometheus metrics** | Native Prometheus `/metrics` | JSON `/metrics` (per-isolate; use [Analytics Engine](https://developers.cloudflare.com/analytics/analytics-engine/) for global) |
| **Rate limiting** | Persistent in-memory (single process) | Per-isolate in-memory; use [Cloudflare Rate Limiting](https://developers.cloudflare.com/waf/rate-limiting-rules/) for global |
| **Graceful shutdown** | 30s drain on SIGTERM | Not needed — Workers are stateless |
| **Proxy header trust** | `TRUST_PROXY_HEADERS` env var | Not needed — Cloudflare always provides `CF-Connecting-IP` |
| **Configuration** | `.env` file | `wrangler.toml` (vars) + `wrangler secret` (secrets) |

---

## Prerequisites

- [Node.js](https://nodejs.org/) v18 or later
- A [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier works)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) (installed as a dev dependency)

---

## Quick Start (Local Development)

### 1. Clone and install dependencies

```bash
cd cloudflare
npm install
```

### 2. Configure secrets for local development

```bash
cp .dev.vars.example .dev.vars
```

Edit `.dev.vars` and set a strong `PROXY_TOKEN`:

```env
PROXY_TOKEN=your-secret-token-here
```

> **Tip:** Generate a secure token with `openssl rand -hex 32`.

### 3. Start the dev server

```bash
npm run dev
```

The Worker starts on `http://localhost:8787`.

### 4. Test it

```bash
# Health check (no token required)
curl http://localhost:8787/health

# Proxy a request (replace TOKEN with your PROXY_TOKEN)
curl -H "X-Proxy-Token: TOKEN" "http://localhost:8787/httpbin.org/get"

# Metrics
curl http://localhost:8787/metrics
```

---

## Deploy to Cloudflare Workers

### Step 1: Authenticate with Cloudflare

```bash
npx wrangler login
```

This opens a browser window to authorize Wrangler with your Cloudflare account.

### Step 2: Set the PROXY_TOKEN secret

```bash
npx wrangler secret put PROXY_TOKEN
```

You'll be prompted to enter the secret value. Use a strong random value:

```bash
# Generate a secure token
openssl rand -hex 32
```

### Step 3: Configure environment variables

Edit `wrangler.toml` to set your desired configuration:

```toml
[vars]
VERSION = "1.0.0"
WHITELIST_IP = ""                        # comma-separated allowed IPs, or empty for all
ALLOWED_UPSTREAM_HOSTS = ""              # comma-separated upstream hosts, or empty for blocklist mode
RATE_LIMIT_RPS = "0"                     # 0 = disabled
RATE_LIMIT_BURST = "0"                   # 0 = defaults to RPS
```

### Step 4: Deploy

```bash
npm run deploy
```

Wrangler outputs the Worker URL:

```
Published go-drp (1.0.0)
  https://go-drp.<your-subdomain>.workers.dev
```

### Step 5: Verify the deployment

```bash
WORKER_URL="https://go-drp.your-subdomain.workers.dev"
TOKEN="your-proxy-token"

# Health check
curl "$WORKER_URL/health"
# → {"status":"ok","version":"1.0.0"}

# Proxy a request
curl -H "X-Proxy-Token: $TOKEN" "$WORKER_URL/httpbin.org/get"

# SSRF protection — should return 403
curl -H "X-Proxy-Token: $TOKEN" "$WORKER_URL/127.0.0.1/test"
# → Forbidden: upstream host not allowed
```

---

## Configuration Reference

### Environment Variables (wrangler.toml `[vars]`)

| Variable | Default | Description |
|----------|---------|-------------|
| `VERSION` | `"dev"` | Version string shown in `/health` response |
| `WHITELIST_IP` | `""` *(all)* | Comma-separated list of allowed client IPs. Leave empty to allow all. Uses `CF-Connecting-IP` for client identification. |
| `ALLOWED_UPSTREAM_HOSTS` | `""` *(blocklist)* | Comma-separated allowlist of upstream hosts. When set, only listed hosts are permitted. When empty, the built-in private-IP blocklist is used. |
| `RATE_LIMIT_RPS` | `"0"` | Max requests per second per client IP. `"0"` disables rate limiting. |
| `RATE_LIMIT_BURST` | `"0"` | Token-bucket burst size. `"0"` defaults to `RATE_LIMIT_RPS`. |

### Secrets (set via `wrangler secret put`)

| Secret | Required | Description |
|--------|----------|-------------|
| `PROXY_TOKEN` | **Yes** | Shared secret for `X-Proxy-Token` authentication. Generate with `openssl rand -hex 32`. |

---

## Request Format

```
GET|POST|PUT|DELETE|PATCH /<upstream-host>/<path>?<query>
X-Proxy-Token: <token>
[X-Request-ID: <optional-client-id>]
```

### Examples

```bash
TOKEN="your-secret-token"
GATEWAY="https://go-drp.your-subdomain.workers.dev"

# Proxy to https://api.example.com/v1/users
curl -H "X-Proxy-Token: $TOKEN" "$GATEWAY/api.example.com/v1/users"

# With query parameters
curl -H "X-Proxy-Token: $TOKEN" "$GATEWAY/api.example.com/search?q=hello&limit=10"

# POST request with JSON body
curl -X POST \
     -H "X-Proxy-Token: $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"key":"value"}' \
     "$GATEWAY/api.example.com/v1/data"

# Health check (no token required)
curl "$GATEWAY/health"
# → {"status":"ok","version":"1.0.0"}

# Metrics (no token required)
curl "$GATEWAY/metrics"
```

### Response Headers

Every response includes:
- `X-Request-ID` — either the client-provided ID or an auto-generated UUID v4.

### Error Responses

| Status | Meaning |
|--------|---------|
| `400 Bad Request` | Invalid path format (missing `/<host>/<path>`) |
| `401 Unauthorized` | Missing or invalid `X-Proxy-Token` |
| `403 Forbidden` | Client IP not in whitelist, or upstream host blocked (SSRF) |
| `429 Too Many Requests` | Per-IP rate limit exceeded |
| `502 Bad Gateway` | Upstream server unreachable or returned an error |

---

## API Endpoints

### `GET /health`

Returns a JSON health/liveness status. **No authentication required.**

```json
{"status":"ok","version":"1.0.0"}
```

### `GET /metrics`

Returns JSON metrics (per-isolate). **No authentication required.**

```json
{
  "requests": [
    {"method": "GET", "status": 200, "count": 42},
    {"method": "POST", "status": 201, "count": 5}
  ],
  "latency": {
    "count": 47,
    "avg_ms": 125,
    "min_ms": 12,
    "max_ms": 1500
  },
  "upstream_errors": [
    {"host": "api.example.com", "count": 2}
  ]
}
```

> **Note:** Metrics are per-isolate and reset when the Worker isolate is recycled. For persistent, global metrics, use [Cloudflare Analytics Engine](https://developers.cloudflare.com/analytics/analytics-engine/).

### `* /<host>/<path>`

Dynamic reverse proxy. **Requires `X-Proxy-Token` header.**

---

## Project Structure

```
cloudflare/
├── src/
│   ├── index.ts          # Main Worker entry point, routing, proxy handler
│   ├── types.ts          # TypeScript type definitions (Env bindings)
│   ├── ssrf.ts           # SSRF protection (allowlist / private-IP blocklist)
│   ├── ratelimit.ts      # Per-IP token-bucket rate limiter
│   ├── requestid.ts      # UUID v4 request ID generation
│   └── metrics.ts        # In-memory JSON metrics collection
├── test/
│   └── index.test.ts     # Unit + integration tests (Vitest + Workers pool)
├── wrangler.toml         # Cloudflare Worker configuration
├── vitest.config.ts      # Vitest test configuration
├── package.json          # Dependencies and scripts
├── tsconfig.json         # TypeScript configuration
├── .dev.vars.example     # Local development secrets template
├── .gitignore            # Git ignore patterns
└── README.md             # This file
```

---

## Development

### Running Tests

```bash
npm test
```

Tests use [Vitest](https://vitest.dev/) with the [`@cloudflare/vitest-pool-workers`](https://developers.cloudflare.com/workers/testing/vitest-integration/) pool, which provides a realistic Cloudflare Workers runtime for integration testing.

### Available Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Start local dev server (port 8787) |
| `npm run deploy` | Deploy to Cloudflare Workers |
| `npm test` | Run all tests |
| `npm run test:watch` | Run tests in watch mode |

---

## Production Deployment Checklist

1. **Set a strong PROXY_TOKEN**
   ```bash
   openssl rand -hex 32  # generate token
   npx wrangler secret put PROXY_TOKEN
   ```

2. **Configure ALLOWED_UPSTREAM_HOSTS** (strongly recommended)
   ```toml
   [vars]
   ALLOWED_UPSTREAM_HOSTS = "api.stripe.com,api.github.com"
   ```
   This eliminates SSRF risk entirely by restricting which upstream hosts the proxy can reach.

3. **Enable IP allowlisting** (if applicable)
   ```toml
   [vars]
   WHITELIST_IP = "203.0.113.10,203.0.113.11"
   ```

4. **Configure rate limiting** (recommended)
   ```toml
   [vars]
   RATE_LIMIT_RPS = "10"
   RATE_LIMIT_BURST = "20"
   ```
   For globally consistent rate limiting, also configure [Cloudflare Rate Limiting Rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) in the dashboard.

5. **Add a custom domain** (optional)
   ```bash
   npx wrangler domains attach go-drp gateway.example.com
   ```
   Or configure via the [Cloudflare dashboard](https://dash.cloudflare.com/) under Workers & Pages → your Worker → Settings → Domains & Routes.

6. **Deploy**
   ```bash
   npm run deploy
   ```

---

## Custom Domain Setup

### Option A: Workers Route (recommended)

1. Add your domain to Cloudflare (if not already).
2. In the Cloudflare dashboard, go to **Workers & Pages** → your Worker → **Settings** → **Domains & Routes**.
3. Click **Add** → **Route** and enter:
   - Route: `gateway.example.com/*`
   - Zone: `example.com`

### Option B: Workers Custom Domain

```bash
npx wrangler domains attach go-drp gateway.example.com
```

Both options automatically provision TLS certificates.

---

## Staging / Production Environments

Wrangler supports multiple environments. Add to `wrangler.toml`:

```toml
[env.staging]
name = "go-drp-staging"
vars = { VERSION = "1.0.0-staging", RATE_LIMIT_RPS = "100" }

[env.production]
name = "go-drp-production"
vars = { VERSION = "1.0.0", RATE_LIMIT_RPS = "50" }
```

Deploy to a specific environment:

```bash
# Deploy to staging
npx wrangler deploy --env staging

# Set secrets per environment
npx wrangler secret put PROXY_TOKEN --env staging
npx wrangler secret put PROXY_TOKEN --env production

# Deploy to production
npx wrangler deploy --env production
```

---

## Security Notes

| Topic | Implementation |
|-------|---------------|
| **Token secrecy** | Cloudflare handles TLS — the token is never sent in cleartext. Store via `wrangler secret put`. |
| **Token strength** | Use `openssl rand -hex 32` for a 256-bit random token. |
| **Constant-time comparison** | Token is compared using a constant-time XOR algorithm to prevent timing attacks. |
| **IP allowlisting** | Uses `CF-Connecting-IP` (set by Cloudflare, not spoofable by clients). |
| **SSRF protection** | Set `ALLOWED_UPSTREAM_HOSTS` to a strict allowlist. The default blocklist covers RFC 1918 ranges and cloud metadata endpoints. |
| **DNS rebinding** | If `ALLOWED_UPSTREAM_HOSTS` is not set, an attacker could craft a hostname resolving to a private IP. Always set an explicit allowlist. |
| **Token stripping** | `X-Proxy-Token` is removed before forwarding to upstream. |
| **CF header stripping** | `CF-Connecting-IP`, `CF-IPCountry`, `CF-RAY`, and `CF-Visitor` headers are removed before forwarding. |

---

## Monitoring & Observability

### Worker Analytics (Built-in)

View request volume, error rates, and latency in the [Cloudflare dashboard](https://dash.cloudflare.com/) under **Workers & Pages** → your Worker → **Analytics**.

### Custom Metrics

The `/metrics` endpoint provides per-isolate request statistics in JSON format. For global, persistent metrics:

1. **Cloudflare Analytics Engine** — write custom data points from the Worker.
2. **External services** — forward metrics to Datadog, Grafana Cloud, etc., using `ctx.waitUntil()`.

### Logs

```bash
# Tail live logs
npx wrangler tail

# Tail with filtering
npx wrangler tail --format json | jq '.logs[]'
```

---

## Troubleshooting

### "PROXY_TOKEN is required" error
Set the secret: `npx wrangler secret put PROXY_TOKEN`

### 401 Unauthorized
Ensure you're sending the correct token in `X-Proxy-Token` header.

### 403 Forbidden — IP not allowed
Your IP is not in the `WHITELIST_IP` list. Check with `curl ifconfig.me`.

### 403 Forbidden — upstream host not allowed
The target host is blocked by SSRF protection. Add it to `ALLOWED_UPSTREAM_HOSTS` if it's a legitimate target.

### 502 Bad Gateway
The upstream server is unreachable. Check that the upstream URL is correct and the server is responding.

### Rate limiting not consistent across requests
The in-memory rate limiter is per-isolate. Different requests may hit different isolates. Use [Cloudflare Rate Limiting Rules](https://developers.cloudflare.com/waf/rate-limiting-rules/) for globally consistent rate limiting.

---

## License

Same license as the parent [go-drp](../README.md) project.
