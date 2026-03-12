# go-drp — Original Design Notes

> The implementation is complete. See [README.md](README.md) for full documentation.

## Origin

`go-drp` was designed as a **Dynamic Reverse Proxy Gateway** to allow a Singapore
server to reach Indonesian APIs that restrict foreign IPs, by routing requests
through a Jakarta-based gateway.

## Core Design Decisions

| Decision | Rationale |
|----------|-----------|
| URL-encoded target host (`/<host>/<path>`) | Zero client configuration — no per-host routes needed. |
| `X-Proxy-Token` header | Simple shared-secret auth that works with any HTTP client. |
| `httputil.ReverseProxy` | Production-grade Go standard library; handles streaming, websockets, and query strings automatically. |
| Configurable IP allowlist | Restrict gateway access to known Singapore server IPs. |
| SSRF allowlist / blocklist | Prevent gateway misuse from reaching internal cloud infrastructure. |
| Distroless Docker image | Minimal attack surface; no shell or package manager in the runtime image. |

## Deployment Topology

```
[ Singapore Server ]
        |
        |  HTTPS  X-Proxy-Token: <secret>
        |  GET /target-api.id/route
        v
[ Jakarta VPS -- go-drp :8080 ]
     Caddy / Nginx (TLS termination)
        |
        |  HTTPS
        v
[ target-api.id ]
```
