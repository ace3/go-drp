# go-drp — Original Design Notes

> The implementation is complete. See [README.md](README.md) for full documentation.

## Origin

`go-drp` was designed as a **Dynamic Reverse Proxy Gateway** to route requests
through a controlled, token-authenticated gateway to reach upstream APIs.

## Core Design Decisions

| Decision | Rationale |
|----------|-----------|
| URL-encoded target host (`/<host>/<path>`) | Zero client configuration — no per-host routes needed. |
| `X-Proxy-Token` header | Simple shared-secret auth that works with any HTTP client. |
| `httputil.ReverseProxy` | Production-grade Go standard library; handles streaming, websockets, and query strings automatically. |
| Configurable IP allowlist | Restrict gateway access to known client IPs. |
| SSRF allowlist / blocklist | Prevent gateway misuse from reaching internal cloud infrastructure. |
| Distroless Docker image | Minimal attack surface; no shell or package manager in the runtime image. |

## Deployment Topology

```
[ Client ]
        |
        |  HTTPS  X-Proxy-Token: <secret>
        |  GET /target-api.example.com/route
        v
[ go-drp :8080 ]
     Caddy / Nginx (TLS termination)
        |
        |  HTTPS
        v
[ target-api.id ]
```
