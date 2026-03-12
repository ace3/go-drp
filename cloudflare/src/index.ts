/**
 * go-drp — Dynamic Reverse Proxy Gateway (Cloudflare Worker edition)
 *
 * A lightweight, secure HTTP gateway that lets a client reach any HTTPS
 * upstream through a single, token-protected Cloudflare Worker endpoint.
 *
 * Mirrors the Go implementation with feature parity:
 * - Dynamic routing via URL path: /<upstream-host>/<path>
 * - Token authentication (X-Proxy-Token, constant-time comparison)
 * - IP allowlisting (via CF-Connecting-IP)
 * - SSRF protection (allowlist or private-IP blocklist)
 * - Per-IP rate limiting (in-memory token bucket)
 * - Request ID generation (UUID v4)
 * - Health endpoint (/health)
 * - Metrics endpoint (/metrics)
 */

import type { Env } from "./types";
import { REQUEST_ID_HEADER, getRequestID } from "./requestid";
import { validateUpstreamHost, parseHostsList } from "./ssrf";
import { RateLimiter } from "./ratelimit";
import { Metrics } from "./metrics";

// Module-level singletons — scoped to the Worker isolate.
let rateLimiter: RateLimiter | null = null;
const metrics = new Metrics();

/**
 * Constant-time string comparison to prevent timing attacks on token
 * validation. Uses the Web Crypto API's timingSafeEqual equivalent
 * via byte-by-byte XOR with fixed iteration count.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // Compare against b anyway to avoid leaking length via timing.
    // Use a dummy string of the same length as b.
    const dummy = "x".repeat(b.length);
    let result = 1; // will be nonzero
    for (let i = 0; i < b.length; i++) {
      result |= dummy.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Extract the client IP address.
 *
 * Cloudflare always sets CF-Connecting-IP to the true client IP, so
 * there is no need for TRUST_PROXY_HEADERS — CF is the trusted proxy.
 */
function extractClientIP(request: Request): string {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

/**
 * Parse the URL path into an upstream host and remaining path.
 *
 * Examples:
 *   "/api.example.com/v1/users" → ["api.example.com", "/v1/users"]
 *   "/api.example.com"          → ["api.example.com", "/"]
 *   "/"                         → null (invalid)
 */
function parseTarget(urlPath: string): [string, string] | null {
  const path = urlPath.startsWith("/") ? urlPath.slice(1) : urlPath;
  if (path === "") return null;

  const slashIndex = path.indexOf("/");
  if (slashIndex === -1) {
    return [path, "/"];
  }
  const host = path.slice(0, slashIndex);
  const remaining = path.slice(slashIndex);
  if (host === "") return null;
  return [host, remaining];
}

/**
 * Parse a comma-separated IP list from an environment variable.
 */
function parseIPList(raw: string | undefined): string[] {
  if (!raw || raw.trim() === "") return [];
  return raw
    .split(",")
    .map((ip) => ip.trim())
    .filter((ip) => ip.length > 0);
}

/**
 * Initialize or return the rate limiter singleton from env config.
 */
function getRateLimiter(env: Env): RateLimiter | null {
  const rps = parseFloat(env.RATE_LIMIT_RPS || "0");
  if (rps <= 0) return null;

  // Re-create if config changed (simple check).
  if (rateLimiter === null) {
    const burst = parseInt(env.RATE_LIMIT_BURST || "0", 10);
    rateLimiter = new RateLimiter(rps, burst);
  }
  return rateLimiter;
}

/**
 * Build a JSON error response.
 */
function errorResponse(
  message: string,
  status: number,
  requestID: string
): Response {
  return new Response(message + "\n", {
    status,
    headers: {
      "Content-Type": "text/plain",
      [REQUEST_ID_HEADER]: requestID,
    },
  });
}

/**
 * Handle GET /health — returns JSON health/liveness status.
 */
function handleHealth(env: Env, requestID: string): Response {
  const version = env.VERSION || "dev";
  return new Response(JSON.stringify({ status: "ok", version }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      [REQUEST_ID_HEADER]: requestID,
    },
  });
}

/**
 * Handle GET /metrics — returns JSON metrics.
 */
function handleMetrics(requestID: string): Response {
  return new Response(JSON.stringify(metrics.toJSON(), null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      [REQUEST_ID_HEADER]: requestID,
    },
  });
}

/**
 * Handle the proxy request — the main handler chain.
 *
 * Security order (mirrors Go implementation):
 * 1. IP allowlist
 * 2. Rate limiting
 * 3. Token authentication (constant-time comparison)
 * 4. Parse target
 * 5. SSRF guard
 * 6. Proxy forward
 */
async function handleProxy(
  request: Request,
  env: Env,
  requestID: string
): Promise<Response> {
  const startTime = Date.now();
  const method = request.method;

  // 1. IP Allowlist
  const whitelistIPs = parseIPList(env.WHITELIST_IP);
  if (whitelistIPs.length > 0) {
    const clientIP = extractClientIP(request);
    if (!whitelistIPs.includes(clientIP)) {
      const resp = errorResponse(
        "Forbidden: IP not allowed",
        403,
        requestID
      );
      metrics.recordRequest(method, 403, Date.now() - startTime);
      return resp;
    }
  }

  // 2. Rate Limiting
  const rl = getRateLimiter(env);
  if (rl !== null) {
    const clientIP = extractClientIP(request);
    if (!rl.allow(clientIP)) {
      const resp = errorResponse(
        "Too Many Requests",
        429,
        requestID
      );
      metrics.recordRequest(method, 429, Date.now() - startTime);
      return resp;
    }
  }

  // 3. Token Authentication (constant-time comparison)
  const proxyToken = env.PROXY_TOKEN || "";
  const token = request.headers.get("X-Proxy-Token") || "";
  if (proxyToken === "" || !timingSafeEqual(token, proxyToken)) {
    const resp = errorResponse("Unauthorized", 401, requestID);
    metrics.recordRequest(method, 401, Date.now() - startTime);
    return resp;
  }

  // 4. Parse Target
  const url = new URL(request.url);
  const target = parseTarget(url.pathname);
  if (!target) {
    const resp = errorResponse(
      "Bad Request: use /<host>/<path>",
      400,
      requestID
    );
    metrics.recordRequest(method, 400, Date.now() - startTime);
    return resp;
  }
  const [targetHost, remainingPath] = target;

  // 5. SSRF Guard
  const allowedHosts = parseHostsList(env.ALLOWED_UPSTREAM_HOSTS);
  const ssrfError = validateUpstreamHost(targetHost, allowedHosts);
  if (ssrfError !== null) {
    const resp = errorResponse(
      "Forbidden: upstream host not allowed",
      403,
      requestID
    );
    metrics.recordRequest(method, 403, Date.now() - startTime);
    return resp;
  }

  // 6. Build upstream URL and forward the request.
  const upstreamURL = `https://${targetHost}${remainingPath}${url.search}`;

  // Clone headers, strip the auth token, and set the correct Host.
  const upstreamHeaders = new Headers(request.headers);
  upstreamHeaders.delete("X-Proxy-Token");
  upstreamHeaders.set("Host", targetHost);
  // Remove Cloudflare-specific headers that should not be forwarded.
  upstreamHeaders.delete("CF-Connecting-IP");
  upstreamHeaders.delete("CF-IPCountry");
  upstreamHeaders.delete("CF-RAY");
  upstreamHeaders.delete("CF-Visitor");

  try {
    const upstreamResponse = await fetch(upstreamURL, {
      method: request.method,
      headers: upstreamHeaders,
      body:
        request.method !== "GET" && request.method !== "HEAD"
          ? request.body
          : undefined,
      redirect: "follow",
    });

    // Clone the response and add the request ID header.
    const responseHeaders = new Headers(upstreamResponse.headers);
    responseHeaders.set(REQUEST_ID_HEADER, requestID);

    const response = new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: responseHeaders,
    });

    metrics.recordRequest(method, upstreamResponse.status, Date.now() - startTime);
    return response;
  } catch (err) {
    metrics.recordUpstreamError(targetHost);
    metrics.recordRequest(method, 502, Date.now() - startTime);
    return errorResponse("Bad Gateway", 502, requestID);
  }
}

export default {
  async fetch(
    request: Request,
    env: Env,
    _ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);
    const requestID = getRequestID(request.headers);

    // Route: /health (no auth required)
    if (url.pathname === "/health") {
      return handleHealth(env, requestID);
    }

    // Route: /metrics (no auth required)
    if (url.pathname === "/metrics") {
      return handleMetrics(requestID);
    }

    // Route: everything else → proxy handler
    return handleProxy(request, env, requestID);
  },
};

// Export internals for testing.
export {
  timingSafeEqual,
  extractClientIP,
  parseTarget,
  parseIPList,
  handleHealth,
  handleMetrics,
  handleProxy,
  metrics,
  rateLimiter,
};
