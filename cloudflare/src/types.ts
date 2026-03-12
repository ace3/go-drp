/**
 * Environment bindings for the Cloudflare Worker.
 *
 * Non-secret variables are defined in wrangler.toml [vars].
 * Secrets (PROXY_TOKEN) are set via `wrangler secret put`.
 */
export interface Env {
  /** Shared secret for X-Proxy-Token authentication. */
  PROXY_TOKEN: string;

  /** Build/deploy version string exposed on /health. */
  VERSION?: string;

  /** Comma-separated list of allowed client IPs (empty = allow all). */
  WHITELIST_IP?: string;

  /** Comma-separated allowlist of upstream hosts for SSRF protection. */
  ALLOWED_UPSTREAM_HOSTS?: string;

  /** Per-IP rate limit: requests per second. "0" = disabled. */
  RATE_LIMIT_RPS?: string;

  /** Burst size for the token-bucket rate limiter. "0" = defaults to RPS. */
  RATE_LIMIT_BURST?: string;
}
