/**
 * Per-IP rate limiting using a sliding-window token-bucket algorithm.
 *
 * Mirrors the Go implementation in proxy/ratelimit.go.
 *
 * NOTE: In Cloudflare Workers, global state (like this in-memory Map) is
 * shared within a single isolate. It is NOT shared across multiple isolates
 * or data centers. For globally consistent rate limiting, use Cloudflare's
 * built-in Rate Limiting rules or Durable Objects.
 *
 * This in-memory approach provides best-effort per-isolate rate limiting,
 * which is sufficient for many use cases.
 */

interface Bucket {
  tokens: number;
  lastRefill: number; // ms timestamp
  lastSeen: number; // ms timestamp
}

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly rps: number;
  private readonly burst: number;
  private readonly ttlMs: number;

  /**
   * @param rps    Requests per second allowed per IP.
   * @param burst  Maximum burst size (token bucket capacity).
   */
  constructor(rps: number, burst: number) {
    this.rps = rps;
    this.burst = burst > 0 ? burst : Math.max(1, Math.floor(rps));
    this.ttlMs = 5 * 60 * 1000; // 5 minutes
  }

  /**
   * Returns true if the request from `ip` is allowed, false if rate-limited.
   */
  allow(ip: string): boolean {
    const now = Date.now();
    this.cleanup(now);

    let bucket = this.buckets.get(ip);
    if (!bucket) {
      bucket = { tokens: this.burst, lastRefill: now, lastSeen: now };
      this.buckets.set(ip, bucket);
    }

    // Refill tokens based on elapsed time.
    const elapsed = (now - bucket.lastRefill) / 1000; // seconds
    const refill = elapsed * this.rps;
    bucket.tokens = Math.min(this.burst, bucket.tokens + refill);
    bucket.lastRefill = now;
    bucket.lastSeen = now;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return true;
    }

    return false;
  }

  /**
   * Evict idle entries older than TTL.
   */
  private cleanup(now: number): void {
    // Only run cleanup periodically to avoid overhead on every request.
    // Clean up at most every 30 seconds.
    const cutoff = now - this.ttlMs;
    for (const [ip, bucket] of this.buckets) {
      if (bucket.lastSeen < cutoff) {
        this.buckets.delete(ip);
      }
    }
  }
}
