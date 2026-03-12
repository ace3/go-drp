/**
 * Simple in-memory metrics collection.
 *
 * Mirrors the Go Prometheus metrics from proxy/metrics.go.
 *
 * NOTE: In Cloudflare Workers, global state is scoped to a single isolate.
 * Metrics reset when the isolate is recycled. For persistent metrics, use
 * Cloudflare Analytics Engine or an external service.
 *
 * The /metrics endpoint returns JSON (not Prometheus text format) since
 * the Prometheus client library is not available in Workers.
 */

interface RequestCount {
  method: string;
  status: number;
  count: number;
}

interface UpstreamError {
  host: string;
  count: number;
}

export class Metrics {
  private readonly requestCounts = new Map<string, number>();
  private readonly requestDurations: number[] = [];
  private readonly upstreamErrors = new Map<string, number>();

  /**
   * Record a completed request.
   */
  recordRequest(method: string, status: number, durationMs: number): void {
    const key = `${method}:${status}`;
    this.requestCounts.set(key, (this.requestCounts.get(key) || 0) + 1);
    this.requestDurations.push(durationMs);
  }

  /**
   * Record an upstream error for a given host.
   */
  recordUpstreamError(host: string): void {
    this.upstreamErrors.set(
      host,
      (this.upstreamErrors.get(host) || 0) + 1
    );
  }

  /**
   * Build the JSON metrics payload.
   */
  toJSON(): object {
    const requests: RequestCount[] = [];
    for (const [key, count] of this.requestCounts) {
      const [method, status] = key.split(":");
      requests.push({ method, status: parseInt(status), count });
    }

    const errors: UpstreamError[] = [];
    for (const [host, count] of this.upstreamErrors) {
      errors.push({ host, count });
    }

    // Compute basic latency stats.
    const durations = this.requestDurations;
    const latency =
      durations.length > 0
        ? {
            count: durations.length,
            avg_ms: Math.round(durations.reduce((a, b) => a + b, 0) / durations.length),
            min_ms: Math.round(Math.min(...durations)),
            max_ms: Math.round(Math.max(...durations)),
          }
        : { count: 0, avg_ms: 0, min_ms: 0, max_ms: 0 };

    return {
      requests,
      latency,
      upstream_errors: errors,
    };
  }
}
