import {
  describe,
  it,
  expect,
  beforeAll,
} from "vitest";
import {
  env,
  createExecutionContext,
  waitOnExecutionContext,
  SELF,
} from "cloudflare:test";
import worker, {
  timingSafeEqual,
  parseTarget,
  parseIPList,
} from "../src/index";
import { generateRequestID } from "../src/requestid";
import {
  isBlockedHost,
  validateUpstreamHost,
  parseHostsList,
} from "../src/ssrf";
import { RateLimiter } from "../src/ratelimit";

// ---------------------------------------------------------------------------
// Unit tests for internal helpers
// ---------------------------------------------------------------------------

describe("parseTarget", () => {
  it("parses host and path", () => {
    expect(parseTarget("/api.example.com/v1/users")).toEqual([
      "api.example.com",
      "/v1/users",
    ]);
  });

  it("parses host-only path", () => {
    expect(parseTarget("/api.example.com")).toEqual([
      "api.example.com",
      "/",
    ]);
  });

  it("returns null for root path", () => {
    expect(parseTarget("/")).toBeNull();
  });

  it("returns null for empty path", () => {
    expect(parseTarget("")).toBeNull();
  });

  it("preserves deep paths", () => {
    expect(parseTarget("/host.com/a/b/c/d")).toEqual([
      "host.com",
      "/a/b/c/d",
    ]);
  });
});

describe("timingSafeEqual", () => {
  it("returns true for equal strings", () => {
    expect(timingSafeEqual("secret", "secret")).toBe(true);
  });

  it("returns false for different strings", () => {
    expect(timingSafeEqual("secret", "wrong")).toBe(false);
  });

  it("returns false for different lengths", () => {
    expect(timingSafeEqual("short", "longer-string")).toBe(false);
  });

  it("returns true for empty strings", () => {
    expect(timingSafeEqual("", "")).toBe(true);
  });
});

describe("parseIPList", () => {
  it("returns empty array for empty string", () => {
    expect(parseIPList("")).toEqual([]);
  });

  it("returns empty array for undefined", () => {
    expect(parseIPList(undefined)).toEqual([]);
  });

  it("parses comma-separated IPs", () => {
    expect(parseIPList("1.2.3.4, 5.6.7.8")).toEqual(["1.2.3.4", "5.6.7.8"]);
  });

  it("handles single IP", () => {
    expect(parseIPList("1.2.3.4")).toEqual(["1.2.3.4"]);
  });
});

describe("generateRequestID", () => {
  it("returns UUID v4 format", () => {
    const id = generateRequestID();
    expect(id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
    );
  });

  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateRequestID()));
    expect(ids.size).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// SSRF protection tests
// ---------------------------------------------------------------------------

describe("isBlockedHost", () => {
  it("blocks localhost", () => {
    expect(isBlockedHost("localhost")).toBe(true);
  });

  it("blocks loopback IP", () => {
    expect(isBlockedHost("127.0.0.1")).toBe(true);
    expect(isBlockedHost("127.0.0.2")).toBe(true);
  });

  it("blocks RFC 1918 addresses", () => {
    expect(isBlockedHost("10.0.0.1")).toBe(true);
    expect(isBlockedHost("172.16.0.1")).toBe(true);
    expect(isBlockedHost("192.168.1.1")).toBe(true);
  });

  it("blocks link-local / metadata", () => {
    expect(isBlockedHost("169.254.169.254")).toBe(true);
    expect(isBlockedHost("169.254.0.1")).toBe(true);
  });

  it("blocks metadata hostnames", () => {
    expect(isBlockedHost("metadata.google.internal")).toBe(true);
    expect(isBlockedHost("metadata.internal")).toBe(true);
  });

  it("blocks carrier-grade NAT", () => {
    expect(isBlockedHost("100.64.0.1")).toBe(true);
    expect(isBlockedHost("100.127.255.255")).toBe(true);
  });

  it("blocks 0.0.0.0/8", () => {
    expect(isBlockedHost("0.0.0.0")).toBe(true);
    expect(isBlockedHost("0.1.2.3")).toBe(true);
  });

  it("allows public IPs", () => {
    expect(isBlockedHost("8.8.8.8")).toBe(false);
    expect(isBlockedHost("1.1.1.1")).toBe(false);
    expect(isBlockedHost("203.0.113.10")).toBe(false);
  });

  it("allows public hostnames", () => {
    expect(isBlockedHost("api.example.com")).toBe(false);
    expect(isBlockedHost("github.com")).toBe(false);
  });
});

describe("validateUpstreamHost", () => {
  it("allows hosts in allowlist", () => {
    expect(
      validateUpstreamHost("api.stripe.com", ["api.stripe.com", "api.github.com"])
    ).toBeNull();
  });

  it("rejects hosts not in allowlist", () => {
    expect(
      validateUpstreamHost("evil.com", ["api.stripe.com"])
    ).not.toBeNull();
  });

  it("is case-insensitive for allowlist", () => {
    expect(
      validateUpstreamHost("API.STRIPE.COM", ["api.stripe.com"])
    ).toBeNull();
  });

  it("strips port before allowlist check", () => {
    expect(
      validateUpstreamHost("api.stripe.com:443", ["api.stripe.com"])
    ).toBeNull();
  });

  it("blocks private IPs in default blocklist mode", () => {
    expect(validateUpstreamHost("127.0.0.1", [])).not.toBeNull();
    expect(validateUpstreamHost("10.0.0.1", [])).not.toBeNull();
    expect(validateUpstreamHost("192.168.1.1", [])).not.toBeNull();
  });

  it("allows public hosts in default blocklist mode", () => {
    expect(validateUpstreamHost("api.example.com", [])).toBeNull();
    expect(validateUpstreamHost("8.8.8.8", [])).toBeNull();
  });
});

describe("parseHostsList", () => {
  it("returns empty array for empty string", () => {
    expect(parseHostsList("")).toEqual([]);
  });

  it("parses comma-separated hosts", () => {
    expect(parseHostsList("api.stripe.com, api.github.com")).toEqual([
      "api.stripe.com",
      "api.github.com",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Rate limiter tests
// ---------------------------------------------------------------------------

describe("RateLimiter", () => {
  it("allows requests under limit", () => {
    const rl = new RateLimiter(10, 10);
    for (let i = 0; i < 10; i++) {
      expect(rl.allow("1.2.3.4")).toBe(true);
    }
  });

  it("blocks requests over limit", () => {
    const rl = new RateLimiter(2, 2);
    expect(rl.allow("1.2.3.4")).toBe(true);
    expect(rl.allow("1.2.3.4")).toBe(true);
    expect(rl.allow("1.2.3.4")).toBe(false);
  });

  it("rate limits are per-IP", () => {
    const rl = new RateLimiter(1, 1);
    expect(rl.allow("1.1.1.1")).toBe(true);
    expect(rl.allow("2.2.2.2")).toBe(true);
    expect(rl.allow("1.1.1.1")).toBe(false);
    expect(rl.allow("2.2.2.2")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Integration tests using SELF (Cloudflare Worker test harness)
// ---------------------------------------------------------------------------

describe("Worker integration", () => {
  it("GET /health returns ok", async () => {
    const response = await SELF.fetch("https://example.com/health");
    expect(response.status).toBe(200);
    const body = (await response.json()) as { status: string; version: string };
    expect(body.status).toBe("ok");
    expect(body).toHaveProperty("version");
    expect(response.headers.get("X-Request-ID")).toBeTruthy();
  });

  it("GET /metrics returns JSON", async () => {
    const response = await SELF.fetch("https://example.com/metrics");
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      requests: unknown[];
      latency: unknown;
      upstream_errors: unknown[];
    };
    expect(body).toHaveProperty("requests");
    expect(body).toHaveProperty("latency");
    expect(body).toHaveProperty("upstream_errors");
  });

  it("rejects requests without token", async () => {
    const response = await SELF.fetch("https://example.com/api.example.com/v1/test");
    expect(response.status).toBe(401);
  });

  it("rejects requests with wrong token", async () => {
    const response = await SELF.fetch(
      "https://example.com/api.example.com/v1/test",
      { headers: { "X-Proxy-Token": "wrong-token" } }
    );
    expect(response.status).toBe(401);
  });

  it("rejects root path with valid token", async () => {
    const response = await SELF.fetch("https://example.com/", {
      headers: { "X-Proxy-Token": env.PROXY_TOKEN },
    });
    expect(response.status).toBe(400);
  });

  it("preserves client-provided X-Request-ID", async () => {
    const customID = "my-custom-request-id-123";
    const response = await SELF.fetch("https://example.com/health", {
      headers: { "X-Request-ID": customID },
    });
    expect(response.headers.get("X-Request-ID")).toBe(customID);
  });

  it("generates X-Request-ID when not provided", async () => {
    const response = await SELF.fetch("https://example.com/health");
    const id = response.headers.get("X-Request-ID");
    expect(id).toBeTruthy();
    expect(id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
    );
  });

  it("blocks SSRF to private IPs with valid token", async () => {
    const response = await SELF.fetch(
      "https://example.com/127.0.0.1/secret",
      { headers: { "X-Proxy-Token": env.PROXY_TOKEN } }
    );
    expect(response.status).toBe(403);
  });

  it("blocks SSRF to metadata endpoints with valid token", async () => {
    const response = await SELF.fetch(
      "https://example.com/169.254.169.254/latest/meta-data/",
      { headers: { "X-Proxy-Token": env.PROXY_TOKEN } }
    );
    expect(response.status).toBe(403);
  });
});
