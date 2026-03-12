/**
 * SSRF protection — mirrors the Go implementation in proxy/proxy.go.
 *
 * Two modes:
 * 1. Allowlist mode: when ALLOWED_UPSTREAM_HOSTS is set, only those hosts are
 *    permitted. All others are rejected.
 * 2. Blocklist mode (default): blocks private/reserved IP ranges and known
 *    cloud-metadata hostnames.
 */

/** Known cloud metadata and internal service hostnames. */
const BLOCKED_METADATA_HOSTS = [
  "localhost",
  "169.254.169.254", // AWS / GCP / Azure / OpenStack instance metadata
  "metadata.google.internal",
  "metadata.internal",
];

/**
 * Private and reserved IP address ranges (CIDR notation).
 * Each entry is stored as { prefix: bigint, mask: bigint, bits: 32|128 }.
 */
interface CIDRBlock {
  prefix: bigint;
  mask: bigint;
  bits: number;
}

const PRIVATE_CIDRS: CIDRBlock[] = buildCIDRBlocks([
  "127.0.0.0/8", // IPv4 loopback
  "10.0.0.0/8", // RFC 1918
  "172.16.0.0/12", // RFC 1918
  "192.168.0.0/16", // RFC 1918
  "169.254.0.0/16", // Link-local (includes cloud metadata)
  "100.64.0.0/10", // Carrier-grade NAT (RFC 6598)
  "0.0.0.0/8", // "This" network
]);

// IPv6 ranges are checked separately since Workers typically only deal
// with IPv4 in CF-Connecting-IP, but we include them for completeness.
const PRIVATE_IPV6_PREFIXES = ["::1", "fc", "fd", "fe80"];

function buildCIDRBlocks(cidrs: string[]): CIDRBlock[] {
  return cidrs.map((cidr) => {
    const [addr, prefixLen] = cidr.split("/");
    const bits = 32;
    const mask = prefixLen === "0" ? 0n : ((1n << BigInt(bits)) - 1n) << BigInt(bits - parseInt(prefixLen));
    const prefix = ipv4ToBigInt(addr) & mask;
    return { prefix, mask, bits };
  });
}

function ipv4ToBigInt(ip: string): bigint {
  const parts = ip.split(".").map(Number);
  return (
    (BigInt(parts[0]) << 24n) |
    (BigInt(parts[1]) << 16n) |
    (BigInt(parts[2]) << 8n) |
    BigInt(parts[3])
  );
}

/**
 * Parse the host, stripping any port component.
 */
function stripPort(host: string): string {
  // IPv6 bracket notation: [::1]:8080
  if (host.startsWith("[")) {
    const bracketEnd = host.indexOf("]");
    if (bracketEnd !== -1) {
      return host.slice(1, bracketEnd);
    }
  }
  // IPv4 or hostname with port
  const lastColon = host.lastIndexOf(":");
  if (lastColon !== -1) {
    // Make sure this is not an IPv6 address without brackets
    const firstColon = host.indexOf(":");
    if (firstColon === lastColon) {
      // Only one colon → host:port
      return host.slice(0, lastColon);
    }
  }
  return host;
}

/**
 * Check if an IPv4 address string is within any of the blocked CIDR ranges.
 */
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  for (const p of parts) {
    const n = parseInt(p, 10);
    if (isNaN(n) || n < 0 || n > 255) return false;
  }
  const ipBig = ipv4ToBigInt(ip);
  for (const block of PRIVATE_CIDRS) {
    if ((ipBig & block.mask) === block.prefix) {
      return true;
    }
  }
  return false;
}

/**
 * Check if a string looks like an IPv6 address and is private.
 */
function isPrivateIPv6(ip: string): boolean {
  if (!ip.includes(":")) return false;
  const normalized = ip.toLowerCase();
  if (normalized === "::1") return true;
  for (const prefix of PRIVATE_IPV6_PREFIXES) {
    if (normalized.startsWith(prefix)) return true;
  }
  return false;
}

/**
 * Returns true if the host is a private/reserved IP or known metadata endpoint.
 * Hostnames that do not parse as IPs are only checked against the static
 * metadata hostname list; full DNS resolution is not performed.
 */
export function isBlockedHost(host: string): boolean {
  const lower = host.toLowerCase();

  // Check metadata hostnames.
  for (const blocked of BLOCKED_METADATA_HOSTS) {
    if (lower === blocked) return true;
  }

  // Check private IPv4.
  if (isPrivateIPv4(host)) return true;

  // Check private IPv6.
  if (isPrivateIPv6(host)) return true;

  return false;
}

/**
 * Validate whether a target host is permitted.
 *
 * - If allowlist is non-empty, the host must appear in the list (exact match,
 *   case-insensitive, port stripped).
 * - If allowlist is empty, private/reserved IP ranges and known metadata
 *   hostnames are blocked.
 *
 * Returns null on success or an error message string on rejection.
 */
export function validateUpstreamHost(
  host: string,
  allowlist: string[]
): string | null {
  const bare = stripPort(host);

  if (allowlist.length > 0) {
    for (const allowed of allowlist) {
      if (bare.toLowerCase() === allowed.toLowerCase()) {
        return null;
      }
    }
    return `host "${bare}" is not in the allowed upstream hosts list`;
  }

  // Default: block private/reserved addresses.
  if (isBlockedHost(bare)) {
    return `host "${bare}" is a private or reserved address`;
  }
  return null;
}

/**
 * Parse a comma-separated hosts string into an array.
 */
export function parseHostsList(raw: string | undefined): string[] {
  if (!raw || raw.trim() === "") return [];
  return raw
    .split(",")
    .map((h) => h.trim())
    .filter((h) => h.length > 0);
}
