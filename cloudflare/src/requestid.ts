/**
 * Request ID generation and propagation.
 *
 * Mirrors the Go implementation in proxy/requestid.go:
 * - Generates a UUID v4 if no X-Request-ID header is provided.
 * - Preserves client-provided IDs.
 * - Echoes the ID back in the response header.
 */

export const REQUEST_ID_HEADER = "X-Request-ID";

/**
 * Generate a cryptographically random UUID v4.
 */
export function generateRequestID(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  // Set version (4) and variant (RFC 4122) bits.
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
}

/**
 * Extracts or generates the request ID from headers.
 */
export function getRequestID(headers: Headers): string {
  return headers.get(REQUEST_ID_HEADER) || generateRequestID();
}
