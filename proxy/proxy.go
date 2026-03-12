package proxy

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

// Config holds the configuration for the gateway handler.
type Config struct {
	// Port is the port to listen on (consumed by main, not by the handler itself).
	Port string
	// ProxyToken is the shared secret required via the X-Proxy-Token header.
	// When MTLSEnabled is true and the client presents a valid certificate,
	// token auth is skipped.
	ProxyToken string
	// WhitelistIPs is an optional list of allowed client IP addresses.
	// When empty, all client IPs are allowed.
	WhitelistIPs []string
	// AllowedUpstreamHosts restricts which upstream hosts the gateway may proxy
	// to (SSRF protection). When non-empty, only those hostnames/IPs are
	// permitted. When empty, a built-in blocklist of private/reserved addresses
	// is applied instead.
	AllowedUpstreamHosts []string
	// TrustProxyHeaders controls whether X-Real-IP and X-Forwarded-For are
	// trusted for client IP extraction. Only set this to true when the gateway
	// is deployed behind a trusted reverse proxy (Nginx, Caddy, …) that sets
	// these headers. If the gateway is directly internet-facing, leave it false
	// to prevent header-spoofing attacks that bypass IP allowlisting.
	// Default: false.
	TrustProxyHeaders bool
	// Version is an optional build version string exposed on the health endpoint.
	Version string
	// UpstreamScheme is the scheme used when contacting upstream servers.
	// Defaults to "https". Set to "http" in tests.
	UpstreamScheme string

	// RateLimitRPS is the maximum number of requests per second allowed from a
	// single client IP. 0 (the default) disables rate limiting.
	RateLimitRPS float64
	// RateLimitBurst is the burst size for the token-bucket rate limiter.
	// When 0, it defaults to RateLimitRPS (i.e. no burst beyond the steady rate).
	RateLimitBurst int

	// UpstreamDialTimeout is the maximum time to wait when establishing a TCP
	// connection to an upstream server. 0 uses Go's default (no explicit timeout).
	UpstreamDialTimeout time.Duration
	// UpstreamResponseTimeout is the maximum time to wait for the upstream server
	// to send the response headers after the request is sent.
	// 0 uses Go's default (no explicit timeout).
	UpstreamResponseTimeout time.Duration

	// MTLSEnabled signals that the server is configured for mutual TLS. When
	// true, a request that arrives with a verified TLS client certificate is
	// authenticated without the X-Proxy-Token header.
	MTLSEnabled bool
}

// handler is the internal http.Handler implementation.
type handler struct {
	cfg       *Config
	logger    *slog.Logger
	rl        *rateLimiter    // nil when rate limiting is disabled
	metrics   *gatewayMetrics // always non-nil
	transport http.RoundTripper
}

// New returns an http.Handler that exposes:
//   - /health  – liveness check (no auth)
//   - /metrics – Prometheus metrics (no auth)
//   - /*       – dynamic reverse proxy (auth required)
//
// UpstreamScheme defaults to "https" when empty.
func New(cfg *Config, logger *slog.Logger) http.Handler {
	if cfg.UpstreamScheme == "" {
		cfg.UpstreamScheme = "https"
	}

	m := newMetrics()

	h := &handler{
		cfg:       cfg,
		logger:    logger,
		metrics:   m,
		transport: buildTransport(cfg),
	}

	// Optional per-IP rate limiter.
	if cfg.RateLimitRPS > 0 {
		burst := cfg.RateLimitBurst
		if burst <= 0 {
			burst = max(1, int(cfg.RateLimitRPS))
		}
		h.rl = newRateLimiter(cfg.RateLimitRPS, burst)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.handleHealth)
	mux.Handle("/metrics", m.handler())

	// Build the proxy handler chain: [rate limit →] metrics → proxy.
	var proxyH http.Handler = http.HandlerFunc(h.handleProxy)
	proxyH = m.metricsMiddleware(proxyH)
	if h.rl != nil {
		proxyH = h.rl.middleware(proxyH, cfg.TrustProxyHeaders)
	}
	mux.Handle("/", proxyH)

	// Request-ID middleware wraps the entire mux.
	return requestIDMiddleware(mux)
}

// buildTransport creates an http.RoundTripper with configurable upstream
// connection and response-header timeouts.
func buildTransport(cfg *Config) http.RoundTripper {
	dialTimeout := cfg.UpstreamDialTimeout
	if dialTimeout == 0 {
		dialTimeout = 10 * time.Second
	}
	responseTimeout := cfg.UpstreamResponseTimeout
	if responseTimeout == 0 {
		responseTimeout = 30 * time.Second
	}
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: responseTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	}
}

// handleHealth returns a JSON health/liveness response without any auth checks.
func (h *handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	version := h.cfg.Version
	if version == "" {
		version = "dev"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok","version":%q}`, version)
}

// handleProxy is the main proxy handler.
//
// Request format: /<upstream-host>/<path>?<query>
//
// Security order:
//  1. IP allowlist   (skipped when Config.WhitelistIPs is empty)
//  2. Token auth     (constant-time comparison; skipped when mTLS client cert present)
//  3. SSRF guard     (allowlist or private-IP blocklist)
//  4. Proxy forward
func (h *handler) handleProxy(w http.ResponseWriter, r *http.Request) {
	reqID := requestIDFromContext(r.Context())

	// 1. IP Allowlist Check
	if len(h.cfg.WhitelistIPs) > 0 {
		clientIP := extractClientIP(r, h.cfg.TrustProxyHeaders)
		if !containsIP(h.cfg.WhitelistIPs, clientIP) {
			h.logger.Info("blocked: IP not in whitelist",
				"ip", clientIP,
				"request_id", reqID,
			)
			http.Error(w, "Forbidden: IP not allowed", http.StatusForbidden)
			return
		}
	}

	// 2. Token Check (constant-time to resist timing attacks).
	// Skipped when mTLS is enabled and the client has presented a verified cert.
	mtlsVerified := h.cfg.MTLSEnabled && r.TLS != nil && len(r.TLS.VerifiedChains) > 0
	if !mtlsVerified {
		token := r.Header.Get("X-Proxy-Token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(h.cfg.ProxyToken)) != 1 {
			h.logger.Info("blocked: invalid or missing token",
				"remote_addr", r.RemoteAddr,
				"request_id", reqID,
			)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// 3. Parse Target
	targetHost, remainingPath, ok := parseTarget(r.URL.Path)
	if !ok {
		http.Error(w, "Bad Request: use /<host>/<path>", http.StatusBadRequest)
		return
	}

	// 4. SSRF Guard – validate the target host before opening a connection.
	if err := validateUpstreamHost(targetHost, h.cfg.AllowedUpstreamHosts); err != nil {
		h.logger.Info("blocked: upstream host rejected",
			"host", targetHost,
			"reason", err.Error(),
			"request_id", reqID,
		)
		http.Error(w, "Forbidden: upstream host not allowed", http.StatusForbidden)
		return
	}

	// 5. Proxy
	scheme := h.cfg.UpstreamScheme
	rp := &httputil.ReverseProxy{
		Transport: h.transport,
		Director: func(req *http.Request) {
			req.URL.Scheme = scheme
			req.URL.Host = targetHost
			req.URL.Path = remainingPath
			req.Host = targetHost
			// Strip the auth token so it is never forwarded to upstream APIs.
			req.Header.Del("X-Proxy-Token")
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			h.logger.Error("upstream error",
				"host", targetHost,
				"err", err,
				"request_id", requestIDFromContext(req.Context()),
			)
			h.metrics.upstreamErrors.WithLabelValues(targetHost).Inc()
			http.Error(rw, "Bad Gateway", http.StatusBadGateway)
		},
	}

	h.logger.Info("forwarding request",
		"method", r.Method,
		"target", scheme+"://"+targetHost+remainingPath,
		"query", r.URL.RawQuery,
		"request_id", reqID,
	)
	rp.ServeHTTP(w, r)
}

// parseTarget splits a URL path into an upstream host and remaining path.
//
// Examples:
//   - "/api.example.com/v1/users" -> ("api.example.com", "/v1/users", true)
//   - "/api.example.com"          -> ("api.example.com", "/",         true)
//   - "/"                         -> ("",                "",          false)
func parseTarget(urlPath string) (host, remainingPath string, ok bool) {
	path := strings.TrimPrefix(urlPath, "/")
	if path == "" {
		return "", "", false
	}
	host, rest, _ := strings.Cut(path, "/")
	if host == "" {
		return "", "", false
	}
	return host, "/" + rest, true
}

// validateUpstreamHost checks whether a target host is permitted.
//
//   - If allowlist is non-empty, the host must appear in the list (exact match,
//     case-insensitive, port stripped before comparison).
//   - If allowlist is empty, private/reserved IP ranges and known cloud-metadata
//     hostnames are blocked. Hostnames that do not resolve to IPs (e.g. public
//     FQDNs) are allowed; DNS-rebinding protection requires a resolver-level
//     control outside this function's scope.
func validateUpstreamHost(host string, allowlist []string) error {
	// Strip port for comparison.
	bare := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		bare = h
	}

	if len(allowlist) > 0 {
		for _, allowed := range allowlist {
			if strings.EqualFold(bare, allowed) {
				return nil
			}
		}
		return fmt.Errorf("host %q is not in the allowed upstream hosts list", bare)
	}

	// Default: block private/reserved addresses.
	if isBlockedHost(bare) {
		return fmt.Errorf("host %q is a private or reserved address", bare)
	}
	return nil
}

// blockedMetadataHosts lists known cloud metadata and internal service hostnames.
var blockedMetadataHosts = []string{
	"localhost",
	"169.254.169.254", // AWS / GCP / Azure / OpenStack instance metadata
	"metadata.google.internal",
	"metadata.internal",
}

// privateIPNets holds private and reserved IP address ranges.
var privateIPNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // Link-local (includes cloud metadata 169.254.169.254)
		"100.64.0.0/10",  // Carrier-grade NAT (RFC 6598)
		"0.0.0.0/8",      // "This" network
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateIPNets = append(privateIPNets, network)
		}
	}
}

// isBlockedHost returns true for private/reserved IPs and known metadata endpoints.
// Hostnames that do not parse as IPs are only checked against the static
// metadata hostname list; full DNS resolution is not performed here.
func isBlockedHost(host string) bool {
	for _, blocked := range blockedMetadataHosts {
		if strings.EqualFold(host, blocked) {
			return true
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range privateIPNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// extractClientIP returns the real client IP address.
// When trustProxy is true, X-Real-IP then X-Forwarded-For (first entry) are
// checked before falling back to RemoteAddr. Only enable trustProxy when the
// gateway sits behind a trusted reverse proxy that controls these headers;
// otherwise a client can forge them to bypass IP allowlisting.
func extractClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			return strings.TrimSpace(ip)
		}
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			first, _, _ := strings.Cut(fwd, ",")
			return strings.TrimSpace(first)
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// containsIP reports whether ip is present in list.
func containsIP(list []string, ip string) bool {
	for _, allowed := range list {
		if allowed == ip {
			return true
		}
	}
	return false
}
