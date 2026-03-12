package proxy

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

// Config holds the configuration for the gateway handler.
type Config struct {
	// Port is the port to listen on (consumed by main, not by the handler itself).
	Port string
	// ProxyToken is the shared secret required via the X-Proxy-Token header.
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
}

// handler is the internal http.Handler implementation.
type handler struct {
	cfg    *Config
	logger *slog.Logger
}

// New returns an http.Handler that exposes a /health endpoint (no auth) and
// routes every other request through the dynamic reverse proxy.
// UpstreamScheme defaults to "https" when empty.
func New(cfg *Config, logger *slog.Logger) http.Handler {
	if cfg.UpstreamScheme == "" {
		cfg.UpstreamScheme = "https"
	}
	h := &handler{cfg: cfg, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.handleHealth)
	mux.HandleFunc("/", h.handleProxy)
	return mux
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
//  2. Token auth     (constant-time comparison)
//  3. SSRF guard     (allowlist or private-IP blocklist)
//  4. Proxy forward
func (h *handler) handleProxy(w http.ResponseWriter, r *http.Request) {
	// 1. IP Allowlist Check
	if len(h.cfg.WhitelistIPs) > 0 {
		clientIP := extractClientIP(r, h.cfg.TrustProxyHeaders)
		if !containsIP(h.cfg.WhitelistIPs, clientIP) {
			h.logger.Info("blocked: IP not in whitelist", "ip", clientIP)
			http.Error(w, "Forbidden: IP not allowed", http.StatusForbidden)
			return
		}
	}

	// 2. Token Check (constant-time to resist timing attacks)
	token := r.Header.Get("X-Proxy-Token")
	if subtle.ConstantTimeCompare([]byte(token), []byte(h.cfg.ProxyToken)) != 1 {
		h.logger.Info("blocked: invalid or missing token", "remote_addr", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 3. Parse Target
	targetHost, remainingPath, ok := parseTarget(r.URL.Path)
	if !ok {
		http.Error(w, "Bad Request: use /<host>/<path>", http.StatusBadRequest)
		return
	}

	// 4. SSRF Guard – validate the target host before opening a connection.
	if err := validateUpstreamHost(targetHost, h.cfg.AllowedUpstreamHosts); err != nil {
		h.logger.Info("blocked: upstream host rejected", "host", targetHost, "reason", err.Error())
		http.Error(w, "Forbidden: upstream host not allowed", http.StatusForbidden)
		return
	}

	// 5. Proxy
	scheme := h.cfg.UpstreamScheme
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = scheme
			req.URL.Host = targetHost
			req.URL.Path = remainingPath
			req.Host = targetHost
			// Strip the auth token so it is never forwarded to upstream APIs.
			req.Header.Del("X-Proxy-Token")
		},
	}

	h.logger.Info("forwarding request",
		"method", r.Method,
		"target", scheme+"://"+targetHost+remainingPath,
		"query", r.URL.RawQuery,
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
