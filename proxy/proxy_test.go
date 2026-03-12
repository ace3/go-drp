package proxy

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// -- parseTarget --------------------------------------------------------------

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name          string
		urlPath       string
		wantHost      string
		wantRemaining string
		wantOK        bool
	}{
		{
			name:          "full path",
			urlPath:       "/api.example.com/v1/users",
			wantHost:      "api.example.com",
			wantRemaining: "/v1/users",
			wantOK:        true,
		},
		{
			name:          "host only no trailing slash",
			urlPath:       "/api.example.com",
			wantHost:      "api.example.com",
			wantRemaining: "/",
			wantOK:        true,
		},
		{
			name:          "host with trailing slash",
			urlPath:       "/api.example.com/",
			wantHost:      "api.example.com",
			wantRemaining: "/",
			wantOK:        true,
		},
		{
			name:          "deep nested path",
			urlPath:       "/host.com/a/b/c/d",
			wantHost:      "host.com",
			wantRemaining: "/a/b/c/d",
			wantOK:        true,
		},
		{
			name:          "host with port",
			urlPath:       "/127.0.0.1:8080/api/data",
			wantHost:      "127.0.0.1:8080",
			wantRemaining: "/api/data",
			wantOK:        true,
		},
		{
			name:    "root slash only",
			urlPath: "/",
			wantOK:  false,
		},
		{
			name:    "empty string",
			urlPath: "",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotRemaining, gotOK := parseTarget(tt.urlPath)
			if gotOK != tt.wantOK {
				t.Fatalf("parseTarget(%q) ok = %v, want %v", tt.urlPath, gotOK, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if gotHost != tt.wantHost {
				t.Errorf("host = %q, want %q", gotHost, tt.wantHost)
			}
			if gotRemaining != tt.wantRemaining {
				t.Errorf("remainingPath = %q, want %q", gotRemaining, tt.wantRemaining)
			}
		})
	}
}

// -- extractClientIP ----------------------------------------------------------

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		trustProxy bool
		wantIP     string
	}{
		{
			name:       "plain RemoteAddr",
			remoteAddr: "192.168.1.1:12345",
			wantIP:     "192.168.1.1",
		},
		{
			name:       "X-Real-IP ignored when trustProxy=false",
			remoteAddr: "10.0.0.1:9999",
			headers:    map[string]string{"X-Real-IP": "203.0.113.5"},
			trustProxy: false,
			wantIP:     "10.0.0.1",
		},
		{
			name:       "X-Real-IP takes priority over RemoteAddr when trustProxy=true",
			remoteAddr: "10.0.0.1:9999",
			headers:    map[string]string{"X-Real-IP": "203.0.113.5"},
			trustProxy: true,
			wantIP:     "203.0.113.5",
		},
		{
			name:       "X-Forwarded-For uses first entry when trustProxy=true",
			remoteAddr: "10.0.0.1:9999",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.5, 10.0.0.1"},
			trustProxy: true,
			wantIP:     "203.0.113.5",
		},
		{
			name:       "X-Forwarded-For ignored when trustProxy=false",
			remoteAddr: "10.0.0.1:9999",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.5, 10.0.0.1"},
			trustProxy: false,
			wantIP:     "10.0.0.1",
		},
		{
			name:       "X-Real-IP beats X-Forwarded-For when trustProxy=true",
			remoteAddr: "10.0.0.1:9999",
			headers: map[string]string{
				"X-Real-IP":       "203.0.113.1",
				"X-Forwarded-For": "203.0.113.5",
			},
			trustProxy: true,
			wantIP:     "203.0.113.1",
		},
		{
			name:       "X-Forwarded-For strips extra whitespace",
			remoteAddr: "10.0.0.1:9999",
			headers:    map[string]string{"X-Forwarded-For": "  203.0.113.5  , 10.0.0.1"},
			trustProxy: true,
			wantIP:     "203.0.113.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			if got := extractClientIP(r, tt.trustProxy); got != tt.wantIP {
				t.Errorf("extractClientIP() = %q, want %q", got, tt.wantIP)
			}
		})
	}
}

// -- Handler: token auth ------------------------------------------------------

func TestHandler_TokenAuth(t *testing.T) {
	h := New(&Config{ProxyToken: "secret", UpstreamScheme: "http"}, discardLogger())

	tests := []struct {
		name       string
		token      string
		wantStatus int
	}{
		// Valid token passes auth and reaches path parsing (empty "/" path -> 400).
		{"valid token", "secret", http.StatusBadRequest},
		{"missing token", "", http.StatusUnauthorized},
		{"wrong token", "bad-token", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.token != "" {
				r.Header.Set("X-Proxy-Token", tt.token)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

// -- Handler: IP whitelist ----------------------------------------------------

func TestHandler_IPWhitelist(t *testing.T) {
	h := New(&Config{
		ProxyToken:        "token",
		WhitelistIPs:      []string{"192.168.1.100"},
		TrustProxyHeaders: true, // needed so X-Real-IP is honoured in tests
		UpstreamScheme:    "http",
	}, discardLogger())

	tests := []struct {
		name       string
		remoteAddr string
		xRealIP    string
		wantStatus int
	}{
		// Passes IP check -> reaches path parsing (empty path -> 400).
		{"allowed IP via RemoteAddr", "192.168.1.100:5000", "", http.StatusBadRequest},
		{"blocked IP", "10.0.0.1:5000", "", http.StatusForbidden},
		// Allowed via X-Real-IP even when RemoteAddr is a different IP.
		{"allowed via X-Real-IP", "10.0.0.1:5000", "192.168.1.100", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			r.Header.Set("X-Proxy-Token", "token")
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

// -- Handler: no whitelist allows all IPs -------------------------------------

func TestHandler_NoWhitelistAllowsAll(t *testing.T) {
	h := New(&Config{ProxyToken: "tok", UpstreamScheme: "http"}, discardLogger())

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:9999"
	r.Header.Set("X-Proxy-Token", "tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	// Reaches path parsing (empty "/" -> 400), not IP blocked (403).
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (IP check skipped)", w.Code)
	}
}

// -- Handler: bad path --------------------------------------------------------

func TestHandler_BadRequestOnEmptyHost(t *testing.T) {
	h := New(&Config{ProxyToken: "tok", UpstreamScheme: "http"}, discardLogger())

	tests := []struct {
		path       string
		wantStatus int
	}{
		// Proxy handler receives path "/" → no target host → 400.
		{"/", http.StatusBadRequest},
		// http.ServeMux redirects a missing leading slash ("") to "/".
		{"", http.StatusMovedPermanently},
	}

	for _, tt := range tests {
		t.Run("path="+tt.path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.URL.Path = tt.path
			r.Header.Set("X-Proxy-Token", "tok")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tt.wantStatus {
				t.Errorf("path=%q: status = %d, want %d", tt.path, w.Code, tt.wantStatus)
			}
		})
	}
}

// -- Handler: proxy forwarding ------------------------------------------------

func TestHandler_ProxyForwarding(t *testing.T) {
	// Fake upstream that echoes back what it received.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Received-Path", r.URL.Path)
		w.Header().Set("X-Received-Query", r.URL.RawQuery)
		w.Header().Set("X-Received-Method", r.Method)
		w.Header().Set("X-Got-Token", r.Header.Get("X-Proxy-Token"))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream response")
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	// Extract bare hostname (no port) for the allowlist.
	upstreamIP, _, _ := net.SplitHostPort(upstreamHost)
	h := New(&Config{
		ProxyToken:           "tok",
		UpstreamScheme:       "http",
		AllowedUpstreamHosts: []string{upstreamIP}, // allow loopback test server
	}, discardLogger())

	tests := []struct {
		name          string
		path          string
		query         string
		method        string
		wantPath      string
		wantQuery     string
		wantTokenGone bool
	}{
		{
			name:          "GET with multi-segment path",
			path:          "/" + upstreamHost + "/api/v1/users",
			method:        http.MethodGet,
			wantPath:      "/api/v1/users",
			wantTokenGone: true,
		},
		{
			name:          "query parameters are preserved",
			path:          "/" + upstreamHost + "/search",
			query:         "q=hello&page=2",
			method:        http.MethodGet,
			wantPath:      "/search",
			wantQuery:     "q=hello&page=2",
			wantTokenGone: true,
		},
		{
			name:          "host-only path maps to upstream root",
			path:          "/" + upstreamHost,
			method:        http.MethodGet,
			wantPath:      "/",
			wantTokenGone: true,
		},
		{
			name:          "POST method is forwarded",
			path:          "/" + upstreamHost + "/data",
			method:        http.MethodPost,
			wantPath:      "/data",
			wantTokenGone: true,
		},
		{
			name:          "X-Proxy-Token is stripped from upstream request",
			path:          "/" + upstreamHost + "/secure",
			method:        http.MethodGet,
			wantPath:      "/secure",
			wantTokenGone: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.path
			if tt.query != "" {
				target += "?" + tt.query
			}
			r := httptest.NewRequest(tt.method, target, nil)
			r.Header.Set("X-Proxy-Token", "tok")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			if got := w.Header().Get("X-Received-Path"); got != tt.wantPath {
				t.Errorf("upstream path = %q, want %q", got, tt.wantPath)
			}
			if tt.wantQuery != "" {
				if got := w.Header().Get("X-Received-Query"); got != tt.wantQuery {
					t.Errorf("upstream query = %q, want %q", got, tt.wantQuery)
				}
			}
			if tt.wantTokenGone {
				if got := w.Header().Get("X-Got-Token"); got != "" {
					t.Errorf("X-Proxy-Token should be stripped, upstream got %q", got)
				}
			}
		})
	}
}

// -- helpers ------------------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// -- validateUpstreamHost -----------------------------------------------------

func TestValidateUpstreamHost(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		allowlist []string
		wantErr   bool
	}{
		// Allowlist mode: only listed hosts pass.
		{"allowlist: exact match", "api.example.com", []string{"api.example.com"}, false},
		{"allowlist: case-insensitive", "API.EXAMPLE.COM", []string{"api.example.com"}, false},
		{"allowlist: host with port stripped", "api.example.com:443", []string{"api.example.com"}, false},
		{"allowlist: not in list", "evil.internal", []string{"api.example.com"}, true},

		// Default blocklist mode (empty allowlist).
		{"blocklist: public hostname allowed", "api.example.com", nil, false},
		{"blocklist: localhost blocked", "localhost", nil, true},
		{"blocklist: loopback IP blocked", "127.0.0.1", nil, true},
		{"blocklist: RFC1918 10.x blocked", "10.0.0.1", nil, true},
		{"blocklist: RFC1918 192.168.x blocked", "192.168.1.1", nil, true},
		{"blocklist: RFC1918 172.16.x blocked", "172.16.0.1", nil, true},
		{"blocklist: link-local blocked", "169.254.169.254", nil, true},
		{"blocklist: metadata hostname blocked", "metadata.google.internal", nil, true},
		{"blocklist: IPv6 loopback blocked", "::1", nil, true},
		{"blocklist: public IP allowed", "203.0.113.5", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUpstreamHost(tt.host, tt.allowlist)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUpstreamHost(%q) error = %v, wantErr %v", tt.host, err, tt.wantErr)
			}
		})
	}
}

// -- Handler: SSRF protection -------------------------------------------------

func TestHandler_SSRFBlocked(t *testing.T) {
	h := New(&Config{ProxyToken: "tok", UpstreamScheme: "http"}, discardLogger())

	for _, host := range []string{"localhost", "127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1"} {
		t.Run("blocked_"+host, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/"+host+"/secret", nil)
			r.Header.Set("X-Proxy-Token", "tok")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Errorf("host %q: status = %d, want 403 (SSRF blocked)", host, w.Code)
			}
		})
	}
}

func TestHandler_SSRFAllowlist(t *testing.T) {
	h := New(&Config{
		ProxyToken:           "tok",
		UpstreamScheme:       "http",
		AllowedUpstreamHosts: []string{"allowed.example.com"},
	}, discardLogger())

	// Blocked even though it's a public hostname (not in allowlist).
	r := httptest.NewRequest(http.MethodGet, "/other.example.com/path", nil)
	r.Header.Set("X-Proxy-Token", "tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (not in allowlist)", w.Code)
	}
}

// -- Handler: health endpoint -------------------------------------------------

func TestHandler_Health(t *testing.T) {
	h := New(&Config{ProxyToken: "tok", Version: "v1.2.3"}, discardLogger())

	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	// No token required for health check.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("body %q does not contain status:ok", body)
	}
	if !strings.Contains(body, "v1.2.3") {
		t.Errorf("body %q does not contain version", body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}
