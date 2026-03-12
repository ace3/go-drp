package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// -- Rate limiting ------------------------------------------------------------

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := newRateLimiter(10, 10) // 10 rps, burst 10
	defer rl.stop()
	for i := range 10 {
		if !rl.getLimiter("1.2.3.4").Allow() {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := newRateLimiter(1, 1) // 1 rps, burst 1
	defer rl.stop()
	// First request consumes the burst token.
	if !rl.getLimiter("1.2.3.4").Allow() {
		t.Fatal("first request should be allowed")
	}
	// Second request should be denied immediately (no refill yet).
	if rl.getLimiter("1.2.3.4").Allow() {
		t.Fatal("second request should be denied when over limit")
	}
}

func TestHandler_RateLimit_Enforced(t *testing.T) {
	h := New(&Config{
		ProxyToken:     "tok",
		UpstreamScheme: "http",
		RateLimitRPS:   1,
		RateLimitBurst: 1,
	}, discardLogger())

	makeReq := func() int {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Proxy-Token", "tok")
		r.RemoteAddr = "5.6.7.8:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// First request: gets past rate limit, fails at path parsing (400).
	if code := makeReq(); code != http.StatusBadRequest {
		t.Errorf("1st request: status = %d, want 400 (past rate limit)", code)
	}
	// Second immediate request: blocked by rate limiter (429).
	if code := makeReq(); code != http.StatusTooManyRequests {
		t.Errorf("2nd request: status = %d, want 429 (rate limited)", code)
	}
}

func TestHandler_RateLimit_PerIP(t *testing.T) {
	h := New(&Config{
		ProxyToken:     "tok",
		UpstreamScheme: "http",
		RateLimitRPS:   1,
		RateLimitBurst: 1,
	}, discardLogger())

	makeReqFrom := func(ip string) int {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Proxy-Token", "tok")
		r.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// Two different IPs each get their own bucket; neither should be 429.
	if code := makeReqFrom("1.1.1.1"); code == http.StatusTooManyRequests {
		t.Errorf("IP 1.1.1.1: unexpected 429")
	}
	if code := makeReqFrom("2.2.2.2"); code == http.StatusTooManyRequests {
		t.Errorf("IP 2.2.2.2: unexpected 429")
	}
}

func TestHandler_NoRateLimit(t *testing.T) {
	// RateLimitRPS == 0 should disable rate limiting entirely.
	h := New(&Config{
		ProxyToken:     "tok",
		UpstreamScheme: "http",
		RateLimitRPS:   0,
	}, discardLogger())

	for i := range 20 {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Proxy-Token", "tok")
		r.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: unexpected 429 when rate limiting is disabled", i)
		}
	}
}

// -- Request IDs --------------------------------------------------------------

func TestRequestID_Generated(t *testing.T) {
	h := New(&Config{ProxyToken: "tok", UpstreamScheme: "http"}, discardLogger())

	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	id := w.Header().Get(RequestIDHeader)
	if id == "" {
		t.Error("X-Request-ID should be generated when not provided")
	}
	// UUID v4 pattern: 8-4-4-4-12 hex chars
	if len(id) != 36 {
		t.Errorf("X-Request-ID = %q, expected 36-char UUID", id)
	}
}

func TestRequestID_Preserved(t *testing.T) {
	h := New(&Config{ProxyToken: "tok", UpstreamScheme: "http"}, discardLogger())

	const clientID = "my-custom-request-id"
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	r.Header.Set(RequestIDHeader, clientID)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got := w.Header().Get(RequestIDHeader); got != clientID {
		t.Errorf("X-Request-ID = %q, want %q (client-provided ID should be preserved)", got, clientID)
	}
}

func TestRequestID_UniquePerRequest(t *testing.T) {
	h := New(&Config{ProxyToken: "tok", UpstreamScheme: "http"}, discardLogger())

	ids := make(map[string]struct{})
	for range 10 {
		r := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		id := w.Header().Get(RequestIDHeader)
		if _, dup := ids[id]; dup {
			t.Fatalf("duplicate X-Request-ID: %q", id)
		}
		ids[id] = struct{}{}
	}
}

func TestGenerateRequestID(t *testing.T) {
	id := generateRequestID()
	if len(id) != 36 {
		t.Errorf("generateRequestID() = %q, expected 36 chars", id)
	}
	// Must contain dashes at positions 8, 13, 18, 23.
	for _, pos := range []int{8, 13, 18, 23} {
		if id[pos] != '-' {
			t.Errorf("expected dash at position %d in %q", pos, id)
		}
	}
}

// -- Prometheus metrics -------------------------------------------------------

func TestMetrics_Endpoint(t *testing.T) {
	// Upstream that echoes a 200 response so metrics get recorded.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	upstreamIP, _, _ := net.SplitHostPort(upstreamHost)

	h := New(&Config{
		ProxyToken:           "tok",
		UpstreamScheme:       "http",
		AllowedUpstreamHosts: []string{upstreamIP},
	}, discardLogger())

	// Make a proxy request so that metrics are recorded.
	req := httptest.NewRequest(http.MethodGet, "/"+upstreamHost+"/ping", nil)
	req.Header.Set("X-Proxy-Token", "tok")
	h.ServeHTTP(httptest.NewRecorder(), req)

	// Now fetch /metrics.
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "go_drp_requests_total") {
		t.Error("metrics body should contain go_drp_requests_total")
	}
	if !strings.Contains(body, "go_drp_request_duration_seconds") {
		t.Error("metrics body should contain go_drp_request_duration_seconds")
	}
}

func TestMetrics_RequestCountIncremented(t *testing.T) {
	// Upstream that echoes a 200 response.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	upstreamIP, _, _ := net.SplitHostPort(upstreamHost)

	h := New(&Config{
		ProxyToken:           "tok",
		UpstreamScheme:       "http",
		AllowedUpstreamHosts: []string{upstreamIP},
	}, discardLogger())

	// Make a proxy request.
	r := httptest.NewRequest(http.MethodGet, "/"+upstreamHost+"/ping", nil)
	r.Header.Set("X-Proxy-Token", "tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("proxy request status = %d, want 200", w.Code)
	}

	// Check /metrics counts the request.
	r2 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	body := w2.Body.String()
	if !strings.Contains(body, `go_drp_requests_total{method="GET",status="200"} 1`) {
		t.Errorf("expected go_drp_requests_total counter to include GET 200, got:\n%s", body)
	}
}

func TestMetrics_UpstreamErrorCounted(t *testing.T) {
	// Handler where the allowlist points at a host that won't accept connections
	// so ReverseProxy's ErrorHandler fires.
	h := New(&Config{
		ProxyToken:           "tok",
		UpstreamScheme:       "http",
		AllowedUpstreamHosts: []string{"203.0.113.1"}, // documentation IP – unreachable in tests
		UpstreamDialTimeout:  50 * time.Millisecond,
		UpstreamResponseTimeout: 50 * time.Millisecond,
	}, discardLogger())

	r := httptest.NewRequest(http.MethodGet, "/203.0.113.1/path", nil)
	r.Header.Set("X-Proxy-Token", "tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (upstream unreachable)", w.Code)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	body := w2.Body.String()
	if !strings.Contains(body, `go_drp_upstream_errors_total{host="203.0.113.1"} 1`) {
		t.Errorf("expected upstream error counter, got:\n%s", body)
	}
}

// -- mTLS authentication ------------------------------------------------------

func TestHandler_MTLSSkipsTokenAuth(t *testing.T) {
	h := New(&Config{
		ProxyToken:     "secret",
		MTLSEnabled:    true,
		UpstreamScheme: "http",
	}, discardLogger())

	// Simulate a verified mTLS client by setting r.TLS with VerifiedChains.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// No X-Proxy-Token header — should be allowed because mTLS cert is present.
	r.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{{}}},
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// Token was skipped; reaches path parsing (empty "/" → 400), not auth (401).
	if w.Code != http.StatusBadRequest {
		t.Errorf("mTLS skip token: status = %d, want 400 (past auth)", w.Code)
	}
}

func TestHandler_MTLSFallsBackToTokenWhenNoCert(t *testing.T) {
	h := New(&Config{
		ProxyToken:     "secret",
		MTLSEnabled:    true,
		UpstreamScheme: "http",
	}, discardLogger())

	// No TLS at all (e.g., non-TLS request or missing cert): must provide token.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// r.TLS is nil – no certificate provided.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no cert, no token: status = %d, want 401", w.Code)
	}

	// With token: passes.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-Proxy-Token", "secret")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("no cert, valid token: status = %d, want 400 (past auth)", w2.Code)
	}
}

func TestHandler_MTLSDisabledRequiresToken(t *testing.T) {
	h := New(&Config{
		ProxyToken:     "secret",
		MTLSEnabled:    false,
		UpstreamScheme: "http",
	}, discardLogger())

	// Even if r.TLS has chains, token is still required when MTLSEnabled=false.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{{}}},
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("MTLSEnabled=false with cert but no token: status = %d, want 401", w.Code)
	}
}

// -- Per-upstream timeouts ----------------------------------------------------

func TestHandler_UpstreamDialTimeout(t *testing.T) {
	// Use a very short dial timeout; the upstream is an unreachable address
	// so the dial will fail quickly.
	h := New(&Config{
		ProxyToken:           "tok",
		UpstreamScheme:       "http",
		AllowedUpstreamHosts: []string{"203.0.113.1"},
		UpstreamDialTimeout:  1 * time.Millisecond,
	}, discardLogger())

	r := httptest.NewRequest(http.MethodGet, "/203.0.113.1/path", nil)
	r.Header.Set("X-Proxy-Token", "tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	// Expect 502 Bad Gateway from the ErrorHandler.
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 (dial timeout)", w.Code)
	}
}
