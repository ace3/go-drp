package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go-drp/proxy"

	"github.com/joho/godotenv"
)

// version is set at build time via:
//
//	go build -ldflags "-X main.version=v1.2.3"
var version = "dev"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if err := godotenv.Load(); err != nil {
		logger.Info("no .env file found, using system environment")
	}

	proxyToken := os.Getenv("PROXY_TOKEN")
	if proxyToken == "" {
		logger.Error("PROXY_TOKEN environment variable is required")
		os.Exit(1)
	}

	cfg := &proxy.Config{
		Port:       envOrDefault("PORT", "8080"),
		ProxyToken: proxyToken,
		Version:    version,
	}

	// WHITELIST_IP accepts a comma-separated list of allowed client IPs.
	// Leave empty to allow all IPs.
	if raw := os.Getenv("WHITELIST_IP"); raw != "" {
		for _, ip := range strings.Split(raw, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				cfg.WhitelistIPs = append(cfg.WhitelistIPs, ip)
			}
		}
	}

	// ALLOWED_UPSTREAM_HOSTS accepts a comma-separated list of upstream hosts
	// the gateway is permitted to proxy to (SSRF protection).
	// Leave empty to use the default private-IP blocklist.
	if raw := os.Getenv("ALLOWED_UPSTREAM_HOSTS"); raw != "" {
		for _, h := range strings.Split(raw, ",") {
			if h = strings.TrimSpace(h); h != "" {
				cfg.AllowedUpstreamHosts = append(cfg.AllowedUpstreamHosts, h)
			}
		}
	}

	// TRUST_PROXY_HEADERS=true|1 enables trusting X-Real-IP / X-Forwarded-For.
	// Only set this when the gateway is behind a trusted reverse proxy.
	cfg.TrustProxyHeaders = isTruthy(os.Getenv("TRUST_PROXY_HEADERS"))

	// RATE_LIMIT_RPS sets the per-IP request rate (requests/second).
	// 0 (default) disables rate limiting.
	if rps, err := strconv.ParseFloat(os.Getenv("RATE_LIMIT_RPS"), 64); err == nil && rps > 0 {
		cfg.RateLimitRPS = rps
	}

	// RATE_LIMIT_BURST sets the burst size for the token-bucket limiter.
	// Defaults to RATE_LIMIT_RPS when not set.
	if burst, err := strconv.Atoi(os.Getenv("RATE_LIMIT_BURST")); err == nil && burst > 0 {
		cfg.RateLimitBurst = burst
	}

	// UPSTREAM_DIAL_TIMEOUT is the max time for a TCP connection to an upstream.
	// Accepts Go duration strings (e.g. "5s", "500ms"). Default: 10s.
	if d, err := time.ParseDuration(os.Getenv("UPSTREAM_DIAL_TIMEOUT")); err == nil && d > 0 {
		cfg.UpstreamDialTimeout = d
	}

	// UPSTREAM_RESPONSE_TIMEOUT is the max time to wait for response headers.
	// Accepts Go duration strings (e.g. "30s"). Default: 30s.
	if d, err := time.ParseDuration(os.Getenv("UPSTREAM_RESPONSE_TIMEOUT")); err == nil && d > 0 {
		cfg.UpstreamResponseTimeout = d
	}

	// mTLS: when MTLS_CA_FILE, MTLS_CERT_FILE, and MTLS_KEY_FILE are all set,
	// the server is configured to require (and verify) client TLS certificates.
	// Token auth (X-Proxy-Token) is then skipped for verified clients.
	tlsCfg, mtlsEnabled := buildTLSConfig(
		os.Getenv("MTLS_CA_FILE"),
		os.Getenv("MTLS_CERT_FILE"),
		os.Getenv("MTLS_KEY_FILE"),
		logger,
	)
	cfg.MTLSEnabled = mtlsEnabled

	handler := proxy.New(cfg, logger)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      handler,
		TLSConfig:    tlsCfg,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown on SIGINT / SIGTERM.
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		logger.Info("shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("server shutdown error", "err", err)
		}
	}()

	logger.Info("Dynamic Reverse Proxy starting",
		"port", cfg.Port,
		"version", version,
		"mtls", mtlsEnabled,
		"rate_limit_rps", cfg.RateLimitRPS,
	)

	var listenErr error
	if mtlsEnabled {
		listenErr = srv.ListenAndServeTLS("", "") // cert/key already in TLSConfig
	} else {
		listenErr = srv.ListenAndServe()
	}
	if listenErr != http.ErrServerClosed {
		logger.Error("server error", "err", listenErr)
		os.Exit(1)
	}
}

// buildTLSConfig constructs a *tls.Config for mutual TLS when all three files
// are provided. Returns (nil, false) when mTLS is not configured.
func buildTLSConfig(caFile, certFile, keyFile string, logger *slog.Logger) (*tls.Config, bool) {
	if caFile == "" || certFile == "" || keyFile == "" {
		return nil, false
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		logger.Error("mTLS: failed to load server cert/key", "err", err)
		os.Exit(1)
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		logger.Error("mTLS: failed to read CA cert file", "err", err)
		os.Exit(1)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		logger.Error("mTLS: no valid CA certificates found in CA file")
		os.Exit(1)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}, true
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func isTruthy(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes"
}
