package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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

	handler := proxy.New(cfg, logger)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      handler,
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

	logger.Info("Jakarta Secure Gateway starting", "port", cfg.Port, "version", version)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
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
