package proxy

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// gatewayMetrics holds the Prometheus collectors for the gateway.
type gatewayMetrics struct {
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	upstreamErrors  *prometheus.CounterVec
	registry        *prometheus.Registry
}

// newMetrics registers gateway metrics in a fresh Prometheus registry and
// returns the metrics struct. A fresh registry is used so that multiple
// calls (e.g. in tests) do not conflict with each other or with the default
// global registry.
func newMetrics() *gatewayMetrics {
	reg := prometheus.NewRegistry()

	m := &gatewayMetrics{
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "go_drp_requests_total",
			Help: "Total number of proxy requests partitioned by HTTP method and status code.",
		}, []string{"method", "status"}),

		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "go_drp_request_duration_seconds",
			Help:    "Histogram of proxy request latencies in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method"}),

		upstreamErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "go_drp_upstream_errors_total",
			Help: "Total number of upstream proxy errors partitioned by upstream host.",
		}, []string{"host"}),

		registry: reg,
	}

	reg.MustRegister(m.requestsTotal, m.requestDuration, m.upstreamErrors)
	return m
}

// metricsMiddleware wraps next, recording Prometheus request counts and
// latency for every request that passes through.
func (m *gatewayMetrics) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		elapsed := time.Since(start).Seconds()
		status := strconv.Itoa(rw.status)
		m.requestsTotal.WithLabelValues(r.Method, status).Inc()
		m.requestDuration.WithLabelValues(r.Method).Observe(elapsed)
	})
}

// handler returns the Prometheus HTTP handler for the /metrics endpoint.
func (m *gatewayMetrics) handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// statusRecorder wraps an http.ResponseWriter to capture the written status
// code so that it can be reported to Prometheus after the handler returns.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
