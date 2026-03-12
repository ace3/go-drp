package proxy

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiter holds a per-IP token-bucket limiter and a last-seen timestamp
// used for periodic cleanup.
type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// rateLimiter manages per-client-IP rate limits using a token-bucket algorithm.
type rateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*ipLimiter
	rps      rate.Limit
	burst    int
	ttl      time.Duration
	stopCh   chan struct{}
}

// newRateLimiter returns a rateLimiter that allows rps requests per second with
// a burst of burst for each unique client IP. A background goroutine evicts
// idle entries after 5 minutes.
func newRateLimiter(rps float64, burst int) *rateLimiter {
	rl := &rateLimiter{
		limiters: make(map[string]*ipLimiter),
		rps:      rate.Limit(rps),
		burst:    burst,
		ttl:      5 * time.Minute,
		stopCh:   make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

func (rl *rateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if l, ok := rl.limiters[ip]; ok {
		l.lastSeen = time.Now()
		return l.limiter
	}
	l := &ipLimiter{
		limiter:  rate.NewLimiter(rl.rps, rl.burst),
		lastSeen: time.Now(),
	}
	rl.limiters[ip] = l
	return l.limiter
}

func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-rl.ttl)
			rl.mu.Lock()
			for ip, l := range rl.limiters {
				if l.lastSeen.Before(cutoff) {
					delete(rl.limiters, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// stop terminates the background cleanup goroutine. Call when the handler is
// no longer needed (e.g. in tests or graceful shutdown).
func (rl *rateLimiter) stop() {
	close(rl.stopCh)
}

// middleware returns an http.Handler that enforces the rate limit before
// delegating to next. The client IP is extracted using trustProxy.
func (rl *rateLimiter) middleware(next http.Handler, trustProxy bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractClientIP(r, trustProxy)
		if !rl.getLimiter(ip).Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
