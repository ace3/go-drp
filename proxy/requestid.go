package proxy

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
)

type contextKey string

const requestIDKey contextKey = "request-id"

// RequestIDHeader is the header name used to carry the request ID.
const RequestIDHeader = "X-Request-ID"

// generateRequestID creates a random UUID v4 string.
func generateRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("go-drp: crypto/rand unavailable: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// requestIDFromContext retrieves the request ID stored in the context.
func requestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// requestIDMiddleware ensures every request carries an X-Request-ID. If the
// client supplies one it is preserved and echoed in the response header;
// otherwise a fresh UUID v4 is generated.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if id == "" {
			id = generateRequestID()
			r.Header.Set(RequestIDHeader, id)
		}
		w.Header().Set(RequestIDHeader, id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
