package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/GetArcan/platform/errors"
)

type bucket struct {
	tokens   float64
	lastTime time.Time
}

// RateLimit returns middleware that limits requests per IP address.
// Uses a simple token bucket algorithm with per-IP tracking.
// rps is the allowed requests per second per IP.
func RateLimit(rps int) func(http.Handler) http.Handler {
	var buckets sync.Map
	rate := float64(rps)
	maxTokens := float64(rps)

	// Periodically clean up stale entries.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-10 * time.Minute)
			buckets.Range(func(key, value any) bool {
				b := value.(*bucket)
				if b.lastTime.Before(cutoff) {
					buckets.Delete(key)
				}
				return true
			})
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)

			val, _ := buckets.LoadOrStore(ip, &bucket{
				tokens:   maxTokens,
				lastTime: time.Now(),
			})
			b := val.(*bucket)

			now := time.Now()
			elapsed := now.Sub(b.lastTime).Seconds()
			b.tokens += elapsed * rate
			if b.tokens > maxTokens {
				b.tokens = maxTokens
			}
			b.lastTime = now

			if b.tokens < 1 {
				apiErr := errors.RateLimited("too many requests")
				errors.WriteJSON(w, r, apiErr)
				return
			}

			b.tokens--
			next.ServeHTTP(w, r)
		})
	}
}

// extractIP returns the client IP from the request, stripping the port.
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For first.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain.
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
