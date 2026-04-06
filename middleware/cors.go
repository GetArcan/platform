package middleware

import (
	"net/http"
	"strconv"
	"strings"
)

// CORSOptions configures CORS behavior.
type CORSOptions struct {
	AllowedOrigins []string // e.g. ["https://app.example.com"]
	AllowedMethods []string // defaults to GET, POST, PUT, DELETE, OPTIONS
	AllowedHeaders []string // defaults to Content-Type, Authorization, X-Request-Id
	MaxAge         int      // preflight cache in seconds (default 86400)
}

var (
	defaultMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	defaultHeaders = []string{"Content-Type", "Authorization", "X-Request-Id"}
)

// CORS returns middleware that handles CORS headers and preflight requests.
func CORS(opts CORSOptions) func(http.Handler) http.Handler {
	if len(opts.AllowedMethods) == 0 {
		opts.AllowedMethods = defaultMethods
	}
	if len(opts.AllowedHeaders) == 0 {
		opts.AllowedHeaders = defaultHeaders
	}
	if opts.MaxAge == 0 {
		opts.MaxAge = 86400
	}

	methods := strings.Join(opts.AllowedMethods, ", ")
	headers := strings.Join(opts.AllowedHeaders, ", ")
	maxAge := strconv.Itoa(opts.MaxAge)

	// Build a set for fast origin lookup.
	originSet := make(map[string]struct{}, len(opts.AllowedOrigins))
	allowAll := false
	for _, o := range opts.AllowedOrigins {
		if o == "*" {
			allowAll = true
		}
		originSet[o] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed.
			allowed := false
			if origin != "" {
				if allowAll {
					allowed = true
				} else if _, ok := originSet[origin]; ok {
					allowed = true
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", methods)
				w.Header().Set("Access-Control-Allow-Headers", headers)
				w.Header().Set("Access-Control-Max-Age", maxAge)
				w.Header().Set("Vary", "Origin")
			}

			// Handle preflight.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
