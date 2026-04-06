package middleware

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/GetArcan/platform/telemetry"
)

const headerRequestID = "X-Request-Id"

// RequestID generates or extracts X-Request-Id header.
// If the incoming request has X-Request-Id, it is preserved.
// Otherwise, a new UUID is generated.
// The ID is set on both the response header and the request context
// via telemetry.WithRequestContext.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(headerRequestID)
			if id == "" {
				id = uuid.New().String()
			}

			// Set on response header.
			w.Header().Set(headerRequestID, id)

			// Set on request header so downstream reads see it.
			r.Header.Set(headerRequestID, id)

			// Store in context via telemetry.RequestContext.
			rc := telemetry.GetRequestContext(r.Context())
			if rc == nil {
				rc = &telemetry.RequestContext{
					RequestID: id,
					StartTime: time.Now(),
				}
			} else {
				rc.RequestID = id
			}
			ctx := telemetry.WithRequestContext(r.Context(), rc)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
