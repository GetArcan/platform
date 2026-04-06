package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/GetArcan/platform/errors"
)

// Recoverer catches panics in handlers and returns a 500 JSON response.
// The panic value and stack trace are logged with the request_id.
// The client sees a structured error response, not a raw stack trace.
func Recoverer() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rv := recover(); rv != nil {
					stack := debug.Stack()

					// Convert panic value to error.
					var panicErr error
					switch v := rv.(type) {
					case error:
						panicErr = v
					default:
						panicErr = fmt.Errorf("%v", v)
					}

					reqID := r.Header.Get(headerRequestID)
					slog.Error("panic recovered",
						"request_id", reqID,
						"panic", panicErr.Error(),
						"stack", string(stack),
					)

					apiErr := errors.Internal("unexpected error").WithCause(panicErr)
					errors.WriteJSON(w, r, apiErr)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
