package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	return w.ResponseWriter.Write(b)
}

// Logger logs each request with method, path, status, duration, and request_id.
// Uses slog.Info for 2xx/3xx, slog.Warn for 4xx, slog.Error for 5xx.
func Logger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)

			duration := time.Since(start)
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", sw.status),
				slog.Float64("duration_ms", float64(duration.Microseconds())/1000.0),
				slog.String("request_id", r.Header.Get(headerRequestID)),
				slog.String("remote_addr", r.RemoteAddr),
			}

			switch {
			case sw.status >= 500:
				logger.LogAttrs(r.Context(), slog.LevelError, "request completed", attrs...)
			case sw.status >= 400:
				logger.LogAttrs(r.Context(), slog.LevelWarn, "request completed", attrs...)
			default:
				logger.LogAttrs(r.Context(), slog.LevelInfo, "request completed", attrs...)
			}
		})
	}
}
