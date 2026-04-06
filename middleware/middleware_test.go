package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/GetArcan/platform/telemetry"
)

// --- RequestID tests ---

func TestRequestID_GeneratesUUID(t *testing.T) {
	handler := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	id := rec.Header().Get("X-Request-Id")
	if id == "" {
		t.Fatal("expected X-Request-Id header to be set")
	}
	// UUID v4 format: 8-4-4-4-12
	if len(id) != 36 {
		t.Fatalf("expected UUID format (36 chars), got %q (%d chars)", id, len(id))
	}
}

func TestRequestID_PreservesExisting(t *testing.T) {
	handler := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "custom-id-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	id := rec.Header().Get("X-Request-Id")
	if id != "custom-id-123" {
		t.Fatalf("expected preserved id %q, got %q", "custom-id-123", id)
	}
}

func TestRequestID_SetsResponseHeader(t *testing.T) {
	var ctxID string
	handler := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := telemetry.GetRequestContext(r.Context())
		if rc != nil {
			ctxID = rc.RequestID
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	headerID := rec.Header().Get("X-Request-Id")
	if headerID == "" {
		t.Fatal("expected X-Request-Id response header")
	}
	if ctxID != headerID {
		t.Fatalf("context ID %q != header ID %q", ctxID, headerID)
	}
}

// --- Logger tests ---

// captureHandler is a slog.Handler that captures log records.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *captureHandler) last() slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.records[len(h.records)-1]
}

func TestLogger_LogsCorrectFields(t *testing.T) {
	ch := &captureHandler{}
	logger := slog.New(ch)

	handler := Logger(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test-path", nil)
	req.Header.Set("X-Request-Id", "log-test-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	record := ch.last()

	// Check that expected attrs exist.
	attrs := map[string]bool{}
	record.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = true
		return true
	})

	for _, key := range []string{"method", "path", "status", "duration_ms", "request_id", "remote_addr"} {
		if !attrs[key] {
			t.Errorf("missing log attribute %q", key)
		}
	}
}

func TestLogger_CorrectLevels(t *testing.T) {
	tests := []struct {
		status int
		level  slog.Level
	}{
		{200, slog.LevelInfo},
		{301, slog.LevelInfo},
		{404, slog.LevelWarn},
		{422, slog.LevelWarn},
		{500, slog.LevelError},
		{503, slog.LevelError},
	}

	for _, tt := range tests {
		ch := &captureHandler{}
		logger := slog.New(ch)

		handler := Logger(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tt.status)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		record := ch.last()
		if record.Level != tt.level {
			t.Errorf("status %d: expected level %v, got %v", tt.status, tt.level, record.Level)
		}
	}
}

// --- RateLimit tests ---

func TestRateLimit_AllowsUnderLimit(t *testing.T) {
	handler := RateLimit(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRateLimit_Returns429WhenExceeded(t *testing.T) {
	handler := RateLimit(2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Send 3 requests rapidly from the same IP; the 3rd should be rejected.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.2:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if i < 2 && rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, rec.Code)
		}
		if i == 2 {
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("request %d: expected 429, got %d", i, rec.Code)
			}
			// Verify JSON body.
			var body map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode body: %v", err)
			}
			if body["code"] != "rate_limited" {
				t.Fatalf("expected code rate_limited, got %q", body["code"])
			}
		}
	}
}

// --- CORS tests ---

func TestCORS_SetsHeadersForAllowedOrigin(t *testing.T) {
	handler := CORS(CORSOptions{
		AllowedOrigins: []string{"https://app.example.com"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("expected origin header %q, got %q", "https://app.example.com", got)
	}
	if !strings.Contains(rec.Header().Get("Access-Control-Allow-Methods"), "GET") {
		t.Fatal("expected default methods to include GET")
	}
}

func TestCORS_DoesNotSetHeadersForDisallowedOrigin(t *testing.T) {
	handler := CORS(CORSOptions{
		AllowedOrigins: []string{"https://app.example.com"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no origin header for disallowed origin, got %q", got)
	}
}

func TestCORS_HandlesPreflight(t *testing.T) {
	handler := CORS(CORSOptions{
		AllowedOrigins: []string{"https://app.example.com"},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for OPTIONS preflight")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for preflight, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("expected origin header on preflight, got %q", got)
	}
}

// --- Recoverer tests ---

func TestRecoverer_CatchesPanicAndReturns500(t *testing.T) {
	handler := Recoverer()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("something went wrong")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "panic-test-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["code"] != "internal" {
		t.Fatalf("expected code internal, got %q", body["code"])
	}
	if body["request_id"] != "panic-test-id" {
		t.Fatalf("expected request_id panic-test-id, got %q", body["request_id"])
	}
}

func TestRecoverer_LogsPanicWithRequestID(t *testing.T) {
	ch := &captureHandler{}
	slog.SetDefault(slog.New(ch))
	defer slog.SetDefault(slog.Default())

	handler := Recoverer()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic value")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "log-panic-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if len(ch.records) == 0 {
		t.Fatal("expected panic to be logged")
	}

	// Check that at least one record has the panic info.
	found := false
	for _, r := range ch.records {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "panic" && strings.Contains(a.Value.String(), "test panic value") {
				found = true
				return false
			}
			return true
		})
	}
	if !found {
		t.Fatal("expected log record with panic attribute")
	}
}

// --- TLS tests ---

func TestTLSConfig_GeneratesSelfSigned(t *testing.T) {
	dir := t.TempDir()

	cfg, err := TLSConfig("", "", dir)
	if err != nil {
		t.Fatalf("TLSConfig failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if len(cfg.Certificates) == 0 {
		t.Fatal("expected at least one certificate")
	}
}

func TestTLSConfig_GeneratedFilesExistWithCorrectPermissions(t *testing.T) {
	dir := t.TempDir()

	_, err := TLSConfig("", "", dir)
	if err != nil {
		t.Fatalf("TLSConfig failed: %v", err)
	}

	for _, name := range []string{"cert.pem", "key.pem"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Errorf("%s: expected permissions 0600, got %04o", name, perm)
		}
	}
}
