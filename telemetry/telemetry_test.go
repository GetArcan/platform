package telemetry

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSetupLogging_Text(t *testing.T) {
	SetupLogging("text", "debug")
	handler := slog.Default().Handler()
	if handler == nil {
		t.Fatal("expected non-nil handler after SetupLogging")
	}
	// Verify debug level is enabled.
	if !handler.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected debug level to be enabled")
	}
}

func TestSetupLogging_JSON(t *testing.T) {
	SetupLogging("json", "warn")
	handler := slog.Default().Handler()
	if handler == nil {
		t.Fatal("expected non-nil handler after SetupLogging")
	}
	// Debug and Info should be disabled at warn level.
	if handler.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected debug level to be disabled at warn level")
	}
	if handler.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("expected info level to be disabled at warn level")
	}
	if !handler.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("expected warn level to be enabled")
	}
}

func TestSetupLogging_Defaults(t *testing.T) {
	SetupLogging("", "")
	handler := slog.Default().Handler()
	if handler == nil {
		t.Fatal("expected non-nil handler after SetupLogging with defaults")
	}
	// Default level is info.
	if handler.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected debug to be disabled at default info level")
	}
	if !handler.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("expected info to be enabled at default level")
	}
}

func TestWithRequestContext_RoundTrip(t *testing.T) {
	rc := &RequestContext{
		RequestID:  "req-123",
		UserID:     "user-456",
		RealmID:    "realm-789",
		RealmSlug:  "acme",
		AuthMethod: "jwt",
		StartTime:  time.Now(),
	}
	ctx := WithRequestContext(context.Background(), rc)
	got := GetRequestContext(ctx)
	if got == nil {
		t.Fatal("expected non-nil RequestContext")
	}
	if got.RequestID != "req-123" {
		t.Errorf("RequestID = %q, want %q", got.RequestID, "req-123")
	}
	if got.UserID != "user-456" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user-456")
	}
	if got.RealmID != "realm-789" {
		t.Errorf("RealmID = %q, want %q", got.RealmID, "realm-789")
	}
	if got.RealmSlug != "acme" {
		t.Errorf("RealmSlug = %q, want %q", got.RealmSlug, "acme")
	}
	if got.AuthMethod != "jwt" {
		t.Errorf("AuthMethod = %q, want %q", got.AuthMethod, "jwt")
	}
}

func TestGetRequestContext_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	got := GetRequestContext(ctx)
	if got != nil {
		t.Errorf("expected nil RequestContext from empty context, got %+v", got)
	}
}

func TestCounter_Inc(t *testing.T) {
	c := NewCounter("test_total")
	c.Inc()
	c.Inc()
	c.Inc()
	if got := c.values[""]; got != 3 {
		t.Errorf("counter value = %d, want 3", got)
	}
}

func TestCounter_Add(t *testing.T) {
	c := NewCounter("test_total", "method")
	c.Add(5, "GET")
	c.Add(3, "POST")
	c.Add(2, "GET")
	if got := c.values[labelKey([]string{"GET"})]; got != 7 {
		t.Errorf("counter GET = %d, want 7", got)
	}
	if got := c.values[labelKey([]string{"POST"})]; got != 3 {
		t.Errorf("counter POST = %d, want 3", got)
	}
}

func TestHistogram_Observe(t *testing.T) {
	h := NewHistogram("request_duration", "method")
	h.Observe(0.1, "GET")
	h.Observe(0.2, "GET")
	h.Observe(0.5, "POST")

	getVals := h.values[labelKey([]string{"GET"})]
	if len(getVals) != 2 {
		t.Fatalf("GET observations = %d, want 2", len(getVals))
	}
	postVals := h.values[labelKey([]string{"POST"})]
	if len(postVals) != 1 {
		t.Fatalf("POST observations = %d, want 1", len(postVals))
	}
}

func TestRegistry_Handler_PrometheusFormat(t *testing.T) {
	reg := NewRegistry()

	c := NewCounter("http_requests_total", "method")
	c.Add(10, "GET")
	c.Add(5, "POST")
	reg.RegisterCounter(c)

	h := NewHistogram("request_duration_seconds", "method")
	h.Observe(0.1, "GET")
	h.Observe(0.2, "GET")
	reg.RegisterHistogram(h)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reg.Handler()(rec, req)

	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	output := string(body)

	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if !strings.Contains(output, "# TYPE http_requests_total counter") {
		t.Errorf("missing counter TYPE line in output:\n%s", output)
	}
	if !strings.Contains(output, `http_requests_total{method="GET"} 10`) {
		t.Errorf("missing GET counter line in output:\n%s", output)
	}
	if !strings.Contains(output, `http_requests_total{method="POST"} 5`) {
		t.Errorf("missing POST counter line in output:\n%s", output)
	}
	if !strings.Contains(output, "# TYPE request_duration_seconds histogram") {
		t.Errorf("missing histogram TYPE line in output:\n%s", output)
	}
	if !strings.Contains(output, "request_duration_seconds_count") {
		t.Errorf("missing histogram count line in output:\n%s", output)
	}
	if !strings.Contains(output, "request_duration_seconds_sum") {
		t.Errorf("missing histogram sum line in output:\n%s", output)
	}
}

func TestCounter_NoLabels(t *testing.T) {
	reg := NewRegistry()
	c := NewCounter("simple_counter")
	c.Inc()
	reg.RegisterCounter(c)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reg.Handler()(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	output := string(body)
	if !strings.Contains(output, "simple_counter 1") {
		t.Errorf("expected 'simple_counter 1' in output:\n%s", output)
	}
}
