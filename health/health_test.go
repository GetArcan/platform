package health

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewChecker_VersionInfo(t *testing.T) {
	c := NewChecker(
		WithVersion("1.0.0", "abc123", "2026-04-01T00:00:00Z"),
		WithMode("standalone"),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	c.Handler(rec, req)

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["version"] != "1.0.0" {
		t.Errorf("version = %v, want 1.0.0", resp["version"])
	}
	if resp["commit"] != "abc123" {
		t.Errorf("commit = %v, want abc123", resp["commit"])
	}
	if resp["built"] != "2026-04-01T00:00:00Z" {
		t.Errorf("built = %v, want 2026-04-01T00:00:00Z", resp["built"])
	}
	if resp["mode"] != "standalone" {
		t.Errorf("mode = %v, want standalone", resp["mode"])
	}
}

func TestChecker_AllHealthy(t *testing.T) {
	c := NewChecker(
		WithCheck("database", func(ctx context.Context) Status { return Healthy() }),
		WithCheck("encryption", func(ctx context.Context) Status { return Healthy() }),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	c.Handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status = %v, want ok", resp["status"])
	}
}

func TestChecker_OneUnhealthy(t *testing.T) {
	c := NewChecker(
		WithCheck("database", func(ctx context.Context) Status {
			return Unhealthy(errors.New("connection refused"))
		}),
		WithCheck("encryption", func(ctx context.Context) Status { return Healthy() }),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	c.Handler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "degraded" {
		t.Errorf("status = %v, want degraded", resp["status"])
	}
}

func TestChecker_Handler_JSONContentType(t *testing.T) {
	c := NewChecker()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	c.Handler(rec, req)

	ct := rec.Result().Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	body, _ := io.ReadAll(rec.Result().Body)
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Errorf("response is not valid JSON: %v\nbody: %s", err, body)
	}
}

func TestChecker_UptimeIncreases(t *testing.T) {
	c := NewChecker()

	rec1 := httptest.NewRecorder()
	c.Handler(rec1, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var resp1 map[string]any
	json.NewDecoder(rec1.Body).Decode(&resp1)
	uptime1 := resp1["uptime"].(string)

	time.Sleep(10 * time.Millisecond)

	rec2 := httptest.NewRecorder()
	c.Handler(rec2, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var resp2 map[string]any
	json.NewDecoder(rec2.Body).Decode(&resp2)
	uptime2 := resp2["uptime"].(string)

	// Both should parse as durations, and the second should be present.
	d1, err1 := time.ParseDuration(uptime1)
	d2, err2 := time.ParseDuration(uptime2)
	if err1 != nil || err2 != nil {
		t.Fatalf("failed to parse uptimes: %v, %v", err1, err2)
	}
	if d2 < d1 {
		t.Errorf("uptime did not increase: %v -> %v", d1, d2)
	}
}

func TestWithCheck_AddsNamedCheck(t *testing.T) {
	c := NewChecker(
		WithCheck("redis", func(ctx context.Context) Status { return Healthy() }),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	c.Handler(rec, req)

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	checks, ok := resp["checks"].(map[string]any)
	if !ok {
		t.Fatal("expected checks map in response")
	}
	redis, ok := checks["redis"].(map[string]any)
	if !ok {
		t.Fatal("expected redis check in response")
	}
	if redis["status"] != "healthy" {
		t.Errorf("redis status = %v, want healthy", redis["status"])
	}
}

func TestHealthyWithDetails(t *testing.T) {
	details := map[string]any{
		"connections": float64(42),
		"version":     "15.2",
	}
	s := HealthyWithDetails(details)
	if s.State != "healthy" {
		t.Errorf("state = %q, want healthy", s.State)
	}
	if s.Details["connections"] != float64(42) {
		t.Errorf("connections = %v, want 42", s.Details["connections"])
	}
	if s.Details["version"] != "15.2" {
		t.Errorf("version = %v, want 15.2", s.Details["version"])
	}

	// Verify details appear in JSON response.
	c := NewChecker(
		WithCheck("database", func(ctx context.Context) Status {
			return HealthyWithDetails(details)
		}),
	)

	rec := httptest.NewRecorder()
	c.Handler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	checks := resp["checks"].(map[string]any)
	db := checks["database"].(map[string]any)
	dbDetails := db["details"].(map[string]any)
	if dbDetails["connections"] != float64(42) {
		t.Errorf("expected connections=42 in details, got %v", dbDetails["connections"])
	}
}

func TestDegraded(t *testing.T) {
	s := Degraded("high latency")
	if s.State != "degraded" {
		t.Errorf("state = %q, want degraded", s.State)
	}
	if s.Error != "high latency" {
		t.Errorf("error = %q, want 'high latency'", s.Error)
	}
}

func TestMockChecker(t *testing.T) {
	m := NewMockChecker()

	rec := httptest.NewRecorder()
	m.Handler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("mock status = %q, want ok", resp["status"])
	}

	m.StatusOverride = "degraded"
	rec = httptest.NewRecorder()
	m.Handler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	json.NewDecoder(rec.Body).Decode(&resp)
	if resp["status"] != "degraded" {
		t.Errorf("mock status = %q, want degraded", resp["status"])
	}
}
