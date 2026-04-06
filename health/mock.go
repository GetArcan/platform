package health

import (
	"encoding/json"
	"net/http"
)

// MockChecker is a test double for health checks.
type MockChecker struct {
	StatusOverride string // "ok", "degraded"
}

// NewMockChecker creates a new MockChecker with "ok" status.
func NewMockChecker() *MockChecker {
	return &MockChecker{StatusOverride: "ok"}
}

// Handler returns a simple JSON health response using the overridden status.
func (m *MockChecker) Handler(w http.ResponseWriter, r *http.Request) {
	resp := map[string]string{
		"status": m.StatusOverride,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
