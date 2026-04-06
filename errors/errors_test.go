package errors

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Compile-time interface check.
var _ error = (*Error)(nil)

func TestConstructors(t *testing.T) {
	tests := []struct {
		name   string
		fn     func(string, ...any) *Error
		code   string
		status int
	}{
		{"NotFound", NotFound, CodeNotFound, 404},
		{"Validation", Validation, CodeValidation, 400},
		{"Forbidden", Forbidden, CodeForbidden, 403},
		{"Unauthorized", Unauthorized, CodeUnauthorized, 401},
		{"Conflict", Conflict, CodeConflict, 409},
		{"RateLimited", RateLimited, CodeRateLimited, 429},
		{"EngineError", EngineError, CodeEngineError, 502},
		{"Unavailable", Unavailable, CodeUnavailable, 503},
		{"Internal", Internal, CodeInternal, 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn("resource %s missing", "foo")
			if err.Code != tt.code {
				t.Errorf("code = %q, want %q", err.Code, tt.code)
			}
			if err.Status != tt.status {
				t.Errorf("status = %d, want %d", err.Status, tt.status)
			}
			if err.Message != "resource foo missing" {
				t.Errorf("message = %q, want %q", err.Message, "resource foo missing")
			}
		})
	}
}

func TestErrorMethod(t *testing.T) {
	err := NotFound("gone")
	if err.Error() != "gone" {
		t.Errorf("Error() = %q, want %q", err.Error(), "gone")
	}
}

func TestBuilders(t *testing.T) {
	cause := errors.New("db down")
	err := Internal("save failed").
		WithFix("check database connection").
		WithField("name").
		WithCause(cause)

	if err.Fix != "check database connection" {
		t.Errorf("Fix = %q", err.Fix)
	}
	if err.Field != "name" {
		t.Errorf("Field = %q", err.Field)
	}
	if err.Cause != cause {
		t.Error("Cause not set")
	}
}

func TestUnwrap(t *testing.T) {
	cause := errors.New("timeout")
	err := Unavailable("upstream timeout").WithCause(cause)

	if !errors.Is(err, cause) {
		t.Error("errors.Is should find cause via Unwrap")
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() should return cause")
	}
}

func TestUnwrapNil(t *testing.T) {
	err := NotFound("missing")
	if err.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no cause")
	}
}

func TestWriteJSON_NonServer(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	e := NotFound("user %s not found", "alice").WithFix("check user list")
	WriteJSON(w, r, e)

	if w.Code != 404 {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)

	if body["error"] != "user alice not found" {
		t.Errorf("error = %q", body["error"])
	}
	if body["code"] != "not_found" {
		t.Errorf("code = %q", body["code"])
	}
	if body["fix"] != "check user list" {
		t.Errorf("fix = %q", body["fix"])
	}
	if _, ok := body["request_id"]; ok {
		t.Error("non-500 should not include request_id")
	}
}

func TestWriteJSON_NoFix(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	WriteJSON(w, r, Validation("bad input"))

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)

	if _, ok := body["fix"]; ok {
		t.Error("fix should be omitted when empty")
	}
}

func TestWriteJSON_500WithRequestID(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Request-Id", "test-req-123")

	old := reportURL
	SetReportURL("https://example.com/issues")
	defer SetReportURL(old)

	WriteJSON(w, r, Internal("database connection lost"))

	if w.Code != 500 {
		t.Errorf("status = %d, want 500", w.Code)
	}

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)

	if body["request_id"] != "test-req-123" {
		t.Errorf("request_id = %q, want %q", body["request_id"], "test-req-123")
	}
	if body["report_url"] != "https://example.com/issues" {
		t.Errorf("report_url = %q", body["report_url"])
	}
	if body["error"] != "database connection lost" {
		t.Errorf("error = %q", body["error"])
	}
}

func TestWriteJSON_500GeneratesRequestID(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	WriteJSON(w, r, Internal("boom"))

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)

	if body["request_id"] == "" {
		t.Error("500 without X-Request-Id should generate one")
	}
}

func TestWriteJSON_500NoReportURL(t *testing.T) {
	old := reportURL
	SetReportURL("")
	defer SetReportURL(old)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	WriteJSON(w, r, Internal("fail"))

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)

	if _, ok := body["report_url"]; ok {
		t.Error("report_url should be omitted when not configured")
	}
}

func TestWriteResponse(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"status": "ok"}
	WriteResponse(w, data, http.StatusOK)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var body map[string]string
	json.NewDecoder(w.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("body = %v", body)
	}
}

func TestStatusFromCode(t *testing.T) {
	if s := StatusFromCode(CodeNotFound); s != 404 {
		t.Errorf("StatusFromCode(%q) = %d", CodeNotFound, s)
	}
	if s := StatusFromCode("unknown_code"); s != 500 {
		t.Errorf("StatusFromCode(unknown) = %d, want 500", s)
	}
}
