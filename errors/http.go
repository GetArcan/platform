package errors

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// reportURL is the base URL for filing bug reports. Set via SetReportURL.
var reportURL string

// SetReportURL configures the URL template used for 500 error responses.
// The URL should point to an issue tracker (e.g. GitHub new-issue page).
func SetReportURL(url string) {
	reportURL = url
}

// WriteJSON writes a structured JSON error response. For 500 errors it logs
// the error, includes the request ID, and optionally a report URL.
func WriteJSON(w http.ResponseWriter, r *http.Request, err *Error) {
	w.Header().Set("Content-Type", "application/json")

	if err.Status >= 500 {
		reqID := r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = fmt.Sprintf("req-%d", time.Now().UnixMilli())
		}
		slog.Error(err.Message, "request_id", reqID, "code", err.Code, "error", err.Cause)

		resp := map[string]string{
			"error":      err.Message,
			"code":       err.Code,
			"request_id": reqID,
		}
		if reportURL != "" {
			resp["report_url"] = reportURL
		}

		w.WriteHeader(err.Status)
		json.NewEncoder(w).Encode(resp)
		return
	}

	resp := map[string]string{
		"error": err.Message,
		"code":  err.Code,
	}
	if err.Fix != "" {
		resp["fix"] = err.Fix
	}

	w.WriteHeader(err.Status)
	json.NewEncoder(w).Encode(resp)
}

// WriteResponse writes an arbitrary value as a JSON response with the given status.
func WriteResponse(w http.ResponseWriter, data any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
