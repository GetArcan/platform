package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Status represents a health check result.
type Status struct {
	State   string         `json:"status"`
	Error   string         `json:"error,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// Healthy returns a healthy status.
func Healthy() Status {
	return Status{State: "healthy"}
}

// Unhealthy returns an unhealthy status with the given error.
func Unhealthy(err error) Status {
	return Status{State: "unhealthy", Error: err.Error()}
}

// Degraded returns a degraded status with the given message.
func Degraded(msg string) Status {
	return Status{State: "degraded", Error: msg}
}

// HealthyWithDetails returns a healthy status with extra data.
func HealthyWithDetails(details map[string]any) Status {
	return Status{State: "healthy", Details: details}
}

// Check is a function that tests a subsystem's health.
type Check func(ctx context.Context) Status

// Checker runs named health checks and produces a JSON response.
type Checker struct {
	version string
	commit  string
	built   string
	mode    string
	checks  map[string]Check
	start   time.Time
}

// Option configures a Checker.
type Option func(*Checker)

// WithVersion sets version metadata.
func WithVersion(version, commit, built string) Option {
	return func(c *Checker) {
		c.version = version
		c.commit = commit
		c.built = built
	}
}

// WithMode sets the operational mode (e.g. "standalone", "cluster").
func WithMode(mode string) Option {
	return func(c *Checker) {
		c.mode = mode
	}
}

// WithCheck registers a named health check.
func WithCheck(name string, check Check) Option {
	return func(c *Checker) {
		c.checks[name] = check
	}
}

// NewChecker creates a new Checker with the given options.
func NewChecker(opts ...Option) *Checker {
	c := &Checker{
		checks: make(map[string]Check),
		start:  time.Now(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// healthResponse is the JSON structure returned by the handler.
type healthResponse struct {
	Status  string            `json:"status"`
	Version string            `json:"version,omitempty"`
	Commit  string            `json:"commit,omitempty"`
	Built   string            `json:"built,omitempty"`
	Mode    string            `json:"mode,omitempty"`
	Uptime  string            `json:"uptime"`
	Checks  map[string]Status `json:"checks,omitempty"`
}

// Handler returns an http.HandlerFunc that runs all checks and returns JSON.
func (c *Checker) Handler(w http.ResponseWriter, r *http.Request) {
	overall := "ok"
	results := make(map[string]Status, len(c.checks))

	for name, check := range c.checks {
		s := check(r.Context())
		results[name] = s
		if s.State != "healthy" {
			overall = "degraded"
		}
	}

	resp := healthResponse{
		Status:  overall,
		Version: c.version,
		Commit:  c.commit,
		Built:   c.built,
		Mode:    c.mode,
		Uptime:  time.Since(c.start).Round(time.Second).String(),
		Checks:  results,
	}

	w.Header().Set("Content-Type", "application/json")

	statusCode := http.StatusOK
	if overall != "ok" {
		statusCode = http.StatusServiceUnavailable
	}
	w.WriteHeader(statusCode)

	json.NewEncoder(w).Encode(resp)
}
