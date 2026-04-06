package telemetry

import (
	"context"
	"time"
)

// RequestContext carries per-request metadata through the handler chain.
type RequestContext struct {
	RequestID  string
	UserID     string
	RealmID    string
	RealmSlug  string
	AuthMethod string // "token", "jwt", "oidc", "k8s", "anonymous"
	StartTime  time.Time
}

// contextKey is an unexported type to prevent collisions with keys from other packages.
type contextKey struct{ name string }

var requestContextKey = &contextKey{"request-context"}

// WithRequestContext stores a RequestContext in the context.
func WithRequestContext(ctx context.Context, rc *RequestContext) context.Context {
	return context.WithValue(ctx, requestContextKey, rc)
}

// GetRequestContext retrieves the RequestContext from the context.
// Returns nil if not set.
func GetRequestContext(ctx context.Context) *RequestContext {
	rc, _ := ctx.Value(requestContextKey).(*RequestContext)
	return rc
}
