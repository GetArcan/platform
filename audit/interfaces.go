package audit

import (
	"context"
	"time"
)

// Event represents an auditable action.
type Event struct {
	Type      string            // "secret.created", "lease.revoked", etc.
	Timestamp time.Time
	Actor     string            // user ID or "system"
	ActorType string            // "user", "token", "system"
	Realm     string            // realm slug
	IP        string            // client IP
	Data      map[string]string // event-specific key-value pairs
	Product   string            // set automatically by dispatcher
}

// Sink delivers audit events to an external system.
type Sink interface {
	Send(ctx context.Context, event Event) error
	Name() string
}

// Store persists audit events to a database.
// This is the narrowest interface — callers implement a single method.
type Store interface {
	InsertAuditEvent(ctx context.Context, event Event) error
}
