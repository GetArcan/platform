package auth

import (
	"context"
	"time"
)

// KeyRecord represents a stored API key.
type KeyRecord struct {
	UserID       string
	Name         string
	Capabilities []string
	ExpiresAt    *time.Time // nil = never expires
}

// KeyStore looks up API keys by hash.
// Each product implements this against their own database.
type KeyStore interface {
	LookupKeyHash(ctx context.Context, hash string) (*KeyRecord, error)
}

// UserResolver resolves a user from a JWT subject claim.
type UserResolver interface {
	ResolveUser(ctx context.Context, subject string) (userID string, err error)
}
