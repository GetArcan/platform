package store

import (
	"context"
	"database/sql"
	"io"
)

// DB wraps a *sql.DB with health check and helpers.
type DB interface {
	// Standard database/sql methods
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row

	// Health
	HealthCheck(ctx context.Context) error

	// Underlying
	RawDB() *sql.DB

	// Close
	io.Closer
}
