package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// postgresDB wraps a *sql.DB for PostgreSQL.
type postgresDB struct {
	db *sql.DB
}

// Compile-time interface check.
var _ DB = (*postgresDB)(nil)

// NewPostgres opens a PostgreSQL connection pool.
// dsn is a standard PostgreSQL connection string (e.g. "postgres://user:pass@host/db?sslmode=disable").
func NewPostgres(dsn string, opts ...Option) (DB, error) {
	o := defaults()
	for _, fn := range opts {
		fn(&o)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening postgres: %w", err)
	}

	db.SetMaxOpenConns(o.poolSize)
	db.SetMaxIdleConns(o.poolSize / 2)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}

	// Run migrations if provided.
	if o.hasMigrations {
		if err := RunMigrations(context.Background(), db, o.migrations, o.migrationDir); err != nil {
			db.Close()
			return nil, fmt.Errorf("running migrations: %w", err)
		}
	}

	return &postgresDB{db: db}, nil
}

func (p *postgresDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return p.db.ExecContext(ctx, query, args...)
}

func (p *postgresDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return p.db.QueryContext(ctx, query, args...)
}

func (p *postgresDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return p.db.QueryRowContext(ctx, query, args...)
}

func (p *postgresDB) HealthCheck(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

func (p *postgresDB) RawDB() *sql.DB {
	return p.db
}

func (p *postgresDB) Close() error {
	return p.db.Close()
}
