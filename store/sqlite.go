package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// sqliteDB wraps a *sql.DB for SQLite.
type sqliteDB struct {
	db *sql.DB
}

// Compile-time interface check.
var _ DB = (*sqliteDB)(nil)

// NewSQLite opens a SQLite database with sensible defaults.
// Creates the file and parent directories if they don't exist.
// Defaults: WAL mode, busy timeout 5000ms, foreign keys on.
func NewSQLite(path string, opts ...Option) (DB, error) {
	o := defaults()
	for _, fn := range opts {
		fn(&o)
	}

	// Create parent directories.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating directory %s: %w", dir, err)
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite %s: %w", path, err)
	}

	// SQLite serialises writes — one connection avoids "database is locked" errors.
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging sqlite: %w", err)
	}

	// Set pragmas.
	journalMode := "DELETE"
	if o.walMode {
		journalMode = "WAL"
	}

	pragmas := []string{
		fmt.Sprintf("PRAGMA journal_mode=%s", journalMode),
		fmt.Sprintf("PRAGMA busy_timeout=%d", o.busyTimeout),
		"PRAGMA foreign_keys=ON",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}

	// Run migrations if provided.
	if o.hasMigrations {
		if err := RunMigrations(context.Background(), db, o.migrations, o.migrationDir); err != nil {
			db.Close()
			return nil, fmt.Errorf("running migrations: %w", err)
		}
	}

	return &sqliteDB{db: db}, nil
}

func (s *sqliteDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, query, args...)
}

func (s *sqliteDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, query, args...)
}

func (s *sqliteDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, query, args...)
}

func (s *sqliteDB) HealthCheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *sqliteDB) RawDB() *sql.DB {
	return s.db
}

func (s *sqliteDB) Close() error {
	return s.db.Close()
}
