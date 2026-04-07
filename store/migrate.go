package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
)

// RunMigrations executes all pending .up.sql migrations from an embedded FS.
// Migrations are numbered: 001_initial.up.sql, 002_add_index.up.sql, etc.
// A schema_migrations table tracks which have been applied.
// The dir parameter ("sqlite" or "postgres") determines SQL dialect.
func RunMigrations(ctx context.Context, db *sql.DB, migrations embed.FS, dir string) error {
	isPostgres := dir == "postgres"

	// Create the tracking table if it doesn't exist.
	var createSQL string
	if isPostgres {
		createSQL = `
			CREATE TABLE IF NOT EXISTS schema_migrations (
				version TEXT PRIMARY KEY,
				applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
			)`
	} else {
		createSQL = `
			CREATE TABLE IF NOT EXISTS schema_migrations (
				version TEXT PRIMARY KEY,
				applied_at TEXT NOT NULL DEFAULT (datetime('now'))
			)`
	}
	if _, err := db.ExecContext(ctx, createSQL); err != nil {
		return fmt.Errorf("creating schema_migrations table: %w", err)
	}

	// Read all .up.sql files from the embedded FS.
	entries, err := fs.ReadDir(migrations, dir)
	if err != nil {
		return fmt.Errorf("reading migrations directory %q: %w", dir, err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	// Apply each migration that hasn't been applied yet.
	for _, name := range files {
		var exists int
		var checkSQL, insertSQL string
		if isPostgres {
			checkSQL = "SELECT COUNT(*) FROM schema_migrations WHERE version = $1"
			insertSQL = "INSERT INTO schema_migrations (version) VALUES ($1)"
		} else {
			checkSQL = "SELECT COUNT(*) FROM schema_migrations WHERE version = ?"
			insertSQL = "INSERT INTO schema_migrations (version) VALUES (?)"
		}

		err := db.QueryRowContext(ctx, checkSQL, name).Scan(&exists)
		if err != nil {
			return fmt.Errorf("checking migration %s: %w", name, err)
		}
		if exists > 0 {
			continue
		}

		content, err := fs.ReadFile(migrations, dir+"/"+name)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", name, err)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("beginning transaction for %s: %w", name, err)
		}

		if _, err := tx.ExecContext(ctx, string(content)); err != nil {
			tx.Rollback()
			return fmt.Errorf("executing migration %s: %w", name, err)
		}

		if _, err := tx.ExecContext(ctx, insertSQL, name); err != nil {
			tx.Rollback()
			return fmt.Errorf("recording migration %s: %w", name, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %s: %w", name, err)
		}

		slog.Info("migration applied", "file", name)
	}

	return nil
}
