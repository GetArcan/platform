package store

import (
	"context"
	"embed"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Compile-time interface checks.
var _ DB = (*sqliteDB)(nil)
var _ DB = (*postgresDB)(nil)

//go:embed testdata/migrations/*.up.sql
var testMigrations embed.FS

func TestNewSQLiteCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "test.db")

	db, err := NewSQLite(path)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	defer db.Close()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("database file was not created")
	}
}

func TestNewSQLiteSetsPragmas(t *testing.T) {
	db := MockDB(t)

	// Check foreign keys are on.
	var fk int
	row := db.QueryRowContext(context.Background(), "PRAGMA foreign_keys")
	if err := row.Scan(&fk); err != nil {
		t.Fatalf("scanning foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1", fk)
	}
}

func TestWALModeDefault(t *testing.T) {
	db := MockDB(t)

	var mode string
	row := db.QueryRowContext(context.Background(), "PRAGMA journal_mode")
	if err := row.Scan(&mode); err != nil {
		t.Fatalf("scanning journal_mode: %v", err)
	}
	// In-memory databases may report "memory" instead of "wal",
	// so test with a file-based database.
	db.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "wal_test.db")
	fileDB, err := NewSQLite(path)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	defer fileDB.Close()

	row = fileDB.QueryRowContext(context.Background(), "PRAGMA journal_mode")
	if err := row.Scan(&mode); err != nil {
		t.Fatalf("scanning journal_mode: %v", err)
	}
	if strings.ToLower(mode) != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
}

func TestRunMigrationsAppliesInOrder(t *testing.T) {
	db := MockDB(t, WithMigrations(testMigrations, "testdata/migrations"))

	ctx := context.Background()

	// The test migrations should have created a "test_users" table.
	_, err := db.ExecContext(ctx, "INSERT INTO test_users (id, name) VALUES ('1', 'alice')")
	if err != nil {
		t.Fatalf("inserting into test_users: %v", err)
	}

	// The second migration should have added an "email" column.
	_, err = db.ExecContext(ctx, "UPDATE test_users SET email = 'alice@example.com' WHERE id = '1'")
	if err != nil {
		t.Fatalf("updating email column: %v", err)
	}
}

func TestRunMigrationsIdempotent(t *testing.T) {
	db := MockDB(t)
	ctx := context.Background()

	// Run migrations twice — second run should be a no-op.
	if err := RunMigrations(ctx, db.RawDB(), testMigrations, "testdata/migrations"); err != nil {
		t.Fatalf("first migration run: %v", err)
	}
	if err := RunMigrations(ctx, db.RawDB(), testMigrations, "testdata/migrations"); err != nil {
		t.Fatalf("second migration run: %v", err)
	}

	// Verify only two migration records exist.
	var count int
	row := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations")
	if err := row.Scan(&count); err != nil {
		t.Fatalf("counting migrations: %v", err)
	}
	if count != 2 {
		t.Errorf("migration count = %d, want 2", count)
	}
}

func TestMockDBUsable(t *testing.T) {
	db := MockDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx, "CREATE TABLE mock_test (id TEXT PRIMARY KEY)")
	if err != nil {
		t.Fatalf("creating table: %v", err)
	}

	_, err = db.ExecContext(ctx, "INSERT INTO mock_test (id) VALUES ('hello')")
	if err != nil {
		t.Fatalf("inserting: %v", err)
	}

	var id string
	row := db.QueryRowContext(ctx, "SELECT id FROM mock_test WHERE id = 'hello'")
	if err := row.Scan(&id); err != nil {
		t.Fatalf("scanning: %v", err)
	}
	if id != "hello" {
		t.Errorf("id = %q, want hello", id)
	}
}

func TestHealthCheckSucceeds(t *testing.T) {
	db := MockDB(t)
	if err := db.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

func TestNowUTCReturnsUTC(t *testing.T) {
	now := NowUTC()
	if now.Location() != time.UTC {
		t.Errorf("NowUTC location = %v, want UTC", now.Location())
	}
}

func TestNewUUIDValid(t *testing.T) {
	id := NewUUID()
	if len(id) != 36 {
		t.Errorf("UUID length = %d, want 36", len(id))
	}
	// Check format: 8-4-4-4-12
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Errorf("UUID parts = %d, want 5", len(parts))
	}

	// Generate two — they should differ.
	id2 := NewUUID()
	if id == id2 {
		t.Error("two UUIDs are identical")
	}
}

func TestFormatAndParseTime(t *testing.T) {
	original := time.Date(2026, 4, 1, 12, 30, 45, 0, time.UTC)
	formatted := FormatTime(original)

	parsed, err := ParseTime(formatted)
	if err != nil {
		t.Fatalf("ParseTime: %v", err)
	}
	if !parsed.Equal(original) {
		t.Errorf("parsed = %v, want %v", parsed, original)
	}
}
