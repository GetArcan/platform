//go:build integration

package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

//go:embed testdata/pg_migrations/*.up.sql
var testPGMigrations embed.FS

// testPostgresDB creates a unique PostgreSQL test database, runs migrations,
// and returns a DB instance plus a cleanup function that drops the database.
func testPostgresDB(t *testing.T) (DB, func()) {
	t.Helper()

	baseURL := os.Getenv("ARCAN_TEST_POSTGRES_URL")
	if baseURL == "" {
		t.Skip("ARCAN_TEST_POSTGRES_URL not set")
	}

	// Connect to the base database to create a test-specific one.
	baseDB, err := sql.Open("postgres", baseURL)
	if err != nil {
		t.Fatalf("connecting to base postgres: %v", err)
	}
	defer baseDB.Close()

	dbName := fmt.Sprintf("arcan_test_%d", time.Now().UnixNano())

	if _, err := baseDB.Exec("CREATE DATABASE " + dbName); err != nil {
		t.Fatalf("creating test database %s: %v", dbName, err)
	}

	// Build DSN for the new database. Replace the database name in the URL.
	// We parse the base URL, swap the path, and reconnect.
	testURL := replaceDBName(baseURL, dbName)

	db, err := NewPostgres(testURL, WithMigrations(testPGMigrations, "testdata/pg_migrations"))
	if err != nil {
		// Clean up on failure.
		baseDB2, _ := sql.Open("postgres", baseURL)
		baseDB2.Exec("DROP DATABASE IF EXISTS " + dbName)
		baseDB2.Close()
		t.Fatalf("opening test postgres: %v", err)
	}

	cleanup := func() {
		db.Close()
		conn, err := sql.Open("postgres", baseURL)
		if err != nil {
			t.Errorf("reconnecting to drop test db: %v", err)
			return
		}
		defer conn.Close()
		// Terminate other connections to the test database.
		conn.Exec(fmt.Sprintf(
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '%s' AND pid <> pg_backend_pid()", dbName))
		if _, err := conn.Exec("DROP DATABASE IF EXISTS " + dbName); err != nil {
			t.Errorf("dropping test database %s: %v", dbName, err)
		}
	}

	return db, cleanup
}

// replaceDBName swaps the database name in a PostgreSQL DSN.
// Supports both postgres://user:pass@host:port/dbname?opts and keyword=value formats.
func replaceDBName(dsn, newDB string) string {
	// For URL-style DSNs, find the last '/' before '?' and replace the db name.
	if len(dsn) > 11 && dsn[:11] == "postgres://" {
		// Find the path portion after host.
		afterScheme := dsn[len("postgres://"):]
		atIdx := -1
		for i, c := range afterScheme {
			if c == '@' {
				atIdx = i
			}
		}
		hostStart := 0
		if atIdx >= 0 {
			hostStart = atIdx + 1
		}
		// Find the '/' that starts the database name.
		slashIdx := -1
		for i := hostStart; i < len(afterScheme); i++ {
			if afterScheme[i] == '/' {
				slashIdx = i
				break
			}
		}
		if slashIdx < 0 {
			return dsn + "/" + newDB
		}
		// Find '?' for query params.
		queryIdx := -1
		for i := slashIdx; i < len(afterScheme); i++ {
			if afterScheme[i] == '?' {
				queryIdx = i
				break
			}
		}
		prefix := "postgres://" + afterScheme[:slashIdx+1]
		if queryIdx >= 0 {
			return prefix + newDB + afterScheme[queryIdx:]
		}
		return prefix + newDB
	}
	// Keyword=value style — not expected in CI but handle gracefully.
	return dsn
}

func TestMigrations_Postgres(t *testing.T) {
	db, cleanup := testPostgresDB(t)
	defer cleanup()

	ctx := context.Background()

	// Verify schema_migrations table exists and has entries.
	var count int
	row := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations")
	if err := row.Scan(&count); err != nil {
		t.Fatalf("querying schema_migrations: %v", err)
	}
	if count != 2 {
		t.Errorf("migration count = %d, want 2", count)
	}

	// Verify test_users table exists with expected columns.
	_, err := db.ExecContext(ctx,
		"INSERT INTO test_users (name, email) VALUES ($1, $2)", "verify", "verify@test.com")
	if err != nil {
		t.Fatalf("inserting into test_users: %v", err)
	}

	// Verify idempotency — running migrations again should not error.
	if err := RunMigrations(ctx, db.RawDB(), testPGMigrations, "testdata/pg_migrations"); err != nil {
		t.Fatalf("second migration run: %v", err)
	}

	// Count should still be 2.
	row = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations")
	if err := row.Scan(&count); err != nil {
		t.Fatalf("re-querying schema_migrations: %v", err)
	}
	if count != 2 {
		t.Errorf("migration count after re-run = %d, want 2", count)
	}
}

func TestInsertAndQuery_Postgres(t *testing.T) {
	db, cleanup := testPostgresDB(t)
	defer cleanup()

	ctx := context.Background()

	_, err := db.ExecContext(ctx,
		"INSERT INTO test_users (name, email, bio) VALUES ($1, $2, $3)",
		"alice", "alice@example.com", "engineer")
	if err != nil {
		t.Fatalf("inserting row: %v", err)
	}

	var name, email, bio string
	row := db.QueryRowContext(ctx,
		"SELECT name, email, bio FROM test_users WHERE email = $1", "alice@example.com")
	if err := row.Scan(&name, &email, &bio); err != nil {
		t.Fatalf("querying row: %v", err)
	}
	if name != "alice" {
		t.Errorf("name = %q, want alice", name)
	}
	if email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", email)
	}
	if bio != "engineer" {
		t.Errorf("bio = %q, want engineer", bio)
	}
}

func TestPlaceholders_Postgres(t *testing.T) {
	db, cleanup := testPostgresDB(t)
	defer cleanup()

	ctx := context.Background()

	// This test specifically validates $1, $2, $3 placeholders work.
	// This is the test that would have caught the placeholder bug.
	_, err := db.ExecContext(ctx,
		"INSERT INTO test_users (name, email, bio) VALUES ($1, $2, $3)",
		"bob", "bob@example.com", "designer")
	if err != nil {
		t.Fatalf("insert with $1/$2/$3 placeholders: %v", err)
	}

	var name, email, bio string
	row := db.QueryRowContext(ctx,
		"SELECT name, email, bio FROM test_users WHERE name = $1 AND email = $2",
		"bob", "bob@example.com")
	if err := row.Scan(&name, &email, &bio); err != nil {
		t.Fatalf("query with $1/$2 placeholders: %v", err)
	}

	if name != "bob" || email != "bob@example.com" || bio != "designer" {
		t.Errorf("got (%q, %q, %q), want (bob, bob@example.com, designer)", name, email, bio)
	}
}

func TestConcurrentWrites_Postgres(t *testing.T) {
	db, cleanup := testPostgresDB(t)
	defer cleanup()

	ctx := context.Background()
	const n = 10

	var wg sync.WaitGroup
	errs := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := db.ExecContext(ctx,
				"INSERT INTO test_users (name, email) VALUES ($1, $2)",
				fmt.Sprintf("user_%d", i),
				fmt.Sprintf("user_%d@example.com", i))
			if err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent write error: %v", err)
	}

	var count int
	row := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM test_users")
	if err := row.Scan(&count); err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	if count != n {
		t.Errorf("row count = %d, want %d", count, n)
	}
}

func TestHealthCheck_Postgres(t *testing.T) {
	db, cleanup := testPostgresDB(t)
	defer cleanup()

	if err := db.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}
