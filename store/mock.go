package store

import "testing"

// MockDB creates an in-memory SQLite database for testing.
// The database is automatically closed when the test completes.
func MockDB(t testing.TB, opts ...Option) DB {
	t.Helper()

	db, err := NewSQLite(":memory:", opts...)
	if err != nil {
		t.Fatalf("creating mock db: %v", err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("closing mock db: %v", err)
		}
	})

	return db
}
