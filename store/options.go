package store

import "embed"

// Options configures database constructors.
type Options struct {
	migrations    embed.FS
	hasMigrations bool
	migrationDir  string
	walMode       bool
	poolSize      int
	busyTimeout   int // ms, SQLite only
}

// Option is a functional option for database constructors.
type Option func(*Options)

// defaults returns Options with sensible defaults.
func defaults() Options {
	return Options{
		walMode:     true,
		poolSize:    10,
		busyTimeout: 5000,
	}
}

// WithMigrations sets an embedded filesystem containing .up.sql migration files.
// The dir parameter specifies the subdirectory within the FS (e.g. "migrations").
func WithMigrations(fs embed.FS, dir string) Option {
	return func(o *Options) {
		o.migrations = fs
		o.hasMigrations = true
		o.migrationDir = dir
	}
}

// WithWAL enables or disables SQLite WAL mode (default true).
func WithWAL(enabled bool) Option {
	return func(o *Options) {
		o.walMode = enabled
	}
}

// WithPoolSize sets the PostgreSQL connection pool size (default 10).
func WithPoolSize(n int) Option {
	return func(o *Options) {
		o.poolSize = n
	}
}

// WithBusyTimeout sets the SQLite busy timeout in milliseconds (default 5000).
func WithBusyTimeout(ms int) Option {
	return func(o *Options) {
		o.busyTimeout = ms
	}
}
