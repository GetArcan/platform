package store

import (
	"time"

	"github.com/google/uuid"
)

const timeFormat = "2006-01-02T15:04:05Z"

// NowUTC returns the current time in UTC.
func NowUTC() time.Time {
	return time.Now().UTC()
}

// NewUUID generates a new UUID v4 string.
func NewUUID() string {
	return uuid.New().String()
}

// FormatTime formats a time for SQLite storage (ISO 8601).
func FormatTime(t time.Time) string {
	return t.UTC().Format(timeFormat)
}

// ParseTime parses a SQLite timestamp string.
func ParseTime(s string) (time.Time, error) {
	return time.Parse(timeFormat, s)
}
