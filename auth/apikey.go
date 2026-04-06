package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// GenerateAPIKey creates a new API key with the given prefix.
// Returns (key, hash) where key is shown to user once and hash is stored.
// Example: GenerateAPIKey("arc_") -> ("arc_a1b2c3d4e5f6...", "sha256:...")
func GenerateAPIKey(prefix string) (key string, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generating API key: %w", err)
	}

	key = prefix + hex.EncodeToString(b)
	hash = HashKey(key)
	return key, hash, nil
}

// HashKey computes SHA-256 hash of an API key for database lookup.
func HashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(h[:])
}
