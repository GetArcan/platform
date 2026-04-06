package crypto

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// loadFileKey reads a 32-byte key from a file.
// If autoGenerate is true and the file doesn't exist, generates a new key.
func loadFileKey(path string, autoGenerate bool) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != 32 {
			return nil, fmt.Errorf("key file %s: expected 32 bytes, got %d", path, len(data))
		}
		return data, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading key file %s: %w", path, err)
	}

	if !autoGenerate {
		return nil, fmt.Errorf("key file %s does not exist — create it or use WithAutoGenerate(true)", path)
	}

	return generateKey(path)
}

// generateKey creates a crypto-random 32-byte key and writes it to path with 0600 permissions.
func generateKey(path string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("creating key directory: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, fmt.Errorf("writing key file %s: %w", path, err)
	}

	return key, nil
}
