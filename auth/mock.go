package auth

import (
	"context"
	"fmt"
	"sync"
)

// MockKeyStore is an in-memory key store for tests.
type MockKeyStore struct {
	mu   sync.Mutex
	keys map[string]*KeyRecord // hash -> record
}

// Compile-time interface check.
var _ KeyStore = (*MockKeyStore)(nil)

// NewMockKeyStore creates an empty in-memory key store.
func NewMockKeyStore() *MockKeyStore {
	return &MockKeyStore{
		keys: make(map[string]*KeyRecord),
	}
}

// AddKey generates and registers an API key for testing. Returns the raw key.
func (m *MockKeyStore) AddKey(prefix, userID string, capabilities []string) string {
	key, hash, err := GenerateAPIKey(prefix)
	if err != nil {
		panic(fmt.Sprintf("MockKeyStore.AddKey: %v", err))
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[hash] = &KeyRecord{
		UserID:       userID,
		Name:         "test-key",
		Capabilities: capabilities,
	}
	return key
}

// LookupKeyHash returns the key record for the given hash, or an error if not found.
func (m *MockKeyStore) LookupKeyHash(_ context.Context, hash string) (*KeyRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.keys[hash]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	return rec, nil
}
