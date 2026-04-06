package crypto

import (
	"context"
	"strings"
)

const mockPrefix = "mock:"

// MockEncryptor provides deterministic encryption for tests.
// Encrypt returns "mock:<plaintext>", Decrypt strips the prefix.
type MockEncryptor struct{}

// NewMockEncryptor creates a MockEncryptor.
func NewMockEncryptor() *MockEncryptor {
	return &MockEncryptor{}
}

// Encrypt returns "mock:<plaintext>".
func (m *MockEncryptor) Encrypt(plaintext string) (string, error) {
	return mockPrefix + plaintext, nil
}

// Decrypt strips the "mock:" prefix. If the value has no prefix, returns as-is.
func (m *MockEncryptor) Decrypt(ciphertext string) (string, error) {
	if !strings.HasPrefix(ciphertext, mockPrefix) {
		return ciphertext, nil
	}
	return strings.TrimPrefix(ciphertext, mockPrefix), nil
}

// HealthCheck always succeeds.
func (m *MockEncryptor) HealthCheck(_ context.Context) error {
	return nil
}

// Compile-time interface checks.
var _ Encryptor = (*AESEncryptor)(nil)
var _ Encryptor = (*MockEncryptor)(nil)
