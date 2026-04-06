// Package crypto provides encryption/decryption for the platform.
//
// All values at rest are encrypted using AES-256-GCM with a random
// 12-byte nonce per value. The master key never leaves memory.
//
// Encrypted format:
//
//	<prefix><base64std(12-byte-nonce || ciphertext || 16-byte-gcm-tag)>
//
// The prefix (default "platform:v1:") allows version-aware key rotation
// and graceful handling of any plaintext values that predate encryption.
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const (
	defaultPrefix = "platform:v1:"
	nonceSize     = 12 // 96-bit nonce recommended by NIST for GCM
)

// Encryptor encrypts and decrypts values.
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
	HealthCheck(ctx context.Context) error
}

// AESEncryptor encrypts values with AES-256-GCM.
// Format: <prefix><base64(12-byte-nonce || ciphertext || 16-byte-gcm-tag)>
type AESEncryptor struct {
	key    []byte
	prefix string
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Returns a string in the format: <prefix><base64(nonce||ciphertext||tag)>
func (e *AESEncryptor) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	// Fresh random nonce per encryption — never reuse a nonce with the same key.
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}

	// Seal appends ciphertext + 16-byte GCM authentication tag to nonce.
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return e.prefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decrypts a value produced by Encrypt.
// If the value is plaintext (no prefix), it is returned as-is to support
// migration from unencrypted deployments.
func (e *AESEncryptor) Decrypt(ciphertext string) (string, error) {
	// Plaintext passthrough — handles migration from unencrypted state.
	if !strings.HasPrefix(ciphertext, e.prefix) {
		return ciphertext, nil
	}

	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertext, e.prefix))
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}

	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: invalid key or tampered data")
	}

	return string(plaintext), nil
}

// HealthCheck performs an encrypt+decrypt round-trip to verify the encryptor works.
func (e *AESEncryptor) HealthCheck(_ context.Context) error {
	const probe = "healthcheck-probe"
	encrypted, err := e.Encrypt(probe)
	if err != nil {
		return fmt.Errorf("encrypt probe: %w", err)
	}
	decrypted, err := e.Decrypt(encrypted)
	if err != nil {
		return fmt.Errorf("decrypt probe: %w", err)
	}
	if decrypted != probe {
		return fmt.Errorf("round-trip mismatch: got %q, want %q", decrypted, probe)
	}
	return nil
}
