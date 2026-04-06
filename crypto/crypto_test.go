package crypto

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestNewEncryptorWithKey(t *testing.T) {
	enc, err := NewEncryptor(WithKey(testKey()))
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	if _, ok := enc.(*AESEncryptor); !ok {
		t.Fatalf("expected *AESEncryptor, got %T", enc)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc, err := NewEncryptor(WithKey(testKey()))
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	original := "hello, world!"
	ciphertext, err := enc.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	plaintext, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if plaintext != original {
		t.Fatalf("round-trip: got %q, want %q", plaintext, original)
	}
}

func TestDecryptPlaintextPassthrough(t *testing.T) {
	enc, err := NewEncryptor(WithKey(testKey()))
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	// No prefix — should return as-is (migration support).
	plain := "some-unencrypted-value"
	got, err := enc.Decrypt(plain)
	if err != nil {
		t.Fatalf("Decrypt plaintext: %v", err)
	}
	if got != plain {
		t.Fatalf("passthrough: got %q, want %q", got, plain)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	enc1, _ := NewEncryptor(WithKey(testKey()))

	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = byte(i + 100)
	}
	enc2, _ := NewEncryptor(WithKey(wrongKey))

	ciphertext, err := enc1.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = enc2.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestCiphertextHasCorrectPrefix(t *testing.T) {
	enc, _ := NewEncryptor(WithKey(testKey()))

	ciphertext, err := enc.Encrypt("test")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if !strings.HasPrefix(ciphertext, defaultPrefix) {
		t.Fatalf("ciphertext should start with %q, got %q", defaultPrefix, ciphertext[:20])
	}
}

func TestCustomPrefix(t *testing.T) {
	prefix := "arcan:v1:"
	enc, _ := NewEncryptor(WithKey(testKey()), WithPrefix(prefix))

	ciphertext, err := enc.Encrypt("test")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if !strings.HasPrefix(ciphertext, prefix) {
		t.Fatalf("ciphertext should start with %q, got %q", prefix, ciphertext)
	}

	// Round-trip with custom prefix.
	plain, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "test" {
		t.Fatalf("round-trip with custom prefix: got %q, want %q", plain, "test")
	}
}

func TestWithFileKeyAutoGenerate(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "subdir", "test.key")

	enc, err := NewEncryptor(WithFileKey(keyPath), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	// Key file should exist.
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}

	// Verify permissions (0600).
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("key file permissions: got %o, want 0600", perm)
	}

	// Verify it works.
	ct, err := enc.Encrypt("file-key-test")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != "file-key-test" {
		t.Fatalf("round-trip: got %q, want %q", pt, "file-key-test")
	}
}

func TestWithFileKeyNoAutoGenerateFails(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "nonexistent.key")

	_, err := NewEncryptor(WithFileKey(keyPath))
	if err == nil {
		t.Fatal("expected error for missing key file without auto-generate")
	}
}

func TestGeneratedKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "perm.key")

	_, err := generateKey(keyPath)
	if err != nil {
		t.Fatalf("generateKey: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("permissions: got %o, want 0600", perm)
	}
}

func TestDeriveKeyDifferentInfo(t *testing.T) {
	enc, _ := NewEncryptor(WithKey(testKey()))
	aes := enc.(*AESEncryptor)

	k1, err := aes.DeriveKey("data-encryption")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	k2, err := aes.DeriveKey("audit-hmac")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	if bytes.Equal(k1, k2) {
		t.Fatal("derived keys for different info strings should differ")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	enc, _ := NewEncryptor(WithKey(testKey()))
	aes := enc.(*AESEncryptor)

	k1, _ := aes.DeriveKey("data-encryption")
	k2, _ := aes.DeriveKey("data-encryption")

	if !bytes.Equal(k1, k2) {
		t.Fatal("derived keys for same info string should be identical")
	}
}

func TestHealthCheck(t *testing.T) {
	enc, _ := NewEncryptor(WithKey(testKey()))

	if err := enc.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

func TestMockEncryptorRoundTrip(t *testing.T) {
	m := NewMockEncryptor()

	ct, err := m.Encrypt("hello")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if ct != "mock:hello" {
		t.Fatalf("mock encrypt: got %q, want %q", ct, "mock:hello")
	}

	pt, err := m.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if pt != "hello" {
		t.Fatalf("mock decrypt: got %q, want %q", pt, "hello")
	}

	if err := m.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

// Compile-time interface checks.
var _ Encryptor = (*AESEncryptor)(nil)
var _ Encryptor = (*MockEncryptor)(nil)
