// Package signing provides Ed25519 signing and verification for Arcan plugins.
// Plugin binaries and WASM files are signed with Ed25519 keys, producing a
// detached .sig file containing the signature, checksum, and signer fingerprint.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

// KeyPair holds an Ed25519 signing key pair.
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair creates a new Ed25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}
	return &KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// SavePrivateKey writes the private key to a file (PEM format, 0600 permissions).
func SavePrivateKey(path string, key ed25519.PrivateKey) error {
	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: key,
	}
	data := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing private key to %s: %w", path, err)
	}
	return nil
}

// SavePublicKey writes the public key to a file (PEM format, 0644 permissions).
func SavePublicKey(path string, key ed25519.PublicKey) error {
	block := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: key,
	}
	data := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing public key to %s: %w", path, err)
	}
	return nil
}

// LoadPrivateKey reads a PEM-encoded Ed25519 private key from a file.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key from %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	if block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM block type %q in %s (expected ED25519 PRIVATE KEY)", block.Type, path)
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size %d in %s (expected %d)", len(block.Bytes), path, ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(block.Bytes), nil
}

// LoadPublicKey reads a PEM-encoded Ed25519 public key from a file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key from %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	if block.Type != "ED25519 PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM block type %q in %s (expected ED25519 PUBLIC KEY)", block.Type, path)
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size %d in %s (expected %d)", len(block.Bytes), path, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(block.Bytes), nil
}

// SignFile signs a file and returns the hex-encoded signature and checksum.
// The signature covers the SHA-256 hash of the file contents.
func SignFile(filePath string, key ed25519.PrivateKey) (signature string, checksum string, err error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", fmt.Errorf("reading file %s: %w", filePath, err)
	}

	hash := sha256.Sum256(data)
	checksum = "sha256:" + hex.EncodeToString(hash[:])

	sig := ed25519.Sign(key, hash[:])
	signature = hex.EncodeToString(sig)

	return signature, checksum, nil
}

// VerifyFile verifies a file's hex-encoded Ed25519 signature against a public key.
// Returns nil if valid, error if not.
func VerifyFile(filePath string, signature string, key ed25519.PublicKey) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading file %s: %w", filePath, err)
	}

	hash := sha256.Sum256(data)

	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decoding signature hex: %w", err)
	}

	if !ed25519.Verify(key, hash[:], sigBytes) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// Fingerprint returns the hex-encoded SHA-256 fingerprint of a public key.
func Fingerprint(key ed25519.PublicKey) string {
	hash := sha256.Sum256(key)
	return hex.EncodeToString(hash[:])
}

// SignatureFile returns the expected .sig file path for a plugin file.
// e.g., "my-engine.wasm" -> "my-engine.wasm.sig"
func SignatureFile(pluginPath string) string {
	return pluginPath + ".sig"
}
