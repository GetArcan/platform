package signing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(kp.PublicKey) == 0 {
		t.Fatal("public key is empty")
	}
	if len(kp.PrivateKey) == 0 {
		t.Fatal("private key is empty")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Create a temp file with known content.
	dir := t.TempDir()
	path := filepath.Join(dir, "test-plugin.wasm")
	if err := os.WriteFile(path, []byte("hello plugin binary"), 0644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	sig, checksum, err := SignFile(path, kp.PrivateKey)
	if err != nil {
		t.Fatalf("SignFile: %v", err)
	}
	if sig == "" {
		t.Fatal("signature is empty")
	}
	if checksum == "" {
		t.Fatal("checksum is empty")
	}
	if checksum[:7] != "sha256:" {
		t.Fatalf("checksum missing sha256: prefix, got %s", checksum)
	}

	// Verify with correct key should succeed.
	if err := VerifyFile(path, sig, kp.PublicKey); err != nil {
		t.Fatalf("VerifyFile should succeed: %v", err)
	}
}

func TestVerifyFailsWithWrongKey(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "test-plugin.wasm")
	os.WriteFile(path, []byte("hello plugin binary"), 0644)

	sig, _, _ := SignFile(path, kp1.PrivateKey)

	// Verify with wrong key should fail.
	if err := VerifyFile(path, sig, kp2.PublicKey); err == nil {
		t.Fatal("VerifyFile should fail with wrong key")
	}
}

func TestVerifyFailsWithTamperedFile(t *testing.T) {
	kp, _ := GenerateKeyPair()

	dir := t.TempDir()
	path := filepath.Join(dir, "test-plugin.wasm")
	os.WriteFile(path, []byte("original content"), 0644)

	sig, _, _ := SignFile(path, kp.PrivateKey)

	// Tamper with the file.
	os.WriteFile(path, []byte("tampered content"), 0644)

	if err := VerifyFile(path, sig, kp.PublicKey); err == nil {
		t.Fatal("VerifyFile should fail with tampered file")
	}
}

func TestSaveLoadKeyRoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPair()
	dir := t.TempDir()

	privPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.pub")

	if err := SavePrivateKey(privPath, kp.PrivateKey); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	if err := SavePublicKey(pubPath, kp.PublicKey); err != nil {
		t.Fatalf("SavePublicKey: %v", err)
	}

	// Check file permissions.
	info, _ := os.Stat(privPath)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private key permissions: got %o, want 0600", info.Mode().Perm())
	}
	info, _ = os.Stat(pubPath)
	if info.Mode().Perm() != 0644 {
		t.Fatalf("public key permissions: got %o, want 0644", info.Mode().Perm())
	}

	// Load and compare.
	loadedPriv, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if !kp.PrivateKey.Equal(loadedPriv) {
		t.Fatal("loaded private key does not match original")
	}

	loadedPub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if !kp.PublicKey.Equal(loadedPub) {
		t.Fatal("loaded public key does not match original")
	}

	// Verify sign+verify works with loaded keys.
	tmpFile := filepath.Join(dir, "test.bin")
	os.WriteFile(tmpFile, []byte("test content"), 0644)
	sig, _, _ := SignFile(tmpFile, loadedPriv)
	if err := VerifyFile(tmpFile, sig, loadedPub); err != nil {
		t.Fatalf("verify with loaded keys failed: %v", err)
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	kp, _ := GenerateKeyPair()
	fp1 := Fingerprint(kp.PublicKey)
	fp2 := Fingerprint(kp.PublicKey)
	if fp1 != fp2 {
		t.Fatalf("fingerprints differ: %s vs %s", fp1, fp2)
	}
	if len(fp1) != 64 { // SHA-256 = 32 bytes = 64 hex chars
		t.Fatalf("fingerprint length: got %d, want 64", len(fp1))
	}
}

func TestSignatureFile(t *testing.T) {
	got := SignatureFile("my-engine.wasm")
	want := "my-engine.wasm.sig"
	if got != want {
		t.Fatalf("SignatureFile: got %q, want %q", got, want)
	}
}
