package ca

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCA_AutoGenerate(t *testing.T) {
	dir := t.TempDir()

	authority, err := NewCA(WithDir(dir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	// Verify files exist.
	if _, err := os.Stat(filepath.Join(dir, "ca.crt")); err != nil {
		t.Fatalf("ca.crt not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("ca.key not created: %v", err)
	}

	if authority.cert == nil {
		t.Fatal("CA certificate is nil")
	}
	if authority.key == nil {
		t.Fatal("CA key is nil")
	}
}

func TestNewCA_AutoGenerate_Idempotent(t *testing.T) {
	dir := t.TempDir()

	ca1, err := NewCA(WithDir(dir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("first NewCA: %v", err)
	}

	ca2, err := NewCA(WithDir(dir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("second NewCA: %v", err)
	}

	// Both should have the same cert (loaded from disk).
	if string(ca1.certPEM) != string(ca2.certPEM) {
		t.Fatal("second call did not load existing CA — certPEM differs")
	}
}

func TestNewCA_IsCA(t *testing.T) {
	dir := t.TempDir()

	authority, err := NewCA(WithDir(dir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	if !authority.cert.IsCA {
		t.Fatal("CA certificate IsCA = false")
	}
	if !authority.cert.BasicConstraintsValid {
		t.Fatal("CA certificate BasicConstraintsValid = false")
	}
}

func TestNewCA_OrgName(t *testing.T) {
	dir := t.TempDir()

	authority, err := NewCA(WithDir(dir), WithAutoGenerate(true), WithOrgName("Test Org"))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	if len(authority.cert.Subject.Organization) == 0 {
		t.Fatal("CA cert has no organization")
	}
	if authority.cert.Subject.Organization[0] != "Test Org" {
		t.Fatalf("org = %q, want %q", authority.cert.Subject.Organization[0], "Test Org")
	}
}

func TestNewCA_DefaultOrgName(t *testing.T) {
	dir := t.TempDir()

	authority, err := NewCA(WithDir(dir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	if authority.cert.Subject.Organization[0] != "Internal CA" {
		t.Fatalf("default org = %q, want %q", authority.cert.Subject.Organization[0], "Internal CA")
	}
}

func TestNewCA_KeyFilePermissions(t *testing.T) {
	dir := t.TempDir()

	_, err := NewCA(WithDir(dir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("stat ca.key: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("ca.key permissions = %o, want 0600", perm)
	}
}

func TestNewCA_CertFilePermissions(t *testing.T) {
	dir := t.TempDir()

	_, err := NewCA(WithDir(dir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("stat ca.crt: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0644 {
		t.Fatalf("ca.crt permissions = %o, want 0644", perm)
	}
}

func TestIssueCert_Creates(t *testing.T) {
	caDir := t.TempDir()
	certDir := t.TempDir()

	authority, err := NewCA(WithDir(caDir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	sc, err := authority.IssueCert(WithCertDir(certDir))
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	if _, err := os.Stat(sc.CertFile); err != nil {
		t.Fatalf("server.crt not created: %v", err)
	}
	if _, err := os.Stat(sc.KeyFile); err != nil {
		t.Fatalf("server.key not created: %v", err)
	}
}

func TestIssueCert_SANs(t *testing.T) {
	caDir := t.TempDir()
	certDir := t.TempDir()

	authority, err := NewCA(WithDir(caDir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	sc, err := authority.IssueCert(
		WithCertDir(certDir),
		WithHosts("example.com", "localhost", "127.0.0.1", "::1"),
	)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	block, _ := pem.Decode(sc.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	// Check DNS SANs.
	dnsFound := map[string]bool{"example.com": false, "localhost": false}
	for _, name := range cert.DNSNames {
		dnsFound[name] = true
	}
	for name, found := range dnsFound {
		if !found {
			t.Errorf("DNS SAN %q not found", name)
		}
	}

	// Check IP SANs.
	ipFound := map[string]bool{"127.0.0.1": false, "::1": false}
	for _, ip := range cert.IPAddresses {
		ipFound[ip.String()] = true
	}
	for ip, found := range ipFound {
		if !found {
			t.Errorf("IP SAN %q not found", ip)
		}
	}
}

func TestIssueCert_DefaultHosts(t *testing.T) {
	caDir := t.TempDir()
	certDir := t.TempDir()

	authority, err := NewCA(WithDir(caDir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	// No WithHosts — should use DefaultHosts().
	sc, err := authority.IssueCert(WithCertDir(certDir))
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	block, _ := pem.Decode(sc.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	found := false
	for _, name := range cert.DNSNames {
		if name == "localhost" {
			found = true
			break
		}
	}
	if !found {
		t.Error("default hosts should include localhost in DNSNames")
	}
}

func TestIssueCert_VerifiesAgainstCA(t *testing.T) {
	caDir := t.TempDir()
	certDir := t.TempDir()

	authority, err := NewCA(WithDir(caDir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	sc, err := authority.IssueCert(
		WithCertDir(certDir),
		WithHosts("localhost"),
	)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Build a cert pool with the CA cert.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(authority.CertPEM())

	block, _ := pem.Decode(sc.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:   pool,
		DNSName: "localhost",
	})
	if err != nil {
		t.Fatalf("server cert does not verify against CA: %v", err)
	}
}

func TestIssueCert_TLSConfig(t *testing.T) {
	caDir := t.TempDir()
	certDir := t.TempDir()

	authority, err := NewCA(WithDir(caDir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	sc, err := authority.IssueCert(
		WithCertDir(certDir),
		WithHosts("localhost"),
	)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	cfg := sc.TLSConfig(authority)
	if cfg == nil {
		t.Fatal("TLSConfig returned nil")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want %d", cfg.MinVersion, tls.VersionTLS12)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("got %d certificates, want 1", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is nil")
	}
}

func TestDefaultHosts(t *testing.T) {
	hosts := DefaultHosts()

	has := func(target string) bool {
		for _, h := range hosts {
			if h == target {
				return true
			}
		}
		return false
	}

	if !has("localhost") {
		t.Error("DefaultHosts missing localhost")
	}
	if !has("127.0.0.1") {
		t.Error("DefaultHosts missing 127.0.0.1")
	}
	if !has("::1") {
		t.Error("DefaultHosts missing ::1")
	}
}

func TestNewCA_LoadFromPaths(t *testing.T) {
	// Generate a CA first.
	genDir := t.TempDir()
	_, err := NewCA(WithDir(genDir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	// Load it via explicit paths.
	certPath := filepath.Join(genDir, "ca.crt")
	keyPath := filepath.Join(genDir, "ca.key")

	loaded, err := NewCA(WithCACert(certPath), WithCAKey(keyPath))
	if err != nil {
		t.Fatalf("load CA: %v", err)
	}

	if !loaded.cert.IsCA {
		t.Fatal("loaded cert is not a CA")
	}
}

func TestNewCA_InvalidCertPath(t *testing.T) {
	_, err := NewCA(
		WithCACert("/nonexistent/ca.crt"),
		WithCAKey("/nonexistent/ca.key"),
	)
	if err == nil {
		t.Fatal("expected error for invalid cert path")
	}
}

func TestNewCA_NoDir_NoAutoGenerate(t *testing.T) {
	dir := t.TempDir()

	_, err := NewCA(WithDir(dir))
	if err == nil {
		t.Fatal("expected error when no CA exists and auto-generate is disabled")
	}
}

func TestIssueCert_CustomValidity(t *testing.T) {
	caDir := t.TempDir()
	certDir := t.TempDir()

	authority, err := NewCA(WithDir(caDir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	sc, err := authority.IssueCert(
		WithCertDir(certDir),
		WithHosts("localhost"),
		WithValidity(30*24*time.Hour),
	)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	block, _ := pem.Decode(sc.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	validity := cert.NotAfter.Sub(cert.NotBefore)
	expected := 30 * 24 * time.Hour
	// Allow 1 minute tolerance for test execution time.
	if validity < expected-time.Minute || validity > expected+time.Minute {
		t.Fatalf("validity = %v, want ~%v", validity, expected)
	}
}

// ── Encrypted CA Key Tests ──────────────────────────────────────────────────

// testEncryptor is a simple encryptor for tests. Prepends "ENC:" on encrypt, strips on decrypt.
type testEncryptor struct{}

func (e *testEncryptor) Encrypt(plaintext string) (string, error) {
	return "ENC:" + plaintext, nil
}

func (e *testEncryptor) Decrypt(ciphertext string) (string, error) {
	if len(ciphertext) > 4 && ciphertext[:4] == "ENC:" {
		return ciphertext[4:], nil
	}
	return ciphertext, nil
}

func TestNewCA_WithEncryptor_KeyEncryptedOnDisk(t *testing.T) {
	dir := t.TempDir()
	enc := &testEncryptor{}

	_, err := NewCA(WithDir(dir), WithAutoGenerate(true), WithEncryptor(enc))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	// Key file should be .key.enc, not .key
	encPath := filepath.Join(dir, "ca.key.enc")
	if _, err := os.Stat(encPath); err != nil {
		t.Fatalf("expected encrypted key file at %s: %v", encPath, err)
	}

	plainPath := filepath.Join(dir, "ca.key")
	if _, err := os.Stat(plainPath); !os.IsNotExist(err) {
		t.Fatalf("plaintext key file should not exist at %s", plainPath)
	}

	// Read the encrypted file — it should start with "ENC:" (our test encryptor prefix)
	data, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("read encrypted key: %v", err)
	}
	if len(data) < 4 || string(data[:4]) != "ENC:" {
		t.Fatalf("encrypted key should start with 'ENC:', got: %s", string(data[:20]))
	}

	// CA cert should still be plaintext PEM (public, safe to distribute)
	certData, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("CA cert should be valid PEM")
	}
}

func TestNewCA_WithEncryptor_ReloadsEncryptedKey(t *testing.T) {
	dir := t.TempDir()
	enc := &testEncryptor{}

	// Generate CA with encryption
	ca1, err := NewCA(WithDir(dir), WithAutoGenerate(true), WithEncryptor(enc))
	if err != nil {
		t.Fatalf("NewCA generate: %v", err)
	}

	// Reload CA with same encryptor — should decrypt and load successfully
	ca2, err := NewCA(WithDir(dir), WithEncryptor(enc))
	if err != nil {
		t.Fatalf("NewCA reload: %v", err)
	}

	// Both should have the same CA cert
	if string(ca1.CertPEM()) != string(ca2.CertPEM()) {
		t.Fatal("reloaded CA has different cert")
	}

	// Issue a cert with the reloaded CA — proves the key was decrypted correctly
	certDir := t.TempDir()
	_, err = ca2.IssueCert(WithHosts("localhost"), WithCertDir(certDir))
	if err != nil {
		t.Fatalf("IssueCert with reloaded CA: %v", err)
	}
}

func TestNewCA_WithEncryptor_FailsWithoutEncryptor(t *testing.T) {
	dir := t.TempDir()
	enc := &testEncryptor{}

	// Generate with encryption
	_, err := NewCA(WithDir(dir), WithAutoGenerate(true), WithEncryptor(enc))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	// Try to reload WITHOUT encryptor — should fail because the key is encrypted
	_, err = NewCA(WithDir(dir))
	if err == nil {
		t.Fatal("expected error loading encrypted key without encryptor")
	}
}

func TestNewCA_PlaintextKeyMigration(t *testing.T) {
	dir := t.TempDir()

	// Generate CA WITHOUT encryption (plaintext key)
	_, err := NewCA(WithDir(dir), WithAutoGenerate(true))
	if err != nil {
		t.Fatalf("NewCA plaintext: %v", err)
	}

	// Now load WITH encryptor — should detect plaintext PEM and load it (migration case)
	enc := &testEncryptor{}
	ca2, err := NewCA(WithDir(dir), WithEncryptor(enc))
	if err != nil {
		t.Fatalf("NewCA with encryptor on plaintext key: %v", err)
	}

	// Should work — issue a cert to prove
	certDir := t.TempDir()
	_, err = ca2.IssueCert(WithHosts("localhost"), WithCertDir(certDir))
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
}
