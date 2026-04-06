package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CA represents an internal certificate authority.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
	dir     string
}

// NewCA creates or loads a certificate authority.
// In standalone mode with WithAutoGenerate(true), generates a new CA if none exists.
// In multi-node mode, loads an existing CA from WithCACert/WithCAKey paths.
func NewCA(opts ...Option) (*CA, error) {
	o := &caOptions{
		orgName: "Internal CA",
	}
	for _, fn := range opts {
		fn(o)
	}

	// Multi-node mode: load from explicit paths.
	if o.caCertPath != "" && o.caKeyPath != "" {
		return loadCA(o.caCertPath, o.caKeyPath, o.encryptor)
	}

	if o.dir == "" {
		return nil, fmt.Errorf("ca: dir is required (use WithDir)")
	}

	certPath := filepath.Join(o.dir, "ca.crt")
	keyPath := keyFilePath(o)

	// Try loading existing CA from dir.
	if _, err := os.Stat(certPath); err == nil {
		return loadCA(certPath, keyPath, o.encryptor)
	}

	if !o.autoGenerate {
		return nil, fmt.Errorf("ca: no CA found at %s and auto-generate is disabled", o.dir)
	}

	return generateCA(o)
}

// CertPEM returns the PEM-encoded CA certificate.
func (c *CA) CertPEM() []byte { return c.certPEM }

func generateCA(o *caOptions) (*CA, error) {
	if err := os.MkdirAll(o.dir, 0700); err != nil {
		return nil, fmt.Errorf("ca: create dir: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{o.orgName},
			CommonName:   o.orgName,
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("ca: create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("ca: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Write CA cert (safe to distribute).
	certPath := filepath.Join(o.dir, "ca.crt")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("ca: write cert: %w", err)
	}

	// Write CA key (keep secret). Encrypt if encryptor is provided.
	keyPath := keyFilePath(o)
	keyData := keyPEM
	if o.encryptor != nil {
		encrypted, err := o.encryptor.Encrypt(string(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("ca: encrypt key: %w", err)
		}
		keyData = []byte(encrypted)
	}
	if err := os.WriteFile(keyPath, keyData, 0600); err != nil {
		return nil, fmt.Errorf("ca: write key: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse certificate: %w", err)
	}

	return &CA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
		keyPEM:  keyPEM,
		dir:     o.dir,
	}, nil
}

// keyFilePath returns the CA key file path, using .key.enc when encrypted.
func keyFilePath(o *caOptions) string {
	if o.encryptor != nil {
		// Check if encrypted file exists first
		encPath := filepath.Join(o.dir, "ca.key.enc")
		if _, err := os.Stat(encPath); err == nil {
			return encPath
		}
		// Check if plaintext file exists (migration from unencrypted)
		plainPath := filepath.Join(o.dir, "ca.key")
		if _, err := os.Stat(plainPath); err == nil {
			return plainPath
		}
		// New CA — use encrypted path
		return encPath
	}
	return filepath.Join(o.dir, "ca.key")
}

func loadCA(certPath, keyPath string, enc Encryptor) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("ca: read cert %s: %w", certPath, err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ca: read key %s: %w", keyPath, err)
	}

	// Decrypt key if encryptor is provided and data looks encrypted (not PEM).
	keyPEM := keyData
	if enc != nil {
		block, _ := pem.Decode(keyData)
		if block == nil {
			// Not valid PEM — must be encrypted. Decrypt it.
			decrypted, err := enc.Decrypt(string(keyData))
			if err != nil {
				return nil, fmt.Errorf("ca: decrypt key %s: %w", keyPath, err)
			}
			keyPEM = []byte(decrypted)
		}
		// If it IS valid PEM, it was stored before encryption was enabled — use as-is.
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("ca: no PEM block in cert file %s", certPath)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse cert: %w", err)
	}

	if !cert.IsCA {
		return nil, fmt.Errorf("ca: certificate at %s is not a CA certificate", certPath)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("ca: no PEM block in key file %s", keyPath)
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse key: %w", err)
	}

	return &CA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
		keyPEM:  keyPEM,
		dir:     filepath.Dir(certPath),
	}, nil
}
