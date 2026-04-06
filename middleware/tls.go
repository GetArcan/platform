package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// TLSConfig generates a tls.Config for the server.
// If certFile and keyFile are empty, generates a self-signed certificate
// and saves it to certDir for reuse.
func TLSConfig(certFile, keyFile, certDir string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		var err error
		certFile, keyFile, err = generateSelfSigned(certDir)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// generateSelfSigned creates a self-signed cert valid for 1 year.
// Saves cert.pem and key.pem to certDir with 0600 permissions.
func generateSelfSigned(certDir string) (certFile, keyFile string, err error) {
	if err = os.MkdirAll(certDir, 0700); err != nil {
		return "", "", fmt.Errorf("create cert dir: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("create certificate: %w", err)
	}

	// Write cert file.
	certFile = filepath.Join(certDir, "cert.pem")
	certOut, err := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", fmt.Errorf("create cert file: %w", err)
	}
	defer certOut.Close()

	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return "", "", fmt.Errorf("encode cert: %w", err)
	}

	// Write key file.
	keyFile = filepath.Join(certDir, "key.pem")
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", fmt.Errorf("create key file: %w", err)
	}
	defer keyOut.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}
	if err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return "", "", fmt.Errorf("encode key: %w", err)
	}

	return certFile, keyFile, nil
}
