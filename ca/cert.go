package ca

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
	"net"
	"os"
	"path/filepath"
	"time"
)

// ServerCert holds a server certificate issued by the CA.
type ServerCert struct {
	CertPEM  []byte
	KeyPEM   []byte
	CertFile string
	KeyFile  string
}

// IssueCert generates a new server certificate signed by this CA.
// The certificate includes the specified hosts as SANs.
// It is saved to the specified directory.
func (c *CA) IssueCert(opts ...CertOption) (*ServerCert, error) {
	o := &certOptions{
		validity: 365 * 24 * time.Hour,
	}
	for _, fn := range opts {
		fn(o)
	}

	if len(o.hosts) == 0 {
		o.hosts = DefaultHosts()
	}

	if o.dir == "" {
		return nil, fmt.Errorf("ca: cert dir is required (use WithCertDir)")
	}

	if err := os.MkdirAll(o.dir, 0700); err != nil {
		return nil, fmt.Errorf("ca: create cert dir: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate server key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: generate serial: %w", err)
	}

	var dnsNames []string
	var ipAddrs []net.IP
	for _, h := range o.hosts {
		if ip := net.ParseIP(h); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}

	cn := o.hosts[0]

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:   now,
		NotAfter:    now.Add(o.validity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: create server certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("ca: marshal server key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile := filepath.Join(o.dir, "server.crt")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		return nil, fmt.Errorf("ca: write server cert: %w", err)
	}

	keyFile := filepath.Join(o.dir, "server.key")
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("ca: write server key: %w", err)
	}

	return &ServerCert{
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		CertFile: certFile,
		KeyFile:  keyFile,
	}, nil
}

// TLSConfig returns a tls.Config using this server certificate.
// The CA certificate is included for client verification.
func (s *ServerCert) TLSConfig(authority *CA) *tls.Config {
	cert, _ := tls.X509KeyPair(s.CertPEM, s.KeyPEM)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(authority.CertPEM())

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
}

// DefaultHosts returns localhost, 127.0.0.1, ::1, and the machine's hostname.
func DefaultHosts() []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		hosts = append(hosts, hostname)
	}
	return hosts
}
