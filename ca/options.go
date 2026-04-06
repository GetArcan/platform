package ca

import "time"

// Encryptor encrypts and decrypts values. Matches the platform/crypto.Encryptor interface.
// Defined here to avoid a circular import — callers pass their crypto.Encryptor.
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// Option configures CA creation or loading.
type Option func(*caOptions)

type caOptions struct {
	dir          string    // directory to store/load CA files
	autoGenerate bool      // generate CA if not exists (standalone mode)
	caCertPath   string    // path to existing CA cert (multi-node mode)
	caKeyPath    string    // path to existing CA key (multi-node mode)
	orgName      string    // organization name in CA subject
	encryptor    Encryptor // if set, CA key is encrypted at rest
}

// WithDir sets the directory for CA file storage.
func WithDir(dir string) Option {
	return func(o *caOptions) { o.dir = dir }
}

// WithAutoGenerate enables automatic CA generation if no CA exists (standalone mode).
func WithAutoGenerate(enabled bool) Option {
	return func(o *caOptions) { o.autoGenerate = enabled }
}

// WithCACert sets the path to an existing CA certificate (multi-node mode).
func WithCACert(path string) Option {
	return func(o *caOptions) { o.caCertPath = path }
}

// WithCAKey sets the path to an existing CA private key (multi-node mode).
func WithCAKey(path string) Option {
	return func(o *caOptions) { o.caKeyPath = path }
}

// WithOrgName sets the organization name in the CA subject.
// Defaults to "Internal CA" if not specified.
func WithOrgName(name string) Option {
	return func(o *caOptions) { o.orgName = name }
}

// WithEncryptor enables encryption of the CA private key at rest.
// When set, the CA key is encrypted before writing to disk and decrypted on load.
// Use the same encryptor that protects the master key (e.g., KMS-backed).
// Without this option, the CA key is stored as plaintext PEM (protected by file permissions only).
func WithEncryptor(enc Encryptor) Option {
	return func(o *caOptions) { o.encryptor = enc }
}

// CertOption configures server certificate issuance.
type CertOption func(*certOptions)

type certOptions struct {
	hosts    []string      // SANs (hostnames and IPs)
	dir      string        // directory to save cert files
	validity time.Duration // cert validity (default 1 year)
}

// WithHosts adds Subject Alternative Names (hostnames and IPs) to the certificate.
func WithHosts(hosts ...string) CertOption {
	return func(o *certOptions) { o.hosts = append(o.hosts, hosts...) }
}

// WithCertDir sets the output directory for the server certificate files.
func WithCertDir(dir string) CertOption {
	return func(o *certOptions) { o.dir = dir }
}

// WithValidity sets the certificate validity duration.
// Defaults to 1 year if not specified.
func WithValidity(d time.Duration) CertOption {
	return func(o *certOptions) { o.validity = d }
}
