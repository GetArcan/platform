package crypto

import "fmt"

type options struct {
	key        []byte
	keyPath    string // file path
	autoGen    bool   // auto-generate if file missing
	prefix     string // encryption prefix (default "platform:v1:")
	awsKeyID   string // AWS KMS key ID
	awsRegion  string
	gcpKeyName string // GCP KMS key name
	azureVault string // Azure Key Vault URL
	azureKey   string // Azure key name
}

// Option configures NewEncryptor.
type Option func(*options)

// WithKey provides the encryption key directly. Useful for tests or manual setup.
func WithKey(key []byte) Option {
	return func(o *options) { o.key = key }
}

// WithFileKey loads the encryption key from a file.
func WithFileKey(path string) Option {
	return func(o *options) { o.keyPath = path }
}

// WithAutoGenerate generates a new file key if the file does not exist.
// Only applies when used with WithFileKey.
func WithAutoGenerate(enabled bool) Option {
	return func(o *options) { o.autoGen = enabled }
}

// WithPrefix sets the encryption prefix. Default is "platform:v1:".
func WithPrefix(prefix string) Option {
	return func(o *options) { o.prefix = prefix }
}

// WithAWSKMS configures AWS KMS envelope encryption.
func WithAWSKMS(keyID, region string) Option {
	return func(o *options) {
		o.awsKeyID = keyID
		o.awsRegion = region
	}
}

// WithGCPKMS configures GCP Cloud KMS envelope encryption.
func WithGCPKMS(keyName string) Option {
	return func(o *options) { o.gcpKeyName = keyName }
}

// WithAzureKV configures Azure Key Vault envelope encryption.
func WithAzureKV(vaultURL, keyName string) Option {
	return func(o *options) {
		o.azureVault = vaultURL
		o.azureKey = keyName
	}
}

// NewEncryptor creates an Encryptor based on the provided options.
// Priority: WithKey > WithAWSKMS/GCP/Azure > WithFileKey.
func NewEncryptor(opts ...Option) (Encryptor, error) {
	o := &options{
		prefix: defaultPrefix,
	}
	for _, fn := range opts {
		fn(o)
	}

	// Priority 1: Direct key.
	if len(o.key) > 0 {
		return newAESEncryptor(o.key, o.prefix)
	}

	// Priority 2: Cloud KMS providers.
	if o.awsKeyID != "" {
		return newAWSKMSEncryptor(o.awsKeyID, o.awsRegion, o.prefix)
	}
	if o.gcpKeyName != "" {
		return newGCPKMSEncryptor(o.gcpKeyName, o.prefix)
	}
	if o.azureVault != "" {
		return newAzureKVEncryptor(o.azureVault, o.azureKey, o.prefix)
	}

	// Priority 3: File-based key.
	if o.keyPath != "" {
		key, err := loadFileKey(o.keyPath, o.autoGen)
		if err != nil {
			return nil, fmt.Errorf("file key: %w", err)
		}
		return newAESEncryptor(key, o.prefix)
	}

	return nil, fmt.Errorf("no encryption key source provided — use WithKey, WithFileKey, or a KMS option")
}

// newAESEncryptor creates an AESEncryptor from a 32-byte key.
func newAESEncryptor(key []byte, prefix string) (*AESEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes (256 bits), got %d bytes", len(key))
	}
	k := make([]byte, 32)
	copy(k, key)
	return &AESEncryptor{key: k, prefix: prefix}, nil
}
