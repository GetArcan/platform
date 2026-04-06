package crypto

import "fmt"

// GCPKMSEncryptor uses GCP Cloud KMS for envelope encryption.
// The master key is wrapped by a Cloud KMS key and stored locally.
// On startup, the wrapped key is decrypted via Cloud KMS, and the plaintext
// key is used for AES-256-GCM encryption of individual values.
type GCPKMSEncryptor struct {
	inner *AESEncryptor
}

// newGCPKMSEncryptor creates an encryptor backed by GCP Cloud KMS.
// For now, this is a stub that returns an error instructing the user
// to install the GCP KMS provider package.
func newGCPKMSEncryptor(keyName, prefix string) (Encryptor, error) {
	_ = keyName
	_ = prefix
	return nil, fmt.Errorf("GCP KMS support requires the gcp provider package — coming soon")
}
