package crypto

import "fmt"

// AWSKMSEncryptor uses AWS KMS for envelope encryption.
// The master key is wrapped by a KMS CMK and stored locally.
// On startup, the wrapped key is decrypted via KMS, and the plaintext key
// is used for AES-256-GCM encryption of individual values.
type AWSKMSEncryptor struct {
	inner *AESEncryptor
}

// newAWSKMSEncryptor creates an encryptor backed by AWS KMS.
// For now, this is a stub that returns an error instructing the user
// to install the AWS KMS provider package.
func newAWSKMSEncryptor(keyID, region, prefix string) (Encryptor, error) {
	_ = keyID
	_ = region
	_ = prefix
	return nil, fmt.Errorf("AWS KMS support requires the aws provider package — coming soon")
}
