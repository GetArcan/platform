package crypto

import "fmt"

// AzureKVEncryptor uses Azure Key Vault for envelope encryption.
// The master key is wrapped via RSA-OAEP and stored locally.
// On startup, the wrapped key is decrypted via Key Vault, and the plaintext
// key is used for AES-256-GCM encryption of individual values.
type AzureKVEncryptor struct {
	inner *AESEncryptor
}

// newAzureKVEncryptor creates an encryptor backed by Azure Key Vault.
// For now, this is a stub that returns an error instructing the user
// to install the Azure provider package.
func newAzureKVEncryptor(vaultURL, keyName, prefix string) (Encryptor, error) {
	_ = vaultURL
	_ = keyName
	_ = prefix
	return nil, fmt.Errorf("Azure Key Vault support requires the azure provider package — coming soon")
}
