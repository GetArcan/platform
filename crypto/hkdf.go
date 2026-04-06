package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey derives a 32-byte subkey from the master key using HKDF-SHA256.
// The info string creates distinct keys for different purposes:
//   - "data-encryption" -> Data Encryption Key
//   - "audit-hmac"      -> Audit HMAC Key
//   - "plugin-auth"     -> Plugin Auth Key
func (e *AESEncryptor) DeriveKey(info string) ([]byte, error) {
	r := hkdf.New(sha256.New, e.key, nil, []byte(info))
	derived := make([]byte, 32)
	if _, err := io.ReadFull(r, derived); err != nil {
		return nil, fmt.Errorf("deriving key for %q: %w", info, err)
	}
	return derived, nil
}
