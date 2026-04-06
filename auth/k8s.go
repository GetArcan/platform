package auth

import "fmt"

// K8sValidator validates Kubernetes service account tokens.
// This is a stub for now — full implementation when K8s auth is needed.
type K8sValidator struct{}

// ValidateToken validates a Kubernetes service account token.
func (v *K8sValidator) ValidateToken(token string) (serviceAccount string, err error) {
	return "", fmt.Errorf("kubernetes auth not yet implemented")
}
