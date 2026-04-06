package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTValidator validates JWTs against a static secret or JWKS endpoint.
type JWTValidator struct {
	secret  []byte // for HS256
	jwksURL string // for RS256/ES256 (future)
}

// NewJWTValidator creates a validator with a static HS256 secret.
func NewJWTValidator(secret []byte) *JWTValidator {
	return &JWTValidator{secret: secret}
}

// ValidateJWT validates a JWT token and returns the subject claim.
// For now, supports HS256 with a static secret only.
func (v *JWTValidator) ValidateJWT(tokenString string) (subject string, err error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.secret, nil
	})
	if err != nil {
		return "", fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid {
		return "", fmt.Errorf("token validation failed")
	}

	sub, err := token.Claims.GetSubject()
	if err != nil {
		return "", fmt.Errorf("missing subject claim: %w", err)
	}
	return sub, nil
}

// GenerateJWT creates a signed JWT with the given claims.
func GenerateJWT(secret []byte, userID, email string, expiryMinutes int) (string, error) {
	now := time.Now()
	exp := now.Add(time.Duration(expiryMinutes) * time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   userID,
		"email": email,
		"exp":   exp.Unix(),
		"iat":   now.Unix(),
	})

	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}
	return signed, nil
}
