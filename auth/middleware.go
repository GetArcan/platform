package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/GetArcan/platform/errors"
	"github.com/GetArcan/platform/telemetry"
)

// Middleware validates incoming requests and sets identity in context.
type Middleware struct {
	keyStore    KeyStore
	keyPrefix   string // e.g. "arc_"
	jwtVal      *JWTValidator
	oidcManager *OIDCManager
	samlManager *SAMLManager // SAML SP — login/callback endpoints handled by the product
	ldapManager *LDAPManager // LDAP — login endpoint handled by the product
	anonymous   bool         // allow unauthenticated requests
}

// NewMiddleware creates auth middleware with the given options.
func NewMiddleware(opts ...Option) *Middleware {
	m := &Middleware{}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Handler returns chi-compatible middleware.
// Extracts Bearer token from Authorization header.
// Checks: API key (prefix match) -> JWT -> anonymous (if enabled) -> 401
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)

		// No token provided.
		if token == "" {
			if m.anonymous {
				ctx := m.setContext(r, "", "anonymous")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			errors.WriteJSON(w, r, errors.Unauthorized("missing authorization token").
				WithFix("provide Authorization: Bearer <token> header"))
			return
		}

		// API key path: token starts with the configured prefix.
		if m.keyPrefix != "" && strings.HasPrefix(token, m.keyPrefix) {
			m.handleAPIKey(w, r, next, token)
			return
		}

		// JWT path: token contains dots (header.payload.signature).
		if m.jwtVal != nil && strings.Contains(token, ".") {
			m.handleJWT(w, r, next, token)
			return
		}

		// OIDC path: token contains dots and OIDC manager is configured.
		// This handles tokens from external identity providers (service-to-service).
		if m.oidcManager != nil && strings.Contains(token, ".") {
			m.handleOIDC(w, r, next, token)
			return
		}

		// Fallback: anonymous if enabled, otherwise 401.
		if m.anonymous {
			ctx := m.setContext(r, "", "anonymous")
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		errors.WriteJSON(w, r, errors.Unauthorized("invalid authorization token").
			WithFix("provide a valid API key or JWT token"))
	})
}

func (m *Middleware) handleAPIKey(w http.ResponseWriter, r *http.Request, next http.Handler, token string) {
	if m.keyStore == nil {
		errors.WriteJSON(w, r, errors.Unauthorized("API key authentication not configured"))
		return
	}

	hash := HashKey(token)
	record, err := m.keyStore.LookupKeyHash(r.Context(), hash)
	if err != nil || record == nil {
		errors.WriteJSON(w, r, errors.Unauthorized("invalid API key").
			WithFix("verify the key is correct or generate a new one"))
		return
	}

	// Check expiry.
	if record.ExpiresAt != nil && record.ExpiresAt.Before(time.Now()) {
		errors.WriteJSON(w, r, errors.Unauthorized("API key expired").
			WithFix("generate a new API key"))
		return
	}

	ctx := m.setContext(r, record.UserID, "token")
	next.ServeHTTP(w, r.WithContext(ctx))
}

func (m *Middleware) handleJWT(w http.ResponseWriter, r *http.Request, next http.Handler, token string) {
	subject, err := m.jwtVal.ValidateJWT(token)
	if err != nil {
		errors.WriteJSON(w, r, errors.Unauthorized("invalid JWT: %s", err.Error()).
			WithFix("re-authenticate to obtain a valid token"))
		return
	}

	ctx := m.setContext(r, subject, "jwt")
	next.ServeHTTP(w, r.WithContext(ctx))
}

func (m *Middleware) handleOIDC(w http.ResponseWriter, r *http.Request, next http.Handler, token string) {
	claims, err := m.oidcManager.ValidateToken(r.Context(), token)
	if err != nil {
		errors.WriteJSON(w, r, errors.Unauthorized("OIDC token validation failed — check issuer and audience configuration").
			WithFix("verify the token was issued by a configured identity provider"))
		return
	}

	ctx := m.setContext(r, claims.Subject, "oidc")
	next.ServeHTTP(w, r.WithContext(ctx))
}

func (m *Middleware) setContext(r *http.Request, userID, authMethod string) context.Context {
	rc := telemetry.GetRequestContext(r.Context())
	if rc == nil {
		rc = &telemetry.RequestContext{
			StartTime: time.Now(),
		}
	}
	rc.UserID = userID
	rc.AuthMethod = authMethod
	return telemetry.WithRequestContext(r.Context(), rc)
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}
