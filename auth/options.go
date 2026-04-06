package auth

// Option configures the auth Middleware.
type Option func(*Middleware)

// WithAPIKeyPrefix sets the prefix used to identify API key tokens (e.g. "arc_", "ops_").
func WithAPIKeyPrefix(prefix string) Option {
	return func(m *Middleware) {
		m.keyPrefix = prefix
	}
}

// WithAPIKeyStore sets the database lookup for API key hashes.
func WithAPIKeyStore(store KeyStore) Option {
	return func(m *Middleware) {
		m.keyStore = store
	}
}

// WithJWKS sets the JWKS endpoint URL for RS256/ES256 validation (future).
func WithJWKS(url string) Option {
	return func(m *Middleware) {
		if m.jwtVal == nil {
			m.jwtVal = &JWTValidator{}
		}
		m.jwtVal.jwksURL = url
	}
}

// WithStaticJWTSecret sets a static HS256 secret for JWT validation.
func WithStaticJWTSecret(secret string) Option {
	return func(m *Middleware) {
		m.jwtVal = NewJWTValidator([]byte(secret))
	}
}

// WithK8sAuth enables Kubernetes service account token validation (stub).
func WithK8sAuth() Option {
	return func(m *Middleware) {
		// K8s auth is a stub — no-op until implemented.
	}
}

// WithOIDC adds OIDC authentication support with the given providers.
// The OIDCManager validates Bearer tokens against configured identity providers.
func WithOIDC(manager *OIDCManager) Option {
	return func(m *Middleware) {
		m.oidcManager = manager
	}
}

// WithSAML adds SAML authentication support with the given providers.
// The SAMLManager handles AuthnRequest generation and Response parsing.
// Products wire SAML login/ACS endpoints separately; after SAML login,
// the product creates a session (JWT or cookie) that the existing middleware validates.
func WithSAML(manager *SAMLManager) Option {
	return func(m *Middleware) {
		m.samlManager = manager
	}
}

// WithLDAP adds LDAP authentication support with the given providers.
// The LDAPManager handles username+password authentication against LDAP/AD.
// Products wire a login endpoint (e.g. POST /api/v1/auth/ldap/{name}/login)
// that calls LDAPManager.Authenticate, then creates a JWT session.
func WithLDAP(manager *LDAPManager) Option {
	return func(m *Middleware) {
		m.ldapManager = manager
	}
}

// WithAnonymous controls whether unauthenticated requests are allowed.
func WithAnonymous(allowed bool) Option {
	return func(m *Middleware) {
		m.anonymous = allowed
	}
}
