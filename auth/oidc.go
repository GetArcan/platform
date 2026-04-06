package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider represents a configured OIDC identity provider.
type OIDCProvider struct {
	Name           string   // "okta", "google", "azure"
	Issuer         string   // https://mycompany.okta.com
	ClientID       string
	ClientSecret   string
	RedirectURL    string   // https://arcan.example.com/api/v1/auth/oidc/{name}/callback
	Scopes         []string // defaults to ["openid", "email", "profile"]
	AllowedDomains []string // restrict to specific email domains (empty = allow all)

	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// OIDCConfig holds configuration for multiple OIDC providers.
type OIDCConfig struct {
	Providers []OIDCProvider
}

// OIDCClaims holds the user information extracted from the ID token.
type OIDCClaims struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Picture  string `json:"picture,omitempty"`
	Issuer   string `json:"iss"`
	Provider string `json:"provider"` // "okta", "google", etc.
}

// OIDCManager manages multiple OIDC providers.
type OIDCManager struct {
	providers map[string]*OIDCProvider
}

// defaultScopes are used when a provider config does not specify scopes.
var defaultScopes = []string{oidc.ScopeOpenID, "email", "profile"}

// NewOIDCManager creates an OIDC manager and initializes all providers.
// For each provider, it performs OIDC discovery (fetches .well-known/openid-configuration)
// to obtain JWKS, authorization, and token endpoints.
func NewOIDCManager(ctx context.Context, configs []OIDCProvider) (*OIDCManager, error) {
	m := &OIDCManager{
		providers: make(map[string]*OIDCProvider, len(configs)),
	}

	for i := range configs {
		cfg := &configs[i]

		if cfg.Name == "" {
			return nil, fmt.Errorf("OIDC provider at index %d has no name", i)
		}
		if cfg.Issuer == "" {
			return nil, fmt.Errorf("OIDC provider %q has no issuer URL", cfg.Name)
		}
		if cfg.ClientID == "" {
			return nil, fmt.Errorf("OIDC provider %q has no client ID", cfg.Name)
		}

		// Discover OIDC configuration from the issuer's .well-known endpoint.
		provider, err := oidc.NewProvider(ctx, cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("OIDC discovery for provider %q (issuer %s) failed: %w", cfg.Name, cfg.Issuer, err)
		}
		cfg.provider = provider

		// Use default scopes if none configured.
		scopes := cfg.Scopes
		if len(scopes) == 0 {
			scopes = defaultScopes
		}

		cfg.oauth2Config = &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		}

		cfg.verifier = provider.Verifier(&oidc.Config{
			ClientID: cfg.ClientID,
		})

		m.providers[cfg.Name] = cfg
	}

	return m, nil
}

// GetProvider returns a configured provider by name.
func (m *OIDCManager) GetProvider(name string) (*OIDCProvider, bool) {
	p, ok := m.providers[name]
	return p, ok
}

// ProviderNames returns all configured provider names.
func (m *OIDCManager) ProviderNames() []string {
	names := make([]string, 0, len(m.providers))
	for name := range m.providers {
		names = append(names, name)
	}
	return names
}

// AuthURL generates the authorization URL for a provider.
// Returns the URL and a state token (random hex string for CSRF protection).
// The caller is responsible for storing the state and validating it on callback.
func (m *OIDCManager) AuthURL(name string) (authURL, state string, err error) {
	p, ok := m.providers[name]
	if !ok {
		return "", "", fmt.Errorf("unknown OIDC provider %q", name)
	}

	state, err = generateState()
	if err != nil {
		return "", "", fmt.Errorf("generating state token: %w", err)
	}

	authURL = p.oauth2Config.AuthCodeURL(state)
	return authURL, state, nil
}

// Exchange handles the callback — exchanges the authorization code for tokens,
// validates the ID token, and extracts user claims.
func (m *OIDCManager) Exchange(ctx context.Context, name, code string) (*OIDCClaims, error) {
	p, ok := m.providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown OIDC provider %q", name)
	}

	// Exchange authorization code for tokens.
	oauth2Token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("OIDC token exchange failed for provider %q: %w", name, err)
	}

	// Extract the ID token from the OAuth2 token response.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("OIDC token response from provider %q missing id_token", name)
	}

	// Verify the ID token signature and claims (issuer, audience, expiry).
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("OIDC ID token verification failed for provider %q: %w", name, err)
	}

	// Parse standard claims from the token.
	var claims OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parsing claims from provider %q: %w", name, err)
	}
	claims.Provider = name

	// Enforce domain restrictions if configured.
	if err := checkAllowedDomain(claims.Email, p.AllowedDomains); err != nil {
		return nil, err
	}

	return &claims, nil
}

// ValidateToken validates a raw OIDC token (typically a Bearer token from an API call)
// against all configured providers. Returns claims from the first provider that
// successfully validates the token. This is used by the middleware for direct
// token authentication (service-to-service calls with an IdP token).
func (m *OIDCManager) ValidateToken(ctx context.Context, rawToken string) (*OIDCClaims, error) {
	var lastErr error
	for name, p := range m.providers {
		idToken, err := p.verifier.Verify(ctx, rawToken)
		if err != nil {
			lastErr = err
			continue
		}

		var claims OIDCClaims
		if err := idToken.Claims(&claims); err != nil {
			lastErr = fmt.Errorf("parsing claims from provider %q: %w", name, err)
			continue
		}
		claims.Provider = name

		if err := checkAllowedDomain(claims.Email, p.AllowedDomains); err != nil {
			lastErr = err
			continue
		}

		return &claims, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("OIDC token validation failed — check issuer and audience configuration: %w", lastErr)
	}
	return nil, fmt.Errorf("no OIDC providers configured for token validation")
}

// checkAllowedDomain validates the email domain against the allowed list.
// Returns nil if no restrictions are set or the domain is allowed.
func checkAllowedDomain(email string, allowedDomains []string) error {
	if len(allowedDomains) == 0 {
		return nil
	}
	if email == "" {
		return fmt.Errorf("OIDC token has no email claim but domain restriction is configured")
	}

	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("OIDC token email %q is not a valid email address", email)
	}
	domain := strings.ToLower(parts[1])

	for _, allowed := range allowedDomains {
		if strings.ToLower(allowed) == domain {
			return nil
		}
	}
	return fmt.Errorf("email domain %q is not in the allowed domains list", domain)
}

// generateState creates a cryptographically random state token for CSRF protection.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

