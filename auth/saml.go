package auth

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// SAMLProvider represents a configured SAML identity provider.
type SAMLProvider struct {
	Name         string // "corporate", "okta-saml"
	ACSURL       string // Assertion Consumer Service URL (our callback)
	MetadataURL  string // IdP metadata URL (preferred — auto-fetches config)
	MetadataFile string // OR: path to IdP metadata XML file
	EntityID     string // Our SP entity ID (defaults to ACSURL)
	CertFile     string // SP certificate for signing/encryption (optional)
	KeyFile      string // SP private key (optional)

	sp *saml.ServiceProvider
}

// SAMLConfig holds configuration for multiple SAML providers.
type SAMLConfig struct {
	Providers []SAMLProvider
}

// SAMLClaims holds user information extracted from the SAML assertion.
type SAMLClaims struct {
	NameID     string            `json:"name_id"`              // unique identifier
	Email      string            `json:"email"`
	Name       string            `json:"name"`
	Groups     []string          `json:"groups,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Provider   string            `json:"provider"` // "corporate", "okta-saml"
	SessionID  string            `json:"session_id"`
}

// Standard SAML attribute names mapped to friendly field names.
var samlAttributeMap = map[string]string{
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         "name",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":     "first_name",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":       "last_name",
	"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups":      "groups",
	"email": "email",
	"name":  "name",
}

// SAMLManager manages multiple SAML identity providers.
type SAMLManager struct {
	providers map[string]*SAMLProvider
}

// NewSAMLManager creates a SAML manager and initializes all providers.
func NewSAMLManager(configs []SAMLProvider) (*SAMLManager, error) {
	m := &SAMLManager{
		providers: make(map[string]*SAMLProvider, len(configs)),
	}

	for i := range configs {
		p := &configs[i]
		if p.Name == "" {
			return nil, fmt.Errorf("SAML provider at index %d has no name", i)
		}
		if p.ACSURL == "" {
			return nil, fmt.Errorf("SAML provider %q requires an ACS URL", p.Name)
		}

		sp, err := buildServiceProvider(p)
		if err != nil {
			return nil, fmt.Errorf("initializing SAML provider %q: %w", p.Name, err)
		}
		p.sp = sp
		m.providers[p.Name] = p
	}

	return m, nil
}

// buildServiceProvider constructs a saml.ServiceProvider from provider config.
func buildServiceProvider(p *SAMLProvider) (*saml.ServiceProvider, error) {
	// Parse ACS URL.
	acsURL, err := url.Parse(p.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ACS URL: %w", err)
	}

	// Determine entity ID.
	entityID := p.EntityID
	if entityID == "" {
		entityID = p.ACSURL
	}

	// Load SP certificate and key (optional).
	var cert *x509.Certificate
	var key *rsa.PrivateKey
	if p.CertFile != "" && p.KeyFile != "" {
		tlsCert, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading SP certificate/key: %w", err)
		}
		cert, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parsing SP certificate: %w", err)
		}
		rsaKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("SP private key must be RSA")
		}
		key = rsaKey
	}

	// Load IdP metadata.
	idpDescriptor, err := loadIDPMetadata(p)
	if err != nil {
		return nil, fmt.Errorf("loading IdP metadata: %w", err)
	}

	sp := &saml.ServiceProvider{
		EntityID:          entityID,
		AcsURL:            *acsURL,
		IDPMetadata:       idpDescriptor,
		Certificate:       cert,
		Key:               key,
		AllowIDPInitiated: true,
	}

	return sp, nil
}

// loadIDPMetadata fetches or reads IdP metadata.
func loadIDPMetadata(p *SAMLProvider) (*saml.EntityDescriptor, error) {
	if p.MetadataURL != "" {
		mdURL, err := url.Parse(p.MetadataURL)
		if err != nil {
			return nil, fmt.Errorf("invalid metadata URL: %w", err)
		}
		entity, err := samlsp.FetchMetadata(
			context.Background(),
			http.DefaultClient,
			*mdURL,
		)
		if err != nil {
			return nil, fmt.Errorf("fetching IdP metadata from %s: %w", p.MetadataURL, err)
		}
		return entity, nil
	}

	if p.MetadataFile != "" {
		data, err := os.ReadFile(p.MetadataFile)
		if err != nil {
			return nil, fmt.Errorf("reading metadata file %s: %w", p.MetadataFile, err)
		}
		entity := &saml.EntityDescriptor{}
		if err := xml.Unmarshal(data, entity); err != nil {
			return nil, fmt.Errorf("parsing metadata XML: %w", err)
		}
		return entity, nil
	}

	return nil, fmt.Errorf("either MetadataURL or MetadataFile is required")
}

// GetProvider returns a configured SAML provider by name.
func (m *SAMLManager) GetProvider(name string) (*SAMLProvider, bool) {
	p, ok := m.providers[name]
	return p, ok
}

// AuthnRequest generates a SAML AuthnRequest URL to redirect the user to the IdP.
func (m *SAMLManager) AuthnRequest(name string) (redirectURL string, err error) {
	p, ok := m.providers[name]
	if !ok {
		return "", fmt.Errorf("unknown SAML provider %q", name)
	}

	authnReq, err := p.sp.MakeAuthenticationRequest(
		p.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return "", fmt.Errorf("creating AuthnRequest for provider %q: %w", name, err)
	}

	redirectTo, err := authnReq.Redirect("", p.sp)
	if err != nil {
		return "", fmt.Errorf("building redirect URL for provider %q: %w", name, err)
	}

	return redirectTo.String(), nil
}

// ParseResponse handles the SAML Response from the IdP.
// Validates the assertion, extracts user attributes, returns claims.
func (m *SAMLManager) ParseResponse(name string, r *http.Request) (*SAMLClaims, error) {
	p, ok := m.providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown SAML provider %q", name)
	}

	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("parsing form data: %w", err)
	}

	assertion, err := p.sp.ParseResponse(r, []string{""})
	if err != nil {
		return nil, fmt.Errorf("SAML assertion validation failed for provider %s — check IdP metadata and time sync: %w", name, err)
	}

	claims := mapAssertionToClaims(assertion, name)
	return claims, nil
}

// mapAssertionToClaims extracts user information from a validated SAML assertion.
func mapAssertionToClaims(assertion *saml.Assertion, provider string) *SAMLClaims {
	claims := &SAMLClaims{
		Provider:   provider,
		Attributes: make(map[string]string),
	}

	// Extract NameID.
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		claims.NameID = assertion.Subject.NameID.Value
	}

	// Extract session ID from AuthnStatement.
	for _, stmt := range assertion.AuthnStatements {
		if stmt.SessionIndex != "" {
			claims.SessionID = stmt.SessionIndex
			break
		}
	}

	// Extract and map attributes.
	attrs := mapSAMLAttributes(assertion)
	claims.Attributes = attrs

	if v, ok := attrs["email"]; ok {
		claims.Email = v
	}
	// Build display name from available attributes.
	if v, ok := attrs["name"]; ok {
		claims.Name = v
	} else {
		first := attrs["first_name"]
		last := attrs["last_name"]
		if first != "" || last != "" {
			claims.Name = first
			if last != "" {
				if claims.Name != "" {
					claims.Name += " "
				}
				claims.Name += last
			}
		}
	}
	if v, ok := attrs["groups"]; ok && v != "" {
		claims.Groups = []string{v}
	}

	// Fall back: if email is empty but NameID looks like an email, use it.
	if claims.Email == "" && claims.NameID != "" {
		claims.Email = claims.NameID
	}

	return claims
}

// mapSAMLAttributes extracts attributes from a SAML assertion and maps
// standard attribute URIs to friendly names.
func mapSAMLAttributes(assertion *saml.Assertion) map[string]string {
	result := make(map[string]string)

	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			// Get the first value.
			val := ""
			if len(attr.Values) > 0 {
				val = attr.Values[0].Value
			}

			// Map by standard name.
			if friendly, ok := samlAttributeMap[attr.Name]; ok {
				result[friendly] = val
			}
			// Also map by FriendlyName if provided.
			if attr.FriendlyName != "" {
				if friendly, ok := samlAttributeMap[attr.FriendlyName]; ok {
					result[friendly] = val
				}
			}

			// Store raw attribute by name.
			result[attr.Name] = val
		}
	}

	return result
}

// ProviderNames returns all configured provider names (sorted).
func (m *SAMLManager) ProviderNames() []string {
	names := make([]string, 0, len(m.providers))
	for name := range m.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Metadata returns the SP metadata XML for a provider.
// The admin downloads this and uploads it to their IdP.
func (m *SAMLManager) Metadata(name string) ([]byte, error) {
	p, ok := m.providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown SAML provider %q", name)
	}

	md := p.sp.Metadata()
	data, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling SP metadata for provider %q: %w", name, err)
	}

	return data, nil
}
