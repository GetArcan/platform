package auth

import (
	"encoding/json"
	"testing"

	"github.com/crewjam/saml"
)

func TestNewSAMLManager_Empty(t *testing.T) {
	m, err := NewSAMLManager(nil)
	if err != nil {
		t.Fatalf("NewSAMLManager(nil): %v", err)
	}
	if len(m.ProviderNames()) != 0 {
		t.Errorf("expected 0 providers, got %d", len(m.ProviderNames()))
	}
}

func TestNewSAMLManager_MissingName(t *testing.T) {
	_, err := NewSAMLManager([]SAMLProvider{
		{ACSURL: "https://example.com/saml/acs"},
	})
	if err == nil {
		t.Error("expected error for provider with no name")
	}
}

func TestNewSAMLManager_MissingACSURL(t *testing.T) {
	_, err := NewSAMLManager([]SAMLProvider{
		{Name: "test"},
	})
	if err == nil {
		t.Error("expected error for provider with no ACS URL")
	}
}

func TestNewSAMLManager_MissingMetadata(t *testing.T) {
	_, err := NewSAMLManager([]SAMLProvider{
		{Name: "test", ACSURL: "https://example.com/saml/acs"},
	})
	if err == nil {
		t.Error("expected error when neither MetadataURL nor MetadataFile is provided")
	}
}

func TestSAMLGetProvider_Unknown(t *testing.T) {
	m, err := NewSAMLManager(nil)
	if err != nil {
		t.Fatalf("NewSAMLManager: %v", err)
	}
	_, ok := m.GetProvider("nonexistent")
	if ok {
		t.Error("expected ok=false for unknown provider")
	}
}

func TestProviderNames_Sorted(t *testing.T) {
	m := &SAMLManager{
		providers: map[string]*SAMLProvider{
			"zebra":     {},
			"alpha":     {},
			"corporate": {},
		},
	}
	names := m.ProviderNames()
	if len(names) != 3 {
		t.Fatalf("expected 3 names, got %d", len(names))
	}
	if names[0] != "alpha" || names[1] != "corporate" || names[2] != "zebra" {
		t.Errorf("names not sorted: %v", names)
	}
}

func TestSAMLClaims_JSON(t *testing.T) {
	claims := &SAMLClaims{
		NameID:    "user@corp.com",
		Email:     "user@corp.com",
		Name:      "Test User",
		Groups:    []string{"engineering"},
		Provider:  "okta-saml",
		SessionID: "sess-123",
		Attributes: map[string]string{
			"department": "engineering",
		},
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded SAMLClaims
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if decoded.Email != "user@corp.com" {
		t.Errorf("Email = %q, want %q", decoded.Email, "user@corp.com")
	}
	if decoded.Provider != "okta-saml" {
		t.Errorf("Provider = %q, want %q", decoded.Provider, "okta-saml")
	}
	if decoded.Attributes["department"] != "engineering" {
		t.Errorf("Attributes[department] = %q, want %q", decoded.Attributes["department"], "engineering")
	}
}

func TestMapSAMLAttributes_Standard(t *testing.T) {
	assertion := &saml.Assertion{
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{
					{
						Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
						Values: []saml.AttributeValue{
							{Value: "alice@corp.com"},
						},
					},
					{
						Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
						Values: []saml.AttributeValue{
							{Value: "Alice"},
						},
					},
					{
						Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
						Values: []saml.AttributeValue{
							{Value: "Smith"},
						},
					},
					{
						Name:         "department",
						FriendlyName: "department",
						Values: []saml.AttributeValue{
							{Value: "eng"},
						},
					},
				},
			},
		},
	}

	attrs := mapSAMLAttributes(assertion)

	if attrs["email"] != "alice@corp.com" {
		t.Errorf("email = %q, want %q", attrs["email"], "alice@corp.com")
	}
	if attrs["first_name"] != "Alice" {
		t.Errorf("first_name = %q, want %q", attrs["first_name"], "Alice")
	}
	if attrs["last_name"] != "Smith" {
		t.Errorf("last_name = %q, want %q", attrs["last_name"], "Smith")
	}
	if attrs["department"] != "eng" {
		t.Errorf("department = %q, want %q", attrs["department"], "eng")
	}
}

func TestMapSAMLAttributes_Empty(t *testing.T) {
	assertion := &saml.Assertion{}
	attrs := mapSAMLAttributes(assertion)
	if len(attrs) != 0 {
		t.Errorf("expected empty map, got %v", attrs)
	}
}

func TestMapAssertionToClaims_NameFallback(t *testing.T) {
	assertion := &saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: "user@example.com"},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{
					{
						Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
						Values: []saml.AttributeValue{
							{Value: "Bob"},
						},
					},
					{
						Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
						Values: []saml.AttributeValue{
							{Value: "Jones"},
						},
					},
				},
			},
		},
	}

	claims := mapAssertionToClaims(assertion, "test-idp")
	if claims.Name != "Bob Jones" {
		t.Errorf("Name = %q, want %q", claims.Name, "Bob Jones")
	}
	// No explicit email attribute — should fall back to NameID.
	if claims.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", claims.Email, "user@example.com")
	}
	if claims.Provider != "test-idp" {
		t.Errorf("Provider = %q, want %q", claims.Provider, "test-idp")
	}
}
