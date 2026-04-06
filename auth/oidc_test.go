package auth

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewOIDCManager_EmptyProviders(t *testing.T) {
	// An empty providers list should succeed — no providers to initialize.
	m, err := NewOIDCManager(t.Context(), nil)
	if err != nil {
		t.Fatalf("expected no error for empty providers, got: %v", err)
	}
	if len(m.ProviderNames()) != 0 {
		t.Errorf("expected 0 providers, got %d", len(m.ProviderNames()))
	}
}

func TestNewOIDCManager_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		configs []OIDCProvider
		wantErr string
	}{
		{
			name:    "missing name",
			configs: []OIDCProvider{{Issuer: "https://example.com", ClientID: "id"}},
			wantErr: "has no name",
		},
		{
			name:    "missing issuer",
			configs: []OIDCProvider{{Name: "test", ClientID: "id"}},
			wantErr: "has no issuer URL",
		},
		{
			name:    "missing client ID",
			configs: []OIDCProvider{{Name: "test", Issuer: "https://example.com"}},
			wantErr: "has no client ID",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewOIDCManager(t.Context(), tc.configs)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestOIDCGetProvider_Unknown(t *testing.T) {
	m := &OIDCManager{providers: make(map[string]*OIDCProvider)}
	_, ok := m.GetProvider("nonexistent")
	if ok {
		t.Error("expected ok=false for unknown provider")
	}
}

func TestOIDCProviderNames(t *testing.T) {
	m := &OIDCManager{
		providers: map[string]*OIDCProvider{
			"google": {},
			"okta":   {},
		},
	}

	names := m.ProviderNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 provider names, got %d", len(names))
	}

	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}
	if !nameSet["google"] || !nameSet["okta"] {
		t.Errorf("expected google and okta, got %v", names)
	}
}

func TestAuthURL_UnknownProvider(t *testing.T) {
	m := &OIDCManager{providers: make(map[string]*OIDCProvider)}
	_, _, err := m.AuthURL("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "unknown OIDC provider") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOIDCClaims_JSON(t *testing.T) {
	claims := OIDCClaims{
		Subject:  "user_123",
		Email:    "alice@example.com",
		Name:     "Alice",
		Picture:  "https://example.com/photo.jpg",
		Issuer:   "https://accounts.google.com",
		Provider: "google",
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded OIDCClaims
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Subject != claims.Subject {
		t.Errorf("subject: got %q, want %q", decoded.Subject, claims.Subject)
	}
	if decoded.Email != claims.Email {
		t.Errorf("email: got %q, want %q", decoded.Email, claims.Email)
	}
	if decoded.Provider != claims.Provider {
		t.Errorf("provider: got %q, want %q", decoded.Provider, claims.Provider)
	}
}

func TestOIDCClaims_JSON_OmitEmpty(t *testing.T) {
	claims := OIDCClaims{Subject: "user_123", Email: "a@b.com"}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Picture should be omitted when empty.
	if strings.Contains(string(data), "picture") {
		t.Errorf("expected picture to be omitted, got: %s", data)
	}
}

func TestCheckAllowedDomain(t *testing.T) {
	tests := []struct {
		name           string
		email          string
		allowedDomains []string
		wantErr        bool
	}{
		{
			name:           "no restrictions",
			email:          "alice@example.com",
			allowedDomains: nil,
			wantErr:        false,
		},
		{
			name:           "allowed domain",
			email:          "alice@acme.com",
			allowedDomains: []string{"acme.com"},
			wantErr:        false,
		},
		{
			name:           "allowed domain case insensitive",
			email:          "alice@ACME.COM",
			allowedDomains: []string{"acme.com"},
			wantErr:        false,
		},
		{
			name:           "disallowed domain",
			email:          "alice@other.com",
			allowedDomains: []string{"acme.com", "example.com"},
			wantErr:        true,
		},
		{
			name:           "empty email with restrictions",
			email:          "",
			allowedDomains: []string{"acme.com"},
			wantErr:        true,
		},
		{
			name:           "invalid email",
			email:          "not-an-email",
			allowedDomains: []string{"acme.com"},
			wantErr:        true,
		},
		{
			name:           "multiple allowed domains",
			email:          "bob@example.com",
			allowedDomains: []string{"acme.com", "example.com", "test.org"},
			wantErr:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAllowedDomain(tc.email, tc.allowedDomains)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

func TestGenerateState(t *testing.T) {
	s1, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	if len(s1) != 32 { // 16 bytes -> 32 hex chars
		t.Errorf("expected 32 hex chars, got %d: %q", len(s1), s1)
	}

	// Two calls should produce different values.
	s2, _ := generateState()
	if s1 == s2 {
		t.Error("expected unique state tokens, got duplicates")
	}
}

