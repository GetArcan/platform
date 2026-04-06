package auth

import (
	"encoding/json"
	"testing"
)

func TestNewLDAPManager_EmptyConfigs(t *testing.T) {
	m, err := NewLDAPManager(nil)
	if err != nil {
		t.Fatalf("expected no error for empty configs, got: %v", err)
	}
	if len(m.ProviderNames()) != 0 {
		t.Fatalf("expected 0 providers, got %d", len(m.ProviderNames()))
	}
}

func TestNewLDAPManager_ValidatesRequired(t *testing.T) {
	tests := []struct {
		name    string
		config  LDAPConfig
		wantErr string
	}{
		{
			name:    "missing name",
			config:  LDAPConfig{URL: "ldaps://ldap.example.com", BindDN: "cn=svc", BaseDN: "dc=example"},
			wantErr: "has no name",
		},
		{
			name:    "missing URL",
			config:  LDAPConfig{Name: "test", BindDN: "cn=svc", BaseDN: "dc=example"},
			wantErr: "requires a URL",
		},
		{
			name:    "missing BindDN",
			config:  LDAPConfig{Name: "test", URL: "ldaps://ldap.example.com", BaseDN: "dc=example"},
			wantErr: "requires a BindDN",
		},
		{
			name:    "missing BaseDN",
			config:  LDAPConfig{Name: "test", URL: "ldaps://ldap.example.com", BindDN: "cn=svc"},
			wantErr: "requires a BaseDN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewLDAPManager([]LDAPConfig{tt.config})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestNewLDAPManager_SetsDefaults(t *testing.T) {
	m, err := NewLDAPManager([]LDAPConfig{{
		Name:         "ad",
		URL:          "ldaps://ldap.example.com:636",
		BindDN:       "cn=service,dc=example,dc=com",
		BindPassword: "secret",
		BaseDN:       "ou=users,dc=example,dc=com",
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg, ok := m.GetProvider("ad")
	if !ok {
		t.Fatal("expected provider 'ad' to exist")
	}

	if cfg.UserAttr != "sAMAccountName" {
		t.Errorf("expected UserAttr default 'sAMAccountName', got %q", cfg.UserAttr)
	}
	if cfg.EmailAttr != "mail" {
		t.Errorf("expected EmailAttr default 'mail', got %q", cfg.EmailAttr)
	}
	if cfg.NameAttr != "displayName" {
		t.Errorf("expected NameAttr default 'displayName', got %q", cfg.NameAttr)
	}
	if cfg.GroupAttr != "memberOf" {
		t.Errorf("expected GroupAttr default 'memberOf', got %q", cfg.GroupAttr)
	}
	if cfg.UserFilter != "(&(objectClass=person)(sAMAccountName=%s))" {
		t.Errorf("expected default UserFilter, got %q", cfg.UserFilter)
	}
}

func TestLDAPGetProvider_Unknown(t *testing.T) {
	m, _ := NewLDAPManager(nil)
	_, ok := m.GetProvider("nonexistent")
	if ok {
		t.Fatal("expected GetProvider to return false for unknown provider")
	}
}

func TestLDAPProviderNames(t *testing.T) {
	m, err := NewLDAPManager([]LDAPConfig{
		{Name: "beta-ldap", URL: "ldaps://b.example.com", BindDN: "cn=svc", BaseDN: "dc=b"},
		{Name: "alpha-ldap", URL: "ldaps://a.example.com", BindDN: "cn=svc", BaseDN: "dc=a"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	names := m.ProviderNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d", len(names))
	}
	if names[0] != "alpha-ldap" || names[1] != "beta-ldap" {
		t.Errorf("expected sorted names [alpha-ldap, beta-ldap], got %v", names)
	}
}

func TestLDAPClaims_JSON(t *testing.T) {
	claims := &LDAPClaims{
		DN:       "cn=John Doe,ou=users,dc=example,dc=com",
		Username: "jdoe",
		Email:    "jdoe@example.com",
		Name:     "John Doe",
		Groups:   []string{"CN=Developers,OU=Groups,DC=example,DC=com"},
		Provider: "corporate-ldap",
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	var decoded LDAPClaims
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal claims: %v", err)
	}

	if decoded.DN != claims.DN {
		t.Errorf("DN mismatch: got %q", decoded.DN)
	}
	if decoded.Username != claims.Username {
		t.Errorf("Username mismatch: got %q", decoded.Username)
	}
	if decoded.Email != claims.Email {
		t.Errorf("Email mismatch: got %q", decoded.Email)
	}
	if decoded.Provider != claims.Provider {
		t.Errorf("Provider mismatch: got %q", decoded.Provider)
	}
	if len(decoded.Groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(decoded.Groups))
	}
}

func TestLDAPClaims_JSON_OmitsEmptyGroups(t *testing.T) {
	claims := &LDAPClaims{
		DN:       "cn=test",
		Username: "test",
		Provider: "test",
	}

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	if contains(string(data), "groups") {
		t.Error("expected groups to be omitted when empty")
	}
}

func TestFormatLDAPFilter_EscapesInjection(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     string
	}{
		{
			name:     "normal username",
			username: "jdoe",
			want:     "(&(objectClass=person)(sAMAccountName=jdoe))",
		},
		{
			name:     "injection attempt with parentheses",
			username: "jdoe)(|(cn=*)",
			want:     "(&(objectClass=person)(sAMAccountName=jdoe\\29\\28|\\28cn=\\2a\\29))",
		},
		{
			name:     "injection attempt with asterisk",
			username: "*",
			want:     "(&(objectClass=person)(sAMAccountName=\\2a))",
		},
		{
			name:     "injection attempt with backslash",
			username: "admin\\",
			want:     "(&(objectClass=person)(sAMAccountName=admin\\5c))",
		},
		{
			name:     "injection attempt with null byte",
			username: "admin\x00",
			want:     "(&(objectClass=person)(sAMAccountName=admin\\00))",
		},
	}

	template := "(&(objectClass=person)(sAMAccountName=%s))"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatLDAPFilter(template, tt.username)
			if got != tt.want {
				t.Errorf("FormatLDAPFilter(%q) = %q, want %q", tt.username, got, tt.want)
			}
		})
	}
}

func TestIsMemberOf(t *testing.T) {
	groups := []string{
		"CN=Developers,OU=Groups,DC=example,DC=com",
		"CN=VPN-Users,OU=Groups,DC=example,DC=com",
	}

	if !isMemberOf(groups, "CN=Developers,OU=Groups,DC=example,DC=com") {
		t.Error("expected membership match for exact case")
	}
	if !isMemberOf(groups, "cn=developers,ou=groups,dc=example,dc=com") {
		t.Error("expected case-insensitive membership match")
	}
	if isMemberOf(groups, "CN=Admins,OU=Groups,DC=example,DC=com") {
		t.Error("expected no match for non-member group")
	}
	if isMemberOf(nil, "CN=Developers,OU=Groups,DC=example,DC=com") {
		t.Error("expected no match for nil groups")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
