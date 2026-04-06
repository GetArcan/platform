package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig configures an LDAP authentication provider.
type LDAPConfig struct {
	Name         string // "corporate-ldap", "active-directory"
	URL          string // "ldaps://ldap.example.com:636" or "ldap://ldap.example.com:389"
	StartTLS     bool   // upgrade plain LDAP to TLS
	SkipVerify   bool   // skip TLS certificate verification (dev only)

	// Bind credentials — service account for user search.
	BindDN       string // "cn=arcan,ou=services,dc=example,dc=com"
	BindPassword string

	// User search.
	BaseDN     string // "ou=users,dc=example,dc=com"
	UserFilter string // "(&(objectClass=person)(sAMAccountName=%s))" — %s replaced with username
	UserAttr   string // attribute for username match (default: "sAMAccountName" for AD, "uid" for OpenLDAP)

	// Attribute mapping.
	EmailAttr string // "mail" (default)
	NameAttr  string // "displayName" (default)
	GroupAttr string // "memberOf" (default, for AD group membership)

	// Group filtering (optional).
	RequiredGroup string // if set, user must be member of this group DN
}

// LDAPClaims holds user information from LDAP authentication.
type LDAPClaims struct {
	DN       string   `json:"dn"`                 // "cn=John Doe,ou=users,dc=example,dc=com"
	Username string   `json:"username"`            // "jdoe"
	Email    string   `json:"email"`               // "jdoe@example.com"
	Name     string   `json:"name"`                // "John Doe"
	Groups   []string `json:"groups,omitempty"`    // ["CN=Developers,OU=Groups,..."]
	Provider string   `json:"provider"`            // "corporate-ldap"
}

// LDAPManager manages LDAP authentication.
type LDAPManager struct {
	configs map[string]*LDAPConfig
}

// NewLDAPManager creates an LDAP manager with the given configurations.
func NewLDAPManager(configs []LDAPConfig) (*LDAPManager, error) {
	m := &LDAPManager{
		configs: make(map[string]*LDAPConfig, len(configs)),
	}

	for i := range configs {
		c := &configs[i]
		if c.Name == "" {
			return nil, fmt.Errorf("LDAP provider at index %d has no name", i)
		}
		if c.URL == "" {
			return nil, fmt.Errorf("LDAP provider %q requires a URL", c.Name)
		}
		if c.BindDN == "" {
			return nil, fmt.Errorf("LDAP provider %q requires a BindDN", c.Name)
		}
		if c.BaseDN == "" {
			return nil, fmt.Errorf("LDAP provider %q requires a BaseDN", c.Name)
		}

		// Set defaults.
		if c.UserAttr == "" {
			c.UserAttr = "sAMAccountName"
		}
		if c.EmailAttr == "" {
			c.EmailAttr = "mail"
		}
		if c.NameAttr == "" {
			c.NameAttr = "displayName"
		}
		if c.GroupAttr == "" {
			c.GroupAttr = "memberOf"
		}
		if c.UserFilter == "" {
			c.UserFilter = fmt.Sprintf("(&(objectClass=person)(%s=%%s))", c.UserAttr)
		}

		m.configs[c.Name] = c
	}

	return m, nil
}

// GetProvider returns a configured LDAP provider by name.
func (m *LDAPManager) GetProvider(name string) (*LDAPConfig, bool) {
	c, ok := m.configs[name]
	return c, ok
}

// ProviderNames returns all configured LDAP provider names (sorted).
func (m *LDAPManager) ProviderNames() []string {
	names := make([]string, 0, len(m.configs))
	for name := range m.configs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Authenticate validates a username and password against the LDAP directory.
// Returns user claims on success, or an error on failure.
//
// Flow:
//  1. Connect to LDAP server (with TLS if configured)
//  2. Bind with service account (BindDN + BindPassword)
//  3. Search for user by username (using UserFilter)
//  4. If user found: attempt bind with user's DN + provided password
//  5. If bind succeeds: read user attributes (email, name, groups)
//  6. If RequiredGroup set: verify group membership
//  7. Return LDAPClaims
func (m *LDAPManager) Authenticate(ctx context.Context, name, username, password string) (*LDAPClaims, error) {
	config, ok := m.configs[name]
	if !ok {
		return nil, fmt.Errorf("unknown LDAP provider %q", name)
	}

	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Step 1: Connect to LDAP server.
	conn, err := dialLDAP(config)
	if err != nil {
		return nil, fmt.Errorf("connecting to LDAP server %s: %w", config.URL, err)
	}
	defer conn.Close()

	// Step 2: Bind with service account.
	if err := conn.Bind(config.BindDN, config.BindPassword); err != nil {
		return nil, fmt.Errorf("service account bind failed — check BindDN and BindPassword: %w", err)
	}

	// Step 3: Search for user.
	filter := FormatLDAPFilter(config.UserFilter, username)
	searchReq := ldap.NewSearchRequest(
		config.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		filter,
		[]string{"dn", config.EmailAttr, config.NameAttr, config.GroupAttr},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("user search failed: %w", err)
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("user %q not found in directory", username)
	}

	entry := result.Entries[0]
	userDN := entry.DN

	// Step 4: Bind as the user to validate password.
	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("authentication failed for user %q", username)
	}

	// Step 5: Read user attributes from search result.
	claims := &LDAPClaims{
		DN:       userDN,
		Username: username,
		Email:    entry.GetAttributeValue(config.EmailAttr),
		Name:     entry.GetAttributeValue(config.NameAttr),
		Groups:   entry.GetAttributeValues(config.GroupAttr),
		Provider: name,
	}

	// Step 6: Check required group membership.
	if config.RequiredGroup != "" {
		if !isMemberOf(claims.Groups, config.RequiredGroup) {
			return nil, fmt.Errorf("user %q is not a member of required group %q", username, config.RequiredGroup)
		}
	}

	return claims, nil
}

// TestConnection verifies connectivity and bind credentials for a provider.
// Useful for `arcan doctor` and setup validation.
func (m *LDAPManager) TestConnection(ctx context.Context, name string) error {
	config, ok := m.configs[name]
	if !ok {
		return fmt.Errorf("unknown LDAP provider %q", name)
	}

	conn, err := dialLDAP(config)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(config.BindDN, config.BindPassword); err != nil {
		return fmt.Errorf("service account bind failed: %w", err)
	}

	return nil
}

// dialLDAP establishes a connection to the LDAP server with TLS if configured.
func dialLDAP(config *LDAPConfig) (*ldap.Conn, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.SkipVerify,
	}

	conn, err := ldap.DialURL(config.URL, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}

	// Upgrade to TLS if StartTLS is requested and URL is plain ldap://.
	if config.StartTLS && strings.HasPrefix(config.URL, "ldap://") {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS upgrade failed: %w", err)
		}
	}

	return conn, nil
}

// FormatLDAPFilter replaces %s in the filter template with the escaped username.
// Exported for testing — ensures LDAP injection prevention via ldap.EscapeFilter.
func FormatLDAPFilter(template, username string) string {
	return strings.ReplaceAll(template, "%s", ldap.EscapeFilter(username))
}

// isMemberOf checks if any group DN matches the required group (case-insensitive).
func isMemberOf(groups []string, requiredGroup string) bool {
	required := strings.ToLower(requiredGroup)
	for _, g := range groups {
		if strings.ToLower(g) == required {
			return true
		}
	}
	return false
}
