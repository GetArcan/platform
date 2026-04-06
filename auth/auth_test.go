package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GetArcan/platform/telemetry"
)

// Compile-time interface checks.
var _ KeyStore = (*MockKeyStore)(nil)

func TestGenerateAPIKey_Prefix(t *testing.T) {
	key, hash, err := GenerateAPIKey("test_")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if !strings.HasPrefix(key, "test_") {
		t.Errorf("key should start with 'test_', got %q", key)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Errorf("hash should start with 'sha256:', got %q", hash)
	}
	// 32 bytes = 64 hex chars + prefix
	if len(key) != len("test_")+64 {
		t.Errorf("unexpected key length: %d", len(key))
	}
}

func TestGenerateAPIKey_Unique(t *testing.T) {
	key1, _, err := GenerateAPIKey("k_")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	key2, _, err := GenerateAPIKey("k_")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if key1 == key2 {
		t.Error("two generated keys should not be equal")
	}
}

func TestHashKey_Deterministic(t *testing.T) {
	key := "test_abc123"
	h1 := HashKey(key)
	h2 := HashKey(key)
	if h1 != h2 {
		t.Errorf("HashKey should be deterministic: %q != %q", h1, h2)
	}
}

func TestJWT_RoundTrip(t *testing.T) {
	secret := []byte("test-secret-key")
	userID := "user-123"
	email := "test@example.com"

	token, err := GenerateJWT(secret, userID, email, 60)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	v := NewJWTValidator(secret)
	sub, err := v.ValidateJWT(token)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}
	if sub != userID {
		t.Errorf("subject = %q, want %q", sub, userID)
	}
}

func TestJWT_Expired(t *testing.T) {
	secret := []byte("test-secret-key")
	// Generate with -1 minute expiry (already expired).
	token, err := GenerateJWT(secret, "user-1", "a@b.com", -1)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	v := NewJWTValidator(secret)
	_, err = v.ValidateJWT(token)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestJWT_WrongSecret(t *testing.T) {
	token, err := GenerateJWT([]byte("secret-a"), "user-1", "a@b.com", 60)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	v := NewJWTValidator([]byte("secret-b"))
	_, err = v.ValidateJWT(token)
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestMiddleware_ValidAPIKey(t *testing.T) {
	store := NewMockKeyStore()
	key := store.AddKey("tk_", "user-42", []string{"read", "write"})

	m := NewMiddleware(
		WithAPIKeyPrefix("tk_"),
		WithAPIKeyStore(store),
	)

	var gotRC *telemetry.RequestContext
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRC = telemetry.GetRequestContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotRC == nil {
		t.Fatal("RequestContext not set")
	}
	if gotRC.UserID != "user-42" {
		t.Errorf("UserID = %q, want %q", gotRC.UserID, "user-42")
	}
	if gotRC.AuthMethod != "token" {
		t.Errorf("AuthMethod = %q, want %q", gotRC.AuthMethod, "token")
	}
}

func TestMiddleware_ExpiredAPIKey(t *testing.T) {
	store := NewMockKeyStore()
	key := store.AddKey("tk_", "user-1", nil)

	// Set expiry in the past.
	hash := HashKey(key)
	store.mu.Lock()
	past := time.Now().Add(-1 * time.Hour)
	store.keys[hash].ExpiresAt = &past
	store.mu.Unlock()

	m := NewMiddleware(
		WithAPIKeyPrefix("tk_"),
		WithAPIKeyStore(store),
	)

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for expired key")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMiddleware_ValidJWT(t *testing.T) {
	secret := "jwt-secret"
	token, err := GenerateJWT([]byte(secret), "user-jwt-1", "test@example.com", 60)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	m := NewMiddleware(WithStaticJWTSecret(secret))

	var gotRC *telemetry.RequestContext
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRC = telemetry.GetRequestContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotRC == nil {
		t.Fatal("RequestContext not set")
	}
	if gotRC.UserID != "user-jwt-1" {
		t.Errorf("UserID = %q, want %q", gotRC.UserID, "user-jwt-1")
	}
	if gotRC.AuthMethod != "jwt" {
		t.Errorf("AuthMethod = %q, want %q", gotRC.AuthMethod, "jwt")
	}
}

func TestMiddleware_NoToken_AnonymousAllowed(t *testing.T) {
	m := NewMiddleware(WithAnonymous(true))

	var gotRC *telemetry.RequestContext
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRC = telemetry.GetRequestContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotRC == nil {
		t.Fatal("RequestContext not set")
	}
	if gotRC.AuthMethod != "anonymous" {
		t.Errorf("AuthMethod = %q, want %q", gotRC.AuthMethod, "anonymous")
	}
}

func TestMiddleware_NoToken_AnonymousDisabled(t *testing.T) {
	m := NewMiddleware(WithAnonymous(false))

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without token")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMockKeyStore_AddAndLookup(t *testing.T) {
	store := NewMockKeyStore()
	key := store.AddKey("mk_", "user-99", []string{"read"})

	hash := HashKey(key)
	rec, err := store.LookupKeyHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("LookupKeyHash: %v", err)
	}
	if rec.UserID != "user-99" {
		t.Errorf("UserID = %q, want %q", rec.UserID, "user-99")
	}
	if len(rec.Capabilities) != 1 || rec.Capabilities[0] != "read" {
		t.Errorf("Capabilities = %v, want [read]", rec.Capabilities)
	}
}

func TestMockKeyStore_LookupMissing(t *testing.T) {
	store := NewMockKeyStore()
	_, err := store.LookupKeyHash(context.Background(), "sha256:nonexistent")
	if err == nil {
		t.Error("expected error for missing key")
	}
}
