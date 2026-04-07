package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSplitAndCombine_3of5(t *testing.T) {
	secret := []byte("this-is-a-test-secret-value!!")

	shares, err := SplitKey(secret, 5, 3)
	if err != nil {
		t.Fatalf("SplitKey: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	// Verify each share has the correct length: secret + 1 byte index.
	for i, s := range shares {
		if len(s) != len(secret)+1 {
			t.Errorf("share %d: expected length %d, got %d", i, len(secret)+1, len(s))
		}
		if s[0] != byte(i+1) {
			t.Errorf("share %d: expected index %d, got %d", i, i+1, s[0])
		}
	}

	// Reconstruct with the first 3 shares.
	reconstructed, err := CombineShares(shares[:3])
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}
	if !bytes.Equal(reconstructed, secret) {
		t.Errorf("reconstructed secret mismatch: got %q, want %q", reconstructed, secret)
	}
}

func TestAnyKSharesReconstruct(t *testing.T) {
	secret := []byte("any-k-shares-should-work")
	n, k := 5, 3

	shares, err := SplitKey(secret, n, k)
	if err != nil {
		t.Fatalf("SplitKey: %v", err)
	}

	// Try all C(5,3) = 10 combinations of 3 shares.
	combos := [][3]int{
		{0, 1, 2}, {0, 1, 3}, {0, 1, 4}, {0, 2, 3}, {0, 2, 4},
		{0, 3, 4}, {1, 2, 3}, {1, 2, 4}, {1, 3, 4}, {2, 3, 4},
	}

	for _, c := range combos {
		subset := [][]byte{shares[c[0]], shares[c[1]], shares[c[2]]}
		reconstructed, err := CombineShares(subset)
		if err != nil {
			t.Errorf("CombineShares(%v): %v", c, err)
			continue
		}
		if !bytes.Equal(reconstructed, secret) {
			t.Errorf("CombineShares(%v): mismatch, got %q", c, reconstructed)
		}
	}
}

func TestFewerThanKSharesFail(t *testing.T) {
	secret := []byte("need-at-least-k")
	n, k := 5, 3

	shares, err := SplitKey(secret, n, k)
	if err != nil {
		t.Fatalf("SplitKey: %v", err)
	}

	// Try with only 2 shares (k=3 required). This should produce wrong output
	// (not an error — Lagrange interpolation will work but give the wrong answer).
	reconstructed, err := CombineShares(shares[:2])
	if err != nil {
		t.Fatalf("CombineShares should not error with 2 shares: %v", err)
	}
	if bytes.Equal(reconstructed, secret) {
		t.Error("reconstructed with fewer than k shares should NOT match the secret")
	}
}

func TestEdgeCase_2of2(t *testing.T) {
	secret := []byte("two-of-two")

	shares, err := SplitKey(secret, 2, 2)
	if err != nil {
		t.Fatalf("SplitKey: %v", err)
	}
	if len(shares) != 2 {
		t.Fatalf("expected 2 shares, got %d", len(shares))
	}

	reconstructed, err := CombineShares(shares)
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}
	if !bytes.Equal(reconstructed, secret) {
		t.Errorf("mismatch: got %q, want %q", reconstructed, secret)
	}
}

func TestEdgeCase_KEquals1_Rejected(t *testing.T) {
	secret := []byte("degenerate")

	_, err := SplitKey(secret, 1, 1)
	if err == nil {
		t.Fatal("SplitKey should reject k=1")
	}
}

func TestAES256Key(t *testing.T) {
	// Test with a 32-byte key (AES-256 size).
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generating random key: %v", err)
	}

	shares, err := SplitKey(key, 5, 3)
	if err != nil {
		t.Fatalf("SplitKey: %v", err)
	}

	// Reconstruct with shares 1, 3, 5.
	subset := [][]byte{shares[0], shares[2], shares[4]}
	reconstructed, err := CombineShares(subset)
	if err != nil {
		t.Fatalf("CombineShares: %v", err)
	}
	if !bytes.Equal(reconstructed, key) {
		t.Errorf("32-byte key reconstruction failed")
	}
}

func TestSplitKey_InvalidParams(t *testing.T) {
	secret := []byte("test")

	tests := []struct {
		name string
		n, k int
	}{
		{"k < 2", 3, 1},
		{"n < k", 2, 3},
		{"n > 255", 256, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SplitKey(secret, tt.n, tt.k)
			if err == nil {
				t.Errorf("expected error for n=%d, k=%d", tt.n, tt.k)
			}
		})
	}
}

func TestSplitKey_EmptySecret(t *testing.T) {
	_, err := SplitKey([]byte{}, 3, 2)
	if err == nil {
		t.Error("expected error for empty secret")
	}
}

func TestGF256Arithmetic(t *testing.T) {
	// Verify basic GF(256) properties.

	// a + a = 0 (characteristic 2)
	for a := 0; a < 256; a++ {
		if gf256Add(byte(a), byte(a)) != 0 {
			t.Errorf("gf256Add(%d, %d) != 0", a, a)
		}
	}

	// a * 1 = a
	for a := 0; a < 256; a++ {
		if gf256Mul(byte(a), 1) != byte(a) {
			t.Errorf("gf256Mul(%d, 1) != %d", a, a)
		}
	}

	// a * inv(a) = 1 for a != 0
	for a := 1; a < 256; a++ {
		inv := gf256Inv(byte(a))
		product := gf256Mul(byte(a), inv)
		if product != 1 {
			t.Errorf("gf256Mul(%d, inv(%d)=%d) = %d, want 1", a, a, inv, product)
		}
	}
}
